
# Import Django utilities for rendering templates, redirecting URLs, and handling HTTP responses.
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.http import JsonResponse

# Import authentication and authorization utilities to manage user sessions and access control.
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User

# Import Django's messaging framework to provide feedback to users about actions (e.g., errors, success messages).
from django.contrib import messages

# Import form handling utilities from Django to manage form submissions and validations.
from .forms import RegistrationForm, CodeForm, UrlForm

# Import utilities for handling CSRF protection to secure form submissions against CSRF attacks.
from django.views.decorators.csrf import csrf_exempt
from django.middleware.csrf import CsrfViewMiddleware
from django.middleware.csrf import get_token

# Import email utilities to send emails from within Django.
from django.core.mail import send_mail
from email.mime.text import MIMEText

# Import Django utilities to manage and manipulate template contexts and content safely.
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.html import escape, strip_tags

# Import model and utility functions specific to the application for managing scans and validations.
from .models import ScanResult
from .utils import fetch_url, detect_xss_vulnerability, detect_sql_injection
from codepulse.validators import CustomPasswordValidator

# Import standard libraries and third-party libraries for additional functionalities.
import random
import smtplib
import logging
import re
import bleach  # Used to sanitize HTML inputs effectively to prevent XSS attacks.

# Import Django's exception classes to handle specific exceptions such as validation errors.
from django.core.exceptions import ValidationError

# Import Django utility to fetch an object from the database or raise a 404 error if not found.
from django.shortcuts import get_object_or_404


# Set up logging for error tracking and debugging.
logger = logging.getLogger(__name__)

# Views for the application

# View function to handle the home page request. Simply renders the 'home.html' template.
def home(request):
    # Simple view that renders the home page template
    return render(request, 'home.html')

# View function for the 'About' page, rendering the 'about.html' template.
def about(request):
    # Simple view that renders the about page template
    return render(request, 'about.html')

# This handels the registration process of users via form submissions.
def register(request):
    # This check if the form was submitted using POST method.
    if request.method == 'POST':
        # This Extract data from form fields submitted by the user.
        username = request.POST.get('username')
        password = request.POST.get('password1')
        email = request.POST.get('email')
        confirm_password = request.POST.get('password2')
      
        # This validate that all fields contain data.
        if not (username and password and email):
            messages.error(request, "Missing fields in the form.")
            return render(request, 'register.html')

        # Check if passwords match
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'register.html')

        # Initialize and apply custom password validator
        password_validator = CustomPasswordValidator()
        try:
            # This will raise a ValidationError if the password fails any checks
            password_validator.validate(password)
        except ValidationError as e:
            messages.error(request, str(e))
            return render(request, 'register.html')

        # This attempt to create a new user and send a verification email.
        try:
            user = User.objects.create_user(username=username, email=email)
            user.set_password(password)  # This ensures that the password is correctly set & Securely set user's password.
            user.is_active = False  # The user will not be active until they verify their email.
            user.save() # This saves the user object in the database.

            # This simply generate a random verification code to be sent to the user.
            verification_code = random.randint(100000, 999999)
            request.session['user_id'] = user.id
            request.session['verification_code'] = verification_code
            
            if send_verification_email(user, verification_code): # This sends the verification email function call.
                messages.success(request, 'Please check your email to confirm your registration.')
                return redirect('verify_email')  # This will then redirect to the email verification page
            else:
                messages.error(request, 'Failed to send verification email. Please try registering again.')
                user.delete()  # this deletes the user if email sending fails
        except Exception as e:
            messages.error(request, f'Registration failed: {e}')
            # If not a POST request, just show the registration form.
            return render(request, 'register.html')
    else:
        return render(request, 'register.html')


# this handles the verification of email through a code sent to the user.
def verify_email(request):
    # this checks if the current request method is POST, meansing data has been submitted to the server.
    if request.method == 'POST':
        # Retrieve code from user input and session.
        user_input_code = request.POST.get('code')
        verification_code = request.session.get('verification_code')
        user_id = request.session.get('user_id')

        # this is Logging session and verification data - attempt details for debugging purposes
        logger.info(f"Verifying email: session data - user ID {user_id}, code {verification_code}")

        # this validates that all required information (code, and user ID) is present.
        if not all([user_input_code, verification_code, user_id]):
            messages.error(request, "Missing information required for verification.")
            return redirect('register')

        # Log available users in database for debugging
        users = User.objects.all()
        logger.info(f"Available users: {[user.username for user in users]}")

        try:
            # This attempts to fetch the user based on the user ID stored in the session.
            user = get_object_or_404(User, id=user_id)
            # this checks if the input code matches the session code.
            if user_input_code == str(verification_code):
                user.is_active = True #this marks the user as active (successfull email verification)
                user.save() # this saves the user and updates to the database.
                # this logs the user in automatically after email verification.
                login(request, user) 
                # this clears the session of the verification data to prevent reuse. 
                del request.session['verification_code']
                del request.session['user_id']
                # this then notifies the user of successful email verification and redirect to the 'scanner' view.
                messages.success(request, 'Email verified successfully!')
                return redirect('scanner')
            else:
                # If verification codes do not match, render the verification page with an error.
                messages.error(request, 'Invalid verification code.')
                return render(request, 'verify_email.html')
        except User.DoesNotExist:
            # this handles the case where the user ID does not correspond to any user in the database.
            messages.error(request, "No such user exists.")
            return redirect('register')
        except Exception as e:
            # this catchs all other exceptions and log them, providing a generic error message to the user.
            messages.error(request, f"Error during verification: {e}")
            return render(request, 'verify_email.html')
    else:
        # If the request method is not POST, simply render the email verification page.
        return render(request, 'verify_email.html')


# this function sends a verification email with SMTP protocol.
def send_verification_email(user, verification_code):
    # this checks if the user object has an email attribute that's not empty
    if not user.email:
        # this logs an error if the user object doesn't have an email address
        logger.error("No email address provided for user.")
        # means the user will exit the function returning False (email could not be sent)
        return False

    try:
        # this formats the message string with the verification code included
        message = f'Your verification code is: {verification_code}'
        # this makes a MIMEText object to specify the contents, type, and encoding of the email        
        msg = MIMEText(message, 'plain', 'utf-8')  
        # sets the subject line of the email
        msg['Subject'] = 'Verify Your Email'
        # sets the sender's email address
        msg['From'] = 'proyectostito12@gmail.com'
        # sets the recipient's email address
        msg['To'] = user.email

        # Logging the email details to ensure correctness
        logger.info(f"Email details: From: {msg['From']}, To: {msg['To']}")

        # this is to set up the SMTP server and establish a connection to the SMTP server at the specified address and port
        s = smtplib.SMTP('smtp.gmail.com', 587)
        s.starttls()  # Start TLS for security & Encrypt connection for security.
        s.login('proyectostito12@gmail.com', 'hnovcndqjdatddun')   # Log into the email server.
        s.sendmail(msg['From'], [msg['To']], msg.as_string()) # Send the email.
        s.quit() # this is to terminate the connection to the server.
        # this shows the successful sending of the email
        logger.info(f"Email sent to {user.email} with verification code {verification_code}")
        # this returns True indicating the email was successfully sent
        return True
    except Exception as e:
        # this catchs any exceptions during the email sending process and log an error
        logger.error(f"Failed to send email to {user.email}: {e}")
        # this return False indicating that sending the email failed
        return False

# This handles user login, authenticating credentials against the database.
def user_login(request):
    # This handles user login - checks if the current request is a POST request. 
    # This is necessary because sensitive data such as usernames and passwords 
    # should be sent via POST requests to ensure they are not visible in the URL.
    if request.method == "POST":
        # this retrieves the username and password from the POST request. 
        # these are expected to be provided by a login form where users enter their credentials.
        username = request.POST.get('username')
        password = request.POST.get('password')
        # this Uses Django's built-in `authenticate` method to verify the credentials. 
        # If the credentials are valid, it returns a User object. Otherwise, it returns None.
        user = authenticate(username=username, password=password) # Authenticate user.
        if user:
            # the `login` function from Django's auth module is called with the request and User object. 
            # this officially logs the user into the system, creating the appropriate session data.
            login(request, user) # Log the user in.
            # After successful login, redirect the user to scanner page. 
            #Here it redirects to a page named 'scanner'.
            return redirect('scanner') 
        else:
            # If authentication fails, display an error message and redirect back to the login form.            
            return render(request, 'login.html', {'error': 'Bad credentials, please try again'}, status=200)
    return render(request, 'login.html')


@login_required
def scanner(request):
    # this views function handles the scanning of code input for XSS and SQL injection vulnerabilities.
    # only allows authenticated users to perform scans.
    # this is to Check if the user is authenticated, proceed only if true.
    if request.user.is_authenticated:
        # The core functionality is executed only when the form data is sent via POST method.
        if request.method == 'POST':
            # Retrieve the code input from the POST data, defaulting to an empty string if not found.
            code_input = request.POST.get('code_input', '')
            
            # use a custom function to detect any XSS vulnerabilities in the code input.
            xss_vulnerabilities = detect_xss_vulnerability(code_input)
            # use another custom function to detect any SQL injection vulnerabilities in the code input.
            sql_injection_vulnerabilities = detect_sql_injection(code_input)

            
            # this lists and collects messages about detected vulnerabilities.
            vulnerability_messages = []
            
            # format messages for XSS vulnerabilities
            if xss_vulnerabilities and xss_vulnerabilities[0]['description'] != "No XSS vulnerabilities detected.":
                xss_message = 'Cross Site Scripting Vulnerabilities Detected:\n' + \
                              '\n'.join(f"{vuln['description']} (Severity: {vuln['severity']}) - {vuln['remediation']}"
                                        for vuln in xss_vulnerabilities)
                vulnerability_messages.append(xss_message)
            elif not xss_vulnerabilities or xss_vulnerabilities[0]['description'] == "No XSS vulnerabilities detected.":
                vulnerability_messages.append("No XSS vulnerabilities detected.")

            # SQL Injection vulnerabilities are formatted into a message if any are detected. 
            # This is important for informing users about the security vul in their SQL queries.
            if sql_injection_vulnerabilities and sql_injection_vulnerabilities[0]['description'] != "No SQL Injection vulnerabilities detected.":
                sql_message = 'SQL Injection Vulnerabilities Detected:\n' + \
                              '\n'.join(f"{vuln['description']} (Severity: {vuln['severity']}) - {vuln['remediation']}"
                                        for vuln in sql_injection_vulnerabilities)
                vulnerability_messages.append(sql_message)
            elif not sql_injection_vulnerabilities or sql_injection_vulnerabilities[0]['description'] == "No SQL Injection vulnerabilities detected.":
                vulnerability_messages.append("No SQL Injection vulnerabilities detected.")

            # combines all vulnerability messages into a single string to be displayed on the scanner page.
            vulnerability_message = '\n\n'.join(vulnerability_messages)

            # this renders the 'scanner.html' template, passing the username, compiled vulnerability messages.
            return render(request, 'scanner.html', {
                'username': request.user.username,
                'vulnerability_message': vulnerability_message,
                'code_input': code_input
            })
        else:
            # if the request method is not POST, the scanner page is simply re-rendered without any scanning operation.
            return render(request, 'scanner.html', {'username': request.user.username})
    else:
        # Redirects to the login page if the user is not authenticated. 
        return redirect('login')


def has_xss_vulnerability(code_input):
    # function to detect basic XSS vulnerabilities
    escaped_code = escape(code_input)
    # this return True if the sanitized code is different from the original, indicating potential XSS vulnerabilities.
    return escaped_code != code_input


 
def custom_404(request, exception):
    return render(request, '404.html', status=404)






# logs out the user and redirects them to the home page.
def signout(request):
    # Handles user logout and redirects to home page
    logout(request) # uses logout function to terminate the user session.
    return redirect('home') # after logging out, redirect the user to the home page.

@login_required
def xss_page(request):
    # renders and return the XSS information page to the user.
    return render(request, 'xss.html')

@login_required
def sql_injection_page(request):
    # render and return the SQL Injection information page to the user.
    return render(request, 'sqlinjection.html')

@login_required
def csrf_page(request):
    # render and return the CSRF (Cross-Site Request Forgery) information page to the user.
    return render(request, 'csrf.html')