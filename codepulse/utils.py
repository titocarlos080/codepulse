from django.http import JsonResponse
import requests
import logging
import re  

# This essentailly sets up logging to help me enable tracking of information and errors 
logger = logging.getLogger(__name__)

def fetch_url(url):
    try:
        # This attempts to retrieve content from the specified URL
        response = requests.get(url)
        response.raise_for_status()  # This will raise an exception
        # This returns the text content of the fetched URL, HTML or similar web content
        return response.text
    except requests.RequestException as e:
        # this Logs any errors encountered during the fetching process
        logger.error(f"Error fetching URL {url}: {e}")
        # this will return None if an error occurs to signify the fetch was unsuccessful
        return None

def detect_xss_vulnerability(html_content):
    # These are the patterns to detect common XSS vectors with severity and remediation - 
    patterns = {
        "Inline script": {
            "pattern": r"<script.*?>.*?</script>",
            "severity": "High",
            "remediation": """Event handlers and inline scripts can be blocked using Content Security Policy (CSP). -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Javascript pseudo-protocol": {
            "pattern": r"javascript:[^\s]*",
            "severity": "High",
            "remediation": """Sanitize inputs to remove or avoid 'javascript:' protocol. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Inline event handlers": {
            "pattern": r"(on\w+=['\"]?)(?!http|https)[^\s>]*",
            "severity": "Medium",
            "remediation": """Remove inline event handlers and use event transfer from JS code. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Suspicious src or href attributes": {
            "pattern": r"(src|href)=['\"]?(?!http|https|\/)[^\s>]*['\"]?",
            "severity": "Medium",
            "remediation": """Make sure that the src or href attributes can only include legitimate, sanitized URLs. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Document cookie access": {
            "pattern": r"document\.cookie",
            "severity": "Medium",
            "remediation": """Restrict and secure cookie access via HTTP headers. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Window location manipulation": {
            "pattern": r"window\.location",
            "severity": "Medium",
            "remediation": """Restrict and secure cookie access using HTTP headers.-- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        },
        "Use of eval()": {
            "pattern": r"eval\s*\(",
            "severity": "High",
            "remediation": """Think about implementing safer alternatives instead of eval() rather than using it. -- Please review the following guide on how to fix XSS vulnerabilities: 
                               '<a href="https://owasp.org/www-community/attacks/xss/" target="_blank">OWASP XSS Guide</a> '
                               'and <a href="https://owasp.org/www-community/attacks/xss/" target="_blank">https://owasp.org/www-community/attacks/xss/</a>"""
        }
    }
    vulnerabilities = []
    # will go over each defined pattern and check if it is present in the HTML content
    for description, info in patterns.items():
        if re.search(info["pattern"], html_content, re.IGNORECASE):
            # If a pattern matches, append the vulnerability description, severity, and remediation advice to the list
            vulnerabilities.append({
                "description": description,
                "severity": info["severity"],
                "remediation": info["remediation"]
            })
    # Return the list of detected vulnerabilities; if none are found, return a default message indicating no vulnerabilities
    return vulnerabilities if vulnerabilities else [{"description": "No XSS vulnerabilities detected.", "severity": "None", "remediation": "No action needed."}]

def detect_sql_injection(html_content):
    # define patterns for detecting SQL Injection vulnerabilities
    patterns = {
        "Tautology-based SQL Injection": {
            "pattern": r"OR 1=1",
            "severity": "High",
            "remediation": """For a solution past this issue, use prepared statements or parameterized queries. -- Please review the following guide on how to fix SQL injection vulnerabilities: 
                                         '<a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection Guide</a> '
                                         'and <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">https://owasp.org/www-community/attacks/sql-injection</a>"""
        },
        "Malicious SQL code": {
            "pattern": r"(SELECT|INSERT|DELETE|UPDATE) .*",
            "severity": "High",
            "remediation": """To prevent SQL injection, use parameterized queries and appropriate input validation. -- Please review the following guide on how to fix SQL injection vulnerabilities: 
                                         '<a href="https://owasp.org/www-community/attacks/SQL_Injection" target="_blank">OWASP SQL Injection Guide</a> '
                                         'and <a href="https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" target="_blank">https://owasp.org/www-community/attacks/sql-injection</a>"""
        }
    }
    vulnerabilities = []
    # Scan the HTML content for each pattern and record any matches with their details
    for description, info in patterns.items():
        # Extract the pattern from the dictionary
        pattern = info["pattern"]
        if re.search(pattern, html_content, re.IGNORECASE):
            vulnerabilities.append({
                "description": description,
                "severity": info["severity"],
                "remediation": info["remediation"]
            })
    # Return detected vulnerabilities or a default message if no issues are found
    return vulnerabilities if vulnerabilities else [{"description": "No SQL Injection vulnerabilities detected.", "severity": "None", "remediation": "No action needed."}]



# this functions is to check if the URL is valid
def is_valid_url(url):
    # this defines a list of regular expression patterns that match URLs considered 'local'. 
    # these patterns ensure that the function can identify URLs that are used for local development environments.
    local_patterns = [
        r'^http://localhost',   # this pattern matches URLs that begin with 'http://localhost'
        r'^http://127.0.0.1',   # this pattern matches URLs that begin with 'http://127.0.0.1'
        r'^http://192\.168\.',  # this pattern matches URLs that start with 'http://192.168.
    ]
    external_pattern = r'^(http|https)://[a-zA-Z0-9-]+\.[a-zA-Z]{2,}'  # General external domain pattern

 # Check if the URL is either a local URL or an external domain.
    is_local = any(re.match(pattern, url) for pattern in local_patterns)
    is_external = re.match(external_pattern, url) is not None

    # Return True if the URL is valid (either local or external)
    return is_local or is_external

# this defines a function called `url_scanner` that takes a Django request object as an argument.
def url_scanner(request):
    # this checks if the request is a POST method, which is typically used for submitting form data.
    if request.method == 'POST':
        # this retrieves the 'url_input' value from the POST data. The second parameter is the default value if 'url_input' isn't found.
        url = request.POST.get('url_input', '')
        print(is_valid_url(url))
        # this calls the `is_valid_url` function to check if the URL meets specific criteria (like being a local URL).
        if not is_valid_url(url):
            # this returns a JSON response with an error message if the URL is invalid, setting the HTTP status to 400 (Bad Request).
            return JsonResponse({'error': 'Invalid URL provided. Please ensure the URL starts with http:// or https://'}, status=400)
        
        # If this is valid, the it proceeds with fetching the URL and scanning
        html_content = fetch_url(url)
        # this checks if the fetching the content failed, then `html_content` would be None.
        if html_content is None:
            # this returns a JSON response showing that the content could not be fetched, with a 500 (Server Error) status.
            return JsonResponse({'error': 'Failed to fetch content'}, status=500)

        # Perform and calls XSS and SQL Injection vulnerability checks
        xss_vulnerabilities = detect_xss_vulnerability(html_content)
        sql_injection_vulnerabilities = detect_sql_injection(html_content)

        # this compiles the results of the scans into a dictionary.
        results = {
            'XSS': xss_vulnerabilities,
            'SQL Injection': sql_injection_vulnerabilities
        }

        # this checks if no vulnerabilities were detected.
        if not xss_vulnerabilities and not sql_injection_vulnerabilities:
            # this returns a JSON response stating that no vulnerabilities were detected.  
            return JsonResponse({'message': 'No vulnerabilities detected.'})

        # If the vulnerabilities were detected, returns a JSON response with the scan results.
        return JsonResponse({'message': 'Scan complete', 'results': results})
    # if the request method is not POST, returns a JSON response indicating the request method is not allowed, with a 405 status.
    return JsonResponse({'error': 'Invalid request method'}, status=405)
