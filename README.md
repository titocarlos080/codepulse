# CodePulse: Web Application Description 

## Introduction
CodePulse is an educational tool designed to help users understand web application vulnerabilities, including Cross-Site Scripting (XSS), SQL Injection, and Cross-Site Request Forgery (CSRF). It features a practical, interactive platform where users can not only learn about these vulnerabilities but also test them in a controlled environment.

## Technologies Used
- Django: A high-level web framework for Python which encourages efficient development and simple, intuitive design.
- JavaScript: Used to create interactive interfaces using client-side scripting.
- HTML/CSS: The web application was designed and structured using markup and style languages.

## Main Features
- **User Authentication**: Supports both two-factor and standard authentication procedures, improving the application's safety features.
- **Scanner Functionality**: Contains resources for identifying and reporting possible SQL injection and XSS vulnerabilities in user-provided code snippets and URLs.
- **Educational Content**: Dedicated pages for XSS, SQL injection, and CSRF that not only describe these vulnerabilities but also demonstrate them and discuss mitigation strategies.

 
## Installation and Setup
To get CodePulse running locally:
```bash
git clone https://github.com/DjenaSiabdellah/CodePulse.git
cd CodePulse
pip install -r requirements.txt
python manage.py runserver
