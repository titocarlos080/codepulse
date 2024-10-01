
# https://www.w3schools.com/django/django_urls.php

# import the path function from urls module to define url patterns
from django.urls import path

# import views from the current directory to use in url patterns
from . import views
# import specific views functions directly for easy access
from . import  utils
from django.conf.urls import handler404

# urlpatterns list to hold the url configurations
urlpatterns = [
    # routes to 'home' view and named as 'home'
    path('', views.home, name='home'),
    # routes to 'about' view and named as 'about'
    path('about/', views.about, name='about'),
    # routes to 'register' view and named as 'register'
    path('register/', views.register, name='register'),
    # routes to 'verify_email' view and named as 'verify_email'
    path('verify_email/', views.verify_email, name='verify_email'),
    # routes to 'user_login' view and named as 'login'
    path('login/', views.user_login, name='login'),
    # routes to 'url_scanner' view and named as 'url_scanner'
    path('url_scanner/', utils.url_scanner, name='url_scanner'),
    # routes to 'scanner' view and named as 'scanner'
    path('scanner/', views.scanner, name='scanner'),
    # routes to 'scaned_sites' view and named as 'scaned_sites'
    path('scaned_sites/', views.scaned_sites, name='scaned_sites'),
    
    path('port_scanner/',views.port_scanner, name='port_scanner'),
    
    # routes to 'signout' view and named as 'signout'
    path('signout/', views.signout, name='signout'),
    # routes to 'xss_page' view and named as 'xss_page'
    path('xss/', views.xss_page, name='xss_page'),
    # routes to 'sql_injection_page' view and named as 'sql_injection_page'
    path('sqlinjection/', views.sql_injection_page, name='sql_injection_page'),
    # routes to 'csrf_page' view and named as 'csrf_page'
    path('csrf/', views.csrf_page, name='csrf_page'),
]

handler404 = 'codepulse.views.custom_404'  # Replace 'codepulse' with your actual app name
 