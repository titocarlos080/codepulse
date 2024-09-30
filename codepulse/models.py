# Author: Djena Siabdellah
# Description: Defines models for CodePulse, including a custom user model and a model for storing scan results.
# References 
# https://github.com/adeyosemanputra/pygoat/blob/master/introduction/models.py


from django.conf import settings  # Import to get the user model
from django.db import models
from django.contrib.auth.models import AbstractUser #, Group, Permission

class CustomUser(AbstractUser):
    # Your custom user model code
    
    # I Added related_name to avoid clashes with the default User model
    # ManyToManyField was setup for the CustomUser model to associate Groups and Permissions explicitly.
    # im using 'related_name' to prevent clashes.
    groups = models.ManyToManyField(
        "auth.Group",
        related_name="custom_user_set",
        related_query_name="custom_user",
        blank=True,
        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="custom_user_set",
        related_query_name="custom_user",
        blank=True,
        help_text="Specific permissions for this user.",
    )

# ScanResult model stores the results of security scans performed on URLs.
class ScanResult(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    url = models.URLField()
    scanned_on = models.DateTimeField(auto_now_add=True)
    xss_detected = models.BooleanField(default=False)
    sql_injection_detected = models.BooleanField(default=False)
    csrf_issues_detected = models.BooleanField(default=False)
    additional_info = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Scan for {self.url} on {self.scanned_on}"

