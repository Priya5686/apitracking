from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    first_name = models.CharField(max_length=50,blank=True,null=True)
    last_name = models.CharField(max_length=50,blank=True,null=True)
    #expires_at = models.DateTimeField(blank=True,null=True)

USERNAME_FIELD = 'email'  # Use email as the unique identifier for authentication
REQUIRED_FIELDS = ['username']

class EmailVerificationToken(models.Model):
    user = models.OneToOneField('drestapp.CustomUser', on_delete=models.CASCADE,related_name="verification_token")
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)



