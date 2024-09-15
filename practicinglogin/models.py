from rest_framework.response import Response
from rest_framework import status
import datetime
from datetime import timedelta
from django.db import models
from django.contrib.auth.models import Permission
from django.contrib.auth.models import (
    UserManager,
    AbstractBaseUser,
    AbstractUser,
    PermissionsMixin,
)
from django.utils import timezone
from django.db import models

from .managers import CustomUserManager

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(blank=True, default="", unique=True)
    username = models.CharField(max_length=100, blank=True, default="")

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    joined_date = models.DateTimeField(default=timezone.now)
    last_login_date = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"

    def get_full_name(self):
        return self.username

    def get_short_name(self):
        return self.username or self.email.split("@")[0]

class OTP(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="otp_requests"
    )
    otp = models.IntegerField()
    created_at = models.DateTimeField()
    
    purpose = models.CharField(
        max_length=20,
        choices=[
            ("registration", "registration"),
            ("password_change", "password_change"),
        ],
    )

    @property
    def otp_expired(self):
        if timezone.now() - self.created_at > timedelta(minutes=10):
            return True
        return False

#class Login(models.Model):
    #user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
