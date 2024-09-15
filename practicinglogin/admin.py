from django.contrib import admin
from .models import User, OTP

# Registering the models
admin.site.register(User)
admin.site.register(OTP)
