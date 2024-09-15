import os
from loginpractice.settings.base import BASE_DIR

DEBUG=False

ALLOWED_HOSTS=["dev.loginpractice.com"]

EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

STATIC_URL = "static/"