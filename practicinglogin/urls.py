from django.contrib import admin
from django.urls import path

from practicinglogin.api import *
from django.urls import path

urlpatterns = [
    path("register/", RegisterView.as_view(), name="auth_register"),
    path("login/", user_login, name="login"),
    path("password_reset", PasswordResetMailView.as_view(), name="password-reset"),
    path(
        "password-reset/<str:token>/", PasswordChangeView.as_view(), name="reset-token"
    ),
    path(
        "password-change/<token>/", PasswordChangeView.as_view(), name="password-change"
    ),
    path("token/", OurTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("send-mail/", send_email, name="send_email"),
    path("verify_otp/", OTPVerificationView.as_view(), name="verify_otp"),
    path("logout", LogoutView.as_view(), name="logout"),
]
