from django.utils import timezone
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, OTP
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from rest_framework.response import Response

import datetime
from datetime import timedelta
from rest_framework import status


class OurTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["user_id"] = user.id
        return token


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )
    email = serializers.EmailField(
        required=True, validators=[UniqueValidator(queryset=User.objects.all())]
    )

    class Meta:
        model = User
        fields = ("username", "email", "password")

    def validate(self, attrs):
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data["username"], email=validated_data["email"]
        )

        user.set_password(validated_data["password"])
        user.save()

        return user


class PasswordResetMailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=100)

    class Meta:
        fields = "email"


class PasswordChangeSerializer(serializers.Serializer):

    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        fields = "password"

    def validate(self, data):
        password = data.get("password")
        password_again = data.get("password_again")
        # otp = data.get("otp")
        token = self.context.get("token")

        # for user_id
        reset_token = AccessToken(token)
        user_id = reset_token.get("user_id")

        user = User.objects.filter(id=user_id).first()

        data["user"] = user
        return data


class OTPCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = OTP
        fields = ["otp", "user", "purpose"]


def validate(self, data):
    otp = data.get("otp")
    user = data.get("user")
    created_at = data.get("created_at")
    purpose = data.get("purpose")

    return data
