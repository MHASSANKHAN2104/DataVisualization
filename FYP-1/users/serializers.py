from rest_framework import serializers
from django.utils import timezone
from django.contrib.auth import authenticate
import re

from .models import User


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'name', 'password')

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password too short.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("Password must contain an uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError("Password must contain a lowercase letter.")
        if not re.search(r"\d", value):
            raise serializers.ValidationError("Password must contain a digit.")
        return value

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        # Generic error message so we don't leak which field is wrong
        error_msg = "Invalid email or password."

        user = authenticate(request=self.context.get('request'),
                            email=email, password=password)

        if not user:
            raise serializers.ValidationError(error_msg)

        if user.status != 'Active':
            raise serializers.ValidationError("Account is not active.")

        if user.is_locked():
            raise serializers.ValidationError("Account is locked. Try again later.")

        data['user'] = user
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'role', 'status',
                  'last_login_at', 'created_at', 'updated_at')


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('role', 'status')
        extra_kwargs = {
            'role': {'required': False},
            'status': {'required': False},
        }
