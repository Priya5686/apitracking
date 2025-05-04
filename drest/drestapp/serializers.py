from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from drestapp.models import CustomUser

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'username': {'required': True},
        }

    # Validate email
    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise ValidationError("A user with this email already exists.")
        return value

    # Validate username
    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise ValidationError("A user with this username already exists.")
        return value

    def validate_password(self, value):
        validate_password(value)  # This enforces rules like length, complexity, etc.
        return value

    def validate(self, attrs):
        email = attrs.get('email')
        username = attrs.get('username')
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError({"email": "A user with this email already exists."})
        if CustomUser.objects.filter(username=username).exists():
            raise serializers.ValidationError({"username": "A user with this username already exists."})
        return attrs

    # Create the user
    def create(self, validated_data):
        try:
            user = CustomUser.objects.create_user(**validated_data)
            user.is_staff = False
            user.is_superuser = False
            user.save()
            return user
        except Exception as e:
            raise serializers.ValidationError({"error": str(e)})



class AccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        #fields = ['username', 'email', 'first_name', 'last_name']
        fields = ['first_name', 'last_name']
        #read_only_fields = ['username', 'email']

    def validate_first_name(self, value):
        if not value.isalpha() or len(value) < 2:
            raise serializers.ValidationError("First name must be at least 2 characters long and only contain letters.")
        return value

    def validate_last_name(self, value):
        if not value.isalpha() or len(value) < 2:
            raise serializers.ValidationError("Last name must be at least 2 characters long and only contain letters.")
        return value

    def validate(self, attrs):
        if not attrs.get("first_name") and not attrs.get("last_name"):
            raise serializers.ValidationError("Both first_name and last_name cannot be empty.")
        return attrs
