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
        validate_password(value)  
        return value

    """def validate(self, attrs):
        return attrs"""

    # Create the user
    def create(self, validated_data):
        try:
            user = CustomUser.objects.create_user(**validated_data)
            user.is_staff = False
            user.is_superuser = False
            user.save()
            return user
        except IntegrityError:
            raise serializers.ValidationError({"non_field_errors": ["User could not be created."]})
        #except Exception as e:
            #raise serializers.ValidationError({"error": str(e)})



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


from django.contrib.auth import authenticate
from rest_framework import serializers

class RegularLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            raise serializers.ValidationError("Both email and password are required.")

        user = authenticate(username=email, password=password)
        if not user:
            raise serializers.ValidationError("Invalid email or password.")

        if not user.is_active:
            raise serializers.ValidationError("This account is inactive. Please contact support.")

        data["user"] = user
        return data
