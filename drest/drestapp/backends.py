from django.contrib.auth.backends import ModelBackend
from drestapp.models import CustomUser


class EmailBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            user = CustomUser.objects.get(email=email)
            if user.check_password(password):
                return user
        except CustomUser.DoesNotExist:
            return None

from django.contrib.auth.backends import ModelBackend
from oauth2_provider.models import AccessToken
from django.utils.timezone import now

class OAuth2CookieBackend(ModelBackend):
    """
    Custom backend to authenticate user from access_token stored in HttpOnly cookie.
    """

    def authenticate(self, request, **kwargs):
        if not request:
            return None

        access_token = request.COOKIES.get('access_token')
        if not access_token:
            return None

        try:
            token = AccessToken.objects.get(token=access_token)

            # ✅ Check if token is not expired
            if token.expires and token.expires > now():
                return token.user

        except AccessToken.DoesNotExist:
            return None

        return None

