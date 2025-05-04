import logging
from datetime import datetime, timezone

from django.conf import settings
from jwt import decode, ExpiredSignatureError, InvalidTokenError
from django.shortcuts import redirect

logger = logging.getLogger(__name__)


class AccessTokenMiddleware:
    """
    Middleware to validate access tokens from cookies.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.excluded_paths = ["/admin/", "/login/"]

    def __call__(self, request):
        if any(request.path.startswith(path) for path in self.excluded_paths):
            return self.get_response(request)

        access_token = request.COOKIES.get("access_token")
        if not access_token:
            logger.warning("Access token is missing.")
            return redirect("/login/?error=token_missing")

        # Validate the token
        try:
            logger.info(f"Validating token: {access_token}")
            decoded_token = decode(access_token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
            # Replace with your secret key and algorithm
            expiration_time = datetime.utcfromtimestamp(decoded_token.get("exp", 0))
            current_time = datetime.now(timezone.utc)

            if current_time > expiration_time:
                logger.warning("Access token has expired.")
                return redirect("/login/?error=token_expired")

            logger.info("Access token is valid.")
        except ExpiredSignatureError:
            logger.error("Access token expired.")
            return redirect("/login/?error=token_expired")
        except InvalidTokenError as e:
            logger.error(f"Invalid access token: {str(e)}")
            return redirect("/login/?error=token_invalid")
        except Exception as e:
            logger.error(f"Error during token validation: {str(e)}")
            return redirect("/login/?error=token_error")

        # Continue processing the request
        response = self.get_response(request)
        return response


