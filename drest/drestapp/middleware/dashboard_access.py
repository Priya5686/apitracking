import logging
from django.shortcuts import redirect

logger = logging.getLogger(__name__)


class DashboardAccessMiddleware:
    """
    Middleware to restrict access to specific paths and validate user authentication.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.protected_paths = ["/dashboard/", "/profile/"]

    def __call__(self, request):
        logger.info(f"Processing request: Path={request.path}, Method={request.method}")

        if any(request.path.startswith(path) for path in self.protected_paths):
            logger.info(
                f"Access attempt detected: User={request.user}, Path={request.path}, IP={request.META.get('REMOTE_ADDR')}")

            if not request.user.is_authenticated:
                logger.warning("Unauthenticated access attempt.")
                return redirect("/login/?error=auth_required")

            # Check for the access token
            access_token = request.COOKIES.get("access_token")
            if not access_token:
                logger.error("Access token missing.")
                return redirect("/login/?error=invalid_token")

            # Optional: Placeholder for token validation
            if not self.validate_token(access_token):
                logger.error("Access token is invalid or expired.")
                return redirect("/login/?error=token_expired")

            logger.info(f"Access granted for user: {request.user}")

        return self.get_response(request)

    def validate_token(self, token):
        try:
            logger.info(f"Validating token: {token}")
            if token and len(token) > 30:  # Placeholder validation logic
                return True
            return False
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return False


