import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class LogRequestTimeMiddleware:
    """
    Middleware to log the UTC timestamp of each request.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get current UTC time
        utc_time = datetime.now(timezone.utc)
        logger.info(f"Request received at UTC Time: {utc_time}, Path: {request.path}, Method: {request.method}")

        # Proceed to the next middleware or view
        response = self.get_response(request)

        # Log response status code
        logger.info(f"Response sent with status code: {response.status_code}")
        return response
