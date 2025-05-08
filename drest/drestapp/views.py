import uuid
import os
import requests
import logging
import json
import hashlib
import base64
from jwt.exceptions import ExpiredSignatureError
from django.conf import settings
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.timezone import now
from django.views.decorators.http import require_POST
from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from requests.cookies import get_cookie_header
from rest_framework.exceptions import NotFound
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from urllib.parse import urlencode
from smtplib import SMTPException
from .models import EmailVerificationToken, CustomUser
from .serializers import RegisterSerializer, AccountSerializer
from oauth2_provider.views import AuthorizationView, TokenView
from django.http import HttpResponseForbidden
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from oauth2_provider.views.generic import ProtectedResourceView
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from datetime import datetime, timezone
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render, redirect
from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponse
from django.utils.timezone import now
from datetime import timedelta
from oauth2_provider.models import AccessToken
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.contrib import messages
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.contrib.auth import login
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework.decorators import api_view, permission_classes

CustomUser = get_user_model()

def home_view(request):
    return render(request, "home.html")

def register_view(request):
    return render(request, "register.html")

def profile_view(request):
    return render(request, "profile.html")

def login_page(request):
    return render(request, "login.html")



logger = logging.getLogger(__name__)

class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    http_method_names = ['post']

    def post(self, request):
        # Explicitly check for the 'email' field
        if not request.data.get('email'):
            return Response({"error": "Email is required."}, status=400)

        try:
            serializer = RegisterSerializer(data=request.data)
            if serializer.is_valid():
                user = serializer.save()
                token = uuid.uuid4().hex
                EmailVerificationToken.objects.create(user=user, token=token)
                # Send verification email
                verification_link = f"{settings.SITE_URL}/api/verify-email/?token={token}"
                #verification_link = f"{request.build_absolute_uri(reverse('verify-email'))}?token={token}"
                print("Verification link:", verification_link)
                send_mail(
                    subject='Verify Your Email',
                    message=f'Click the link to verify your email: {verification_link}',
                    from_email=settings.EMAIL_HOST_USER,
                    recipient_list=[user.email],
                    fail_silently=False,
                )
                logger.info(f"Verification email sent to user {user.email} with token {token}.")
                return Response({"msg": "Verification email sent. Please check your inbox."}, status=201)
            logger.error(f"Validation failed: {serializer.errors}")
            return Response(serializer.errors, status=400)

        except Exception as e:
            logger.error(f"Unhandled error: {str(e)}")
            return Response({"error": "Internal server error occurred."}, status=500)


def verify_email(request):
    token = request.GET.get('token')  # Get the token from the query parameters
    if not token:
        return HttpResponse("<h1>Error</h1><p>Invalid token. No token provided.</p>", status=400)

    try:
        email_verification = EmailVerificationToken.objects.get(token=token)


        if now() > email_verification.created_at + timedelta(hours=1):
            return HttpResponse("<h1>Error</h1><p>This verification link has expired. Please request a new one.</p>",
                                status=400)

        user = email_verification.user
        user.email_verified = True
        user.save()

        email_verification.delete()

        return redirect("/login/?verified=true")

    except EmailVerificationToken.DoesNotExist:
        # Token is invalid or does not exist
        return HttpResponse("<h1>Error</h1><p>Invalid or expired token.</p>", status=400)

    except Exception as e:
        # Handle any other unexpected errors
        return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)


def resend_verification_link(request):
    if request.method == "POST":
        email = request.POST.get("email")  # Get email from the form
        try:
            # Check if the user exists and their email is not yet verified
            user = CustomUser.objects.get(email=email)  # Replace with your custom user model
            if user.email_verified:
                return HttpResponse("<h1>Error</h1><p>Email is already verified.</p>", status=400)

            # Generate a new token
            new_token = secrets.token_urlsafe(32)
            email_verification, created = EmailVerificationToken.objects.update_or_create(
                user=user,
                defaults={"token": new_token, "created_at": now()},
            )

            # Send a new verification email
            send_verification_email(user, new_token)
            return HttpResponse("<h1>Success</h1><p>A new verification email has been sent.</p>", status=200)

        except CustomUser.DoesNotExist:
            return HttpResponse("<h1>Error</h1><p>User with this email does not exist.</p>", status=400)
    else:
        #return render(request, "resend_verification.html")
        return render(request, "resend_email.html")


import secrets

def generate_code_verifier():
    return secrets.token_urlsafe(64)

def generate_code_challenge(verifier):
    hashed = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(hashed).decode().rstrip("=")



@csrf_protect
def login_view(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            return render(request, "login.html", {"error": "Email and password are required."})

        # Authenticate user
        user = authenticate(request, email=email, password=password)
        if not user:
            return render(request, "login.html", {"error": "Invalid credentials"})

        # Login user
        login(request, user)

        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)

        # Save the verifier in session for later use
        request.session["pkce_verifier"] = code_verifier


        print(f"PKCE Code Verifier: {code_verifier}")
        print(f"PKCE Code Challenge: {code_challenge}")

        # Generate PKCE code verifier and challenge
        #code_verifier = "random_generated_code_verifier"  # Replace with dynamic generation
        #code_challenge = generate_code_challenge(code_verifier)
        #request.session["pkce_verifier"] = code_verifier
        #print(f"PKCE Code Verifier: {code_verifier}")
        #print(f"PKCE Code Challenge: {code_challenge}")

        # Redirect to OAuth provider
        auth_url = (
            f"{settings.OAUTH_AUTHORIZE_URL}?response_type=code&client_id={settings.OAUTH_CLIENT_ID}&"
            f"redirect_uri=http://127.0.0.1:8000/oauth/callback/&scope=read write&"
            f"code_challenge={code_challenge}&code_challenge_method=S256"
        )
        return redirect(auth_url)


    if not request.GET.get("force_login"):
        if request.session.get("access_token") or request.COOKIES.get("access_token"):
            # Redirect if authenticated
            return redirect("/dashboard/")


    verified = request.GET.get("verified","").lower() == "true"
    context = {"verified": verified}
    return render(request, "login.html", context)




def log_event(event_message):
    utc_time = datetime.now(timezone.utc)
    logger.info(f"[{utc_time}] {event_message}")

def oauth_callback(request):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "Authorization code is required."}, status=400)

    # Retrieve PKCE code verifier from session
    code_verifier = request.session.pop("pkce_verifier", None)
    if not code_verifier:
        return JsonResponse({"error": "PKCE verifier is required."}, status=400)

    # Exchange the authorization code for tokens
    token_url = "http://127.0.0.1:8000/o/token/"
    response = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://127.0.0.1:8000/oauth/callback/",
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_CLIENT_SECRET,
        "code_verifier": code_verifier,
    })

    if response.status_code != 200:
        return JsonResponse({"error": "Token exchange failed."}, status=response.status_code)

    tokens = response.json()


    res = redirect("/dashboard/")
    res.set_cookie(
        key="access_token",
        value=tokens.get("access_token"),
        httponly=True,
        max_age=3600,
        samesite="Lax",
        secure=not settings.DEBUG
    )
    res.set_cookie(
        key="refresh_token",
        value=tokens.get("refresh_token"),
        httponly=True,
        max_age=86400,
        samesite="Lax",
        secure=not settings.DEBUG
    )
    return res

class CustomAuthorizationView(AuthorizationView):
    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect(f"/login/?next={request.get_full_path()}")


        if not getattr(user, "email_verified", False):
            return HttpResponseForbidden("Authorization denied: user not verified.")

        print("✔️ User entering authorize flow:", user.email)
        return super().dispatch(request, *args, **kwargs)


def validate_access_token(access_token):
    try:
        # Decode JWT token
        decoded_token = jwt_decode(access_token, settings.JWT_SECRET_KEY, algorithms=["HS256"])
        logger.info(f"Token successfully decoded: {decoded_token}")

        # Validate the expiration (exp) claim
        expiration = decoded_token.get("exp")
        expiration_time = datetime.utcfromtimestamp(expiration)
        logger.debug(f"Token expiration time: {expiration_time}")
        if not expiration:
            logger.warning("Token does not have an expiration claim.")
            return {"status": False, "error": "Missing expiration claim."}

        # Convert expiration timestamp to datetime
        expiration_time = datetime.utcfromtimestamp(expiration)
        if expiration_time < datetime.now(timezone.utc):
            logger.warning(f"Token expired at {expiration_time}.")
            return {"status": False, "error": "Token expired."}

        logger.info(f"Token is valid. Expiration time: {expiration_time}")
        return {"status": True, "message": "Token is valid."}

    except ExpiredSignatureError:
        logger.error("Token has expired.")
        return {"status": False, "error": "Token has expired."}
    except InvalidTokenError as e:
        logger.error(f"Invalid token: {str(e)}")
        return {"status": False, "error": f"Invalid token: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error during token validation: {str(e)}")
        return {"status": False, "error": f"Unexpected error: {str(e)}"}

import logging
import requests
from django.conf import settings
from rest_framework.response import Response
#from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import AllowAny

logger = logging.getLogger(__name__)

from rest_framework.decorators import api_view,permission_classes

@api_view(["GET"])
@permission_classes([AllowAny])
def refresh_access_token(request):
    refresh_token = request.COOKIES.get("refresh_token")
    if not refresh_token:
        return Response({"error": "Refresh token not found"}, status=400)

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_CLIENT_SECRET,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    try:
        response = requests.post(
            "http://127.0.0.1:8000/o/token/",
            data=data,
            headers=headers,
            timeout=10
        )

        # Get the JSON whether it's 200 or 400
        response_data = response.json()

        if response.status_code == 200:
            return Response({
                "access_token": response_data.get("access_token")
            })
        else:
            return Response(response_data, status=response.status_code)

    except requests.RequestException as e:
        return Response({"error": str(e)}, status=500)

    


logger = logging.getLogger(__name__)

def token_from_cookie(request):
    try:
        # Retrieve token from cookies
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            logger.warning("Access token is missing in cookies.")
            return None

        # Query AccessToken model
        try:
            token = AccessToken.objects.filter(token=access_token).first()
            if token is None:
                logger.warning(f"No AccessToken found for token: {access_token}")
                return None

            if token.is_expired():
                logger.warning(f"AccessToken has expired: {access_token}")
                return None

            logger.info(f"Valid token found for user: {token.user.username}")
            return token.user
        except Exception as e:
            logger.error(f"Error retrieving token from AccessToken model: {str(e)}")
            return None

    except Exception as e:
        logger.error(f"Unexpected error in token_from_cookie: {str(e)}")
        return None


from oauth2_provider.views.generic import ProtectedResourceView
from django.http import JsonResponse
from social_django.models import UserSocialAuth


class DashboardApiView(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Unauthorized"}, status=401)

        #social_auths = UserSocialAuth.objects.filter(user=request.user).values("provider", "uid")
        user = request.user
        return JsonResponse({
            "username": user.username,
            "email": user.email,
            "is_staff": user.is_staff,
            #"social_associations": list(social_auths)
        })


def dashboard_view(request):
    return render(request, "dashboard.html")



class AccountView(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = AccountSerializer(request.user)
        return Response(serializer.data)

    def put(self, request):
        serializer = AccountSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "Account updated successfully!", "data": serializer.data},status=200)
        print("Serializer errors:", serializer.errors)
        return Response({"errors": serializer.errors, "msg": "Account update failed."}, status=400)


from oauth2_provider.contrib.rest_framework import OAuth2Authentication
class WhoAmIEndpoint(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        social = user.social_auth.first() if user.social_auth.exists() else None

        return Response({
            "id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "is_staff": user.is_staff,
            "role": "admin" if user.is_staff else "user",
            "auth_provider": social.provider if social else "local",
            "social_uid": social.uid if social else None,
            "has_social_auth": user.social_auth.exists(),
        })


logger = logging.getLogger(__name__)


def example_view(request):
    try:
        utc_time = datetime.now(timezone.utc)
        param = request.GET.get("param", None)
        if not param:
            return Response({"message": "Error", "detail": "Missing parameter 'param'."}, status=400)

        client_ip = request.META.get('REMOTE_ADDR', 'unknown')
        user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')

        return Response({
            "message": "Success",
            "utc_time": utc_time.isoformat(),
            "param": param,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "detail": "Request processed successfully."
        })
    except Exception as e:
        return Response({
            "message": "Error",
            "detail": str(e)
        }, status=500)

from django.contrib.auth import logout

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        response = Response({"msg": "Logged out successfully!"})
        response.delete_cookie("access_token")
        response.delete_cookie("sessionid")
        #response.delete_cookie("refresh_token")
        return response


def forgot_password_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        User = get_user_model()   # ✅ use custom user model
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            reset_link = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")

            send_mail(
                'Password Reset Request',
                f'Hi {user.username}, click the link to reset your password: {reset_link}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return render(request, 'forgot_password.html', {
                "message": "Reset link sent! Please check your email."
            })
            #messages.success(request, "Password reset link has been sent to your email.")
            #return redirect('login')
        except User.DoesNotExist:
            return render(request, 'forgot_password.html', {
                "error": "⚠️ No account found with that email address."
            })
            #messages.error(request, "No account found with that email address.")
            #return redirect('forgot-password')

    return render(request, 'forgot_password.html')



def reset_password_view(request, uidb64, token):
    User = get_user_model()

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')

            if password1 == password2:
                user.set_password(password1)
                user.save()
                messages.success(request, "✅ Password reset successful! Please log in with your new password.")
                return redirect('/login_page/')
                #return redirect('login')
            else:
                messages.error(request, "❌ Passwords do not match. Please try again.")
                return redirect(request.path)
        else:
            return render(request, 'reset_password.html')
    else:
        messages.error(request, "❌ Invalid or expired reset link.")
        return redirect('forgot-password')




from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class GetAccessTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        access_token = request.COOKIES.get('access_token')
        if access_token:
            return JsonResponse({"access_token": access_token})
        return JsonResponse({"error": "No access token found."}, status=401)



import requests
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.shortcuts import render


class WeatherAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        API_KEY = settings.TOMORROW_IO_API_KEY
        location = request.GET.get("location", "Dubai")
        print("Location requested:", location)
        #LAT = 25.276987
        #LON = 55.296249

        if not API_KEY:
            return JsonResponse({"error": "Missing API key."}, status=500)

        url = f"https://api.tomorrow.io/v4/weather/realtime?location={location}&apikey={API_KEY}"

        try:
            res = requests.get(url)
            if res.status_code == 200:
                data = res.json()
                values = data.get("data", {}).get("values", {})
                return JsonResponse({
                    "temperature": values.get("temperature"),
                    "weatherCode": values.get("weatherCode")
                })
            else:
                return JsonResponse({"error": "Failed to fetch weather data."}, status=500)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

def weather_view(request):
    return render(request, "weather.html")


#@csrf_protect
#@require_POST
"""def store_pkce_verifier(request):
    try:
        body = json.loads(request.body)
        verifier = body.get("verifier")
        if not verifier:
            return JsonResponse({"error": "Missing verifier"}, status=400)

        print(f"CSRF token received: {request.META.get('HTTP_X_CSRFTOKEN')}")

        # Store the PKCE verifier in session for server-side handling
        request.session["pkce_verifier"] = verifier
        # Set secure, HttpOnly cookie for additional storage
        response = JsonResponse({"status": "ok"})
        response.set_cookie(
            key="pkce_verifier",
            value=verifier,
            max_age=300,  # Short-lived cookie
            httponly=True,  # Prevent JS access (XSS mitigation)
            secure=not settings.DEBUG,  # Secure flag for production
            samesite="Lax"  # Prevent CSRF attacks
        )
        print("✅ Stored verifier in session and cookie:", verifier)
        return response
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format"}, status=400)
    except Exception as e:
        print("❌ Error storing verifier:", str(e))
        return JsonResponse({"error": "Server error"}, status=500)"""

"""class DashboardAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "username": request.user.username,
            "email": request.user.email,
        })"""


from oauth2_provider.models import AccessToken, RefreshToken, Application
from oauthlib.common import generate_token
from datetime import timedelta
from django.utils import timezone
from django.shortcuts import redirect

def oauth_success_redirect(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('/login/')

    app = Application.objects.get(name='demo app')

    now = timezone.now()
    access_token = AccessToken.objects.filter(
        user=user,
        application=app
    ).order_by('-expires').first()

    if access_token and access_token.expires > now:
        # ✅ Token is still valid — reuse it
        token = access_token.token

    else:
        # 🔄 Token expired — try to refresh
        refresh = RefreshToken.objects.filter(
            user=user,
            application=app,
            access_token=access_token
        ).first()

        if refresh:
            # 🔁 Refresh token exists — generate new access token
            token = generate_token()
            expires = now + timedelta(hours=1)

            access_token = AccessToken.objects.create(
                user=user,
                application=app,
                token=token,
                expires=expires,
                scope='read write'
            )

            # Update refresh token to point to new access token
            refresh.access_token = access_token
            refresh.save()

        else:
            # ❌ No valid refresh token — issue both new tokens
            token = generate_token()
            refresh_token = generate_token()
            expires = now + timedelta(hours=1)

            access_token = AccessToken.objects.create(
                user=user,
                application=app,
                token=token,
                expires=expires,
                scope='read write'
            )

            RefreshToken.objects.create(
                user=user,
                token=refresh_token,
                application=app,
                access_token=access_token
            )

    # ✅ Set token in cookie
    response = redirect('/dashboard/')
    response.set_cookie(
        'access_token',
        token,
        httponly=True,
        samesite='Lax',
        secure=False  # change to True in production
    )
    return response
