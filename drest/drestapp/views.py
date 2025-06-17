from urllib.parse import urlencode
import uuid
import os
import secrets
import json
import logging
import hashlib
import base64
import requests
from datetime import datetime, timedelta
from django.utils import timezone
from dateutil.parser import parse as parse_date

import re

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, Http404, HttpResponseBadRequest, HttpResponseForbidden
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.timezone import now
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.decorators.http import require_POST
from .models import ExtractedEvent, GmailMessage

from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import NotFound


from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.models import User


from oauth2_provider.contrib.rest_framework import OAuth2Authentication
from oauth2_provider.views import AuthorizationView, TokenView
from oauth2_provider.models import AccessToken, RefreshToken, Application
from oauth2_provider.views.generic import ProtectedResourceView
from oauthlib.common import generate_token

from social_django.models import UserSocialAuth

from drestapp.models import (
    EmailVerificationToken,
    CustomUser,
    FlightRecord,
    GmailMessage,
    ExtractedEvent,
)
from drestapp.serializers import RegisterSerializer, AccountSerializer
#from drestapp.utils import extract_events_with_ollama, extract_events_fallback
import logging


CustomUser = get_user_model()

def home_view(request):
    return render(request, "home.html")

def register_view(request):
    return render(request, "register.html")

def profile_view(request):
    return render(request, "profile.html")

def login_page(request):
    return render(request, "login.html")

def dashboard_view(request):
    return render(request, "dashboard.html")





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


def generate_code_verifier():
    return secrets.token_urlsafe(64)

def generate_code_challenge(verifier):
    hashed = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(hashed).decode().rstrip("=")


def log_event(event_message):
    utc_time = datetime.now(timezone.utc)
    logger.info(f"[{utc_time}] {event_message}")


class CustomAuthorizationView(AuthorizationView):
    def dispatch(self, request, *args, **kwargs):
        user = request.user
        if not user.is_authenticated:
            return redirect(f"/login/?next={request.get_full_path()}")


        if not getattr(user, "email_verified", False):
            return HttpResponseForbidden("Authorization denied: user not verified.")

        print("✔️ User entering authorize flow:", user.email)
        return super().dispatch(request, *args, **kwargs)
    

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
            f"{settings.OAUTH_TOKEN_URL}",
            data=data,
            headers=headers,
            timeout=10
        )
        response_data = response.json()

        if response.status_code == 200:
            access = response_data.get("access_token")
            refresh = response_data.get("refresh_token") or refresh_token
            res = Response({"access_token": access})
            # Auto-renew cookie
            res.set_cookie(
                key="access_token",
                value=access,
                httponly=True,
                max_age=3600,
                samesite="Lax",
                secure=not settings.DEBUG
            )
            res.set_cookie(
            key="refresh_token",
            value=refresh,
            httponly=True,
            max_age=86400,
            samesite="Lax",
            secure=not settings.DEBUG
            )
            return res

        return Response(response_data, status=response.status_code)

    except requests.RequestException as e:
        return Response({"error": f"Refresh request failed: {str(e)}"}, status=500)


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
            "has_social_auth": user.social_auth.exists() if hasattr(user, "social_auth") else False,
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


class GetAccessTokenView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        #access_token = request.COOKIES.get('access_token')
        access_token = request.session.get('access_token') or request.COOKIES.get('access_token')
        print("Session token:", request.session.get('access_token'))
        print("Cookie token:", request.COOKIES.get('access_token'))
        print("Access token from cookie:", access_token)

        if not access_token:
            return JsonResponse({"error": "No access token found."}, status=401)
        
        try:
            token = AccessToken.objects.filter(token=access_token).first()
            print("Token from DB:", token)

            if token is None or token.is_expired():
                return JsonResponse({"error": "Token expired or invalid."}, status=401)

            return JsonResponse({"access_token": token.token})
        except Exception as e:
            logger.error(f"Error retrieving access token: {e}")
            return JsonResponse({"error": "Internal server error"}, status=500)


        #if access_token:
            #return JsonResponse({"access_token": access_token})


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


"""def oauth_success_redirect(request):
    user = request.user
    if not user.is_authenticated:
        return redirect('/login/')

    app = Application.objects.get(name='testoauth')

    now = timezone.now()
    access_token = AccessToken.objects.filter(
        user=user,
        application=app
    ).order_by('-expires').first()

    if access_token and access_token.expires > now:
        #Token is still valid,reuse it
        token = access_token.token

    else:
        #Token expired,refresh
        refresh = RefreshToken.objects.filter(
            user=user,
            application=app,
            access_token=access_token
        ).first()

        if refresh:
            #Refresh token exists — generate new access token
            token = generate_token()
            expires = now + timedelta(hours=1)

            access_token = AccessToken.objects.create(
                user=user,
                application=app,
                token=token,
                expires=expires,
                scope='read write'
            )

            #Update refresh token to point to new access token
            refresh.access_token = access_token
            refresh.save()

        else:
            #No valid refresh token — issue both new tokens
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

    #Set token in cookie
    response = redirect('/dashboard/')
    response.set_cookie(
        'access_token',
        token,
        httponly=True,
        samesite='Lax',
        secure=False  # change to True in production
    )
    return response"""



def safe_parse(value):
    if isinstance(value, str):
        try:
            return parse(value)
        except ValueError:
            return None
    return value

class GmailEventDetectionView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        all_events = []
        messages = GmailMessage.objects.order_by('-received_at')[:3]  # Fetch multiple emails

        for msg in messages:
            #email_text = msg.plain_content.replace("**", "").strip()
            email_text = (msg.plain_content or "").replace("**", "").strip()


            # Primary event extraction using DeepSeek model
            events = extract_events_with_ollama(email_text)

            # Fallback check: If events have "TBD" or missing dates, try fallback extraction
            for idx, e in enumerate(events):
                if e.get("start") in ["TBD", None] or e.get("end") in ["TBD", None]:
                    fallback_events = json.loads(extract_events_fallback(email_text)).get("events", [])
                    
                    # Ensure only missing fields are updated, rather than replacing full objects
                    for fallback in fallback_events:
                        if e.get("description") == fallback.get("description"):
                            events[idx]["start"] = fallback.get("date", e.get("start"))
                            events[idx]["end"] = fallback.get("date", e.get("end"))

            # Deduplication logic before saving to DB
            for e in events:
                exists = ExtractedEvent.objects.filter(
                    type=e.get("type", ""),
                    description=e.get("description", ""),
                    start_datetime=safe_parse(e.get("start"))
                ).exists()

                if not exists:
                    event_obj, created = ExtractedEvent.objects.get_or_create(
                        type=e.get("type", ""),
                        description=e.get("description", ""),
                        start_datetime=safe_parse(e.get("start")),
                        end_datetime=safe_parse(e.get("end")),
                        user=request.user
                    )
             
                    all_events.append({
                        "id": event_obj.id,
                        "type": event_obj.type,
                        "description": event_obj.description,
                        "start": event_obj.start_datetime.isoformat() if event_obj.start_datetime else None,
                        "end": event_obj.end_datetime.isoformat() if event_obj.end_datetime else None
                    })
        upcoming_events = ExtractedEvent.objects.filter(user=request.user,start_datetime__gte=now()).order_by("start_datetime")

        return Response({
            "events": all_events,
            "message_count": len(messages)
        })





class GoogleOAuthAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        access_token = auth_header.split("Bearer ")[1]

        # ✅ Validate Google OAuth token
        user_info_url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={access_token}"
        response = requests.get(user_info_url)

        if response.status_code != 200:
            return None  # Invalid token
        
        user_data = response.json()
        email = user_data.get("email")

        if not email:
            return None  # Missing email

        # ✅ Find or create user in Django
        user, _ = User.objects.get_or_create(username=email, defaults={"email": email})
        return (user, None)
    
    
from django.contrib.auth import login

def google_login_success(request):
    user = request.user
    if user.is_authenticated:
        login(request, user) 
        return redirect('/dashboard/')
    return redirect('/login/')




from dateutil.parser import parse 

logger = logging.getLogger(__name__)  # ✅ Initialize logging

#AVIATIONSTACK_API_KEY = "452dd185aa6fd62185cd598aa1453998"
AVIATIONSTACK_API_KEY = settings.AVIATIONAPI_KEY

AIRLINE_MAP = {
    "Emirates": "EK",
    "Qatar Airways": "QR",
    "Etihad": "EY",
    "IndiGo": "6E",
    "Air India": "AI",
    "SpiceJet": "SG",
    "Air Arabia": "G9"
}

def normalize_date(date_input: str) -> str:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_input, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    raise ValueError("Invalid date format. Use YYYY-MM-DD or DD/MM/YYYY.")

def fetch_flight_info(flight_number: str, scheduled_date: str, airline_name: str):
    airline_iata = AIRLINE_MAP.get(airline_name)
    if not airline_iata:
        return {"error": "Unsupported airline name"}

    url = "http://api.aviationstack.com/v1/flights"
    params = {
        "access_key": AVIATIONSTACK_API_KEY,
        "flight_number": flight_number,
        "airline_iata": airline_iata,
        "scheduled": scheduled_date 
        #"scheduled": flight_date
    }

    response = requests.get(url, params=params)
    logger.info(f"📡 API Request: {response.url}")  # ✅ Log request URL
    data = response.json().get("data", [])

    if not data:
        return {"error": "No matching flight found for that date."}

    flight = data[0]  
    return {
        "scheduled_departure_airport": flight["departure"].get("airport"),
        "scheduled_departure_code": flight["departure"].get("iata"),
        "scheduled_arrival_airport": flight["arrival"].get("airport"),
        "scheduled_arrival_code": flight["arrival"].get("iata"),
        "airline_name": flight["airline"].get("name"),
        "flight_number": flight["flight"].get("number"),
        "scheduled_departure_time": flight["departure"].get("scheduled"),
        "actual_departure_time": flight["departure"].get("actual"),
        "departure_delay_time": flight["departure"].get("delay"),
        "scheduled_arrival_time": flight["arrival"].get("scheduled"),
        "actual_arrival_time": flight["arrival"].get("actual"),
        "arrival_delay_time": flight["arrival"].get("delay"),
        "arrival_gate": flight["arrival"].get("gate"),
        "arrival_belt_number": flight["arrival"].get("baggage")
    }


logger = logging.getLogger(__name__)

def flight_data_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "User not authenticated."}, status=401)

    try:
        flight_number = request.GET.get("flight_number")
        scheduled_date = request.GET.get("scheduled")
        airline_name = request.GET.get("airline_name")

        if not (flight_number and scheduled_date and airline_name):
            return JsonResponse({"error": "Missing required parameters"}, status=400)

        formatted_date = normalize_date(scheduled_date)
        flight_info = fetch_flight_info(flight_number, formatted_date, airline_name)

        if not flight_info or "error" in flight_info:
            return JsonResponse({"error": "No matching flight found for that date."}, status=404)

        logger.info(f"📡 Flight info: {flight_info}")

        # Save to DB
        scheduled_departure_time = parse_date(flight_info["scheduled_departure_time"])
        scheduled_date_obj = scheduled_departure_time.date()

        FlightRecord.objects.update_or_create(
            user=request.user,
            flight_number=flight_info["flight_number"],
            airline_name=flight_info["airline_name"],
            scheduled_date=scheduled_date_obj,
            defaults={
                "scheduled_departure_airport": flight_info["scheduled_departure_airport"],
                "scheduled_departure_code": flight_info["scheduled_departure_code"],
                "scheduled_arrival_airport": flight_info["scheduled_arrival_airport"],
                "scheduled_arrival_code": flight_info["scheduled_arrival_code"],
                "scheduled_departure_time": scheduled_departure_time,
                "scheduled_arrival_time": flight_info["scheduled_arrival_time"],
                "actual_departure_time": flight_info["actual_departure_time"],
                "actual_arrival_time": flight_info["actual_arrival_time"],
                "arrival_gate": flight_info.get("arrival_gate"),
                "arrival_belt_number": flight_info.get("arrival_belt_number"),
            }
        )

        return JsonResponse(flight_info)

    except Exception as e:
        logger.error(f"❌ Error fetching/saving flight data: {e}")
        return JsonResponse({"error": "Internal server error"}, status=500)


def fetch_stored_flights(request):
    if not request.user.is_authenticated:
        return JsonResponse({"error": "User not authenticated."}, status=401)

    flights = FlightRecord.objects.filter(user=request.user)

    if not flights.exists():
        return JsonResponse({"flights": [], "message": "No stored flights found."})

    flight_data = []
    for flight in flights:
        flight_data.append({
            "flight_number": flight.flight_number,
            "airline_name": flight.airline_name,
            "scheduled_departure_airport": flight.scheduled_departure_airport,
            "scheduled_arrival_airport": flight.scheduled_arrival_airport,
            "scheduled_departure_time": flight.scheduled_departure_time.isoformat() if flight.scheduled_departure_time else None,
            "scheduled_arrival_time": flight.scheduled_arrival_time.isoformat() if flight.scheduled_arrival_time else None,
            "actual_departure_time": flight.actual_departure_time.isoformat() if flight.actual_departure_time else None,
            "actual_arrival_time": flight.actual_arrival_time.isoformat() if flight.actual_arrival_time else None,
            "gate_number": flight.gate_number,
            "belt_number": flight.belt_number,
        })

    return JsonResponse({"flights": flight_data})


#Local host login view
from urllib.parse import urlencode  # ✅ Make sure this is at the top of views.py

@csrf_protect
def login_view(request):
    # ✅ Redirect if already logged in
    if request.user.is_authenticated:
        return redirect("/dashboard/")

    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not email or not password:
            return render(request, "login.html", {"error": "Email and password are required."})

        user = authenticate(request, email=email, password=password)
        if not user:
            return render(request, "login.html", {"error": "Invalid credentials"})

        if not user.email_verified:
            return render(request, "login.html", {"error": "Please verify your email first."})

        login(request, user)

        # Check for OAuth2 PKCE redirect
        next_url = request.GET.get("next")
        if next_url and next_url.startswith("/o/authorize"):
            code_verifier = generate_code_verifier()
            code_challenge = generate_code_challenge(code_verifier)
            request.session["pkce_verifier"] = code_verifier

            oauth_params = {
                "client_id": settings.OAUTH_CLIENT_ID,
                "response_type": "code",
                "redirect_uri": f"{settings.SITE_URL}/oauth/callback/",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "scope": "read write",
            }

            oauth_url = f"/o/authorize/?{urlencode(oauth_params)}"
            return redirect(oauth_url)

        # Default: logged in successfully → dashboard
        return redirect("/dashboard/")

    # GET request fallback logic
    if not request.GET.get("force_login"):
        if request.session.get("access_token") or request.COOKIES.get("access_token"):
            return redirect("/dashboard/")

    verified = request.GET.get("verified", "").lower() == "true"
    return render(request, "login.html", {"verified": verified})


#Local host oauth
def oauth_callback(request):
    code = request.GET.get("code")
    if not code:
        return JsonResponse({"error": "Authorization code is required."}, status=400)

    # Retrieve PKCE code verifier from session
    code_verifier = request.session.pop("pkce_verifier", None)
    #code_verifier = request.session.get("pkce_verifier")
    print("verifier from session:", code_verifier)
    if not code_verifier:
        return JsonResponse({"error": "PKCE verifier is required."}, status=400)

    # Exchange the authorization code for tokens
    #token_url = "http://127.0.0.1:8000/o/token/"
    token_url = settings.OAUTH_TOKEN_URL
    response = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{settings.SITE_URL}/oauth/callback/",
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_CLIENT_SECRET,
        "code_verifier": code_verifier,
    })
    print("token response:", response.text)

    if response.status_code != 200:
        return JsonResponse({"error": "Token exchange failed."}, status=response.status_code)

    tokens = response.json()

    request.session["access_token"] = tokens.get("access_token")


    res = redirect("/dashboard/")
    res.set_cookie(
        key="access_token",
        value=tokens.get("access_token"),
        httponly=True,
        max_age=3600,
        samesite="Lax",
        secure=not settings.DEBUG,
        path="/"
    )
    res.set_cookie(
        key="refresh_token",
        value=tokens.get("refresh_token"),
        httponly=True,
        max_age=86400,
        samesite="Lax",
        secure=not settings.DEBUG,
        path="/"
    )
    return res

#local host oauth_access
"""def validate_access_token(access_token):
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
        return {"status": False, "error": f"Unexpected error: {str(e)}"}"""



"""class DashboardApiView(APIView):
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
        })"""
        

import requests
from django.conf import settings

def validate_access_token(access_token):
    data = {
        "token": access_token,
        "token_type_hint": "access_token",
        "client_id": settings.OAUTH_CLIENT_ID,
        "client_secret": settings.OAUTH_CLIENT_SECRET,
    }

    try:
        response = requests.post(
            f"{settings.SITE_URL}/o/introspect/",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5
        )

        if response.status_code == 200:
            info = response.json()
            if info.get("active"):
                return {
                    "status": True,
                    "user_id": info.get("user_id"),
                    "scope": info.get("scope"),
                    "username": info.get("username"),
                    "client_id": info.get("client_id"),
                }
            return {"status": False, "error": "Token inactive or expired."}

        return {"status": False, "error": f"Failed introspect: {response.status_code}"}

    except requests.RequestException as e:
        return {"status": False, "error": f"Token introspection error: {str(e)}"}



from django.utils.decorators import method_decorator

class DashboardApiView(APIView):
    permission_classes = [AllowAny]

    @method_decorator(csrf_exempt)
    def get(self, request, *args, **kwargs):
        access_token = request.session.get("access_token") or request.COOKIES.get("access_token")
        print("🎫 Dashboard access token:", access_token)

        if not access_token:
            return JsonResponse({"error": "No access token provided"}, status=401)

        result = validate_access_token(access_token)

        if not result["status"]:
            return JsonResponse({"error": result["error"]}, status=401)

        return JsonResponse({
            "username": result["username"],
            "client_id": result["client_id"],
            "user_id": result["user_id"],
            "scope": result["scope"],
        })
