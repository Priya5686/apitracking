from django.urls import path
from .views import (
    home_view,
    register_view,
    login_view,
    dashboard_view,
    DashboardApiView,
    oauth_callback,
    CustomAuthorizationView,
    RegisterView,
    verify_email,
    resend_verification_link,
    AccountView,
    refresh_access_token,
    WhoAmIEndpoint,LogoutView, forgot_password_view, reset_password_view, GetAccessTokenView,
    profile_view,WeatherAPIView,weather_view, oauth_success_redirect, login_page, GmailEventDetectionView,
    extract_events_fallback, flight_data_view,fetch_stored_flights,create_superuser_view
)

urlpatterns = [
    # Main application routes
    path('', home_view, name='home'),
    path('register/', register_view, name='register'),
    #Call oauthcallbackapi
    path('login/', login_view, name='login'),
    #Render HTML
    path('login_page/', login_page, name='login_page'),
    path('dashboard/', dashboard_view, name='dashboard'),
    path('profile/', profile_view, name='profile'),
    path('api/dashboard/', DashboardApiView.as_view(), name='dashboard-api'),
    #Exchange token
    path('oauth/callback/', oauth_callback, name='oauth_callback'),
    path('o/authorize/', CustomAuthorizationView.as_view(), name='authorize'),
    path('api/register/', RegisterView.as_view(), name='api_register'),
    path('api/verify-email/', verify_email, name='verify_email'),
    path('api/resend-verification/', resend_verification_link, name='resend_verification'),
    path('api/account/', AccountView.as_view(), name='account_view'),
    path('api/refresh-token/', refresh_access_token, name='refresh_token'),
    path('api/whoami/', WhoAmIEndpoint.as_view(), name='whoami'),
    path('api/dashboard/', dashboard_view, name='dashboard_view'),
    path('api/logout/', LogoutView.as_view(), name='logout_view'),
    path('forgot-password/', forgot_password_view, name='forgot-password'),
    path('reset-password/<uidb64>/<token>/', reset_password_view, name='reset-password'),
    path('api/get-token/', GetAccessTokenView.as_view(), name='get-access-token'),
    path('api/weather/', WeatherAPIView.as_view(), name='weather'),
    path('weather/', weather_view, name='weather'),
    #after login,validates the token
    path('oauth/success/', oauth_success_redirect, name='oauth-success'),
    path('api/gmail-events/', GmailEventDetectionView.as_view(), name='gmail-events'),
    path('api/extract-events-fallback/', extract_events_fallback, name='extract-events-fallback'),
    path("api/fetch-flight-data/", flight_data_view, name="fetch-flight-data"),
    path("api/fetch-stored-flights/", fetch_stored_flights, name="fetch-stored-flights"), 
    path("create-superuser/", create_superuser_view),
]
