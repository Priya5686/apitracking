from django.urls import path
from .views import flight_status, flight_form_view, save_subscription, rapidapi_webhook

urlpatterns = [
    path('flight-status/', flight_form_view), 
    path('api/flightstatus/',flight_status),
    path("api/save-subscription/", save_subscription),
    path('api/rapidapi-webhook/', rapidapi_webhook),  
]
