from django.urls import path
from .views import FlightStatusAPIView, flight_form_view

urlpatterns = [
    path('flight-form/', flight_form_view), 
    path('api/flightstatus/',FlightStatusAPIView.as_view ),


]
