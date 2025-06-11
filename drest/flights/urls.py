from django.urls import path
from .views import flight_status, flight_form_view

urlpatterns = [
    path('flight-form/', flight_form_view), 
    path('api/flightstatus/', flight_status),

]
