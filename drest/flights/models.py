# models.py

from django.db import models
import uuid

class FlightStatusRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flight_number = models.CharField(max_length=10)
    airline_name = models.CharField(max_length=100)

    departure_airport = models.CharField(max_length=100)
    departure_iata = models.CharField(max_length=10)
    departure_gate = models.CharField(max_length=10, null=True, blank=True)
    departure_time = models.DateTimeField()

    arrival_airport = models.CharField(max_length=100)
    arrival_iata = models.CharField(max_length=10)
    arrival_gate = models.CharField(max_length=10, null=True, blank=True)
    arrival_baggage_belt = models.CharField(max_length=10, null=True, blank=True)
    arrival_time = models.DateTimeField()

    created_at = models.DateTimeField(auto_now_add=True)
