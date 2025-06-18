# models.py

from django.db import models
import uuid

class FlightStatusRecord(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    flight_number = models.CharField(max_length=10)
    airline_name = models.CharField(max_length=100)

    departure_airport = models.CharField(max_length=100)
    departure_iata = models.CharField(max_length=10)
    scheduled_departure_time = models.DateTimeField()
    actual_departure_time = models.DateTimeField(null=True, blank=True)
    departure_gate = models.CharField(max_length=10, null=True, blank=True)

    arrival_airport = models.CharField(max_length=100)
    arrival_iata = models.CharField(max_length=10)
    scheduled_arrival_time = models.DateTimeField()
    actual_arrival_time = models.DateTimeField(null=True, blank=True)
    arrival_gate = models.CharField(max_length=10, null=True, blank=True)
    arrival_baggage_belt = models.CharField(max_length=10, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


class PushSubscription(models.Model):
    endpoint = models.TextField(unique=True)
    subscription_info = models.JSONField()
    p256dh = models.TextField(blank=True, null=True)  # From subscription["keys"]["p256dh"]
    auth = models.TextField(blank=True, null=True)    # From subscription["keys"]["auth"]
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Subscription to {self.endpoint[:30]}..."