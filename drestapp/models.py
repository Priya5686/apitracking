from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser): 
    email = models.EmailField(unique=True)
    email_verified = models.BooleanField(default=False)
    first_name = models.CharField(max_length=50,blank=True,null=True)
    last_name = models.CharField(max_length=50,blank=True,null=True)
    #expires_at = models.DateTimeField(blank=True,null=True)

USERNAME_FIELD = 'email'  # Use email as the unique identifier for authentication
REQUIRED_FIELDS = ['username']

class EmailVerificationToken(models.Model):
    user = models.OneToOneField('drestapp.CustomUser', on_delete=models.CASCADE,related_name="verification_token")
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

from django.db import models
from django.conf import settings

class GmailMessage(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    message_id = models.CharField(max_length=255, unique=True)
    from_email = models.TextField()
    to_email = models.TextField()
    cc = models.TextField(blank=True, null=True)
    bcc = models.TextField(blank=True, null=True)
    subject = models.TextField(blank=True, null=True)
    plain_content = models.TextField(blank=True, null=True)
    html_content = models.TextField(blank=True, null=True)
    received_at = models.DateTimeField(auto_now_add=True)

    #flight_number = models.CharField(max_length=10, null=True, blank=True)
    #airline_name = models.CharField(max_length=50, null=True, blank=True)
    #departure_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.subject} from {self.from_email}"
    
from django.db import models
from django.utils.timezone import now

class ExtractedEvent(models.Model):
    EVENT_TYPES = [
        ("schedule", "Schedule"),
        ("deadline", "Deadline"),
        ("appointment", "Appointment"),
        ("renewal", "Renewal"),
        ("due", "Due"),
        ("receipt", "Receipt"),
        ("delivery", "Delivery"),
        ("task", "Task"),
        ("other", "Other")
    ]

    type = models.CharField(max_length=100, choices=EVENT_TYPES, db_index=True)
    description = models.TextField()
    start_datetime = models.DateTimeField(null=True, blank=True)
    end_datetime = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True, null=True)  # ✅ Allow extra details
    #user = models.ForeignKey("auth.User", on_delete=models.CASCADE, related_name="events", null=True, blank=True)  # ✅ Associate events with users
    user = models.ForeignKey('drestapp.CustomUser', on_delete=models.CASCADE, related_name="events", null=True, blank=True)  # ✅ Associate events with users
    created_at = models.DateTimeField(auto_now_add=True)  # ✅ Track event creation
    updated_at = models.DateTimeField(auto_now=True)  # ✅ Track last update

    def __str__(self):
        return f"{self.get_type_display()} - {self.description[:50]}"
    

class FlightRecord(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    flight_number = models.CharField(max_length=10)
    airline_name = models.CharField(max_length=50)
    #flight_date = models.DateField(null=True, blank=True)
    scheduled_date = models.DateField(null=True, blank=True)
    scheduled_departure_airport = models.CharField(max_length=100, null=True, blank=True)
    scheduled_departure_code = models.CharField(max_length=10, null=True, blank=True)
    scheduled_departure_time = models.DateTimeField(null=True, blank=True)
    gate_number_departure = models.CharField(max_length=10, null=True, blank=True)
    actual_departure_time = models.DateTimeField(null=True, blank=True)
    scheduled_arrival_airport = models.CharField(max_length=100, null=True, blank=True)
    scheduled_arrival_code = models.CharField(max_length=10, null=True, blank=True)
    scheduled_arrival_time = models.DateTimeField(null=True, blank=True)
    actual_arrival_time = models.DateTimeField(null=True, blank=True)
    arrival_gate = models.CharField(max_length=10, null=True, blank=True)
    arrival_belt_number = models.CharField(max_length=10, null=True, blank=True)
    #status = models.CharField(max_length=20, default="Scheduled")  # ✅ Add flight status tracking
    last_updated = models.DateTimeField(auto_now=True)  # ✅ Track updates

class Meta:
    #unique_together = ('user', 'flight_number', 'scheduled_date', 'airline_name')
    pass

def __str__(self):
    return f"{self.airline_name} {self.flight_number} on {self.scheduled_date}"

