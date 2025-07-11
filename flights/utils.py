#Aviation Stack
"""nabled
AIRLINE_MAP = {
    "Emirates": "EK",
    "Qatar Airways": "QR",
    "Etihad": "EY",
    "IndiGo": "6E",
    "Air India": "AI",
    "SpiceJet": "SG",
    "Air Arabia": "G9",
    "American Airlines": "AA",
}

def normalize_date(date_input: str) -> str:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_input, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    raise ValueError("Invalid date format. Use YYYY-MM-DD or DD/MM/YYYY.")

def fetch_flight_info(flight_number: str, dep_date: str, airline_name: str) -> dict:
    airline_iata = AIRLINE_MAP.get(airline_name.strip())
    if not airline_iata:
        return {"error": "Unsupported airline name"}

    url = "https://api.aviationstack.com/v1/flights"
    params = {
        "access_key": settings.AVIATIONAPI_KEY,
        "flight_number": flight_number,
        "airline_iata": airline_iata,
        "scheduled": dep_date
    }

    response = requests.get(url, params=params)
    print("📤 Sending request to AviationStack:", params)
    print("🌐 Full URL:", response.url)
    print("📥 API Response Status:", response.status_code)
    print("📥 API Response Body:", response.text)

    response.raise_for_status()  # This will raise HTTPError for 4xx/5xx

    data = response.json().get("data", [])

    for flight in data:
        dep_time = flight.get("departure", {}).get("scheduled")
        if dep_time and dep_time.split("T")[0] == dep_date:
            return {
                "scheduled_departure_airport": flight["departure"].get("airport"),
                "scheduled_departure_code": flight["departure"].get("iata"),
                "scheduled_arrival_airport": flight["arrival"].get("airport"),
                "scheduled_arrival_code": flight["arrival"].get("iata"),
                "airline_name": flight["airline"].get("name"),
                "flight_number": flight["flight"].get("number"),
                "scheduled_departure_time": dep_time,
                "gate_number_departure": flight["departure"].get("gate"),
                "actual_departure_time": flight["departure"].get("actual"),
                "departure_delay_time": flight["departure"].get("delay"),
                "scheduled_arrival_time": flight["arrival"].get("scheduled"),
                "actual_arrival_time": flight["arrival"].get("actual"),
                "arrival_delay_time": flight["arrival"].get("delay"),
                "arrival_gate": flight["arrival"].get("gate"),
                "arrival_belt_number": flight["arrival"].get("baggage"),
            }

    return {"error": "No matching flight found for that date."}"""


import requests
from django.conf import settings
from datetime import datetime



def normalize_date(date_input: str) -> str:
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_input, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    raise ValueError("Invalid date format. Use YYYY-MM-DD or DD/MM/YYYY.")

def fetch_flight_info(iata_number, departure_date):
    try:
        url = f"https://aerodatabox.p.rapidapi.com/flights/number/{iata_number}/{departure_date}"
        headers = {
            "X-RapidAPI-Key":  settings.NEWAPI_KEY,
            "X-RapidAPI-Host": "aerodatabox.p.rapidapi.com"
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if isinstance(data, list) and data:
            flight = data[0]
        elif isinstance(data, dict) and "flights" in data and isinstance(data["flights"], list) and data["flights"]:
            flight = data["flights"][0]
        else:
            return {"error": "Flight not found or response format unexpected"}


        return {
            "flight_number": flight.get("number") or flight.get("flightNumber"),
            "airline_name": flight.get("airline", {}).get("name"),

            "scheduled_departure_airport": flight.get("departure", {}).get("airport", {}).get("name"),
            "departure_iata": flight.get("departure", {}).get("airport", {}).get("iata"),
            #"scheduled_departure_time_utc": flight.get("departure", {}).get("scheduledTime", {}).get("utc"),
            "scheduled_departure_time_local": flight.get("departure", {}).get("scheduledTime", {}).get("local"),
            #departure_time = f"UTC: {scheduled_departure_time_utc} | Local: {scheduled_departure_time_local}"
            #"actual_departure_time_utc": flight.get("departure", {}).get("actualTime", {}).get("utc"),
            "actual_departure_time_local": flight.get("departure", {}).get("actualTime", {}).get("local"),
            "departure_gate": flight.get("departure", {}).get("gate"),

            "scheduled_arrival_airport": flight.get("arrival", {}).get("airport", {}).get("name"),
            "arrival_iata": flight.get("arrival", {}).get("airport", {}).get("iata"),
            #"scheduled_arrival_time_utc": flight.get("arrival", {}).get("scheduledTime", {}).get("utc"),
            "scheduled_arrival_time_local": flight.get("arrival", {}).get("scheduledTime", {}).get("local"),
            #"actual_arrival_time_utc": flight.get("arrival", {}).get("actualTime", {}).get("utc"),
            "actual_arrival_time_local": flight.get("arrival", {}).get("actualTime", {}).get("local"),
            "arrival_gate": flight.get("arrival", {}).get("gate"),
            "arrival_baggage_belt": flight.get("arrival", {}).get("baggageBelt"),
            

            #"delay_departure_minutes": flight.get("departure", {}).get("delay"),
            #"delay_arrival_minutes": flight.get("arrival", {}).get("delay"),
        }

    except requests.RequestException as e:
        return {"error": str(e)}


"""import json
from pywebpush import webpush, WebPushException
from django.conf import settings
from .models import PushSubscription

def notify_subscribers(title, body):
    payload = {
        "title": title,
        "body": body
    }

    for sub in PushSubscription.objects.all():
        sub_info = sub.subscription_info or {}
        keys = sub_info.get("keys", {})

        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {
                        "p256dh": keys.get("p256dh"),
                        "auth": keys.get("auth")
                    }
                },
                data=json.dumps(payload),
                vapid_private_key=settings.VAPID_PRIVATE_KEY,
                vapid_claims={"sub": "mailto:you@example.com"}
            )
            print(f"✅ Notification sent to {sub.endpoint[:50]}...")
        except WebPushException as e:
            print("❌ Push error:", e)"""

                
               



