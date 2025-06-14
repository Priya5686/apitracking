"""import requests
from django.conf import settings

def get_flight_status_from_aviationstack(flight_number, airline_name, departure_date):
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
    airline_iata = AIRLINE_MAP.get(airline_name)
    if not airline_iata:
        return {"error": "Unsupported airline name"}
    
    #flight_iata = f"{airline_iata}{flight_number}"
    
    API_KEY = settings.AVIATIONAPI_KEY
    url = 'http://api.aviationstack.com/v1/flights'

    params = {
        'access_key': API_KEY,
        'flight_iata': flight_number,
        #'flight_iata': flight_iata,
        'airline_name': airline_name,
        'dep_date': departure_date,
    }

    response = requests.get(url, params=params)
    response.raise_for_status()

    data = response.json()
    # Parse or simplify data as needed
    return data"""



import requests
from datetime import datetime
from django.conf import settings

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

    return {"error": "No matching flight found for that date."}
