"""import requests
from datetime import datetime

API_KEY = "452dd185aa6fd62185cd598aa1453998"
FLIGHT_NUM = "806"
AIRLINE = "EK"
today = datetime.today().strftime('%d-%m-%Y')

url = f"https://api.aviationstack.com/v1/flights"
params = {
    "access_key": API_KEY,
    "flight_number": FLIGHT_NUM,
    "airline_iata": AIRLINE,
    "scheduled": today
}

response = requests.get(url, params=params)
data = response.json()
#print(data)

import json

# Your response dict
data = {
    "flight_number": "EK806",
    "status": "scheduled",
    "departure": {"airport": "Dubai", "iata": "DXB"},
    "arrival": {"airport": "Jeddah", "iata": "JED"}
}
print(json.dumps(data, indent=2))
"""


import requests
from datetime import datetime
from pprint import pprint

AVIATIONSTACK_API_KEY = "5e36f3bb48068d619916ef7eada884d3"

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

def fetch_flight_info(flight_number: str, flight_date: str, airline_iata: str):
    airline_iata = AIRLINE_MAP.get(airline_name)
    if not airline_iata:
        print("❌ Unsupported airline name.")
        return {"error": "Unsupported airline name"}

    url = "http://api.aviationstack.com/v1/flights"
    params = {
        "access_key": AVIATIONSTACK_API_KEY,
        "flight_number": flight_number,
        "airline_iata": airline_iata,
        "scheduled": flight_date 
        #"flight_date": flight_date
    }

    response = requests.get(url, params=params)
    print("API URL:", response.url)
    data = response.json().get("data", [])

    for flight in data:
        departure_scheduled = flight.get("departure", {}).get("scheduled")
        #scheduled_depart_date = flight.get("flight_date")

        if not departure_scheduled:
            continue

        dep_date = departure_scheduled.split("T")[0]
        if dep_date != flight_date:
            continue

        return {
            "scheduled_departure_airport": flight["departure"].get("airport"),
            "scheduled_departure_code": flight["departure"].get("iata"),
            "scheduled_arrival_airport": flight["arrival"].get("airport"),
            "scheduled_arrival_code": flight["arrival"].get("iata"),
            "airline_name": flight["airline"].get("name"),
            "flight_number": flight["flight"].get("number"),
            "scheduled_departure_time": flight["departure"].get("scheduled"),
            #"depart_date": data.get("flight_date"),
            "baggage_checkin_starttime": None,
            "baggage_checkin_endtime": None,
            "boarding_pass_info": None,
            "checkin_tag_number": None,
            "gate_number_departure": flight["departure"].get("gate"),
            "scheduled_boarding_time_start": None,
            "scheduled_boarding_time_end": None,
            "actual_boarding_time": None,
            "actual_departure_time": flight["departure"].get("actual"),
            "departure_delay_time": flight["departure"].get("delay"),
            "scheduled_arrival_time": flight["arrival"].get("scheduled"),
            "actual_arrival_time": flight["arrival"].get("actual"),
            "arrival_delay_time": flight["arrival"].get("delay"),
            "arrival_gate": flight["arrival"].get("gate"),
            "arrival_belt_number": flight["arrival"].get("baggage")
         
        }

    return {"error": "No matching flight found for that date."}

if __name__ == "__main__":
    flight_number = input("Enter flight number (e.g. 546): ").strip()
    date_input = input("Enter flight date (YYYY-MM-DD or DD/MM/YYYY): ").strip()
    airline_name = input("Enter the airline name: ").strip()

    try:
        flight_date = normalize_date(date_input)
        result = fetch_flight_info(flight_number, flight_date, airline_name)
        pprint(result)
    except ValueError as e:
        print(f"❌ Error: {e}")



