import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .utils import fetch_flight_info, normalize_date
from .models import FlightStatusRecord
import requests
from django.utils.dateparse import parse_datetime

def flight_form_view(request):
    return render(request, 'flight_form.html')

@csrf_exempt
def flight_status(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            flight_number = data.get('flight_number')
            airline_name = data.get('airline_name')
            departure_date = data.get('departure_date')

            if not all([flight_number, airline_name, departure_date]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            dep_date = normalize_date(departure_date)
            flight_info = fetch_flight_info(flight_number, dep_date, airline_name)

            if "error" in flight_info:
                return JsonResponse({'error': flight_info["error"]}, status=404)

            # Save to DB
            FlightStatusRecord.objects.create(
                flight_number=flight_info["flight_number"],
                airline_name=flight_info["airline_name"],
                departure_airport=flight_info["scheduled_departure_airport"],
                departure_iata=flight_info["scheduled_departure_code"],
                departure_time=parse_datetime(flight_info["scheduled_departure_time"]),
                departure_gate=flight_info["gate_number_departure"],
                #departure_time=flight_info["scheduled_departure_time"],
                arrival_airport=flight_info["scheduled_arrival_airport"],
                arrival_iata=flight_info["scheduled_arrival_code"],
                arrival_gate=flight_info["arrival_gate"],
                arrival_baggage_belt=flight_info["arrival_belt_number"],
                arrival_time=parse_datetime(flight_info["scheduled_arrival_time"])
                #arrival_time=flight_info["scheduled_arrival_time"]
            )

            return JsonResponse(flight_info)
            print("Saving to DB:", flight_info)


        except requests.HTTPError as http_err:
            return JsonResponse({'error': f'API error: {http_err}'}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid method'}, status=405)
