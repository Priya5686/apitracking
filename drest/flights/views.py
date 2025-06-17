import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .utils import fetch_flight_info, normalize_date
from .models import FlightStatusRecord
import requests
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_http_methods
from django.conf import settings

def flight_form_view(request):
    return render(request, 'flight_status.html', {
        'vapid_public_key': settings.VAPID_PUBLIC_KEY
    })

@csrf_exempt
@require_http_methods(["POST"])
def flight_status(request):
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST
            flight_number = data.get('flight_number')
            airline_name = data.get('airline_name')
            departure_date = data.get('departure_date')

            if not all([flight_number, airline_name, departure_date]):
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            dep_date = normalize_date(departure_date)

            existing = FlightStatusRecord.objects.filter(
            flight_number=flight_number,
            airline_name=airline_name,
            departure_time__date=dep_date
        ).first()
            
            if existing:
                  return JsonResponse({"message": "Flight already exists", "id": existing.id})
            

            flight_info = fetch_flight_info(flight_number, dep_date, airline_name)

            if "error" in flight_info:
                return JsonResponse({'error': flight_info["error"]}, status=404)

            # Save to DB
            record = FlightStatusRecord.objects.create(
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

              # Register webhook to RapidAPI
            subscribe_url = f"https://aerodatabox.p.rapidapi.com/subscriptions/webhook/FlightByNumber/{record.airline_name}{record.flight_number}"
            payload = {"url": f"{settings.SITE_URL}/api/rapidapi-webhook/"}
            headers = {
                "x-rapidapi-key": settings.RAPIDAPI_KEY,
                "x-rapidapi-host": "aerodatabox.p.rapidapi.com",
                "Content-Type": "application/json"
            }

            sub_response = requests.post(subscribe_url, json=payload, headers=headers)
            print("Webhook subscription response:", sub_response.text)

            return JsonResponse({"message": "Flight info saved", "flight": flight_info})

            return JsonResponse(flight_info)
            print("Saving to DB:", flight_info)


        except requests.HTTPError as http_err:
            return JsonResponse({'error': f'API error: {http_err}'}, status=500)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
        

@csrf_exempt
@require_http_methods(["POST"])
def rapidapi_webhook(request):
    try:
        payload = json.loads(request.body)
        print("📥 Webhook received:", payload)

        # Extract relevant fields
        flight_id = payload.get("flight", {}).get("number")
        updated_info = {
            # Map fields as needed
            "departure_gate": payload.get("departure", {}).get("gate"),
            "arrival_gate": payload.get("arrival", {}).get("gate"),
            "arrival_baggage_belt": payload.get("arrival", {}).get("baggage"),
        }

        updated = FlightStatusRecord.objects.filter(flight_number=flight_id).update(**updated_info)
        print("✅ Updated flight records:", updated)
        return JsonResponse({"message": "Flight update processed."})

    except Exception as e:
        print("❌ Webhook processing error:", str(e))
        return JsonResponse({"error": "Invalid webhook data."}, status=400)
    



#return JsonResponse({'error': 'Invalid method'}, status=405)
