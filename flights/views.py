"""import json
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

    return JsonResponse({'error': 'Invalid method'}, status=405)"""




import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from .utils import fetch_flight_info, normalize_date
import requests
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_http_methods
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from .models import PushSubscription, FlightStatusRecord, RapidAPISubscription   # Create this model


def flight_form_view(request):
    return render(request, 'flight_status.html', {
        'vapid_public_key': settings.VAPID_PUBLIC_KEY
    })

@csrf_exempt
@require_http_methods(["POST"])
def flight_status(request):
    try:
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            data = request.POST

        iata_number = data.get('iata_number', '').strip()
        departure_date = data.get('departure_date', '').strip()

        if not all([iata_number, departure_date]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)

        airline_code = ''.join([c for c in iata_number if c.isalpha()])
        flight_number = ''.join([c for c in iata_number if c.isdigit()])
        dep_date = normalize_date(departure_date)

        existing = FlightStatusRecord.objects.filter(
            flight_number=flight_number,
            airline_name=airline_code,
            scheduled_departure_time__date=dep_date
        ).first()

        if existing:
            return JsonResponse({"message": "Flight already exists", "id": existing.id})

        flight_info = fetch_flight_info(iata_number, dep_date)
        print("🔍 Flight info received:", flight_info)

        if "error" in flight_info:
            return JsonResponse({'error': flight_info["error"]}, status=404)

        # Save flight record
        record = FlightStatusRecord.objects.create(
            flight_number=flight_info["flight_number"],
            airline_name=flight_info["airline_name"],
            departure_airport=flight_info["scheduled_departure_airport"],
            departure_iata=flight_info["departure_iata"],
            #scheduled_departure_time_utc=parse_datetime(flight_info["scheduled_departure_time_utc"]),
            scheduled_departure_time_local=parse_datetime(flight_info["scheduled_departure_time_local"]),
            #actual_departure_time_utc=parse_datetime(flight_info["actual_departure_time_utc"]) if flight_info["actual_departure_time_utc"] else None,
            actual_departure_time_local=parse_datetime(flight_info["actual_departure_time_local"]) if flight_info["actual_departure_time_local"] else None,
            departure_gate=flight_info["departure_gate"],
            arrival_airport=flight_info["scheduled_arrival_airport"],
            arrival_iata=flight_info["arrival_iata"],
            #scheduled_arrival_time_utc=parse_datetime(flight_info["scheduled_arrival_time_utc"]),
            scheduled_arrival_time_local=parse_datetime(flight_info["scheduled_arrival_time_local"]),
            actual_arrival_time_local=parse_datetime(flight_info["actual_arrival_time_local"]) if flight_info["actual_arrival_time_local"] else None,
            arrival_gate=flight_info["arrival_gate"],
            arrival_baggage_belt=flight_info["arrival_baggage_belt"],
        )

        # Subscribe to webhook
        subscribe_url = f"https://aerodatabox.p.rapidapi.com/subscriptions/webhook/FlightByNumber/{iata_number}"
        payload = {"url": f"{settings.SITE_URL}/api/rapidapi-webhook/"}
        headers = {
            "X-RapidAPI-Key": settings.RAPIDWEBHOOK_KEY,
            "X-RapidAPI-Host": "aerodatabox.p.rapidapi.com",
            "Content-Type": "application/json"
        }

        sub_response = requests.post(subscribe_url, json=payload, headers=headers)
        print("Webhook subscription response:", sub_response.text)

        if sub_response.status_code != 200:
            return JsonResponse({'error': 'Failed to subscribe to webhook'}, status=500)

        sub_data = sub_response.json()
        import uuid
        from .models import RapidAPISubscription

        # Save subscription record
        RapidAPISubscription.objects.update_or_create(
            id=uuid.UUID(sub_data["id"]),
            defaults={
                "flight": record,
                "is_active": sub_data.get("isActive", True),
                "expires_on": parse_datetime(sub_data["expiresOnUtc"]),
            }
        )

        return JsonResponse({"message": "Flight info saved", "flight": flight_info, "subscription_id": sub_data["id"]})

    except requests.HTTPError as http_err:
        return JsonResponse({'error': f'API error: {http_err}'}, status=500)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def rapidapi_webhook(request):
    try:
        raw_body = request.body.decode()
        print("Raw Body Received:", raw_body)
        payload = json.loads(request.body)
        print("Webhook received:", payload)

        subject = payload.get("subject", {})
        flight_number = subject.get("id")  # e.g., "EK 809"
        if not flight_number:
            return JsonResponse({"error": "Missing flight number"}, status=400)
        
        record = FlightStatusRecord.objects.filter(flight_number=flight_number).replace(" ", "").first()
        if not record:
            return JsonResponse({"error": "Flight not found"}, status=404)
        

        url = f"https://aerodatabox.p.rapidapi.com/flights/number/{flight_number}/{record.scheduled_departure_time.date()}"
        headers = {
            "X-RapidAPI-Key": settings.RAPIDWEBHOOK_KEY,
            "X-RapidAPI-Host": "aerodatabox.p.rapidapi.com"
        }
        response = requests.get(url, headers=headers)
        data = response.json()

        # Safely extract and update gate and baggage info
        updates = {
            "departure_gate": data.get("departure", {}).get("gate"),
            "scheduled_departure_time_local": data.get("departure", {}).get("scheduledTimeLocal"),
            "actual_departure_time_local": data.get("departure", {}).get("actualTimeLocal"),
    
            "arrival_gate": data.get("arrival", {}).get("gate"),
            "arrival_baggage_belt": data.get("arrival", {}).get("baggageBelt") or data.get("arrival", {}).get("baggage"),
            "scheduled_arrival_time_local": data.get("arrival", {}).get("scheduledTimeLocal"),
            "actual_arrival_time_local": data.get("arrival", {}).get("actualTimeLocal"),
        }

        cleaned = {k: v for k, v in updates.items() if v}
        print("🔄 Updating:", cleaned)

        for key, value in cleaned.items():
              if 'time' in key:
                 value = parse_datetime(value)  # safely parse to datetime
              setattr(record, key, value)
        record.save()
           

        from .utils import notify_subscribers
        notify_subscribers(f"Flight {flight_number} updated", "Check your dashboard for changes.")

        return JsonResponse({"message": "Flight update processed."})

    except Exception as e:
        print("Webhook error:", str(e))
        return JsonResponse({"error": "Invalid webhook data."}, status=400)

    
@csrf_exempt
@require_http_methods(["POST"])
def save_subscription(request):
    try:
        subscription = json.loads(request.body)

        endpoint = subscription.get("endpoint")
        if not endpoint:
            return JsonResponse({"error": "Missing endpoint in subscription"}, status=400)


        keys = subscription.get("keys", {})
        p256dh = keys.get("p256dh")
        auth = keys.get("auth")

        # Save or update the subscription
        PushSubscription.objects.update_or_create(
            endpoint=endpoint,
             defaults={
                "subscription_info": subscription,
                "p256dh": p256dh or '',
                "auth": auth or '',
            }
        )

        return JsonResponse({"message": "Subscription saved."})
    
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


#return JsonResponse({'error': 'Invalid method'}, status=405)

from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from datetime import timedelta
from .models import RapidAPISubscription, FlightStatusRecord
from django.conf import settings
from .utils import notify_subscribers
import requests

@csrf_exempt
@require_http_methods(["PATCH"])
def refresh_subscription(request, subscription_id):
    try:
        sub = RapidAPISubscription.objects.select_related('flight').get(id=subscription_id)
        flight = sub.flight

        # ⏱ Check if it's within 1 hour before departure
        if not (now() <= flight.scheduled_departure_time_local <= now() + timedelta(hours=1)):
            return JsonResponse({'error': 'Flight is not within refresh window'}, status=400)

        # 🔁 Call RapidAPI refresh endpoint
        refresh_url = f"https://aerodatabox.p.rapidapi.com/subscriptions/refresh/{subscription_id}"
        headers = {
            "X-RapidAPI-Key": settings.RAPIDWEBHOOK_KEY,
            "X-RapidAPI-Host": "aerodatabox.p.rapidapi.com"
        }

        refresh_response = requests.patch(refresh_url, headers=headers)
        if refresh_response.status_code != 200:
            return JsonResponse({'error': 'Failed to refresh subscription'}, status=500)

        # 📥 Now fetch updated flight info
        flight_info_url = f"https://aerodatabox.p.rapidapi.com/flights/number/{flight.flight_number}/{flight.scheduled_departure_time.date()}"
        data_response = requests.get(flight_info_url, headers=headers)
        flight_data = data_response.json()

        updated_fields = {
            "departure_gate": flight_data.get("departure", {}).get("gate"),
            "arrival_gate": flight_data.get("arrival", {}).get("gate"),
            "arrival_baggage_belt": flight_data.get("arrival", {}).get("baggageBelt") or flight_data.get("arrival", {}).get("baggage"),
            "scheduled_departure_time_local": flight_data.get("departure", {}).get("scheduledTimeLocal"),
            "scheduled_arrival_time_local": flight_data.get("arrival", {}).get("scheduledTimeLocal"),
            "actual_departure_time_local": flight_data.get("departure", {}).get("actualTimeLocal"),
            "actual_arrival_time_local": flight_data.get("arrival", {}).get("actualTimeLocal"),
        }

        # 🛠 Update DB if changed
        changes = {}
        for field, value in updated_fields.items():
            if value and str(getattr(flight, field)) != str(value):
                setattr(flight, field, value)
                changes[field] = value

        if changes:
            flight.save()
            notify_subscribers(f"Flight {flight.flight_number} updated via refresh", f"Changed: {', '.join(changes.keys())}")

        return JsonResponse({
            'message': 'Flight data refreshed',
            'updated_fields': changes
        })

    except RapidAPISubscription.DoesNotExist:
        return JsonResponse({'error': 'Subscription not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
