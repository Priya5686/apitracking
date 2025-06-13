from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .utils import normalize_date, fetch_flight_info
from .models import FlightStatusRecord
from django.utils.dateparse import parse_datetime
from django.shortcuts import render,redirect
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
class FlightStatusAPIView(APIView):
    def post(self, request):
        try:
            data = request.data  # works for both JSON and form data
            flight_number = data.get('flight_number')
            airline_name = data.get('airline_name')
            departure_date = data.get('departure_date')

            if not all([flight_number, airline_name, departure_date]):
                return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

            dep_date = normalize_date(departure_date)
            flight_info = fetch_flight_info(flight_number, dep_date, airline_name)

            if "error" in flight_info:
                return Response({'error': flight_info["error"]}, status=status.HTTP_404_NOT_FOUND)

            # Save to DB
            FlightStatusRecord.objects.create(
                flight_number=flight_info["flight_number"],
                airline_name=flight_info["airline_name"],
                departure_airport=flight_info["scheduled_departure_airport"],
                departure_iata=flight_info["scheduled_departure_code"],
                departure_time=parse_datetime(flight_info["scheduled_departure_time"]),
                departure_gate=flight_info["gate_number_departure"],
                arrival_airport=flight_info["scheduled_arrival_airport"],
                arrival_iata=flight_info["scheduled_arrival_code"],
                arrival_gate=flight_info["arrival_gate"],
                arrival_baggage_belt=flight_info["arrival_belt_number"],
                arrival_time=parse_datetime(flight_info["scheduled_arrival_time"])
            )

            return Response(flight_info, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
def flight_form_view(request):
    return render(request, "flight_form.html")

