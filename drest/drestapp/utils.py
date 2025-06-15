"""import os
import json
import requests
from django.utils import timezone as dj_timezone
from dateutil.parser import parse as parse_date
from dateutil.tz import gettz
from datetime import datetime, timezone
import re
    




def extract_events_with_ollama(text):
    today = dj_timezone.localtime().strftime("%Y-%m-%d")
    events = []

    prompt = (
    f"Today is {today}.\n"
    "Extract only calendar events directly mentioned in the following email.\n"
    "Do NOT infer or create events—only extract what is explicitly stated.\n"
    "Return structured data in JSON format, with the following fields:\n"
    "- type (Meeting, Appointment, Due, Deadline, Reminder, Tracking, Social Event)\n"
    "- description (exact wording from the email)\n"
    "- start_datetime (ISO 8601 format, required if available)\n"
    "- end_datetime (ISO 8601 format, optional)\n"
    "- location (if explicitly mentioned)\n"
    "- notes (additional info, if stated in the email)\n\n"
    "Do not include explanations—just return a JSON object formatted like this:\n"
    "{\n"
    "  \"events\": [\n"
    "    {\"type\": \"meeting\", \"description\": \"Project update meeting\", \"start_datetime\": \"2025-05-29T14:00:00\", \"location\": \"Al Qusais Conference Room\"}\n"
    "  ]\n"
    "}\n\n"
    f"Email:\n{text}"
)


    try:
        response = requests.post("http://localhost:11434/api/generate", json={
            "model": "deepseek-r1:1.5b",
            "prompt": prompt,
            "format": "json",
            "stream": False
        }, timeout=180)

        print("🔍 Raw Ollama Response:", response.json())  

        if response.status_code != 200:
            return []

        raw = response.json().get("response", "")

        # ✅ Improved JSON parsing—handling AI-generated formatting errors
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            raw = raw.strip().replace("\n", "").replace("\\", "")
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                print("❌ Failed to parse Ollama output, returning empty response.")
                return []

        json_blocks = parsed.get("events", [])

        # ✅ Improved Time Zone Handling
        tzinfos = {
            "EST": gettz("America/New_York"),
            "PST": gettz("America/Los_Angeles"),
            "CST": gettz("America/Chicago"),
            "IST": gettz("Asia/Kolkata"),
            "GMT": gettz("Etc/GMT"),
            "UTC": gettz("UTC"),
        }

        for data in json_blocks:
            if not isinstance(data, dict):
                continue

            type_ = (data.get("type") or "").strip().lower()
            desc = (data.get("description") or "").strip()
            location = (data.get("location") or "").strip()
            notes = (data.get("notes") or "").strip()

            if not type_ or "..." in desc:
                continue

            start_str = data.get("start_datetime") or data.get("delivery_date") or data.get("due_datetime") or ""
            end_str = data.get("end_datetime") or ""

            try:
                start = parse_date(start_str, fuzzy=True, tzinfos=tzinfos) if start_str else None

                if start and start.strftime("%H:%M:%S") == "00:00:00":
                    start = start.replace(hour=9, minute=0)

                if start and not start.tzinfo:
                    start = dj_timezone.make_aware(start).astimezone(timezone.utc)
            except ValueError:
                start = None

            try:
                end = parse_date(end_str, fuzzy=True, tzinfos=tzinfos) if end_str else None
    
                if not end and end_str in ["TBD", None]:  
                    if type_ in ["meeting", "appointment"]:
                        end = start + timedelta(hours=1) if start else None
                    elif type_ in ["social event"]:
                        end = start + timedelta(hours=2) if start else None
                    else:
                        end = start + timedelta(minutes=30) if start else None

                if end and not end.tzinfo:
                    end = dj_timezone.make_aware(end).astimezone(timezone.utc)

            except ValueError:
                    print(f"⚠️ Warning: Failed to parse end_datetime for event '{desc}'. Using fallback.")
                    end = None

            events.append({
                "type": type_,
                "description": desc,
                "start": start.isoformat() if isinstance(start, datetime) else None,
                "end": end.isoformat() if isinstance(end, datetime) else None,
                "location": location if location else None,
                "notes": notes if notes else None
            })

    except (requests.RequestException, json.JSONDecodeError):
        return []

    return events"""


"""import json
import re
from dateutil.parser import parse as parse_date
from django.utils import timezone as dj_timezone
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def extract_events_fallback_view(request):
    text = request.GET.get("text", "")  # ✅ Extract text from query parameter
    
    if not text:
        return JsonResponse({"error": "Missing text parameter"}, status=400)

    try:
        event_data = extract_events_fallback(text)  # ✅ Pass only extracted text, not request object
        return JsonResponse(json.loads(event_data))
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def extract_events_fallback(text):
    events = []

    event_keywords = {
        "meeting": "Meeting",
        "appointment": "Appointment",
        "deadline": "Deadline",
        "reminder": "Reminder",
        "conference": "Conference",
        "call": "Call",
        "webinar": "Webinar",
        "invoice due": "Due",
        "payment due": "Due",
        "tracking": "Tracking",
        "room": "Meeting",
        "conference room": "Meeting",
        "office": "Meeting"
    }

    date_pattern = r"\b(?:\w+\s\d{1,2}(?:th|st|rd)?,?\s\d{4}|\d{4}-\d{2}-\d{2}|\b(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)\b)"
    time_pattern = r"\b(?:\d{1,2}:\d{2}\s?(?:AM|PM)?|\b(?:morning|afternoon|evening|night)\b)"
    location_pattern = r"\bin\b\s([A-Za-z\s]+)"

    dates = re.findall(date_pattern, text)
    times = re.findall(time_pattern, text)
    locations = re.findall(location_pattern, text)

    for i, d in enumerate(dates):
        try:
            dt = parse_date(d, fuzzy=True)
            if dj_timezone.is_naive(dt):
                dt = dj_timezone.make_aware(dt)
            dates[i] = dt.isoformat()
        except ValueError:
            dates[i] = None

    sentences = text.split(".")
    for sentence in sentences:
        for keyword in event_keywords:
            if keyword in sentence.lower():
                event_type = keyword.capitalize()
                event_date = next((d for d in dates if d in sentence), None)
                event_time = next((t for t in times if t in sentence), None)
                location = next((loc for loc in locations if loc in sentence), None)

                parsed_event = {
                    "type": event_type,
                    "description": sentence.strip(),
                    "date": event_date,
                    "time": event_time,
                    "location": location if location else None
                }
                events.append(parsed_event)

    return json.dumps({"events": events}, indent=2)"""


