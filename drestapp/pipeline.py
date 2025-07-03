from django.conf import settings
import requests
from django.shortcuts import redirect
from social_core.pipeline.partial import partial
from django.contrib.auth import get_user_model
from social_core.exceptions import AuthException

def associate_by_email_if_safe(strategy, details, backend, user=None, *args, **kwargs):
    if user:
        return  # already authenticated

    email = details.get('email')
    if not email:
        raise AuthException(backend, "No email address provided by Google.")

    User = get_user_model()

    try:
        existing_user = User.objects.get(email=email)

        if existing_user.has_usable_password():
            # Prevent linking to accounts that have passwords (for safety)
            raise AuthException(backend, "An account already exists with this email. Please sign in using your email and password.")
        else:
            # Safe to associate — user came from social only
            return {'user': existing_user}

    except User.DoesNotExist:
        return  # Allow pipeline to create new user


"""@partial
def link_to_existing_user(strategy, backend, details, user=None, *args, **kwargs):
    if user:
        # Already logged in — proceed normally
        return {'user': user}

    email = details.get('email')
    if not email:
        return

    try:
        existing_user = User.objects.get(email=email)
    except User.DoesNotExist:
        return  # No existing user, allow pipeline to continue

    # Social account is not yet linked, and this email already exists
    strategy.session_set("link_email", email)
    return redirect("/link-account/")"""


"""def link_to_existing_user(backend, details, user=None, *args, **kwargs):
    #If not logged in, try to link Google to existing user with same email.
    if user:
        return {'user': user}

    email = details.get('email')
    if not email:
        return

    try:
        existing_user = User.objects.get(email=email)
        # Raise if this user already linked to a different social account
        if backend.strategy.storage.user.get_social_auth(backend.name, kwargs['uid']):
            raise AuthAlreadyAssociated(backend, "That social account is already in use.")

        return {'user': existing_user}
    except User.DoesNotExist:
        return

def debug_pipeline_step(backend, user=None, *args, **kwargs):
    print(f"Backend: {backend.name}")
    print(f"User: {user}")
    print(f"Args: {args}")
    print(f"Kwargs: {kwargs}")"""


"""import requests
import base64
import logging
from django.conf import settings
logger = logging.getLogger(__name__)

def decode_base64(data):
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data.encode()).decode(errors="ignore")
    except Exception:
        return ""

def extract_gmail_details(message_json):
    headers = {h["name"]: h["value"] for h in message_json.get("payload", {}).get("headers", [])}

    msg_id = message_json.get("id")
    subject = headers.get("Subject", "")
    sender = headers.get("From", "")
    to = headers.get("To", "")
    cc = headers.get("Cc", "")
    bcc = headers.get("Bcc", "")

    plain_body = ""
    html_body = ""

    def walk_parts(part):
        nonlocal plain_body, html_body
        if part.get("mimeType") == "text/plain":
            plain_body = part.get("body", {}).get("data", "")
        elif part.get("mimeType") == "text/html":
            html_body = part.get("body", {}).get("data", "")
        elif "parts" in part:
            for p in part["parts"]:
                walk_parts(p)

    walk_parts(message_json.get("payload", {}))

    return {
        "message_id": msg_id,
        "from": sender,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "plain_content": decode_base64(plain_body),
        "html_content": decode_base64(html_body),
        "raw_base64": message_json.get("raw")
    }

import re

def clean_plain_text(content):
    if not content:
        return ""

    # 1. Remove URLs
    content = re.sub(r'https?://\S+|www\.\S+', '', content)

    # 2. Remove email addresses
    content = re.sub(r'\S+@\S+', '', content)

    # 3. Remove "On [date], [name] wrote:" (reply quotes)
    content = re.sub(r"On.*wrote:", "", content)

    # 4. Remove common footer lines (optional: customize more)
    content = re.sub(r"(?i)(unsubscribe|view in browser|confidential).*", "", content)

    # 5. Remove extra spaces and line breaks
    content = re.sub(r'\n+', '\n', content).strip()

    return content

from drestapp.pipeline import clean_plain_text


from drestapp.models import GmailMessage

def save_emails_to_db(strategy, backend, user, **kwargs):
    if backend.name != "google-oauth2":
        return

    logger.debug("✅ Gmail DB pipeline triggered for: %s", user)

    try:
        social = user.social_auth.get(provider='google-oauth2')
        token = social.extra_data.get("access_token")
    except Exception as e:
        logger.error("❌ Token fetch failed: %s", e)
        return

    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"maxResults": 3, "labelIds": "INBOX"}
    )

    if res.status_code != 200:
        logger.warning("❌ Gmail fetch failed: %s", res.text)
        return

    for msg in res.json().get("messages", []):
        detail = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg['id']}",
            headers=headers,
            params={"format": "full"}
        ).json()

        email_data = extract_gmail_details(detail)
        plain_clean = clean_plain_text(email_data["plain_content"])

        # Avoid duplicates
        if GmailMessage.objects.filter(message_id=email_data["message_id"]).exists():
            continue

        GmailMessage.objects.create(
            user=user,
            message_id=email_data["message_id"],
            from_email=email_data["from"],
            to_email=email_data["to"],
            cc=email_data["cc"],
            bcc=email_data["bcc"],
            subject=email_data["subject"],
            plain_content=plain_clean,
            html_content=email_data["html_content"],
            
        )



def save_emails_to_google_sheet(strategy, backend, user, **kwargs):
    if backend.name != "google-oauth2":
        return

    logger.debug("✅ Gmail pipeline triggered for: %s", user)

    try:
        social = user.social_auth.get(provider='google-oauth2')
        token = social.extra_data.get("access_token")
    except Exception as e:
        logger.error("❌ Token fetch failed: %s", e)
        return

    # Step 1: Fetch recent Gmail messages
    headers = {"Authorization": f"Bearer {token}"}
    res = requests.get(
        "https://gmail.googleapis.com/gmail/v1/users/me/messages",
        headers=headers,
        params={"maxResults": 5, "labelIds": "INBOX"}
    )

    if res.status_code != 200:
        logger.warning("❌ Gmail fetch failed: %s", res.text)
        return

    messages = []
    for msg in res.json().get("messages", []):
        detail = requests.get(
            f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg['id']}",
            headers=headers,
            params={"format": "full"}
        ).json()

        email_data = extract_gmail_details(detail)

        plain_clean = clean_plain_text(email_data["plain_content"])

        messages.append([
            email_data["message_id"],
            email_data["from"],
            email_data["to"],
            email_data["cc"],
            email_data["bcc"],
            email_data["subject"],
            #email_data["plain_content"],
            plain_clean,

        ])

    # Step 2: Save to Google Sheet
    sheet_id = getattr(settings, "GOOGLE_SPREADSHEET_ID", None)
    if not sheet_id:
        logger.error("❌ Missing GOOGLE_SPREADSHEET_ID in settings.")
        return

    # ✅ Add headers if sheet is empty
    sheet_headers_row = ["Message ID", "From", "To", "Cc", "Bcc", "Subject", "Plain Content"]
    sheet_headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    # Check if sheet is empty
    check_url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/Sheet1!A1"
    check_res = requests.get(check_url, headers=sheet_headers)
    sheet_is_empty = not check_res.ok or not check_res.json().get("values")

    if sheet_is_empty:
        messages.insert(0, sheet_headers_row)

    # Append to sheet
    sheet_url = f"https://sheets.googleapis.com/v4/spreadsheets/{sheet_id}/values/Sheet1!A1:append"
    sheet_body = {"values": messages, "majorDimension": "ROWS"}
    sheet_params = {
        "valueInputOption": "RAW",
        "insertDataOption": "INSERT_ROWS"
    }

    sheet_res = requests.post(sheet_url, headers=sheet_headers, params=sheet_params, json=sheet_body)
    logger.info("📄 Sheet status: %s", sheet_res.status_code)
    logger.debug("📄 Sheet response: %s", sheet_res.text)"""


