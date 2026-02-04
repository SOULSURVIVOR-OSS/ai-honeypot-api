from fastapi import FastAPI, Header, HTTPException, Request
import re

app = FastAPI()

API_KEY = "mysecurekey123"

scam_keywords = ["otp", "bank", "upi", "account", "password", "verify"]

def extract_data(text):
    links = re.findall(r'https?://\S+', text)
    upi_ids = re.findall(r'\b\w+@\w+\b', text)
    phones = re.findall(r'\b\d{10}\b', text)
    return links, upi_ids, phones


@app.api_route("/honeypot", methods=["GET", "POST"])
async def honeypot(request: Request, x_api_key: str = Header(None)):

    if x_api_key != API_KEY:
        return {
            "status": "unauthorized",
            "message": "Invalid API Key"
        }

    # Try to read body safely
    try:
        data = await request.json()
        if not isinstance(data, dict):
            data = {}
    except:
        data = {}

    message = str(data.get("message", "")).lower()

    detected = [k for k in scam_keywords if k in message]
    links, upi_ids, phones = extract_data(message)

    is_scam = len(detected) > 0
    risk = "high" if len(detected) >= 2 else "medium" if is_scam else "low"

    return {
        "status": "ok",
        "is_scam": is_scam,
        "detected_keywords": detected,
        "risk_level": risk,
        "extracted_data": {
            "links": links,
            "upi_ids": upi_ids,
            "phone_numbers": phones
        }
    }
