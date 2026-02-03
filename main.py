from fastapi import FastAPI, Header, HTTPException
import re

app = FastAPI()

API_KEY = "mysecurekey123"

scam_keywords = ["otp", "bank", "upi", "account", "password", "verify"]

def extract_data(text):
    links = re.findall(r'https?://\S+', text)
    upi_ids = re.findall(r'\b\w+@\w+\b', text)
    phones = re.findall(r'\b\d{10}\b', text)

    return links, upi_ids, phones

@app.post("/honeypot")
def honeypot(data: dict, x_api_key: str = Header(None)):
    
    # API key check
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    message = data.get("message", "").lower()

    # Scam detection
    detected = [k for k in scam_keywords if k in message]

    links, upi_ids, phones = extract_data(message)

    is_scam = len(detected) > 0

    risk = "high" if len(detected) >= 2 else "medium" if is_scam else "low"

    return {
        "is_scam": is_scam,
        "detected_keywords": detected,
        "risk_level": risk,
        "extracted_data": {
            "links": links,
            "upi_ids": upi_ids,
            "phone_numbers": phones
        }
    }
