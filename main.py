from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
import re

app = FastAPI(title="Agentic Honeypot API")

API_KEY = "mysecurekey123"


class HoneyPotRequest(BaseModel):
    message: Optional[str] = ""


def extract_phone_numbers(text: str):
    return re.findall(r"\b\d{10}\b", text)

def extract_upi_ids(text: str):
    return re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}", text)

def extract_links(text: str):
    return re.findall(r"https?://\S+", text)

def detect_keywords(text: str):
    keywords = ["otp", "bank", "account", "verify", "urgent", "blocked"]
    return [k for k in keywords if k in text.lower()]


@app.post("/honeypot")
def honeypot(
    payload: Optional[HoneyPotRequest] = None,
    x_api_key: str = Header(...)
):

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


    message = payload.message if payload and payload.message else ""

    if message.strip() == "":
        return {
            "status": "ok",
            "is_scam": False,
            "detected_keywords": [],
            "risk_level": "low",
            "extracted_data": {
                "links": [],
                "upi_ids": [],
                "phone_numbers": []
            }
        }


    detected_keywords = detect_keywords(message)
    phone_numbers = extract_phone_numbers(message)
    upi_ids = extract_upi_ids(message)
    links = extract_links(message)

    is_scam = bool(detected_keywords or phone_numbers or upi_ids or links)
    risk_level = "high" if is_scam else "low"

    return {
        "status": "ok",
        "is_scam": is_scam,
        "detected_keywords": detected_keywords,
        "risk_level": risk_level,
        "extracted_data": {
            "links": links,
            "upi_ids": upi_ids,
            "phone_numbers": phone_numbers
        }
    }


@app.get("/")
def health():
    return {"status": "alive"}
