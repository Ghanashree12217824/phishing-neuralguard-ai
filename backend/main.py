from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
import traceback
import re
from urllib.parse import urlparse

from features import extract_features
from model import load_model, explain_prediction  # 👈 added
from advanced_features import get_domain_age, has_valid_ssl, get_domain
import socket
import requests


app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------
# LOAD MODEL
# -------------------------------
try:
    model = load_model()
    print("Model loaded successfully")
except Exception:
    print("Model loading failed")
    traceback.print_exc()
    model = None


# -------------------------------
# REQUEST SCHEMA
# -------------------------------
class URLRequest(BaseModel):
    url: str


# -------------------------------
# URL VALIDATION FUNCTION
# -------------------------------
def is_valid_url(url: str):
    try:
        if len(url) > 2048:
            return False, "URL too long"

        parsed = urlparse(url)

        if not parsed.scheme or not parsed.netloc:
            return False, "Malformed URL"

        if re.match(r"(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)", parsed.netloc):
            return False, "Internal IPs are not allowed"

        return True, None

    except:
        return False, "Invalid URL"


# -------------------------------
# HEALTH CHECK
# -------------------------------
@app.get("/")
def health():
    return {"status": "API is running"}


# -------------------------------
# PREDICT ENDPOINT (UNCHANGED LOGIC)
# -------------------------------
@app.post("/predict")
def predict(request: URLRequest):
    if model is None:
        return {
            "error": "Model not loaded",
            "message": "Check server logs"
        }

    try:
        url = request.url.strip()

        valid, error = is_valid_url(url)
        if not valid:
            return {"error": error}

        features = extract_features(url, use_advanced=False)

        if not features or len(features) != 12:
            return {
                "error": "Feature extraction failed",
                "features": features
            }

        features_array = np.array(features).reshape(1, -1)

        prediction = model.predict(features_array)[0]
        probabilities = model.predict_proba(features_array)[0]

        confidence = float(probabilities[prediction])

        return {
            "url": url,
            "prediction": "Phishing" if prediction == 1 else "Legitimate",
            "confidence": round(confidence, 4)
        }

    except Exception as e:
        traceback.print_exc()
        return {
            "error": str(e),
            "type": type(e).__name__,
            "message": "Prediction failed"
        }


# -------------------------------
# 🔥 NEW: EXPLAIN ENDPOINT
# -------------------------------
@app.post("/explain")
def explain(request: URLRequest):
    if model is None:
        return {
            "error": "Model not loaded"
        }

    try:
        url = request.url.strip()

        # Validate URL (same as predict)
        valid, error = is_valid_url(url)
        if not valid:
            return {"error": error}

        shap_vals, features = explain_prediction(model, url)

        return {
            "url": url,
            "shap_values": shap_vals,
            "features": features
        }

    except Exception as e:
        traceback.print_exc()
        return {
            "error": str(e),
            "type": type(e).__name__,
            "message": "Explanation failed"
        }


# -------------------------------
# 🔥 NEW: INTEL ENDPOINT
# -------------------------------
@app.post("/intel")
def get_intel(request: URLRequest):
    try:
        url = request.url.strip()
        domain = get_domain(url)
        if not domain:
            return {"error": "Could not extract domain"}

        # 1. Resolve IP
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = "Unknown"

        # 2. GeoIP Data
        geo_data = {"country": "Unknown", "isp": "Unknown", "city": "Unknown"}
        if ip_address != "Unknown":
            try:
                resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3)
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        geo_data = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "isp": data.get("isp", "Unknown")
                        }
            except:
                pass

        # 3. Domain Age & SSL
        age = get_domain_age(url)
        ssl_valid = has_valid_ssl(url)

        return {
            "url": url,
            "domain": domain,
            "ip": ip_address,
            "geo": geo_data,
            "domain_age_days": age,
            "ssl_valid": bool(ssl_valid)
        }

    except Exception as e:
        traceback.print_exc()
        return {"error": str(e)}