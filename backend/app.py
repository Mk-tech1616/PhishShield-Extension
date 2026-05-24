# app.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import xgboost as xgb
from url_feature_extractor import URLFeatureExtractor

app = FastAPI(title="PhishShield API", version="1.0")

# -------------------------
# Enable CORS
# -------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Load model artifacts
# -------------------------
scaler = joblib.load("scaler.pkl")
booster = xgb.Booster()
booster.load_model("xgb_model.json")

# -------------------------
# Feature columns
# -------------------------
FEATURE_COLUMNS = [
    "URLLength", "DomainLength", "TLDLength", "NoOfImage", "NoOfJS", "NoOfCSS",
    "NoOfSelfRef", "NoOfExternalRef", "IsHTTPS", "HasObfuscation", "HasTitle",
    "HasDescription", "HasSubmitButton", "HasSocialNet", "HasFavicon",
    "HasCopyrightInfo", "popUpWindow", "Iframe", "Abnormal_URL",
    "LetterToDigitRatio", "Redirect_0", "Redirect_1"
]

# -------------------------
# Request schema
# -------------------------
class URLInput(BaseModel):
    url: str

# -------------------------
# Helpers
# -------------------------
def predict_with_model(input_df: pd.DataFrame):
    scaled = scaler.transform(input_df)
    dmat = xgb.DMatrix(scaled, feature_names=FEATURE_COLUMNS)
    prob = float(booster.predict(dmat)[0])
    label = 1 if prob >= 0.5 else 0
    return prob, label


def get_top_reasons(input_df: pd.DataFrame, top_k=4):
    dmat = xgb.DMatrix(input_df.values, feature_names=FEATURE_COLUMNS)
    contribs = booster.predict(dmat, pred_contribs=True)[0][:-1]  # drop bias
    pairs = list(zip(FEATURE_COLUMNS, contribs))
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)

    feature_map = {
        "IsHTTPS": "No HTTPS (insecure connection)",
        "Abnormal_URL": "Abnormal URL structure",
        "HasObfuscation": "Obfuscated URL detected",
        "Redirect_1": "Multiple redirects detected",
        "NoOfExternalRef": "Very few external references",
        "NoOfSelfRef": "Suspicious internal references pattern",
        "Iframe": "Hidden iframe detected",
        "popUpWindow": "Popup behavior detected",
        "LetterToDigitRatio": "Unusual character pattern in URL",
        "DomainLength": "Suspicious domain length",
        "URLLength": "Suspicious URL length",
        "TLDLength": "Unusual top-level domain length",
    }

    reasons = []
    for f, _ in pairs[:top_k]:
        reasons.append(feature_map.get(f, f))
    return reasons

# -------------------------
# Routes
# -------------------------
@app.get("/")
def root():
    return {"message": "PhishShield API is running 🚀"}

@app.post("/predict_url")
def predict_from_url(data: URLInput):
    url = data.url.strip()

    # ✅ FIX 1: Whitelist localhost / development URLs
    if url.startswith("http://127.0.0.1") or url.startswith("http://localhost") \
       or url.startswith("https://127.0.0.1") or url.startswith("https://localhost"):
        return {
            "url": url,
            "probability": 1.0,
            "prediction": 1,
            "result": "Legitimate",
            "reasons": ["Localhost / development environment"]
        }

    try:
        extractor = URLFeatureExtractor(url)
        feats = extractor.extract_model_features()

        # Safety check
        if not isinstance(feats, dict):
            return {"error": "Feature extraction failed"}

        df = pd.DataFrame([feats], columns=FEATURE_COLUMNS)

        prob, label = predict_with_model(df)
        reasons = get_top_reasons(df, top_k=4)

        return {
            "url": url,
            "probability": round(prob, 4),
            "prediction": label,
            "result": "Legitimate" if label == 1 else "Phishing",
            "reasons": reasons
        }

    except Exception as e:
        return {"error": str(e)}