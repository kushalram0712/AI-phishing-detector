from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel
import joblib
import pandas as pd
import re

# 1. Initialize App and Load Model
app = FastAPI(title="Phishing Detection API")
model = joblib.load('phishing_model_compressed.pkl')

class URLRequest(BaseModel):
    url: str

# 2. Feature Extraction Function
def extract_features(url):
    features = {}
    url_lower = url.lower()
    
    features['url_length'] = len(url)
    ip_pattern = r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
    features['has_ip'] = 1 if re.search(ip_pattern, url) else 0
    features['count_dots'] = url.count('.')
    features['count_hyphens'] = url.count('-')
    features['count_at'] = url.count('@')
    features['is_https'] = 1 if url_lower.startswith('https') else 0
    
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'confirm', 'urgent', 'free']
    features['has_suspicious_word'] = 1 if any(word in url_lower for word in suspicious_words) else 0
    features['many_subdomains'] = 1 if url.count('.') > 3 else 0
    
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    features['is_shortened'] = 1 if any(short in url_lower for short in shorteners) else 0
    features['count_underscores'] = url.count('_')
    features['count_equals'] = url.count('=')
    
    return features

# ==========================================
# ROUTE 1: SERVE THE FRONTEND WEBSITE
# ==========================================
@app.get("/")
def serve_frontend():
    return FileResponse("index.html")

# ==========================================
# ROUTE 2: THE AI PREDICTION ENGINE
# ==========================================
@app.post("/predict")
def predict_phishing(request: URLRequest):
    url_lower = request.url.lower()
    
    # Hard Guardrail Check
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    has_keyword = any(word in url_lower for word in suspicious_words)
    
    if url_lower.startswith('http://') and has_keyword:
        return {"url": request.url, "status": "DANGER", "message": "Blocked by Guardrail (Insecure URL with sensitive keywords)."}
    
    # Machine Learning Check
    features = extract_features(request.url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    
    if prediction == 1:
        return {"url": request.url, "status": "DANGER", "message": "Phishing detected by AI analysis!"}
    else:
        return {"url": request.url, "status": "SAFE", "message": "Looks legitimate."}