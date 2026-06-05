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
    
    # 1. HARD GUARDRAIL
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    has_keyword = any(word in url_lower for word in suspicious_words)
    
    if url_lower.startswith('http://') and has_keyword:
        return {
            "url": request.url, 
            "status": "DANGER", 
            "risk_score": 100, # Max risk
            "message": "Blocked by Guardrail (Insecure URL with sensitive keywords).",
            "breakdown": {"Keyword Threat": 100, "Structural Threat": 50, "Security Protocol": 100}
        }
    
    # 2. MACHINE LEARNING ANALYSIS
    features = extract_features(request.url)
    features_df = pd.DataFrame([features])
    
    # Use predict_proba to get the percentage of trees that voted "Phishing"
    probability = model.predict_proba(features_df)[0][1] 
    risk_score = round(probability * 100, 1)
    
    # Generate mock breakdown data based on our extracted features for the graph
    structural_threat = min((features['count_dots'] + features['count_hyphens']) * 15, 100)
    protocol_threat = 0 if features['is_https'] else 50
    keyword_threat = features['has_suspicious_word'] * 100

    status = "DANGER" if risk_score > 50 else "SAFE"
    message = "Phishing detected by AI analysis!" if status == "DANGER" else "Domain appears legitimate."

    return {
        "url": request.url, 
        "status": status, 
        "risk_score": risk_score,
        "message": message,
        "breakdown": {
            "Keyword Threat": keyword_threat,
            "Structural Threat": structural_threat,
            "Security Protocol": protocol_threat
        }
    }