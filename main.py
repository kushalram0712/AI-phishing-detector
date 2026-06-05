from fastapi import FastAPI
from fastapi.responses import FileResponse # <-- ADD THIS IMPORT
from pydantic import BaseModel
import joblib
import pandas as pd
import re

app = FastAPI(title="Phishing Detection API")
# Change this line in main.py
model = joblib.load('phishing_model_compressed.pkl')

class URLRequest(BaseModel):
    url: str

# --- ADD THIS NEW ROUTE ---
@app.get("/")
@app.post("/predict")
def predict_phishing(request: URLRequest):
    url_lower = request.url.lower()
    
    # 1. HARD GUARDRAIL: Catch highly obvious HTTP phishing patterns instantly
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account', 'banking']
    has_keyword = any(word in url_lower for word in suspicious_words)
    
    if url_lower.startswith('http://') and has_keyword:
        return {
            "url": request.url, 
            "status": "DANGER", 
            "message": "Blocked by Threat Intelligence Guardrail (Insecure URL containing sensitive keywords)."
        }
    
    # 2. MACHINE LEARNING PIPELINE: If it passes the guardrail, let the AI analyze it
    features = extract_features(request.url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)[0]
    
    if prediction == 1:
        return {"url": request.url, "status": "DANGER", "message": "Phishing detected by AI analysis!"}
    else:
        return {"url": request.url, "status": "SAFE", "message": "Looks legitimate."}