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
def serve_frontend():
    return FileResponse("index.html")
# --------------------------

# (Keep your existing extract_features function here)

# (Keep your existing @app.post("/predict") route here)