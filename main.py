# main.py
from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import re
from typing import List

app = FastAPI(title="Email Spoof Checker API")

# Configure CORS so your frontend can call the API
origins = [
    "http://localhost:3000",  # local React dev
    "https://your-netlify-site.netlify.app"  # replace with your Netlify URL
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root endpoint
@app.get("/")
def root():
    return {"message": "Email Spoof Checker is live! Use /docs to test or POST to /analyze"}

# Helper function to parse email headers and detect spoofing
def parse_email_headers(raw_headers: str) -> dict:
    result = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown",
        "phishing_links": [],
        "suspicious_attachments": [],
        "status": "unknown"
    }

    # Extract SPF
    spf_match = re.search(r'spf=(pass|fail|neutral|softfail|temperror|permerror)', raw_headers, re.IGNORECASE)
    if spf_match:
        result["spf"] = spf_match.group(1).lower()

    # Extract DKIM
    dkim_match = re.search(r'dkim=(pass|fail|neutral|policy|temperror|permerror)', raw_headers, re.IGNORECASE)
    if dkim_match:
        result["dkim"] = dkim_match.group(1).lower()

    # Extract DMARC
    dmarc_match = re.search(r'dmarc=(pass|fail|bestguess|none)', raw_headers, re.IGNORECASE)
    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1).lower()

    # Simple spoof detection logic
    if result["spf"] != "pass" or result["dkim"] != "pass" or result["dmarc"] != "pass":
        result["status"] = "spoof"
    else:
        result["status"] = "legit"

    # Optional: extract URLs for phishing check
    urls = re.findall(r'https?://[^\s<>"]+', raw_headers)
    for url in urls:
        # mark suspicious if domain is unusual (can be extended with a blacklist)
        if "gmail.com" not in url.lower():  
            result["phishing_links"].append(url)

    return result

# Main endpoint to analyze headers
@app.post("/analyze")
async def analyze_email(raw_headers: str = Form(..., description="Paste full Gmail headers here")):
    if not raw_headers.strip():
        raise HTTPException(status_code=400, detail="No headers provided")
    
    analysis_result = parse_email_headers(raw_headers)
    return JSONResponse(content=analysis_result)
