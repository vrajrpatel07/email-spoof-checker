from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse
import re

app = FastAPI(title="User-Friendly Email Spoof Checker")

# Helper function to extract key authentication results
def parse_email_headers(raw_headers: str):
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
        # Simple example: mark suspicious if domain is unusual (can be extended with blacklist)
        if "gmail.com" not in url.lower():  
            result["phishing_links"].append(url)

    return result

@app.post("/analyze")
async def analyze_email(raw_headers: str = Form(..., description="Paste full Gmail headers here")):
    """
    Analyze email headers pasted by the user. Returns spoof/legit status.
    """
    analysis_result = parse_email_headers(raw_headers)
    return JSONResponse(content=analysis_result)
