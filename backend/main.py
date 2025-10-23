# main.py
from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import re
import base64
from typing import List, Dict, Any
import os
import uvicorn

app = FastAPI(title="Email Spoof Checker")

# --------------------------------------------------------------------------- #
#  CORS (open for dev)
# --------------------------------------------------------------------------- #
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------- #
#  AUTHENTICATION RESULT PARSING
# --------------------------------------------------------------------------- #
def check_spf(headers: str) -> str:
    match = re.search(r"(?:Received-SPF|Authentication-Results).*spf=(pass|fail|softfail|neutral|temperror|permerror)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    match2 = re.search(r"Received-SPF:\s*(\w+)", headers, re.IGNORECASE)
    return match2.group(1).lower() if match2 else "none"

def check_dkim(headers: str) -> str:
    match = re.search(r"(?:Authentication-Results|ARC-Authentication-Results).*dkim=(pass|fail|neutral|policy|temperror|permerror)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    match2 = re.search(r"dkim=(pass|fail|neutral|policy|temperror|permerror)", headers, re.IGNORECASE)
    return match2.group(1).lower() if match2 else "none"

def check_dmarc(headers: str) -> str:
    match = re.search(r"(?:Authentication-Results|ARC-Authentication-Results).*dmarc=(pass|fail|none|bestguess)", headers, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    match2 = re.search(r"dmarc=(pass|fail|none|bestguess)", headers, re.IGNORECASE)
    return match2.group(1).lower() if match2 else "none"

# --------------------------------------------------------------------------- #
#  MALICIOUS DETECTION HELPERS
# --------------------------------------------------------------------------- #
EICAR_B = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

SUSPICIOUS_EXT = {
    ".exe", ".scr", ".pif", ".bat", ".com", ".jar", ".js", ".vbs",
    ".wsf", ".cmd", ".ps1", ".psm1", ".dll", ".hta", ".docm", ".xlsm", ".pptm",
    ".zip", ".rar", ".7z", ".iso"
}

SUSPICIOUS_TLD_RE = re.compile(r"\.(xyz|top|club|work|men|loan|gq|site|online)(?:/|$)", re.IGNORECASE)

def find_base64_blocks(text: str) -> List[str]:
    return re.findall(r"(?:[A-Za-z0-9+/=\r\n]{200,})", text)

def detect_magic_bytes(b: bytes) -> List[str]:
    flags = []
    if b.startswith(b"MZ"): flags.append("pe_executable")
    if b.startswith(b"PK\x03\x04"): flags.append("zip_archive")
    if b.startswith(b"%PDF-"): flags.append("pdf")
    if b.startswith(b"\xD0\xCF\x11\xE0"): flags.append("ole_compound")
    return flags

def detect_text_indicators(text: str) -> List[str]:
    flags = []
    tl = text.lower()
    if "document.cookie" in tl or "<script" in tl or "eval(" in tl:
        flags.append("embedded_javascript")
    if re.search(r"\bsub\b|\bend\s+sub\b|\bthisdocument\b|\bword\.document\b", tl):
        flags.append("vba_macro_like")
    return flags

def extract_filenames_from_headers(text: str) -> List[str]:
    names = re.findall(r'filename="([^"]+)"', text, flags=re.IGNORECASE)
    names += re.findall(r"name=\"([^\"]+)\"", text, flags=re.IGNORECASE)
    return names

# --------------------------------------------------------------------------- #
#  NEW: SCAM / EXTORTION PHRASE DETECTION
# --------------------------------------------------------------------------- #
def detect_scam_phrases(text: str) -> List[str]:
    patterns = {
        "extortion_threat": r"(i have.*(photo|video|recording|evidence)|leak|expose).*you",
        "payment_demand": r"(pay|send|transfer).*?(bitcoin|wallet|money|\$|usd|crypto|account)",
        "deadline_pressure": r"(within|in the next)\s*\d{1,3}\s*(hours|days)",
        "fear_trigger": r"(hack(ed)?|compromised|breach|infected|virus|malware)",
        "blackmail_keywords": r"(private|personal|intimate|secret).*?(photo|video|info|data)",
    }
    flags = []
    for name, pat in patterns.items():
        if re.search(pat, text, flags=re.IGNORECASE | re.DOTALL):
            flags.append(name)
    return flags

# --------------------------------------------------------------------------- #
#  MAIN MALICIOUS ANALYZER
# --------------------------------------------------------------------------- #
def analyze_for_malicious(raw_text: str) -> Dict[str, Any]:
    findings: Dict[str, Any] = {
        "malicious": "none",
        "malicious_findings": [],
        "suspicious_attachments": [],
        "suspicious_urls": [],
    }

    # 1) EICAR
    if EICAR_B in raw_text.encode("utf-8", errors="ignore") or "eicar" in raw_text.lower():
        findings["malicious_findings"].append("eicar_test_signature_detected")
        findings["malicious"] = "malicious"

    # 2) URLs
    urls = re.findall(r"https?://[^\s<'\">]+", raw_text, flags=re.IGNORECASE)
    for u in urls:
        reason = []
        if SUSPICIOUS_TLD_RE.search(u):
            reason.append("suspicious_tld")
        hostmatch = re.match(r"https?://([^/:]+)", u, flags=re.IGNORECASE)
        if hostmatch:
            host = hostmatch.group(1)
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                reason.append("ip_address_host")
        if len(u) > 200:
            reason.append("very_long_url")
        if reason:
            findings["suspicious_urls"].append({"url": u, "reasons": reason})
    if findings["suspicious_urls"]:
        findings["malicious"] = "suspicious"
        findings["malicious_findings"].append("suspicious_urls_found")

    # 3) Filenames
    filenames = extract_filenames_from_headers(raw_text)
    for name in filenames:
        for ext in SUSPICIOUS_EXT:
            if name.lower().endswith(ext):
                findings["suspicious_attachments"].append({"filename": name, "reason": f"suspicious_ext_{ext}"})

    # 4) NEW: scam/extortion detection
    scam_flags = detect_scam_phrases(raw_text)
    if scam_flags:
        findings["malicious_findings"].extend(scam_flags)
        findings["malicious"] = "malicious"  # escalate to MALICIOUS

    # 5) Decode inline base64
    b64_blocks = find_base64_blocks(raw_text)
    for idx, b64 in enumerate(b64_blocks[:6]):
        try:
            decoded = base64.b64decode(b64, validate=False)
        except Exception:
            continue
        magic = detect_magic_bytes(decoded)
        tflags = detect_text_indicators(decoded.decode("utf-8", errors="ignore"))
        if "pe_executable" in magic or "vba_macro_like" in tflags or "embedded_javascript" in tflags:
            findings["malicious_findings"].append(f"inline_block_{idx}_suspicious")
            findings["malicious"] = "malicious"

    # 6) Text hints for attachments
    if re.search(r"please download|open the attached|see attached", raw_text.lower()):
        findings["malicious_findings"].append("attachment_prompt_text")
        if findings["malicious"] != "malicious":
            findings["malicious"] = "suspicious"

    findings["malicious_findings"] = list(set(findings["malicious_findings"]))
    return findings

# --------------------------------------------------------------------------- #
#  API ENDPOINT
# --------------------------------------------------------------------------- #
@app.post("/analyze")
async def analyze(raw_headers: str = Form(...)):
    try:
        text = raw_headers or ""
        if not text.strip():
            raise HTTPException(status_code=400, detail="No headers/email provided")

        spf_result = check_spf(text)
        dkim_result = check_dkim(text)
        dmarc_result = check_dmarc(text)

        status = "Legit" if spf_result == "pass" and dkim_result == "pass" and dmarc_result == "pass" else "Spoof"

        mal = analyze_for_malicious(text)

        result = {
            "status": status,
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "malicious": mal.get("malicious", "none"),
            "malicious_findings": mal.get("malicious_findings", []),
            "suspicious_attachments": mal.get("suspicious_attachments", []),
            "suspicious_urls": mal.get("suspicious_urls", []),
            "num_lines": len(text.splitlines()),
        }
        return JSONResponse(content=result)
    except HTTPException as he:
        raise he
    except Exception as e:
        return JSONResponse(content={"error": "Internal error", "detail": str(e)}, status_code=500)

# --------------------------------------------------------------------------- #
#  RUN SERVER (for Render)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)