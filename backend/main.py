"""
SecureMailScope Backend - Member 3 (File-Based Orchestrator)
==============================================================
M1 and M2 provide JSON files. This server reads them, calculates the score,
and serves the frontend (M4).
"""

import os
import json
import sqlite3
import logging
import asyncio
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# --------------------------- CONFIG ---------------------------
# Paths to the JSON files M1 and M2 will provide
EMAIL_DATA_PATH = os.getenv("EMAIL_DATA_PATH", "./data/email_data.json")
TLS_DATA_PATH = os.getenv("TLS_DATA_PATH", "./data/tls_data.json")

# If true, uses fake data so you don't need the files (for testing)
USE_MOCKS =   False#os.getenv("USE_MOCKS", "true").lower() == "true"  # Set to "false" when files are ready

# --------------------------- LOGGING ---------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------- FASTAPI APP ---------------------------
app = FastAPI(title="SecureMailScope Backend", version="2.0")

# CORS - allow frontend (M4) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------- DATABASE ---------------------------
def init_db():
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            score INTEGER,
            severity TEXT,
            findings_json TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized.")

def save_scan(domain: str, score: int, severity: str, findings: List[dict]):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (domain, score, severity, findings_json, timestamp) VALUES (?, ?, ?, ?, ?)",
        (domain, score, severity, json.dumps(findings), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    logger.info(f"Scan saved for {domain}")

init_db()

# --------------------------- PYDANTIC SCHEMAS ---------------------------
class Finding(BaseModel):
    category: str
    status: str      # PASS, FAIL, WARN
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str
    recommendation: str

class ScanRequest(BaseModel):
    domain: str

class ScanResponse(BaseModel):
    domain: str
    score: int
    severity: str
    findings: List[Finding]

# --------------------------- DATA SOURCE (READS JSON FILES) ---------------------------
async def read_email_data(domain: str) -> dict:
    """Reads M1's JSON file from the data folder."""
    if USE_MOCKS:
        logger.info(f"Mock Email Data for: {domain}")
        await asyncio.sleep(0.5)  # Simulate reading delay
        return {"spf": "pass", "dkim": "pass", "dmarc": "missing"}
    
    try:
        with open(EMAIL_DATA_PATH, 'r') as f:
            data = json.load(f)
        logger.info(f"Loaded email data from {EMAIL_DATA_PATH}")
        # If the file has a specific domain key, you can map it, but just return the whole dict
        return data
    except FileNotFoundError:
        logger.error(f"Email data file not found at {EMAIL_DATA_PATH}")
        return {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "error": "File not found"}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {EMAIL_DATA_PATH}")
        return {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "error": "Invalid JSON"}

async def read_tls_data(domain: str) -> dict:
    """Reads M2's JSON file from the data folder."""
    if USE_MOCKS:
        logger.info(f"Mock TLS Data for: {domain}")
        await asyncio.sleep(0.5)
        return {"tls_version": "TLS 1.2", "cert_valid": True, "cert_expiry_days": 45, "starttls": "supported"}
    
    try:
        with open(TLS_DATA_PATH, 'r') as f:
            data = json.load(f)
        logger.info(f"Loaded TLS data from {TLS_DATA_PATH}")
        return data
    except FileNotFoundError:
        logger.error(f"TLS data file not found at {TLS_DATA_PATH}")
        return {"tls_version": "unknown", "cert_valid": False, "starttls": "unknown", "error": "File not found"}
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON in {TLS_DATA_PATH}")
        return {"tls_version": "unknown", "cert_valid": False, "starttls": "unknown", "error": "Invalid JSON"}

# --------------------------- NORMALIZER (Universal Schema) ---------------------------
def normalize_findings(email_data: dict, tls_data: dict) -> List[Finding]:
    findings = []

    # --- SPF ---
    spf = email_data.get("spf", "unknown")
    if spf == "fail":
        findings.append(Finding(
            category="SPF", status="FAIL", severity="HIGH",
            evidence="SPF validation failed. Check your SPF record syntax.",
            recommendation="Publish a valid SPF record with include:your-provider.com and -all"
        ))
    elif spf == "pass":
        findings.append(Finding(
            category="SPF", status="PASS", severity="LOW",
            evidence="SPF record exists and passes validation.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="SPF", status="WARN", severity="MEDIUM",
            evidence=f"SPF status: {spf}",
            recommendation="Check if SPF record is published correctly."
        ))

    # --- DKIM ---
    dkim = email_data.get("dkim", "unknown")
    if dkim == "missing":
        findings.append(Finding(
            category="DKIM", status="FAIL", severity="HIGH",
            evidence="No DKIM record found for any selector.",
            recommendation="Generate a DKIM key pair and publish the public key in DNS."
        ))
    elif dkim == "pass":
        findings.append(Finding(
            category="DKIM", status="PASS", severity="LOW",
            evidence="DKIM record found and valid.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="DKIM", status="WARN", severity="MEDIUM",
            evidence=f"DKIM status: {dkim}",
            recommendation="Verify DKIM selectors are published correctly."
        ))

    # --- DMARC ---
    dmarc = email_data.get("dmarc", "missing")
    if dmarc == "missing":
        findings.append(Finding(
            category="DMARC", status="FAIL", severity="HIGH",
            evidence="No DMARC TXT record found in DNS.",
            recommendation="Publish a DMARC policy starting with p=none, then move to p=reject."
        ))
    elif dmarc == "none":
        findings.append(Finding(
            category="DMARC", status="WARN", severity="MEDIUM",
            evidence="DMARC policy is set to 'none' (monitoring only).",
            recommendation="Move to p=quarantine or p=reject to enforce authentication."
        ))
    elif dmarc in ["quarantine", "reject"]:
        findings.append(Finding(
            category="DMARC", status="PASS", severity="LOW",
            evidence=f"DMARC policy is '{dmarc}' (enforcing).",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="DMARC", status="WARN", severity="MEDIUM",
            evidence=f"DMARC status: {dmarc}",
            recommendation="Check DMARC record syntax and alignment."
        ))

    # --- TLS Version ---
    tls = tls_data.get("tls_version", "unknown")
    if tls in ["TLS 1.0", "TLS 1.1"]:
        findings.append(Finding(
            category="TLS_VERSION", status="FAIL", severity="CRITICAL",
            evidence=f"Deprecated TLS version {tls} detected.",
            recommendation="Upgrade to TLS 1.2 or TLS 1.3 immediately."
        ))
    elif tls in ["TLS 1.2", "TLS 1.3"]:
        findings.append(Finding(
            category="TLS_VERSION", status="PASS", severity="LOW",
            evidence=f"Modern TLS version {tls} detected.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="TLS_VERSION", status="WARN", severity="MEDIUM",
            evidence=f"TLS version: {tls}",
            recommendation="Check if STARTTLS is properly configured."
        ))

    # --- Certificate Validity ---
    cert_valid = tls_data.get("cert_valid", False)
    if not cert_valid:
        findings.append(Finding(
            category="CERTIFICATE", status="FAIL", severity="CRITICAL",
            evidence="Certificate validation failed (expired, revoked, or self-signed).",
            recommendation="Renew your TLS certificate from a trusted CA."
        ))
    else:
        expiry_days = tls_data.get("cert_expiry_days", 0)
        if expiry_days > 0 and expiry_days < 30:
            findings.append(Finding(
                category="CERTIFICATE", status="WARN", severity="MEDIUM",
                evidence=f"Certificate expires in {expiry_days} days.",
                recommendation="Renew certificate within the next 30 days."
            ))
        else:
            findings.append(Finding(
                category="CERTIFICATE", status="PASS", severity="LOW",
                evidence=f"Certificate valid. Expires in {expiry_days} days." if expiry_days > 0 else "Certificate is valid.",
                recommendation="None"
            ))

    # --- STARTTLS ---
    starttls = tls_data.get("starttls", "unknown")
    if starttls in ["unsupported", "false"]:
        findings.append(Finding(
            category="STARTTLS", status="FAIL", severity="CRITICAL",
            evidence="STARTTLS not supported on the mail server.",
            recommendation="Enable STARTTLS on your SMTP server."
        ))
    elif starttls in ["supported", "true"]:
        findings.append(Finding(
            category="STARTTLS", status="PASS", severity="LOW",
            evidence="STARTTLS is supported.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="STARTTLS", status="WARN", severity="MEDIUM",
            evidence=f"STARTTLS status: {starttls}",
            recommendation="Verify STARTTLS configuration on your mail server."
        ))

    return findings

# --------------------------- RISK ENGINE ---------------------------
def calculate_risk(findings: List[Finding]) -> tuple[int, str]:
    severity_points = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}
    base_score = 100
    highest_severity = "LOW"
    highest_points = 0

    for f in findings:
        if f.status == "FAIL":
            points = severity_points.get(f.severity, 0)
            base_score -= points
            if points > highest_points:
                highest_points = points
                highest_severity = f.severity
        elif f.status == "WARN":
            points = severity_points.get(f.severity, 0) // 2
            base_score -= points
            if points > highest_points:
                highest_points = points
                highest_severity = f.severity

    final_score = max(0, base_score)
    return final_score, highest_severity

# --------------------------- MAIN SCAN ENDPOINT ---------------------------
@app.post("/scan", response_model=ScanResponse)
async def scan_domain(request: ScanRequest):
    logger.info(f"Received scan request for: {request.domain}")

    try:
        # Step 1: Read data from JSON files (or mocks)
        email_result, tls_result = await asyncio.gather(
            read_email_data(request.domain),
            read_tls_data(request.domain)
        )

        logger.info(f"Email result: {email_result}")
        logger.info(f"TLS result: {tls_result}")

        # Step 2: Normalize into universal schema
        findings = normalize_findings(email_result, tls_result)

        # Step 3: Calculate risk score
        score, severity = calculate_risk(findings)

        # Step 4: Save to database
        save_scan(request.domain, score, severity, [f.dict() for f in findings])

        # Step 5: Return response
        return ScanResponse(
            domain=request.domain,
            score=score,
            severity=severity,
            findings=findings
        )

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# --------------------------- HEALTH CHECK ---------------------------
@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

# --------------------------- HISTORY ENDPOINT ---------------------------
@app.get("/history/{domain}")
async def get_history(domain: str):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT domain, score, severity, findings_json, timestamp FROM scan_history WHERE domain = ? ORDER BY timestamp DESC LIMIT 10",
        (domain,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        raise HTTPException(status_code=404, detail="No scans found for this domain")

    history = [
        {
            "domain": row[0],
            "score": row[1],
            "severity": row[2],
            "findings": json.loads(row[3]),
            "timestamp": row[4]
        }
        for row in rows
    ]
    return {"domain": domain, "history": history}

# --------------------------- RUN SERVER ---------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
