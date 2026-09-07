
import os
import json
import sqlite3
import logging
import subprocess
import shutil
from datetime import datetime
from typing import List, Optional
from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# --------------------------- CONFIG ---------------------------
# Paths
DATA_DIR = Path("./data")
PCAP_DIR = DATA_DIR / "pcap_uploads"
EMAIL_OUTPUT_PATH = DATA_DIR / "email_data.json"
TLS_OUTPUT_PATH = DATA_DIR / "tls_data.json"

# M1's script (the analyzer)
M1_SCRIPT = Path("./M1/analyzer.py")  # or whatever M1's main file is

# If true, uses fake data for testing
USE_MOCKS = os.getenv("USE_MOCKS", "true").lower() == "true"

# --------------------------- SETUP ---------------------------
# Create necessary directories
DATA_DIR.mkdir(exist_ok=True)
PCAP_DIR.mkdir(exist_ok=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------- FASTAPI APP ---------------------------
app = FastAPI(title="SecureMailScope Backend", version="3.0")

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
            filename TEXT NOT NULL,
            score INTEGER,
            severity TEXT,
            findings_json TEXT,
            timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized.")

def save_scan(filename: str, score: int, severity: str, findings: List[dict]):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_history (filename, score, severity, findings_json, timestamp) VALUES (?, ?, ?, ?, ?)",
        (filename, score, severity, json.dumps(findings), datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    logger.info(f"Scan saved for {filename}")

init_db()

# --------------------------- PYDANTIC SCHEMAS ---------------------------
class Finding(BaseModel):
    category: str
    status: str      # PASS, FAIL, WARN
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    evidence: str
    recommendation: str

class ScanResponse(BaseModel):
    filename: str
    score: int
    severity: str
    findings: List[Finding]

# --------------------------- NORMALIZER (Universal Schema) ---------------------------
def normalize_findings(email_data: dict, tls_data: dict) -> List[Finding]:
    findings = []

    # --- SPF ---
    spf = email_data.get("spf", "unknown")
    if spf == "fail":
        findings.append(Finding(
            category="SPF", status="FAIL", severity="HIGH",
            evidence="SPF validation failed.",
            recommendation="Publish a valid SPF record."
        ))
    elif spf == "pass":
        findings.append(Finding(
            category="SPF", status="PASS", severity="LOW",
            evidence="SPF passes.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="SPF", status="WARN", severity="MEDIUM",
            evidence=f"SPF status: {spf}",
            recommendation="Check SPF record."
        ))

    # --- DKIM ---
    dkim = email_data.get("dkim", "unknown")
    if dkim == "missing":
        findings.append(Finding(
            category="DKIM", status="FAIL", severity="HIGH",
            evidence="No DKIM record found.",
            recommendation="Publish DKIM public key."
        ))
    elif dkim == "pass":
        findings.append(Finding(
            category="DKIM", status="PASS", severity="LOW",
            evidence="DKIM valid.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="DKIM", status="WARN", severity="MEDIUM",
            evidence=f"DKIM status: {dkim}",
            recommendation="Check DKIM selectors."
        ))

    # --- DMARC ---
    dmarc = email_data.get("dmarc", "missing")
    if dmarc == "missing":
        findings.append(Finding(
            category="DMARC", status="FAIL", severity="HIGH",
            evidence="No DMARC record found.",
            recommendation="Publish DMARC policy."
        ))
    elif dmarc == "none":
        findings.append(Finding(
            category="DMARC", status="WARN", severity="MEDIUM",
            evidence="DMARC is monitor-only (p=none).",
            recommendation="Move to p=quarantine or p=reject."
        ))
    elif dmarc in ["quarantine", "reject"]:
        findings.append(Finding(
            category="DMARC", status="PASS", severity="LOW",
            evidence=f"DMARC policy is '{dmarc}'.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="DMARC", status="WARN", severity="MEDIUM",
            evidence=f"DMARC status: {dmarc}",
            recommendation="Check DMARC syntax."
        ))

    # --- TLS Version ---
    tls = tls_data.get("tls_version", "unknown")
    if tls in ["TLS 1.0", "TLS 1.1"]:
        findings.append(Finding(
            category="TLS_VERSION", status="FAIL", severity="CRITICAL",
            evidence=f"Deprecated TLS: {tls}",
            recommendation="Upgrade to TLS 1.2+."
        ))
    elif tls in ["TLS 1.2", "TLS 1.3"]:
        findings.append(Finding(
            category="TLS_VERSION", status="PASS", severity="LOW",
            evidence=f"TLS {tls} detected.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="TLS_VERSION", status="WARN", severity="MEDIUM",
            evidence=f"TLS version: {tls}",
            recommendation="Check TLS configuration."
        ))

    # --- Certificate ---
    cert_valid = tls_data.get("cert_valid", False)
    if not cert_valid:
        findings.append(Finding(
            category="CERTIFICATE", status="FAIL", severity="CRITICAL",
            evidence="Certificate invalid.",
            recommendation="Renew certificate."
        ))
    else:
        expiry = tls_data.get("cert_expiry_days", 0)
        if expiry > 0 and expiry < 30:
            findings.append(Finding(
                category="CERTIFICATE", status="WARN", severity="MEDIUM",
                evidence=f"Certificate expires in {expiry} days.",
                recommendation="Renew within 30 days."
            ))
        else:
            findings.append(Finding(
                category="CERTIFICATE", status="PASS", severity="LOW",
                evidence="Certificate valid.",
                recommendation="None"
            ))

    # --- STARTTLS ---
    starttls = tls_data.get("starttls", "unknown")
    if starttls in ["unsupported", "false"]:
        findings.append(Finding(
            category="STARTTLS", status="FAIL", severity="CRITICAL",
            evidence="STARTTLS not supported.",
            recommendation="Enable STARTTLS."
        ))
    elif starttls in ["supported", "true"]:
        findings.append(Finding(
            category="STARTTLS", status="PASS", severity="LOW",
            evidence="STARTTLS supported.",
            recommendation="None"
        ))
    else:
        findings.append(Finding(
            category="STARTTLS", status="WARN", severity="MEDIUM",
            evidence=f"STARTTLS: {starttls}",
            recommendation="Verify STARTTLS config."
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

    return max(0, base_score), highest_severity

# --------------------------- CALL M1 TO ANALYZE PCAP ---------------------------
def run_m1_analyzer(pcap_path: Path) -> dict:
    """
    Runs M1's analyzer script on the PCAP file.
    Returns the JSON output from M1.
    """
    try:
        # Option 1: If M1's script is a Python file
        result = subprocess.run(
            ["python", str(M1_SCRIPT), str(pcap_path)],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Try to parse output as JSON
        try:
            output = result.stdout.strip()
            if output.startswith('{'):
                return json.loads(output)
            else:
                logger.warning(f"M1 output not JSON: {output[:200]}")
                return {"error": "M1 output not JSON", "raw": output[:500]}
        except json.JSONDecodeError:
            logger.error(f"Failed to parse M1 output as JSON")
            return {"error": "JSON parse error", "raw": result.stdout[:500]}
            
    except subprocess.TimeoutExpired:
        logger.error("M1 analyzer timed out")
        return {"error": "Timeout"}
    except Exception as e:
        logger.error(f"M1 error: {str(e)}")
        return {"error": str(e)}

# --------------------------- MOCK DATA (for testing without M1) ---------------------------
async def get_mock_data() -> tuple[dict, dict]:
    """Returns mock email and TLS data for testing."""
    return {
        "spf": "pass",
        "dkim": "missing",
        "dmarc": "none"
    }, {
        "tls_version": "TLS 1.2",
        "cert_valid": True,
        "cert_expiry_days": 45,
        "starttls": "supported"
    }

# --------------------------- MAIN SCAN ENDPOINT (PCAP UPLOAD) ---------------------------
from fastapi.responses import FileResponse
import os

# Add this near your other routes (after the imports)
HTML_PATH = os.path.join(os.path.dirname(__file__), "ui_sih1.html")

@app.get("/")
async def serve_frontend():
    """Serve the backup HTML frontend at root."""
    if os.path.exists(HTML_PATH):
        return FileResponse(HTML_PATH)
    return {"message": "SecureMailScope Backend is running. Visit /docs for API documentation."}
@app.post("/scan", response_model=ScanResponse)
async def scan_pcap(
    file: UploadFile = File(...),
    domain: Optional[str] = Form(None)  # Optional fallback
):
    """
    Accepts a PCAP file upload. M1 analyzes it and returns security score.
    """
    logger.info(f"Received PCAP file: {file.filename}")

    try:
        # Step 1: Save the uploaded PCAP file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"
        pcap_path = PCAP_DIR / safe_filename
        
        with open(pcap_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        logger.info(f"PCAP saved to: {pcap_path}")

        # Step 2: Run M1's analyzer on the PCAP (or use mocks)
        if USE_MOCKS:
            logger.info("Using mock data (USE_MOCKS=true)")
            email_data, tls_data = await get_mock_data()
        else:
            # Run M1's script
            result = run_m1_analyzer(pcap_path)
            
            # Expect M1 to return something like:
            # {
            #   "spf": "pass",
            #   "dkim": "missing",
            #   "dmarc": "none",
            #   "tls_version": "TLS 1.2",
            #   "cert_valid": true,
            #   "cert_expiry_days": 45,
            #   "starttls": "supported"
            # }
            
            # Split the result into email and TLS parts
            email_data = {
                "spf": result.get("spf", "unknown"),
                "dkim": result.get("dkim", "unknown"),
                "dmarc": result.get("dmarc", "unknown")
            }
            tls_data = {
                "tls_version": result.get("tls_version", "unknown"),
                "cert_valid": result.get("cert_valid", False),
                "cert_expiry_days": result.get("cert_expiry_days", 0),
                "starttls": result.get("starttls", "unknown")
            }

        # Step 3: Normalize findings
        findings = normalize_findings(email_data, tls_data)

        # Step 4: Calculate risk
        score, severity = calculate_risk(findings)

        # Step 5: Save to database
        save_scan(file.filename, score, severity, [f.dict() for f in findings])

        # Step 6: Return response
        return ScanResponse(
            filename=file.filename,
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
@app.get("/history/{filename}")
async def get_history(filename: str):
    conn = sqlite3.connect("scans.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT filename, score, severity, findings_json, timestamp FROM scan_history WHERE filename = ? ORDER BY timestamp DESC LIMIT 10",
        (filename,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        raise HTTPException(status_code=404, detail="No scans found for this file")

    history = [
        {
            "filename": row[0],
            "score": row[1],
            "severity": row[2],
            "findings": json.loads(row[3]),
            "timestamp": row[4]
        }
        for row in rows
    ]
    return {"filename": filename, "history": history}

# --------------------------- RUN SERVER ---------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
