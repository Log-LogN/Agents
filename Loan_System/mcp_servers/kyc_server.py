"""mcp_servers/kyc_server.py — KYC & Fraud Detection tools (port 8002)"""
import sys, os, random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_kyc_approved_email

mcp = FastMCP("KYCServer", host="127.0.0.1", port=8002,
              stateless_http=True, json_response=True)

def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# Simulated AML/Sanctions watchlist (fake names for demo)
SANCTIONS_WATCHLIST = ["john.doe.sanctions@test.com", "blacklisted@fraud.com", "fraud.test@email.com"]
HIGH_RISK_EMPLOYERS = ["unknown corp", "shell co", "offshore ltd"]


@mcp.tool()
def get_kyc_status(applicant_email: str) -> dict:
    """Get current KYC verification status for an applicant."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM kyc_records WHERE applicant_email=%s", (applicant_email,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "kyc_status": "not_started",
                "message": f"No KYC record for '{applicant_email}'. Run verification first."}
    d = dict(row)
    d["verified_at"] = str(d["verified_at"]) if d["verified_at"] else None
    return {"found": True, **d}


@mcp.tool()
def verify_identity(applicant_email: str) -> dict:
    """
    Verify applicant identity against government records.
    Checks: name match, DOB, PAN/Aadhaar consistency.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, age FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"verified": False, "message": f"Applicant '{applicant_email}' not found."}

    # Simulate identity verification (always passes for real applicants)
    _ensure_kyc_record(c, conn, applicant_email)
    c.execute("UPDATE kyc_records SET identity_verified=TRUE WHERE applicant_email=%s", (applicant_email,))
    conn.commit(); conn.close()
    return {
        "verified": True, "applicant": applicant["name"],
        "message": f"[OK] Identity verified for {applicant['name']}. Government records match."
    }


@mcp.tool()
def check_document_authenticity(applicant_email: str) -> dict:
    """
    Authenticate submitted documents (ID proof, income proof, address proof).
    Detects AI-generated, tampered, or mismatched documents.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, employer FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"authentic": False, "message": f"Applicant '{applicant_email}' not found."}

    _ensure_kyc_record(c, conn, applicant_email)

    # Simulate: fraud test email gets flagged
    is_fraud_email = applicant_email in SANCTIONS_WATCHLIST
    employer_suspicious = any(w in (applicant["employer"] or "").lower() for w in HIGH_RISK_EMPLOYERS)

    if is_fraud_email or employer_suspicious:
        c.execute(
            "UPDATE kyc_records SET doc_verified=FALSE, fraud_flag=TRUE, fraud_reason=%s WHERE applicant_email=%s",
            ("Document metadata mismatch. Font inconsistency detected. Possible AI-generated document.", applicant_email)
        )
        conn.commit(); conn.close()
        return {
            "authentic": False, "fraud_detected": True,
            "findings": ["Metadata date mismatch", "Font inconsistency", "Possible AI-generated content"],
            "message": "[ALERT] Document authenticity FAILED. Fraud flag raised."
        }

    c.execute("UPDATE kyc_records SET doc_verified=TRUE WHERE applicant_email=%s", (applicant_email,))
    conn.commit(); conn.close()
    return {
        "authentic": True, "fraud_detected": False,
        "findings": ["Metadata valid", "Font consistent", "Document template verified"],
        "message": "[OK] All documents verified as authentic."
    }


@mcp.tool()
def verify_employment(applicant_email: str) -> dict:
    """
    Verify employment and income with employer database.
    Checks: employer existence, stated income vs payslip, employment continuity.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, employer, annual_income, employment_type FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"verified": False, "message": f"Applicant '{applicant_email}' not found."}

    _ensure_kyc_record(c, conn, applicant_email)
    employer_suspicious = any(w in (applicant["employer"] or "").lower() for w in HIGH_RISK_EMPLOYERS)

    if employer_suspicious:
        c.execute("UPDATE kyc_records SET employment_verified=FALSE WHERE applicant_email=%s", (applicant_email,))
        conn.commit(); conn.close()
        return {"verified": False, "message": f"[ERROR] Employer '{applicant['employer']}' not found in verified employer database."}

    c.execute("UPDATE kyc_records SET employment_verified=TRUE WHERE applicant_email=%s", (applicant_email,))
    conn.commit(); conn.close()
    return {
        "verified": True,
        "employer": applicant["employer"],
        "employment_type": applicant["employment_type"],
        "annual_income_verified": float(applicant["annual_income"]),
        "message": f"[OK] Employment verified. {applicant['name']} confirmed at {applicant['employer']}."
    }


@mcp.tool()
def run_aml_check(applicant_email: str) -> dict:
    """
    Run Anti-Money Laundering (AML) check.
    Screens for suspicious transaction patterns, known fraud networks.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"passed": False, "message": f"Applicant '{applicant_email}' not found."}

    _ensure_kyc_record(c, conn, applicant_email)
    aml_fail = applicant_email in SANCTIONS_WATCHLIST

    if aml_fail:
        c.execute("UPDATE kyc_records SET aml_passed=FALSE, fraud_flag=TRUE, fraud_reason=%s WHERE applicant_email=%s",
                  ("AML screening: suspicious transaction pattern detected.", applicant_email))
        conn.commit(); conn.close()
        return {"passed": False, "alerts": ["Suspicious transaction pattern", "Linked to flagged network"],
                "message": "[ALERT] AML check FAILED. Application flagged for compliance review."}

    c.execute("UPDATE kyc_records SET aml_passed=TRUE WHERE applicant_email=%s", (applicant_email,))
    conn.commit(); conn.close()
    return {"passed": True, "alerts": [],
            "message": f"[OK] AML check passed for {applicant['name']}. No suspicious activity found."}


@mcp.tool()
def screen_sanctions(applicant_email: str) -> dict:
    """Screen applicant against global sanctions lists (OFAC, UN, EU)."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"clear": False, "message": f"Applicant '{applicant_email}' not found."}

    _ensure_kyc_record(c, conn, applicant_email)
    on_list = applicant_email in SANCTIONS_WATCHLIST

    c.execute("UPDATE kyc_records SET sanctions_clear=%s WHERE applicant_email=%s",
              (not on_list, applicant_email))
    conn.commit(); conn.close()

    if on_list:
        return {"clear": False, "lists_matched": ["OFAC SDN List"],
                "message": "[ALERT] Sanctions match found. Application must be blocked immediately."}
    return {"clear": True, "lists_checked": ["OFAC", "UN Consolidated", "EU Sanctions"],
            "message": f"[OK] {applicant['name']} cleared on all sanctions lists."}


@mcp.tool()
def flag_fraud_risk(applicant_email: str, reason: str) -> dict:
    """Manually flag an application for fraud review with a reason."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    _ensure_kyc_record(c, conn, applicant_email)
    c.execute(
        "UPDATE kyc_records SET fraud_flag=TRUE, fraud_reason=%s, kyc_status='flagged' WHERE applicant_email=%s",
        (reason, applicant_email)
    )
    c.execute(
        "UPDATE loan_applications SET status='flagged' WHERE applicant_email=%s AND status NOT IN ('approved','rejected')",
        (applicant_email,)
    )
    conn.commit(); conn.close()
    return {"status": "flagged", "applicant": applicant["name"],
            "message": f"[ALERT] Application for {applicant['name']} flagged for fraud review. Reason: {reason}"}


@mcp.tool()
def approve_kyc(applicant_email: str) -> dict:
    """
    Approve KYC for an applicant after all checks pass.
    Sends KYC approval email automatically.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    c.execute("SELECT * FROM kyc_records WHERE applicant_email=%s", (applicant_email,))
    kyc = c.fetchone()
    if not kyc:
        conn.close()
        return {"status": "error", "message": "No KYC record found. Run verification checks first."}

    if kyc["fraud_flag"]:
        conn.close()
        return {"status": "error", "message": "Cannot approve KYC — fraud flag is set."}

    checks_passed = kyc["identity_verified"] and kyc["doc_verified"] and kyc["employment_verified"] and kyc["aml_passed"]
    if not checks_passed:
        missing = [k for k, v in {
            "Identity": kyc["identity_verified"], "Documents": kyc["doc_verified"],
            "Employment": kyc["employment_verified"], "AML": kyc["aml_passed"]
        }.items() if not v]
        conn.close()
        return {"status": "incomplete", "missing_checks": missing,
                "message": f"Cannot approve — pending checks: {', '.join(missing)}"}

    c.execute(
        "UPDATE kyc_records SET kyc_status='approved', verified_at=NOW() WHERE applicant_email=%s",
        (applicant_email,)
    )
    conn.commit(); conn.close()
    email_r = send_kyc_approved_email(applicant["name"], applicant_email)
    note = "[MAIL] KYC approval email sent." if email_r["success"] else f"[WARN] Email failed: {email_r['message']}"
    return {"status": "approved", "applicant": applicant["name"],
            "message": f"[OK] KYC fully approved for {applicant['name']}. {note}"}


def _ensure_kyc_record(cur, conn, email):
    cur.execute("SELECT id FROM kyc_records WHERE applicant_email=%s", (email,))
    if not cur.fetchone():
        cur.execute("INSERT INTO kyc_records (applicant_email) VALUES (%s)", (email,))
        conn.commit()


if __name__ == "__main__":
    init_db()
    print("[START] KYC MCP Server on http://127.0.0.1:8002/mcp")
    mcp.run(transport="streamable-http")