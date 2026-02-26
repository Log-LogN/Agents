"""mcp_servers/application_server.py — Loan Application tools (port 8001)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_application_confirmation

mcp = FastMCP("ApplicationServer", host="127.0.0.1", port=8001,
              stateless_http=True, json_response=True)

def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def get_loan_types() -> list:
    """Return all available loan types with typical rates and terms."""
    return [
        {"type": "personal",  "description": "Personal Loan",  "max_amount": 1500000, "rate_range": "10.5–18%", "max_term_months": 60},
        {"type": "home",      "description": "Home Loan",      "max_amount": 10000000,"rate_range": "8.5–11%",  "max_term_months": 240},
        {"type": "education",  "description": "Education Loan", "max_amount": 2000000, "rate_range": "9–13%",    "max_term_months": 84},
        {"type": "business",  "description": "Business Loan",  "max_amount": 5000000, "rate_range": "12–18%",   "max_term_months": 60},
        {"type": "vehicle",   "description": "Vehicle Loan",   "max_amount": 2500000, "rate_range": "9–13%",    "max_term_months": 84},
    ]


@mcp.tool()
def register_applicant(name: str, email: str, age: int,
                        employment_type: str, employer: str, annual_income: float) -> dict:
    """
    Register a new loan applicant.
    employment_type: 'salaried' or 'self_employed'
    Returns existing record if email already registered.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id, name FROM applicants WHERE email=%s", (email,))
    existing = c.fetchone()
    if existing:
        conn.close()
        return {"status": "already_exists", "applicant_id": existing["id"],
                "message": f"Applicant '{existing['name']}' already registered with {email}."}
    if age < 18 or age > 70:
        conn.close()
        return {"status": "error", "message": "Applicant age must be between 18 and 70."}
    if employment_type not in ("salaried", "self_employed"):
        conn.close()
        return {"status": "error", "message": "employment_type must be 'salaried' or 'self_employed'."}
    c.execute(
        "INSERT INTO applicants (name,email,age,employment_type,employer,annual_income) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
        (name, email, age, employment_type, employer, annual_income)
    )
    aid = c.fetchone()["id"]
    conn.commit(); conn.close()
    return {"status": "registered", "applicant_id": aid,
            "message": f"[OK] Applicant '{name}' registered successfully. ID: {aid}"}


@mcp.tool()
def submit_application(applicant_email: str, loan_type: str,
                        amount_requested: float, purpose: str) -> dict:
    """
    Submit a new loan application.
    loan_type: personal | home | education | business | vehicle
    Sends confirmation email automatically.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id, name FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found. Please register first."}

    # Check KYC status
    c.execute("SELECT kyc_status FROM kyc_records WHERE applicant_email=%s", (applicant_email,))
    kyc = c.fetchone()
    if not kyc or kyc["kyc_status"] != "approved":
        conn.close()
        return {"status": "error", "message": f"[ERROR] KYC not approved for '{applicant_email}'. Please complete KYC and fraud verification before applying for a loan."}
    valid_types = ("personal", "home", "education", "business", "vehicle")
    if loan_type not in valid_types:
        conn.close()
        return {"status": "error", "message": f"Invalid loan_type. Choose from: {valid_types}"}
    if amount_requested <= 0:
        conn.close()
        return {"status": "error", "message": "amount_requested must be positive."}
    c.execute(
        "INSERT INTO loan_applications (applicant_email,loan_type,amount_requested,purpose) VALUES (%s,%s,%s,%s) RETURNING id",
        (applicant_email, loan_type, amount_requested, purpose)
    )
    app_id = c.fetchone()["id"]
    conn.commit(); conn.close()
    email_r = send_application_confirmation(
        applicant["name"], applicant_email, app_id, loan_type, amount_requested, purpose
    )
    note = "[MAIL] Confirmation email sent." if email_r["success"] else f"[WARN] Email failed: {email_r['message']}"
    return {
        "status": "submitted", "application_id": app_id,
        "message": f"[OK] Application #{app_id} submitted for {loan_type} loan of Rs.{amount_requested:,.0f}. {note}"
    }


@mcp.tool()
def get_application_status(applicant_email: str) -> list:
    """Get all loan applications and their current status for an applicant."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, loan_type, amount_requested, purpose, status, created_at
        FROM loan_applications WHERE applicant_email=%s ORDER BY created_at DESC
    """, (applicant_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No applications found for '{applicant_email}'."}]
    return [{**dict(r), "created_at": str(r["created_at"]),
             "amount_requested": float(r["amount_requested"])} for r in rows]


@mcp.tool()
def get_applicant_profile(applicant_email: str) -> dict:
    """Get full profile of an applicant including registration details."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM applicants WHERE email=%s", (applicant_email,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Applicant '{applicant_email}' not found."}
    d = dict(row)
    d["annual_income"] = float(d["annual_income"])
    d["created_at"]    = str(d["created_at"])
    return {"found": True, **d}


@mcp.tool()
def update_application_status(application_id: int, new_status: str) -> dict:
    """
    Update the status of a loan application.
    Valid statuses: submitted | under_review | approved | rejected | escalated | flagged
    """
    valid = ("submitted", "under_review", "approved", "rejected", "escalated", "flagged")
    if new_status not in valid:
        return {"status": "error", "message": f"Invalid status. Choose from: {valid}"}
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id FROM loan_applications WHERE id=%s", (application_id,))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": f"Application #{application_id} not found."}
    c.execute("UPDATE loan_applications SET status=%s WHERE id=%s", (new_status, application_id))
    conn.commit(); conn.close()
    return {"status": "updated", "message": f"[OK] Application #{application_id} status -> '{new_status}'."}


if __name__ == "__main__":
    init_db()
    print("[START] Application MCP Server on http://127.0.0.1:8001/mcp")
    mcp.run(transport="streamable-http")