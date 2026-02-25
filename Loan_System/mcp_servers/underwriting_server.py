"""mcp_servers/underwriting_server.py — Underwriting & Decision tools (port 8004)"""
import sys, os, math
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from datetime import date, timedelta
from database.db import get_connection, init_db
from utils.email_service import send_approval_email, send_rejection_email

mcp = FastMCP("UnderwritingServer", host="127.0.0.1", port=8004,
              stateless_http=True, json_response=True)

def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def _calc_emi(principal: float, annual_rate: float, months: int) -> float:
    r = (annual_rate / 100) / 12
    if r == 0:
        return round(principal / months, 2)
    emi = principal * r * (1 + r) ** months / ((1 + r) ** months - 1)
    return round(emi, 2)


@mcp.tool()
def run_underwriting_decision(application_id: int) -> dict:
    """
    Run the full underwriting decision for a loan application.
    Reads KYC, credit score, and risk data to make approve / reject / escalate decision.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT la.*, a.name, a.annual_income FROM loan_applications la JOIN applicants a ON la.applicant_email=a.email WHERE la.id=%s", (application_id,))
    app = c.fetchone()
    if not app:
        conn.close()
        return {"status": "error", "message": f"Application #{application_id} not found."}

    email = app["applicant_email"]

    # Check KYC
    c.execute("SELECT kyc_status, fraud_flag FROM kyc_records WHERE applicant_email=%s", (email,))
    kyc = c.fetchone()
    if not kyc or kyc["kyc_status"] != "approved":
        conn.close()
        return {"status": "blocked", "message": f"KYC not approved for '{email}'. Complete KYC first."}
    if kyc["fraud_flag"]:
        conn.close()
        return {"status": "blocked", "message": "Cannot underwrite — fraud flag set on this application."}

    # Get credit score
    c.execute("SELECT credit_score, risk_level, debt_to_income_pct FROM credit_scores WHERE applicant_email=%s ORDER BY score_date DESC LIMIT 1", (email,))
    cs = c.fetchone()
    if not cs:
        conn.close()
        return {"status": "blocked", "message": "No credit score found. Run credit scoring first."}

    score = cs["credit_score"]
    risk  = cs["risk_level"]
    dti   = float(cs["debt_to_income_pct"])
    amount = float(app["amount_requested"])
    income = float(app["annual_income"])

    # Decision logic
    if score < 550 or dti > 65:
        decision = "reject"
        reason   = f"Credit score too low ({score}) or DTI too high ({dti}%)."
        approved_amount = None
        rate = None; months = None; emi = None
    elif amount > income * 5 or risk == "Very High":
        decision = "escalate"
        reason   = f"High amount ({amount:,.0f}) relative to income, or very high risk. Human review needed."
        approved_amount = None
        rate = None; months = None; emi = None
    else:
        decision = "approve"
        # Determine rate by risk
        if risk == "Low":        rate = 10.5 if app["loan_type"] in ("home","education") else 11.5
        elif risk == "Medium":   rate = 13.0 if app["loan_type"] in ("home","education") else 14.0
        else:                    rate = 15.5
        # Reduce amount if DTI is borderline
        approved_amount = amount if dti < 40 else amount * 0.8
        approved_amount = round(approved_amount, -3)  # round to nearest 1000
        # Default term by loan type
        term_map = {"home": 180, "education": 72, "business": 60, "personal": 36, "vehicle": 60}
        months = term_map.get(app["loan_type"], 36)
        emi    = _calc_emi(approved_amount, rate, months)
        reason = f"Credit score {score} ({risk} risk). DTI {dti}%. Auto-approved."

    # Save decision
    c.execute("""
        INSERT INTO underwriting_decisions
          (application_id,decision,approved_amount,interest_rate,term_months,monthly_emi,reason)
        VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
    """, (application_id, decision, approved_amount, rate, months, emi, reason))
    dec_id = c.fetchone()["id"]

    # Update application status
    status_map = {"approve": "approved", "reject": "rejected", "escalate": "escalated"}
    c.execute("UPDATE loan_applications SET status=%s WHERE id=%s", (status_map[decision], application_id))

    # If approved, create loan record
    loan_id = None
    if decision == "approve":
        c.execute("""
            INSERT INTO loans (application_id,applicant_email,principal,interest_rate,term_months,outstanding_balance)
            VALUES (%s,%s,%s,%s,%s,%s) RETURNING id
        """, (application_id, email, approved_amount, rate, months, approved_amount))
        loan_id = c.fetchone()["id"]
        # Build repayment schedule
        today = date.today()
        schedule = []
        for i in range(1, months + 1):
            due = today + timedelta(days=30 * i)
            schedule.append((loan_id, i, due, emi, 0, "pending"))
        c.executemany(
            "INSERT INTO repayment_schedule (loan_id,installment_no,due_date,amount_due,amount_paid,status) VALUES (%s,%s,%s,%s,%s,%s)",
            schedule
        )

    conn.commit(); conn.close()

    # Email
    if decision == "approve":
        c2 = get_connection(); cu2 = c2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cu2.execute("SELECT name FROM applicants WHERE email=%s", (email,))
        row = cu2.fetchone(); c2.close()
        send_approval_email(row["name"], email, application_id, approved_amount, rate, months, emi)
    elif decision == "reject":
        c2 = get_connection(); cu2 = c2.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cu2.execute("SELECT name FROM applicants WHERE email=%s", (email,))
        row = cu2.fetchone(); c2.close()
        send_rejection_email(row["name"], email, application_id, reason)

    return {
        "decision_id": dec_id, "application_id": application_id,
        "decision": decision.upper(), "reason": reason,
        "approved_amount": approved_amount, "interest_rate": rate,
        "term_months": months, "monthly_emi": emi, "loan_id": loan_id,
        "message": f"{'[OK] APPROVED' if decision=='approve' else '[ERROR] REJECTED' if decision=='reject' else '[WARN] ESCALATED'}: {reason}"
    }


@mcp.tool()
def calculate_loan_terms(principal: float, loan_type: str, risk_level: str) -> dict:
    """
    Preview loan terms (rate, EMI, schedule) before making a decision.
    risk_level: Low | Medium | High
    loan_type: personal | home | education | business | vehicle
    """
    rate_map = {
        ("home","Low"): 9.5, ("home","Medium"): 10.5, ("home","High"): 12.0,
        ("education","Low"): 9.0, ("education","Medium"): 10.5, ("education","High"): 13.0,
        ("personal","Low"): 11.5, ("personal","Medium"): 14.0, ("personal","High"): 16.5,
        ("business","Low"): 12.0, ("business","Medium"): 14.5, ("business","High"): 17.0,
        ("vehicle","Low"): 9.5, ("vehicle","Medium"): 11.0, ("vehicle","High"): 13.5,
    }
    term_map = {"home": 180, "education": 72, "business": 60, "personal": 36, "vehicle": 60}
    rate   = rate_map.get((loan_type, risk_level), 14.0)
    months = term_map.get(loan_type, 36)
    emi    = _calc_emi(principal, rate, months)
    total  = round(emi * months, 2)
    return {
        "principal": principal, "loan_type": loan_type, "risk_level": risk_level,
        "interest_rate_pct": rate, "term_months": months,
        "monthly_emi": emi, "total_payable": total,
        "total_interest": round(total - principal, 2)
    }


@mcp.tool()
def get_underwriting_decision(application_id: int) -> dict:
    """Get the underwriting decision for a specific application."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM underwriting_decisions WHERE application_id=%s ORDER BY decided_at DESC LIMIT 1", (application_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"No underwriting decision for application #{application_id}."}
    d = dict(row)
    for f in ("approved_amount", "interest_rate", "monthly_emi"):
        if d[f] is not None: d[f] = float(d[f])
    d["decided_at"] = str(d["decided_at"])
    return {"found": True, **d}


@mcp.tool()
def escalate_to_human(application_id: int, reason: str) -> dict:
    """Escalate a loan application to a human underwriter for manual review."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id FROM loan_applications WHERE id=%s", (application_id,))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": f"Application #{application_id} not found."}
    c.execute("UPDATE loan_applications SET status='escalated' WHERE id=%s", (application_id,))
    c.execute("""
        INSERT INTO underwriting_decisions (application_id,decision,reason)
        VALUES (%s,'escalate',%s) RETURNING id
    """, (application_id, reason))
    conn.commit(); conn.close()
    return {"status": "escalated",
            "message": f"[WARN] Application #{application_id} escalated to human underwriter. Reason: {reason}"}


if __name__ == "__main__":
    init_db()
    print("[START] Underwriting MCP Server on http://127.0.0.1:8004/mcp")
    mcp.run(transport="streamable-http")