"""mcp_servers/repayment_server.py — Repayment & Collections tools (port 8005)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from datetime import date, timedelta
from database.db import get_connection, init_db
from utils.email_service import send_payment_reminder

mcp = FastMCP("RepaymentServer", host="127.0.0.1", port=8005,
              stateless_http=True, json_response=True)

def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def get_loan_status(applicant_email: str) -> list:
    """Get all active loans and their current status for an applicant."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT l.id, l.principal, l.interest_rate, l.term_months,
               l.outstanding_balance, l.status, l.disbursed_at, la.loan_type
        FROM loans l JOIN loan_applications la ON l.application_id=la.id
        WHERE l.applicant_email=%s ORDER BY l.disbursed_at DESC
    """, (applicant_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No loans found for '{applicant_email}'."}]
    return [{**dict(r),
             "principal": float(r["principal"]),
             "outstanding_balance": float(r["outstanding_balance"]),
             "disbursed_at": str(r["disbursed_at"])} for r in rows]


@mcp.tool()
def get_repayment_schedule(loan_id: int) -> list:
    """Get the full repayment schedule for a specific loan."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT installment_no, due_date, amount_due, amount_paid, status
        FROM repayment_schedule WHERE loan_id=%s ORDER BY installment_no
    """, (loan_id,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No repayment schedule for loan #{loan_id}."}]
    return [{**dict(r), "amount_due": float(r["amount_due"]),
             "amount_paid": float(r["amount_paid"]), "due_date": str(r["due_date"])} for r in rows]


@mcp.tool()
def record_payment(loan_id: int, applicant_email: str, amount_paid: float,
                   method: str = "bank_transfer", notes: str = "") -> dict:
    """
    Record a loan repayment payment.
    method: bank_transfer | upi | net_banking | cash | cheque
    Updates the next pending installment and reduces outstanding balance.
    """
    conn = get_connection(); c = _cur(conn)
    # Verify loan belongs to applicant
    c.execute("SELECT * FROM loans WHERE id=%s AND applicant_email=%s", (loan_id, applicant_email))
    loan = c.fetchone()
    if not loan:
        conn.close()
        return {"status": "error", "message": f"Loan #{loan_id} not found for '{applicant_email}'."}

    # Find next pending/missed installment
    c.execute("""
        SELECT * FROM repayment_schedule
        WHERE loan_id=%s AND status IN ('pending','missed','overdue')
        ORDER BY installment_no LIMIT 1
    """, (loan_id,))
    installment = c.fetchone()
    if not installment:
        conn.close()
        return {"status": "error", "message": f"No pending installments for loan #{loan_id}. Loan may be fully paid."}

    # Update installment
    c.execute(
        "UPDATE repayment_schedule SET amount_paid=%s, status='paid' WHERE id=%s",
        (amount_paid, installment["id"])
    )
    # Reduce outstanding balance
    new_balance = max(0, float(loan["outstanding_balance"]) - amount_paid)
    new_status = "closed" if new_balance == 0 else "active"
    c.execute("UPDATE loans SET outstanding_balance=%s, status=%s WHERE id=%s",
              (new_balance, new_status, loan_id))
    # Record payment
    c.execute("""
        INSERT INTO payments (loan_id,applicant_email,amount_paid,payment_date,method,notes)
        VALUES (%s,%s,%s,CURRENT_DATE,%s,%s) RETURNING id
    """, (loan_id, applicant_email, amount_paid, method, notes or "Payment received"))
    pay_id = c.fetchone()["id"]
    conn.commit(); conn.close()

    return {
        "status": "recorded", "payment_id": pay_id,
        "installment_no": installment["installment_no"],
        "amount_paid": amount_paid, "outstanding_balance": new_balance,
        "loan_status": new_status,
        "message": f"[OK] Payment of Rs.{amount_paid:,.0f} recorded for Loan #{loan_id}, Installment #{installment['installment_no']}. Outstanding: Rs.{new_balance:,.0f}"
    }


@mcp.tool()
def get_payment_history(loan_id: int) -> list:
    """Get all payment history for a specific loan."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, amount_paid, payment_date, method, notes
        FROM payments WHERE loan_id=%s ORDER BY payment_date DESC
    """, (loan_id,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No payment history for loan #{loan_id}."}]
    return [{**dict(r), "amount_paid": float(r["amount_paid"]),
             "payment_date": str(r["payment_date"])} for r in rows]


@mcp.tool()
def flag_missed_payment(loan_id: int, installment_no: int) -> dict:
    """Flag a specific installment as missed and update loan status."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM repayment_schedule WHERE loan_id=%s AND installment_no=%s",
              (loan_id, installment_no))
    inst = c.fetchone()
    if not inst:
        conn.close()
        return {"status": "error", "message": f"Installment #{installment_no} not found for loan #{loan_id}."}
    if inst["status"] == "paid":
        conn.close()
        return {"status": "error", "message": f"Installment #{installment_no} is already paid."}

    c.execute("UPDATE repayment_schedule SET status='missed' WHERE loan_id=%s AND installment_no=%s",
              (loan_id, installment_no))
    conn.commit(); conn.close()
    return {
        "status": "flagged", "loan_id": loan_id, "installment_no": installment_no,
        "amount_due": float(inst["amount_due"]),
        "message": f"[WARN] Installment #{installment_no} for Loan #{loan_id} marked as MISSED. Amount due: Rs.{float(inst['amount_due']):,.0f}"
    }


@mcp.tool()
def send_payment_reminder_email(loan_id: int) -> dict:
    """Send a payment reminder email to the borrower for the next due installment."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM loans WHERE id=%s", (loan_id,))
    loan = c.fetchone()
    if not loan:
        conn.close()
        return {"status": "error", "message": f"Loan #{loan_id} not found."}

    c.execute("""
        SELECT * FROM repayment_schedule
        WHERE loan_id=%s AND status IN ('pending','missed','overdue')
        ORDER BY due_date LIMIT 1
    """, (loan_id,))
    inst = c.fetchone()
    if not inst:
        conn.close()
        return {"status": "error", "message": "No pending installments found."}

    c.execute("SELECT name, email FROM applicants WHERE email=%s", (loan["applicant_email"],))
    applicant = c.fetchone(); conn.close()

    email_r = send_payment_reminder(
        applicant["name"], applicant["email"], loan_id,
        str(inst["due_date"]), float(inst["amount_due"]), inst["installment_no"]
    )
    note = "[MAIL] Reminder sent." if email_r["success"] else f"[WARN] Email failed: {email_r['message']}"
    return {
        "status": "sent", "installment_no": inst["installment_no"],
        "due_date": str(inst["due_date"]), "amount_due": float(inst["amount_due"]),
        "message": f"Payment reminder for Installment #{inst['installment_no']} (Rs.{float(inst['amount_due']):,.0f} due {inst['due_date']}). {note}"
    }


@mcp.tool()
def assess_default_risk(applicant_email: str) -> dict:
    """
    Assess the probability of loan default for an applicant.
    Based on: missed payments, outstanding balance, credit score, DTI.
    Returns risk level: Low | Medium | High.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT annual_income FROM applicants WHERE email=%s", (applicant_email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    c.execute("""
        SELECT COUNT(*) AS missed FROM repayment_schedule rs
        JOIN loans l ON rs.loan_id=l.id
        WHERE l.applicant_email=%s AND rs.status='missed'
    """, (applicant_email,))
    missed = c.fetchone()["missed"]

    c.execute("SELECT credit_score, debt_to_income_pct FROM credit_scores WHERE applicant_email=%s ORDER BY score_date DESC LIMIT 1", (applicant_email,))
    cs = c.fetchone()

    c.execute("SELECT COALESCE(SUM(outstanding_balance),0) AS debt FROM loans WHERE applicant_email=%s AND status='active'", (applicant_email,))
    debt = float(c.fetchone()["debt"])
    conn.close()

    score = cs["credit_score"] if cs else 600
    dti   = float(cs["debt_to_income_pct"]) if cs else 30

    risk_score = 0
    if missed >= 3:  risk_score += 3
    elif missed >= 1: risk_score += 2
    if dti > 60:     risk_score += 2
    elif dti > 40:   risk_score += 1
    if score < 580:  risk_score += 2
    elif score < 650: risk_score += 1

    risk = "High" if risk_score >= 4 else "Medium" if risk_score >= 2 else "Low"
    interventions = []
    if risk in ("Medium","High"):
        interventions = ["Send payment reminder", "Offer payment deferral", "Assign collections officer"]
    if risk == "High":
        interventions.append("Consider loan restructuring or legal notice")

    return {
        "applicant_email": applicant_email, "missed_payments": missed,
        "credit_score": score, "dti_pct": dti, "outstanding_balance": debt,
        "default_risk": risk, "risk_score": risk_score,
        "recommended_interventions": interventions,
        "message": f"Default risk: {risk}. Missed payments: {missed}. Score: {score}. DTI: {dti}%."
    }


@mcp.tool()
def restructure_loan(loan_id: int, defer_installments: int = 2) -> dict:
    """
    Restructure a loan by deferring upcoming installments.
    Shifts unpaid installments forward by defer_installments months.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM loans WHERE id=%s", (loan_id,))
    loan = c.fetchone()
    if not loan:
        conn.close()
        return {"status": "error", "message": f"Loan #{loan_id} not found."}

    # Shift all pending/missed installments forward
    c.execute("""
        UPDATE repayment_schedule
        SET due_date = due_date + INTERVAL '1 month' * %s,
            status = CASE WHEN status='missed' THEN 'pending' ELSE status END
        WHERE loan_id=%s AND status IN ('pending','missed','overdue')
    """, (defer_installments, loan_id))
    affected = c.rowcount
    conn.commit(); conn.close()

    return {
        "status": "restructured", "loan_id": loan_id,
        "installments_deferred": defer_installments,
        "installments_affected": affected,
        "message": f"[OK] Loan #{loan_id} restructured. {affected} installments deferred by {defer_installments} month(s). Missed payment penalties cleared."
    }


if __name__ == "__main__":
    init_db()
    print("[START] Repayment MCP Server on http://127.0.0.1:8005/mcp")
    mcp.run(transport="streamable-http")