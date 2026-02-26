"""mcp_servers/credit_risk_server.py — Credit Risk & Scoring tools (port 8003)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("CreditRiskServer", host="127.0.0.1", port=8003,
              stateless_http=True, json_response=True)

def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def get_credit_report(applicant_email: str) -> dict:
    """Get the latest credit score report for an applicant."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT cs.*, a.name, a.annual_income, a.employment_type
        FROM credit_scores cs JOIN applicants a ON cs.applicant_email=a.email
        WHERE cs.applicant_email=%s ORDER BY cs.score_date DESC LIMIT 1
    """, (applicant_email,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"No credit report for '{applicant_email}'. Run calculate_credit_score first."}
    d = dict(row)
    d["annual_income"]    = float(d["annual_income"])
    d["debt_to_income_pct"] = float(d["debt_to_income_pct"])
    d["total_existing_debt"] = float(d["total_existing_debt"])
    d["score_date"]       = str(d["score_date"])
    return {"found": True, **d}


@mcp.tool()
def calculate_credit_score(applicant_email: str) -> dict:
    """
    Calculate a multi-factor credit score for an applicant.
    Factors: income, employment stability, existing debt, repayment history, age.
    Score range: 300 (poor) to 850 (excellent).
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM applicants WHERE email=%s", (applicant_email,))
    applicant = c.fetchone()
    if not applicant:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    # Check existing debt
    c.execute("""
        SELECT COALESCE(SUM(outstanding_balance),0) AS total_debt
        FROM loans WHERE applicant_email=%s AND status='active'
    """, (applicant_email,))
    debt_row = c.fetchone()
    total_debt = float(debt_row["total_debt"]) if debt_row else 0.0
    income = float(applicant["annual_income"])

    # Scoring algorithm (simplified but realistic)
    score = 600  # base
    monthly_income = income / 12

    # Income factor
    if income >= 1000000:   score += 80
    elif income >= 700000:  score += 60
    elif income >= 500000:  score += 40
    elif income >= 300000:  score += 20
    else:                   score -= 20

    # Employment type
    if applicant["employment_type"] == "salaried":  score += 30
    else:                                           score += 10

    # Age factor
    age = applicant["age"]
    if 30 <= age <= 50:     score += 20
    elif 25 <= age < 30:    score += 10
    elif age > 55:          score -= 10

    # Debt-to-income ratio
    monthly_debt = total_debt / 12 if total_debt > 0 else 0
    dti = round((monthly_debt / monthly_income * 100) if monthly_income > 0 else 0, 2)
    if dti < 20:    score += 40
    elif dti < 35:  score += 20
    elif dti < 50:  score -= 20
    else:           score -= 50

    # Repayment history
    c.execute("""
        SELECT COUNT(*) as missed FROM repayment_schedule rs
        JOIN loans l ON rs.loan_id=l.id
        WHERE l.applicant_email=%s AND rs.status='missed'
    """, (applicant_email,))
    missed = c.fetchone()["missed"]
    score -= missed * 30

    # Clamp to valid range
    score = max(300, min(850, score))

    # Risk tier
    if score >= 750:   risk = "Low"
    elif score >= 650: risk = "Medium"
    elif score >= 550: risk = "High"
    else:              risk = "Very High"

    # Save or update
    c.execute("SELECT id FROM credit_scores WHERE applicant_email=%s", (applicant_email,))
    if c.fetchone():
        c.execute(
            "UPDATE credit_scores SET credit_score=%s,risk_level=%s,debt_to_income_pct=%s,total_existing_debt=%s,score_date=CURRENT_DATE WHERE applicant_email=%s",
            (score, risk, dti, total_debt, applicant_email)
        )
    else:
        c.execute(
            "INSERT INTO credit_scores (applicant_email,credit_score,risk_level,debt_to_income_pct,total_existing_debt) VALUES (%s,%s,%s,%s,%s)",
            (applicant_email, score, risk, dti, total_debt)
        )
    conn.commit(); conn.close()
    return {
        "applicant": applicant["name"], "credit_score": score, "risk_level": risk,
        "debt_to_income_pct": dti, "total_existing_debt": total_debt,
        "annual_income": income, "missed_payments": missed,
        "message": f"[OK] Credit score calculated: {score} ({risk} risk). DTI: {dti}%."
    }


@mcp.tool()
def get_debt_to_income_ratio(applicant_email: str) -> dict:
    """Calculate current debt-to-income ratio for an applicant."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT annual_income FROM applicants WHERE email=%s", (applicant_email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}
    income = float(row["annual_income"])

    c.execute("SELECT COALESCE(SUM(outstanding_balance),0) AS debt FROM loans WHERE applicant_email=%s AND status='active'", (applicant_email,))
    debt = float(c.fetchone()["debt"])
    conn.close()

    monthly_income = income / 12
    monthly_debt   = debt / 12
    dti = round((monthly_debt / monthly_income * 100) if monthly_income > 0 else 0, 2)

    level = "Excellent (<20%)" if dti < 20 else "Good (20–35%)" if dti < 35 else "Moderate (35–50%)" if dti < 50 else "High (>50%)"
    return {
        "annual_income": income, "total_existing_debt": debt,
        "monthly_income": round(monthly_income, 2), "monthly_debt_obligation": round(monthly_debt, 2),
        "debt_to_income_pct": dti, "dti_level": level
    }


@mcp.tool()
def check_existing_loans(applicant_email: str) -> list:
    """List all active loans for an applicant with outstanding balances."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT l.id, l.principal, l.interest_rate, l.term_months,
               l.outstanding_balance, l.status, l.disbursed_at,
               la.loan_type
        FROM loans l JOIN loan_applications la ON l.application_id=la.id
        WHERE l.applicant_email=%s ORDER BY l.disbursed_at DESC
    """, (applicant_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No active loans for '{applicant_email}'."}]
    return [{**dict(r),
             "principal": float(r["principal"]),
             "outstanding_balance": float(r["outstanding_balance"]),
             "disbursed_at": str(r["disbursed_at"])} for r in rows]


@mcp.tool()
def assess_risk_level(applicant_email: str, requested_amount: float) -> dict:
    """
    Give a final risk assessment for a specific loan amount request.
    Considers credit score, DTI, income, and existing obligations.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT annual_income FROM applicants WHERE email=%s", (applicant_email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    c.execute("SELECT credit_score, risk_level, debt_to_income_pct FROM credit_scores WHERE applicant_email=%s ORDER BY score_date DESC LIMIT 1", (applicant_email,))
    score_row = c.fetchone()
    conn.close()

    if not score_row:
        return {"status": "error", "message": "No credit score found. Run calculate_credit_score first."}

    income = float(row["annual_income"])
    score  = score_row["credit_score"]
    risk   = score_row["risk_level"]
    dti    = float(score_row["debt_to_income_pct"])
    # Amount-to-income ratio
    ati = round(requested_amount / income, 2) if income > 0 else 99

    concerns = []
    if score < 600:     concerns.append(f"Low credit score ({score})")
    if dti > 50:        concerns.append(f"High DTI ({dti}%)")
    if ati > 3:         concerns.append(f"Loan amount is {ati}x annual income")
    if risk == "Very High": concerns.append("Very high risk tier")

    recommendation = "Approve" if not concerns else ("Conditional Approve" if len(concerns) == 1 else "Reject")
    return {
        "credit_score": score, "risk_level": risk, "dti_pct": dti,
        "amount_to_income_ratio": ati, "concerns": concerns,
        "recommendation": recommendation,
        "message": f"Risk assessment: {recommendation}. Issues: {concerns if concerns else 'None'}."
    }


@mcp.tool()
def generate_risk_summary(applicant_email: str) -> dict:
    """Generate a comprehensive risk summary report for underwriting."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM applicants WHERE email=%s", (applicant_email,))
    app = c.fetchone()
    if not app:
        conn.close()
        return {"status": "error", "message": f"Applicant '{applicant_email}' not found."}

    c.execute("SELECT * FROM credit_scores WHERE applicant_email=%s ORDER BY score_date DESC LIMIT 1", (applicant_email,))
    cs = c.fetchone()

    c.execute("SELECT kyc_status, fraud_flag FROM kyc_records WHERE applicant_email=%s", (applicant_email,))
    kyc = c.fetchone()

    c.execute("SELECT COUNT(*) AS missed FROM repayment_schedule rs JOIN loans l ON rs.loan_id=l.id WHERE l.applicant_email=%s AND rs.status='missed'", (applicant_email,))
    missed = c.fetchone()["missed"]

    c.execute("SELECT COALESCE(SUM(outstanding_balance),0) AS debt FROM loans WHERE applicant_email=%s AND status='active'", (applicant_email,))
    debt = float(c.fetchone()["debt"])
    conn.close()

    return {
        "applicant": app["name"], "email": applicant_email,
        "annual_income": float(app["annual_income"]),
        "employment_type": app["employment_type"],
        "credit_score": cs["credit_score"] if cs else "Not calculated",
        "risk_level":   cs["risk_level"]   if cs else "Unknown",
        "dti_pct":      float(cs["debt_to_income_pct"]) if cs else 0,
        "total_existing_debt": debt,
        "missed_payments": missed,
        "kyc_status": kyc["kyc_status"] if kyc else "pending",
        "fraud_flag":  kyc["fraud_flag"] if kyc else False,
        "summary": f"{'[WARN] FRAUD FLAG SET. ' if (kyc and kyc['fraud_flag']) else ''}Score: {cs['credit_score'] if cs else 'N/A'}, Risk: {cs['risk_level'] if cs else 'N/A'}, KYC: {kyc['kyc_status'] if kyc else 'pending'}."
    }


if __name__ == "__main__":
    init_db()
    print("[START] Credit Risk MCP Server on http://127.0.0.1:8003/mcp")
    mcp.run(transport="streamable-http")