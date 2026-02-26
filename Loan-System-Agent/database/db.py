"""
database/db.py
--------------
PostgreSQL database for the Loan & Credit Multi-Agent System.

Tables:
  applicants, loan_applications, kyc_records, credit_scores,
  underwriting_decisions, loans, repayment_schedule, payments

Auto-creates the database if it doesn't exist.
Seeds rich fake data on first run so the system is immediately usable.
"""
import os
import json
import psycopg2
import psycopg2.extras
from datetime import date, timedelta, datetime
from dotenv import load_dotenv

load_dotenv()


# ── Connection helpers ────────────────────────────────────────────────────────

def get_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "loan_db"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def create_database_if_not_exists():
    db_name = os.getenv("DB_NAME", "loan_db")
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname="postgres",
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
    if not cur.fetchone():
        try:
            cur.execute(f'CREATE DATABASE "{db_name}"')
            print(f"[OK] Database '{db_name}' created.")
        except psycopg2.errors.UniqueViolation:
            # This can happen if another process created it just after our check
            print(f"[OK] Database '{db_name}' was just created by another process.")
        except Exception as e:
            if "already exists" in str(e).lower():
                print(f"[OK] Database '{db_name}' already exists.")
            else:
                raise e
    cur.close()
    conn.close()


# ── Table creation ────────────────────────────────────────────────────────────

def init_db():
    create_database_if_not_exists()
    conn = get_connection()
    cur = conn.cursor()

    # 1. Applicants
    cur.execute("""
        CREATE TABLE IF NOT EXISTS applicants (
            id               SERIAL PRIMARY KEY,
            name             TEXT    NOT NULL,
            email            TEXT    NOT NULL UNIQUE,
            age              INTEGER NOT NULL,
            employment_type  TEXT    NOT NULL DEFAULT 'salaried',
            employer         TEXT,
            annual_income    NUMERIC(14,2) DEFAULT 0,
            created_at       TIMESTAMP DEFAULT NOW()
        )
    """)

    # 2. Loan Applications
    cur.execute("""
        CREATE TABLE IF NOT EXISTS loan_applications (
            id               SERIAL PRIMARY KEY,
            applicant_email  TEXT    NOT NULL,
            loan_type        TEXT    NOT NULL,
            amount_requested NUMERIC(14,2) NOT NULL,
            purpose          TEXT,
            status           TEXT    DEFAULT 'submitted',
            created_at       TIMESTAMP DEFAULT NOW()
        )
    """)

    # 3. KYC Records
    cur.execute("""
        CREATE TABLE IF NOT EXISTS kyc_records (
            id                   SERIAL PRIMARY KEY,
            applicant_email      TEXT    NOT NULL UNIQUE,
            identity_verified    BOOLEAN DEFAULT FALSE,
            doc_verified         BOOLEAN DEFAULT FALSE,
            employment_verified  BOOLEAN DEFAULT FALSE,
            aml_passed           BOOLEAN DEFAULT FALSE,
            sanctions_clear      BOOLEAN DEFAULT FALSE,
            fraud_flag           BOOLEAN DEFAULT FALSE,
            fraud_reason         TEXT,
            kyc_status           TEXT    DEFAULT 'pending',
            verified_at          TIMESTAMP
        )
    """)

    # 4. Credit Scores
    cur.execute("""
        CREATE TABLE IF NOT EXISTS credit_scores (
            id                  SERIAL PRIMARY KEY,
            applicant_email     TEXT    NOT NULL,
            credit_score        INTEGER NOT NULL,
            risk_level          TEXT    NOT NULL,
            debt_to_income_pct  NUMERIC(5,2) DEFAULT 0,
            total_existing_debt NUMERIC(14,2) DEFAULT 0,
            score_date          DATE    DEFAULT CURRENT_DATE
        )
    """)

    # 5. Underwriting Decisions
    cur.execute("""
        CREATE TABLE IF NOT EXISTS underwriting_decisions (
            id              SERIAL PRIMARY KEY,
            application_id  INTEGER REFERENCES loan_applications(id),
            decision        TEXT    NOT NULL,
            approved_amount NUMERIC(14,2),
            interest_rate   NUMERIC(5,2),
            term_months     INTEGER,
            monthly_emi     NUMERIC(10,2),
            reason          TEXT,
            decided_at      TIMESTAMP DEFAULT NOW()
        )
    """)

    # 6. Loans (disbursed)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS loans (
            id                  SERIAL PRIMARY KEY,
            application_id      INTEGER REFERENCES loan_applications(id),
            applicant_email     TEXT    NOT NULL,
            principal           NUMERIC(14,2) NOT NULL,
            interest_rate       NUMERIC(5,2)  NOT NULL,
            term_months         INTEGER       NOT NULL,
            outstanding_balance NUMERIC(14,2) NOT NULL,
            status              TEXT    DEFAULT 'active',
            disbursed_at        DATE    DEFAULT CURRENT_DATE
        )
    """)

    # 7. Repayment Schedule
    cur.execute("""
        CREATE TABLE IF NOT EXISTS repayment_schedule (
            id              SERIAL PRIMARY KEY,
            loan_id         INTEGER REFERENCES loans(id),
            installment_no  INTEGER NOT NULL,
            due_date        DATE    NOT NULL,
            amount_due      NUMERIC(10,2) NOT NULL,
            amount_paid     NUMERIC(10,2) DEFAULT 0,
            status          TEXT    DEFAULT 'pending'
        )
    """)

    # 8. Payments
    cur.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id              SERIAL PRIMARY KEY,
            loan_id         INTEGER REFERENCES loans(id),
            applicant_email TEXT    NOT NULL,
            amount_paid     NUMERIC(10,2) NOT NULL,
            payment_date    DATE    DEFAULT CURRENT_DATE,
            method          TEXT    DEFAULT 'bank_transfer',
            notes           TEXT
        )
    """)

    conn.commit()
    _seed_data(conn, cur)
    cur.close()
    conn.close()
    print("[OK] Loan database fully initialized with seed data.")


# ── Seed Data ─────────────────────────────────────────────────────────────────

def _seed_data(conn, cur):
    cur.execute("SELECT COUNT(*) FROM applicants")
    if cur.fetchone()[0] > 0:
        print("[OK] Seed data already present — skipping.")
        return

    print("[SEED] Seeding fake data...")

    # ── Applicants ────────────────────────────────────────────────────────
    applicants = [
        ("Aarav Sharma",    "aarav.sharma@email.com",    32, "salaried",    "Infosys Ltd",          720000),
        ("Priya Mehta",     "priya.mehta@email.com",     28, "salaried",    "TCS",                  580000),
        ("Rohan Verma",     "rohan.verma@email.com",     45, "self_employed","Own Business",         1200000),
        ("Sneha Patel",     "sneha.patel@email.com",     26, "salaried",    "Wipro",                420000),
        ("Karan Gupta",     "karan.gupta@email.com",     38, "salaried",    "HDFC Bank",            950000),
        ("Anjali Nair",     "anjali.nair@email.com",     31, "salaried",    "Accenture",            660000),
        ("Vikram Singh",    "vikram.singh@email.com",    50, "self_employed","Singh Traders",        1800000),
        ("Meena Joshi",     "meena.joshi@email.com",     24, "salaried",    "Cognizant",            380000),
        ("Arjun Das",       "arjun.das@email.com",       35, "salaried",    "Amazon India",         1100000),
        ("Kavya Reddy",     "kavya.reddy@email.com",     29, "salaried",    "Flipkart",             510000),
        ("Fraud User",      "fraud.test@email.com",      33, "salaried",    "Unknown Corp",         500000),
        ("Defaulter Mike",  "defaulter.mike@email.com",  40, "salaried",    "XYZ Ltd",              350000),
    ]
    cur.executemany(
        "INSERT INTO applicants (name,email,age,employment_type,employer,annual_income) VALUES (%s,%s,%s,%s,%s,%s)",
        applicants
    )

    # ── Loan Applications ─────────────────────────────────────────────────
    today = date.today()
    apps = [
        # (email, type, amount, purpose, status)
        ("aarav.sharma@email.com",   "personal",  500000,  "Home renovation",        "approved"),
        ("priya.mehta@email.com",    "education",  300000,  "MBA program fees",       "approved"),
        ("rohan.verma@email.com",    "business",  2000000, "Expand workshop",        "approved"),
        ("sneha.patel@email.com",    "personal",  150000,  "Wedding expenses",       "under_review"),
        ("karan.gupta@email.com",    "home",      5000000, "Purchase apartment",     "approved"),
        ("anjali.nair@email.com",    "personal",  250000,  "Medical emergency",      "approved"),
        ("vikram.singh@email.com",   "business",  3500000, "New machinery",          "escalated"),
        ("meena.joshi@email.com",    "education",  200000,  "Online certification",   "submitted"),
        ("arjun.das@email.com",      "personal",  400000,  "Vehicle purchase",       "approved"),
        ("kavya.reddy@email.com",    "personal",  180000,  "Laptop & equipment",     "rejected"),
        ("fraud.test@email.com",     "personal",  800000,  "Investment",             "flagged"),
        ("defaulter.mike@email.com", "personal",  220000,  "Personal expenses",      "approved"),
    ]
    cur.executemany(
        "INSERT INTO loan_applications (applicant_email,loan_type,amount_requested,purpose,status,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
        [(a[0], a[1], a[2], a[3], a[4], today - timedelta(days=30 - i * 2)) for i, a in enumerate(apps)]
    )

    # ── KYC Records ──────────────────────────────────────────────────────
    kyc_data = [
        # (email, id_ok, doc_ok, emp_ok, aml_ok, sanct_ok, fraud, reason, status)
        ("aarav.sharma@email.com",   True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("priya.mehta@email.com",    True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("rohan.verma@email.com",    True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("sneha.patel@email.com",    True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("karan.gupta@email.com",    True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("anjali.nair@email.com",    True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("vikram.singh@email.com",   True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("meena.joshi@email.com",    True,  False, True,  True,  True,  False, None,                                      "pending"),
        ("arjun.das@email.com",      True,  True,  True,  True,  True,  False, None,                                      "approved"),
        ("kavya.reddy@email.com",    True,  True,  True,  False, True,  False, None,                                      "failed"),
        ("fraud.test@email.com",     True,  False, False, False, False, True,  "Document metadata mismatch. AML alert.",  "flagged"),
        ("defaulter.mike@email.com", True,  True,  True,  True,  True,  False, None,                                      "approved"),
    ]
    cur.executemany(
        """INSERT INTO kyc_records
           (applicant_email,identity_verified,doc_verified,employment_verified,aml_passed,sanctions_clear,fraud_flag,fraud_reason,kyc_status,verified_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        [(k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7], k[8], today - timedelta(days=25)) for k in kyc_data]
    )

    # ── Credit Scores ─────────────────────────────────────────────────────
    scores = [
        ("aarav.sharma@email.com",   742, "Low",    28.5,  150000),
        ("priya.mehta@email.com",    698, "Low",    22.0,   80000),
        ("rohan.verma@email.com",    775, "Low",    18.0,  400000),
        ("sneha.patel@email.com",    620, "Medium", 35.0,   60000),
        ("karan.gupta@email.com",    801, "Low",    20.0,  800000),
        ("anjali.nair@email.com",    715, "Low",    26.0,  120000),
        ("vikram.singh@email.com",   680, "Medium", 42.0,  900000),
        ("meena.joshi@email.com",    580, "Medium", 38.0,   40000),
        ("arjun.das@email.com",      758, "Low",    24.0,  200000),
        ("kavya.reddy@email.com",    540, "High",   55.0,  180000),
        ("fraud.test@email.com",     310, "High",   78.0,  500000),
        ("defaulter.mike@email.com", 595, "High",   62.0,  210000),
    ]
    cur.executemany(
        "INSERT INTO credit_scores (applicant_email,credit_score,risk_level,debt_to_income_pct,total_existing_debt,score_date) VALUES (%s,%s,%s,%s,%s,%s)",
        [(s[0], s[1], s[2], s[3], s[4], today - timedelta(days=20)) for s in scores]
    )

    # ── Underwriting Decisions ────────────────────────────────────────────
    # Get application IDs in order
    cur.execute("SELECT id, applicant_email FROM loan_applications ORDER BY id")
    app_rows = cur.fetchall()
    email_to_app = {r[1]: r[0] for r in app_rows}

    decisions = [
        ("aarav.sharma@email.com",    "approve",   500000,  11.5, 36,  16420,  "Good credit, stable employment, low DTI."),
        ("priya.mehta@email.com",     "approve",   300000,  10.5, 24,  13900,  "Excellent profile, low risk."),
        ("rohan.verma@email.com",     "approve",  1800000,  13.0, 60,  41200,  "Strong business income, manageable DTI."),
        ("sneha.patel@email.com",     "approve",   120000,  13.5, 12,  10700,  "Approved reduced amount due to medium risk."),
        ("karan.gupta@email.com",     "approve",  5000000,   9.5, 180, 52300,  "Prime applicant, home loan approved."),
        ("anjali.nair@email.com",     "approve",   250000,  11.0, 24,  11550,  "Low risk, good income-to-debt ratio."),
        ("vikram.singh@email.com",    "escalate",  None,    None,  None, None, "High amount + medium risk. Needs human review."),
        ("meena.joshi@email.com",     None,        None,    None,  None, None, None),   # pending
        ("arjun.das@email.com",       "approve",   400000,  11.5, 36,  13100,  "Strong profile, vehicle loan approved."),
        ("kavya.reddy@email.com",     "reject",    None,    None,  None, None, "High DTI (55%), high credit risk, AML flag."),
        ("fraud.test@email.com",      "reject",    None,    None,  None, None, "Fraud flag raised. Application blocked."),
        ("defaulter.mike@email.com",  "approve",   220000,  14.0, 24,  10600,  "Approved at higher rate due to high DTI."),
    ]
    for d in decisions:
        email = d[0]
        app_id = email_to_app.get(email)
        if not app_id or d[1] is None:
            continue
        cur.execute(
            """INSERT INTO underwriting_decisions
               (application_id,decision,approved_amount,interest_rate,term_months,monthly_emi,reason,decided_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (app_id, d[1], d[2], d[3], d[4], d[5], d[6], today - timedelta(days=15))
        )

    # ── Disbursed Loans ───────────────────────────────────────────────────
    loans_data = [
        # (email, app_email_key, principal, rate, months, outstanding, status, disbursed_ago_days)
        ("aarav.sharma@email.com",    500000,  11.5, 36, 462000,  "active",  14),
        ("priya.mehta@email.com",     300000,  10.5, 24, 260000,  "active",  20),
        ("rohan.verma@email.com",    1800000,  13.0, 60,1800000,  "active",   5),
        ("karan.gupta@email.com",    5000000,   9.5,180,5000000,  "active",   3),
        ("anjali.nair@email.com",     250000,  11.0, 24, 238000,  "active",  10),
        ("arjun.das@email.com",       400000,  11.5, 36, 400000,  "active",   7),
        ("defaulter.mike@email.com",  220000,  14.0, 24, 220000,  "active",  30),
    ]
    loan_ids = {}
    for ld in loans_data:
        email = ld[0]
        app_id = email_to_app.get(email)
        cur.execute(
            """INSERT INTO loans (application_id,applicant_email,principal,interest_rate,term_months,outstanding_balance,status,disbursed_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (app_id, email, ld[1], ld[2], ld[3], ld[4], ld[5], today - timedelta(days=ld[6]))
        )
        loan_ids[email] = cur.fetchone()[0]

    # ── Repayment Schedules ───────────────────────────────────────────────
    def build_schedule(loan_id, principal, annual_rate, months, disbursed_days_ago):
        r = (annual_rate / 100) / 12
        if r == 0:
            emi = principal / months
        else:
            emi = principal * r * (1 + r) ** months / ((1 + r) ** months - 1)
        emi = round(emi, 2)
        disbursed_date = today - timedelta(days=disbursed_days_ago)
        rows = []
        for i in range(1, months + 1):
            due = disbursed_date + timedelta(days=30 * i)
            if due < today:
                status = "paid"
                paid = emi
            else:
                status = "pending"
                paid = 0
            rows.append((loan_id, i, due, emi, paid, status))
        return rows

    schedule_configs = [
        ("aarav.sharma@email.com",    500000,  11.5, 36, 14),
        ("priya.mehta@email.com",     300000,  10.5, 24, 20),
        ("rohan.verma@email.com",    1800000,  13.0, 60,  5),
        ("karan.gupta@email.com",    5000000,   9.5,180,  3),
        ("anjali.nair@email.com",     250000,  11.0, 24, 10),
        ("arjun.das@email.com",       400000,  11.5, 36,  7),
        ("defaulter.mike@email.com",  220000,  14.0, 24, 30),
    ]
    for sc in schedule_configs:
        email = sc[0]
        lid = loan_ids.get(email)
        if not lid:
            continue
        rows = build_schedule(lid, sc[1], sc[2], sc[3], sc[4])
        cur.executemany(
            "INSERT INTO repayment_schedule (loan_id,installment_no,due_date,amount_due,amount_paid,status) VALUES (%s,%s,%s,%s,%s,%s)",
            rows
        )

    # Override defaulter — mark installment 1 as missed
    defaulter_lid = loan_ids.get("defaulter.mike@email.com")
    if defaulter_lid:
        cur.execute(
            "UPDATE repayment_schedule SET status='missed', amount_paid=0 WHERE loan_id=%s AND installment_no=1",
            (defaulter_lid,)
        )

    # ── Payment History ───────────────────────────────────────────────────
    payment_data = [
        ("aarav.sharma@email.com",  "bank_transfer", 14),
        ("priya.mehta@email.com",   "upi",           20),
        ("anjali.nair@email.com",   "net_banking",   10),
    ]
    for pd in payment_data:
        email = pd[0]
        lid = loan_ids.get(email)
        if not lid:
            continue
        cur.execute("SELECT amount_due FROM repayment_schedule WHERE loan_id=%s AND status='paid' LIMIT 1", (lid,))
        row = cur.fetchone()
        if row:
            cur.execute(
                "INSERT INTO payments (loan_id,applicant_email,amount_paid,payment_date,method,notes) VALUES (%s,%s,%s,%s,%s,%s)",
                (lid, email, row[0], today - timedelta(days=pd[2] - 1), pd[1], "Auto-debit successful")
            )

    conn.commit()
    print("[OK] All seed data inserted successfully.")
    print(f"   -> {len(applicants)} applicants, {len(apps)} applications, {len(loans_data)} active loans")
    print(f"   -> KYC records, credit scores, repayment schedules all seeded.")


if __name__ == "__main__":
    init_db()