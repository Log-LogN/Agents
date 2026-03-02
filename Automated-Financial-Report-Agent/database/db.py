"""
database/db.py
══════════════
PostgreSQL schema + seed data for the Automated Financial Report Generator.

11 Tables:
  users             – RBAC login (4 roles: admin, cfo, analyst, controller)
  accounts          – Chart of accounts (30 seed accounts)
  transactions      – All GL journal entries (source of truth)
  budgets           – Department budgets by period
  budget_actuals    – Running actuals vs budget
  cash_accounts     – Cash and bank accounts (3 seed accounts)
  cash_transactions – Cash flow detail
  report_log        – Report audit trail
  report_schedules  – Scheduled recurring reports
  kpi_snapshots     – Historical KPI values for trend analysis
  alerts            – Fired financial alerts log
"""

import os
import hashlib
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

_SALT = "fin_salt_2026"


def _hash(pw: str) -> str:
    return hashlib.sha256((pw + _SALT).encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return _hash(plain) == hashed


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 5432)),
        dbname=os.getenv("DB_NAME", "finreport"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "postgres"),
    )


def _ensure_db():
    try:
        c = get_connection(); c.close()
    except psycopg2.OperationalError:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", 5432)),
            dbname="postgres",
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
        )
        conn.autocommit = True
        conn.cursor().execute(f"CREATE DATABASE {os.getenv('DB_NAME','finreport')}")
        conn.close()


def init_db():
    """Create all tables and seed data. Safe to call multiple times."""
    _ensure_db()
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id            SERIAL PRIMARY KEY,
        name          VARCHAR(120) NOT NULL,
        email         VARCHAR(120) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role          VARCHAR(20)  NOT NULL
                        CHECK (role IN ('admin','cfo','analyst','controller')),
        department    VARCHAR(80),
        is_active     BOOLEAN DEFAULT TRUE,
        created_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS accounts (
        id          SERIAL PRIMARY KEY,
        code        VARCHAR(20) UNIQUE NOT NULL,
        name        VARCHAR(150) NOT NULL,
        type        VARCHAR(20) NOT NULL
                      CHECK (type IN ('asset','liability','equity','revenue','expense')),
        category    VARCHAR(80),
        department  VARCHAR(80),
        is_active   BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id          SERIAL PRIMARY KEY,
        txn_date    DATE NOT NULL,
        account_id  INTEGER REFERENCES accounts(id),
        description TEXT,
        amount      NUMERIC(15,2) NOT NULL,
        txn_type    VARCHAR(10) NOT NULL CHECK (txn_type IN ('debit','credit')),
        category    VARCHAR(80),
        department  VARCHAR(80),
        reference   VARCHAR(100),
        posted_by   VARCHAR(120),
        created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS budgets (
        id          SERIAL PRIMARY KEY,
        department  VARCHAR(80) NOT NULL,
        fiscal_year INTEGER NOT NULL,
        period      INTEGER NOT NULL,
        amount      NUMERIC(15,2) NOT NULL,
        category    VARCHAR(80),
        created_by  VARCHAR(120),
        created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS budget_actuals (
        id            SERIAL PRIMARY KEY,
        budget_id     INTEGER REFERENCES budgets(id),
        actual_amount NUMERIC(15,2) DEFAULT 0,
        as_of_date    DATE DEFAULT CURRENT_DATE,
        updated_at    TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cash_accounts (
        id           SERIAL PRIMARY KEY,
        name         VARCHAR(120) NOT NULL,
        account_type VARCHAR(30) DEFAULT 'current',
        balance      NUMERIC(15,2) DEFAULT 0,
        currency     VARCHAR(10) DEFAULT 'INR',
        institution  VARCHAR(120),
        updated_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cash_transactions (
        id              SERIAL PRIMARY KEY,
        cash_account_id INTEGER REFERENCES cash_accounts(id),
        txn_date        DATE NOT NULL,
        txn_type        VARCHAR(10) NOT NULL CHECK (txn_type IN ('inflow','outflow')),
        amount          NUMERIC(15,2) NOT NULL,
        category        VARCHAR(80),
        description     TEXT,
        created_at      TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS report_log (
        id           SERIAL PRIMARY KEY,
        report_type  VARCHAR(80),
        generated_by VARCHAR(120),
        recipients   TEXT,
        sent_at      TIMESTAMP DEFAULT NOW(),
        period       VARCHAR(30),
        status       VARCHAR(20) DEFAULT 'sent'
    );

    CREATE TABLE IF NOT EXISTS report_schedules (
        id          SERIAL PRIMARY KEY,
        report_type VARCHAR(80),
        frequency   VARCHAR(20) CHECK (frequency IN ('daily','weekly','monthly')),
        recipients  TEXT,
        next_run    TIMESTAMP,
        is_active   BOOLEAN DEFAULT TRUE,
        created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS kpi_snapshots (
        id            SERIAL PRIMARY KEY,
        metric_name   VARCHAR(100),
        metric_value  NUMERIC(15,4),
        period        VARCHAR(30),
        calculated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id            SERIAL PRIMARY KEY,
        alert_type    VARCHAR(80),
        threshold     NUMERIC(15,2),
        current_value NUMERIC(15,2),
        triggered_at  TIMESTAMP DEFAULT NOW(),
        sent_to       TEXT,
        resolved      BOOLEAN DEFAULT FALSE
    );
    """)
    conn.commit()

    # ── Seed only if empty ──────────────────────────────────────────────────
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        conn.close()
        return

    # Users (4 roles)
    cur.execute("""
    INSERT INTO users (name, email, password_hash, role, department) VALUES
      ('System Admin',  'admin@finapp.com',       %s, 'admin',      'IT Administration'),
      ('Vikram Mehra',  'cfo@finapp.com',          %s, 'cfo',        'Finance'),
      ('Shreya Kapoor', 'analyst@finapp.com',      %s, 'analyst',    'FP&A'),
      ('Rajan Iyer',    'controller@finapp.com',   %s, 'controller', 'Accounting')
    """, (_hash("admin123"), _hash("cfo123"), _hash("analyst123"), _hash("ctrl123")))

    # Chart of accounts (30 accounts)
    cur.execute("""
    INSERT INTO accounts (code,name,type,category,department) VALUES
      ('1001','Cash - HDFC Current','asset','cash','Finance'),
      ('1002','Cash - ICICI Savings','asset','cash','Finance'),
      ('1003','Petty Cash','asset','cash','Admin'),
      ('1010','Accounts Receivable','asset','receivable','Finance'),
      ('1020','Inventory','asset','inventory','Operations'),
      ('1030','Prepaid Expenses','asset','prepaid','Finance'),
      ('1100','Fixed Assets - Equipment','asset','fixed_asset','IT'),
      ('1101','Fixed Assets - Furniture','asset','fixed_asset','Admin'),
      ('1110','Accumulated Depreciation','asset','depreciation','Finance'),
      ('2001','Accounts Payable','liability','payable','Finance'),
      ('2010','Accrued Salaries','liability','accrued','HR'),
      ('2020','Short-term Loan - HDFC','liability','short_term_debt','Finance'),
      ('2100','Long-term Loan - SBI','liability','long_term_debt','Finance'),
      ('2110','Deferred Revenue','liability','deferred_revenue','Sales'),
      ('3001','Share Capital','equity','capital','Finance'),
      ('3010','Retained Earnings','equity','retained','Finance'),
      ('4001','Product Sales Revenue','revenue','product','Sales'),
      ('4002','SaaS Subscription Revenue','revenue','saas','Sales'),
      ('4003','Professional Services Revenue','revenue','services','Sales'),
      ('4004','Other Revenue','revenue','other','Sales'),
      ('5001','Cost of Goods Sold - Products','expense','cogs','Operations'),
      ('5002','Cloud Infrastructure Costs','expense','cogs','Engineering'),
      ('6001','Salaries - Engineering','expense','salary','Engineering'),
      ('6002','Salaries - Sales','expense','salary','Sales'),
      ('6003','Salaries - Marketing','expense','salary','Marketing'),
      ('6004','Salaries - Admin','expense','salary','Admin'),
      ('6010','Rent & Utilities','expense','overhead','Admin'),
      ('6020','Marketing & Advertising','expense','marketing','Marketing'),
      ('6030','Travel & Entertainment','expense','travel','Sales'),
      ('6040','Software & Subscriptions','expense','software','IT')
    """)

    # Transactions — 3 months of realistic data (Dec 2025, Jan 2026, Feb 2026)
    cur.execute("""
    INSERT INTO transactions
      (txn_date,account_id,description,amount,txn_type,category,department,reference,posted_by)
    VALUES
      -- ── February 2026 Revenue ──────────────────────────────────────
      ('2026-02-01',17,'Product sales Feb batch-1',4200000,'credit','product','Sales','REV-FEB-001','controller@finapp.com'),
      ('2026-02-10',17,'Product sales Feb batch-2',3800000,'credit','product','Sales','REV-FEB-002','controller@finapp.com'),
      ('2026-02-01',18,'SaaS subscriptions Feb',8500000,'credit','saas','Sales','SAAS-FEB-001','controller@finapp.com'),
      ('2026-02-15',18,'SaaS renewals Feb',2200000,'credit','saas','Sales','SAAS-FEB-002','controller@finapp.com'),
      ('2026-02-01',19,'Consulting projects Feb',3500000,'credit','services','Sales','SVC-FEB-001','controller@finapp.com'),
      ('2026-02-20',19,'Implementation fees Feb',1800000,'credit','services','Sales','SVC-FEB-002','controller@finapp.com'),
      -- ── February 2026 COGS ────────────────────────────────────────
      ('2026-02-28',21,'Product COGS Feb',3200000,'debit','cogs','Operations','COGS-FEB-001','controller@finapp.com'),
      ('2026-02-28',22,'Cloud infra Feb',1800000,'debit','cogs','Engineering','COGS-FEB-002','controller@finapp.com'),
      -- ── February 2026 OpEx ────────────────────────────────────────
      ('2026-02-28',23,'Engineering salaries Feb',3200000,'debit','salary','Engineering','SAL-FEB-ENG','controller@finapp.com'),
      ('2026-02-28',24,'Sales salaries Feb',2100000,'debit','salary','Sales','SAL-FEB-SAL','controller@finapp.com'),
      ('2026-02-28',25,'Marketing salaries Feb',1400000,'debit','salary','Marketing','SAL-FEB-MKT','controller@finapp.com'),
      ('2026-02-28',26,'Admin salaries Feb',800000,'debit','salary','Admin','SAL-FEB-ADM','controller@finapp.com'),
      ('2026-02-28',27,'Rent Feb',600000,'debit','overhead','Admin','RENT-FEB','controller@finapp.com'),
      ('2026-02-15',28,'Google Ads Feb',920000,'debit','marketing','Marketing','MKT-FEB-001','controller@finapp.com'),
      ('2026-02-20',28,'LinkedIn Ads Feb',480000,'debit','marketing','Marketing','MKT-FEB-002','controller@finapp.com'),
      ('2026-02-28',29,'Sales travel Feb',340000,'debit','travel','Sales','TRV-FEB','controller@finapp.com'),
      ('2026-02-28',30,'AWS Slack Zoom Feb',210000,'debit','software','IT','SOFT-FEB','controller@finapp.com'),
      -- ── January 2026 Revenue ─────────────────────────────────────
      ('2026-01-01',17,'Product sales Jan',7500000,'credit','product','Sales','REV-JAN-001','controller@finapp.com'),
      ('2026-01-01',18,'SaaS subscriptions Jan',10200000,'credit','saas','Sales','SAAS-JAN-001','controller@finapp.com'),
      ('2026-01-01',19,'Consulting Jan',4800000,'credit','services','Sales','SVC-JAN-001','controller@finapp.com'),
      -- ── January 2026 COGS ────────────────────────────────────────
      ('2026-01-31',21,'Product COGS Jan',4100000,'debit','cogs','Operations','COGS-JAN-001','controller@finapp.com'),
      ('2026-01-31',22,'Cloud infra Jan',1900000,'debit','cogs','Engineering','COGS-JAN-002','controller@finapp.com'),
      -- ── January 2026 OpEx ────────────────────────────────────────
      ('2026-01-31',23,'Engineering salaries Jan',3200000,'debit','salary','Engineering','SAL-JAN-ENG','controller@finapp.com'),
      ('2026-01-31',24,'Sales salaries Jan',2100000,'debit','salary','Sales','SAL-JAN-SAL','controller@finapp.com'),
      ('2026-01-31',25,'Marketing salaries Jan',1400000,'debit','salary','Marketing','SAL-JAN-MKT','controller@finapp.com'),
      ('2026-01-31',26,'Admin salaries Jan',800000,'debit','salary','Admin','SAL-JAN-ADM','controller@finapp.com'),
      ('2026-01-31',27,'Rent Jan',600000,'debit','overhead','Admin','RENT-JAN','controller@finapp.com'),
      ('2026-01-15',28,'Digital ads Jan',1200000,'debit','marketing','Marketing','MKT-JAN-001','controller@finapp.com'),
      -- ── December 2025 Revenue ────────────────────────────────────
      ('2025-12-01',17,'Product sales Dec',8200000,'credit','product','Sales','REV-DEC-001','controller@finapp.com'),
      ('2025-12-01',18,'SaaS subscriptions Dec',9800000,'credit','saas','Sales','SAAS-DEC-001','controller@finapp.com'),
      ('2025-12-01',19,'Consulting Dec',3200000,'credit','services','Sales','SVC-DEC-001','controller@finapp.com'),
      -- ── December 2025 COGS & OpEx ────────────────────────────────
      ('2025-12-31',21,'Product COGS Dec',3900000,'debit','cogs','Operations','COGS-DEC-001','controller@finapp.com'),
      ('2025-12-31',22,'Cloud infra Dec',1750000,'debit','cogs','Engineering','COGS-DEC-002','controller@finapp.com'),
      ('2025-12-31',23,'Engineering salaries Dec',3200000,'debit','salary','Engineering','SAL-DEC-ENG','controller@finapp.com'),
      ('2025-12-31',24,'Sales salaries Dec',2100000,'debit','salary','Sales','SAL-DEC-SAL','controller@finapp.com'),
      ('2025-12-31',25,'Marketing salaries Dec',1400000,'debit','salary','Marketing','SAL-DEC-MKT','controller@finapp.com'),
      ('2025-12-31',26,'Admin salaries Dec',800000,'debit','salary','Admin','SAL-DEC-ADM','controller@finapp.com'),
      ('2025-12-31',27,'Rent Dec',600000,'debit','overhead','Admin','RENT-DEC','controller@finapp.com')
    """)

    # Budgets — February 2026 (period=2)
    cur.execute("""
    INSERT INTO budgets (department,fiscal_year,period,amount,category,created_by) VALUES
      ('Engineering',2026,2,3000000,'salary','analyst@finapp.com'),
      ('Sales',2026,2,1950000,'salary','analyst@finapp.com'),
      ('Marketing',2026,2,1150000,'salary','analyst@finapp.com'),
      ('Admin',2026,2,800000,'salary','analyst@finapp.com'),
      ('Marketing',2026,2,1200000,'marketing','analyst@finapp.com'),
      ('Sales',2026,2,300000,'travel','analyst@finapp.com'),
      ('IT',2026,2,180000,'software','analyst@finapp.com'),
      ('Admin',2026,2,600000,'overhead','analyst@finapp.com'),
      ('Operations',2026,2,3000000,'cogs','analyst@finapp.com'),
      ('Engineering',2026,2,1700000,'cogs','analyst@finapp.com')
    """)

    # Budget actuals (Feb 2026)
    cur.execute("""
    INSERT INTO budget_actuals (budget_id,actual_amount,as_of_date) VALUES
      (1,3200000,'2026-02-28'),(2,2100000,'2026-02-28'),(3,1400000,'2026-02-28'),
      (4,800000,'2026-02-28'),(5,1400000,'2026-02-28'),(6,340000,'2026-02-28'),
      (7,210000,'2026-02-28'),(8,600000,'2026-02-28'),(9,3200000,'2026-02-28'),
      (10,1800000,'2026-02-28')
    """)

    # Cash accounts
    cur.execute("""
    INSERT INTO cash_accounts (name,account_type,balance,currency,institution) VALUES
      ('HDFC Current Account','current',11200000,'INR','HDFC Bank'),
      ('ICICI Savings Account','savings',4500000,'INR','ICICI Bank'),
      ('Petty Cash','petty',85000,'INR','Internal')
    """)

    # Cash transactions (3 months)
    cur.execute("""
    INSERT INTO cash_transactions (cash_account_id,txn_date,txn_type,amount,category,description) VALUES
      (1,'2026-02-01','inflow',8500000,'saas_revenue','SaaS collections Feb'),
      (1,'2026-02-05','inflow',4200000,'product_revenue','Product collections Feb'),
      (1,'2026-02-10','inflow',3500000,'services_revenue','Services collections Feb'),
      (1,'2026-02-28','outflow',7500000,'salaries','Payroll Feb 2026'),
      (1,'2026-02-15','outflow',1400000,'marketing','Digital ads payment Feb'),
      (1,'2026-02-20','outflow',600000,'rent','Office rent Feb'),
      (1,'2026-02-25','outflow',3200000,'cogs','Supplier payment Feb'),
      (1,'2026-01-01','inflow',10200000,'saas_revenue','SaaS collections Jan'),
      (1,'2026-01-01','inflow',7500000,'product_revenue','Product sales Jan'),
      (1,'2026-01-31','outflow',7600000,'salaries','Payroll Jan 2026'),
      (1,'2026-01-20','outflow',4100000,'cogs','COGS payments Jan'),
      (2,'2026-02-01','inflow',1800000,'services_revenue','Services ICICI received'),
      (2,'2026-02-10','outflow',340000,'travel','Sales travel reimbursement')
    """)

    # KPI snapshots (3 months)
    cur.execute("""
    INSERT INTO kpi_snapshots (metric_name,metric_value,period) VALUES
      ('gross_margin_pct',54.20,'2026-02'),('ebitda_margin_pct',25.10,'2026-02'),
      ('net_profit_margin',18.30,'2026-02'),('current_ratio',2.10,'2026-02'),
      ('quick_ratio',1.85,'2026-02'),('debt_to_equity',0.34,'2026-02'),
      ('revenue_growth_mom',-8.50,'2026-02'),
      ('gross_margin_pct',52.80,'2026-01'),('ebitda_margin_pct',26.40,'2026-01'),
      ('current_ratio',2.05,'2026-01'),
      ('gross_margin_pct',53.60,'2025-12'),('ebitda_margin_pct',24.80,'2025-12')
    """)

    # Report schedules
    cur.execute("""
    INSERT INTO report_schedules (report_type,frequency,recipients,next_run,is_active) VALUES
      ('weekly_kpi_digest','weekly','cfo@finapp.com,admin@finapp.com',NOW()+INTERVAL '7 days',TRUE),
      ('monthly_pl','monthly','cfo@finapp.com,controller@finapp.com',NOW()+INTERVAL '30 days',TRUE),
      ('cash_flow_summary','weekly','cfo@finapp.com,controller@finapp.com',NOW()+INTERVAL '7 days',TRUE)
    """)

    conn.commit()
    conn.close()
    print("✅  Financial Report DB initialised with 3-month seed data.")