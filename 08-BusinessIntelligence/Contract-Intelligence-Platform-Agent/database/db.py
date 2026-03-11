"""
database/db.py
PostgreSQL schema creation, connection, and seed data.
Auto-initialises on first run — no manual setup required.
"""

import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

from urllib.parse import urlparse
from psycopg2.sql import SQL, Identifier

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password@localhost:5432/contract_db")

def create_database_if_not_exists():
    url = urlparse(DATABASE_URL)
    db_name = url.path.lstrip('/')
    base_url = url._replace(path='/postgres').geturl()
    
    conn = None
    try:
        conn = psycopg2.connect(base_url)
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (db_name,))
        if not cur.fetchone():
            cur.execute(SQL("CREATE DATABASE {}").format(Identifier(db_name)))
            logger.info("Auto-created database: %s", db_name)
    except Exception as e:
        logger.warning("DB auto-create skipped (might lack permissions or already exist): %s", e)
    finally:
        if conn:
            conn.close()


# ── Connection ─────────────────────────────────────────────────────────────────

def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def fetch_one(sql: str, params: tuple = ()):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchone()
    finally:
        conn.close()


def fetch_all(sql: str, params: tuple = ()):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()
    finally:
        conn.close()


def execute(sql: str, params: tuple = ()):
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()
        try:
            return cur.fetchone()
        except Exception:
            return None
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ─────────────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50)  NOT NULL DEFAULT 'viewer'
                    CHECK (role IN ('admin','legal_counsel','contract_manager','procurement','finance','viewer')),
    full_name       VARCHAR(255),
    department      VARCHAR(100),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS templates (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    contract_type   VARCHAR(50)  NOT NULL,
    content         TEXT,
    fields          JSONB,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clauses (
    id              SERIAL PRIMARY KEY,
    title           VARCHAR(255) NOT NULL,
    clause_type     VARCHAR(100) NOT NULL,
    category        VARCHAR(100),
    content         TEXT NOT NULL,
    risk_level      VARCHAR(20) DEFAULT 'LOW' CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    is_standard     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS playbooks (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    contract_type   VARCHAR(50),
    rules           JSONB,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contracts (
    id              SERIAL PRIMARY KEY,
    contract_number VARCHAR(50) UNIQUE NOT NULL,
    title           VARCHAR(500) NOT NULL,
    contract_type   VARCHAR(50)  NOT NULL,
    status          VARCHAR(30)  NOT NULL DEFAULT 'DRAFT'
                    CHECK (status IN ('DRAFT','REVIEW','APPROVAL','EXECUTION','ACTIVE','EXPIRED','TERMINATED','AMENDED')),
    party_a_name    VARCHAR(255),
    party_b_name    VARCHAR(255),
    party_a_email   VARCHAR(255),
    party_b_email   VARCHAR(255),
    value           NUMERIC(18,2) DEFAULT 0,
    currency        VARCHAR(10) DEFAULT 'USD',
    start_date      DATE,
    end_date        DATE,
    renewal_date    DATE,
    jurisdiction    VARCHAR(100),
    content         TEXT,
    risk_score      INTEGER DEFAULT 0,
    risk_flags      JSONB DEFAULT '[]',
    template_id     INTEGER REFERENCES templates(id),
    created_by      INTEGER REFERENCES users(id),
    owner_id        INTEGER REFERENCES users(id),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contract_versions (
    id              SERIAL PRIMARY KEY,
    contract_id     INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    version_number  INTEGER NOT NULL,
    content         TEXT,
    changed_by      INTEGER REFERENCES users(id),
    change_summary  VARCHAR(500),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS obligations (
    id              SERIAL PRIMARY KEY,
    contract_id     INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    obligation_type VARCHAR(50) NOT NULL CHECK (obligation_type IN ('PAYMENT','DELIVERY','REPORT','COMPLIANCE','RENEWAL','MILESTONE','OTHER')),
    description     TEXT NOT NULL,
    owner_email     VARCHAR(255),
    due_date        DATE,
    status          VARCHAR(30) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','OVERDUE','WAIVED')),
    priority        VARCHAR(20) DEFAULT 'MEDIUM' CHECK (priority IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    amount          NUMERIC(18,2),
    reminder_sent   BOOLEAN DEFAULT FALSE,
    completed_at    TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_workflows (
    id              SERIAL PRIMARY KEY,
    contract_id     INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    status          VARCHAR(30) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','IN_PROGRESS','APPROVED','REJECTED','WITHDRAWN')),
    approvers       JSONB NOT NULL DEFAULT '[]',
    current_step    INTEGER DEFAULT 0,
    deadline        TIMESTAMP,
    created_by      INTEGER REFERENCES users(id),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_actions (
    id              SERIAL PRIMARY KEY,
    workflow_id     INTEGER NOT NULL REFERENCES approval_workflows(id) ON DELETE CASCADE,
    contract_id     INTEGER NOT NULL REFERENCES contracts(id),
    approver_id     INTEGER REFERENCES users(id),
    approver_email  VARCHAR(255),
    action          VARCHAR(20) NOT NULL CHECK (action IN ('APPROVED','REJECTED','ESCALATED','DELEGATED')),
    comments        TEXT,
    step_number     INTEGER,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_issues (
    id              SERIAL PRIMARY KEY,
    contract_id     INTEGER NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    issue_type      VARCHAR(100) NOT NULL,
    regulation      VARCHAR(100),
    severity        VARCHAR(20) DEFAULT 'MEDIUM' CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    description     TEXT NOT NULL,
    recommendation  TEXT,
    status          VARCHAR(30) DEFAULT 'OPEN' CHECK (status IN ('OPEN','RESOLVED','ACCEPTED','ESCALATED')),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id),
    session_id      VARCHAR(100),
    contract_id     INTEGER REFERENCES contracts(id),
    intent_key      VARCHAR(100),
    agent_used      VARCHAR(100),
    mcp_tool        VARCHAR(100),
    user_message    TEXT,
    agent_response  TEXT,
    duration_ms     INTEGER,
    status          VARCHAR(20) DEFAULT 'success',
    ts              TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contracts_status    ON contracts(status);
CREATE INDEX IF NOT EXISTS idx_contracts_type      ON contracts(contract_type);
CREATE INDEX IF NOT EXISTS idx_contracts_owner     ON contracts(owner_id);
CREATE INDEX IF NOT EXISTS idx_obligations_contract ON obligations(contract_id);
CREATE INDEX IF NOT EXISTS idx_obligations_due     ON obligations(due_date);
CREATE INDEX IF NOT EXISTS idx_audit_log_user      ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts        ON audit_log(ts);
"""


def create_schema():
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(SCHEMA_SQL)
        conn.commit()
        logger.info("Database schema created/verified.")
    except Exception as e:
        conn.rollback()
        logger.error("Schema creation failed: %s", e)
        raise
    finally:
        conn.close()


# ── Seed Data ──────────────────────────────────────────────────────────────────

def seed_users():
    import bcrypt
    users = [
        ("admin@contract.ai",   "Admin@123",   "admin",            "System Admin",      "IT"),
        ("legal@contract.ai",   "Legal@123",   "legal_counsel",    "Sarah Legal",       "Legal"),
        ("manager@contract.ai", "Manager@123", "contract_manager", "John Manager",      "Operations"),
        ("procure@contract.ai", "Procure@123", "procurement",      "Alice Procurement", "Procurement"),
        ("finance@contract.ai", "Finance@123", "finance",          "Bob Finance",       "Finance"),
        ("viewer@contract.ai",  "Viewer@123",  "viewer",           "Carol Viewer",      "General"),
    ]
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM users")
        if cur.fetchone()["cnt"] > 0:
            conn.close()
            return
        for email, pwd, role, name, dept in users:
            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            cur.execute(
                "INSERT INTO users (email, password_hash, role, full_name, department) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (email, hashed, role, name, dept)
            )
        conn.commit()
        logger.info("Demo users seeded.")
    finally:
        conn.close()


def seed_templates():
    templates = [
        ("Standard NDA (Mutual)",          "NDA",        "Mutual Non-Disclosure Agreement between {party_a} and {party_b}..."),
        ("Master Services Agreement",       "MSA",        "This Master Services Agreement is entered into by {party_a} and {party_b}..."),
        ("Statement of Work",               "SOW",        "Statement of Work for {project_name} between {party_a} and {party_b}..."),
        ("Vendor / Supplier Agreement",     "Vendor",     "Vendor Agreement between {party_a} (Buyer) and {party_b} (Vendor)..."),
        ("Employment Agreement",            "Employment", "Employment Agreement between {company} and {employee}..."),
        ("Software License Agreement",      "SaaS",       "Software License Agreement for {product_name}..."),
        ("Office / Commercial Lease",       "Lease",      "Commercial Lease Agreement for premises at {address}..."),
    ]
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM templates")
        if cur.fetchone()["cnt"] > 0:
            conn.close()
            return
        for name, ctype, content in templates:
            cur.execute(
                "INSERT INTO templates (name, contract_type, content) VALUES (%s,%s,%s)",
                (name, ctype, content)
            )
        conn.commit()
        logger.info("Templates seeded.")
    finally:
        conn.close()


def seed_clauses():
    clauses = [
        ("Standard Limitation of Liability", "Liability",       "Risk",       "Neither party shall be liable for indirect, incidental, or consequential damages...", "MEDIUM"),
        ("GDPR Data Processing Addendum",     "Data_Privacy",    "Compliance", "The parties agree to comply with applicable data protection legislation including GDPR...", "HIGH"),
        ("Force Majeure",                     "Force_Majeure",   "Risk",       "Neither party shall be liable for failure to perform obligations due to circumstances beyond reasonable control...", "LOW"),
        ("IP Assignment",                     "Intellectual_Property","IP",    "All intellectual property created under this agreement shall vest in the commissioning party...", "HIGH"),
        ("Standard NDA",                      "Confidentiality", "Security",   "Each party agrees to keep confidential all proprietary information disclosed by the other party...", "MEDIUM"),
        ("Payment Terms Net 30",              "Payment",         "Finance",    "Payment shall be due within 30 days of invoice date. Late payments attract 1.5% monthly interest...", "MEDIUM"),
        ("Termination for Convenience",       "Termination",     "Exit",       "Either party may terminate this agreement upon 30 days written notice without cause...", "LOW"),
        ("Governing Law New York",            "Jurisdiction",    "Legal",      "This agreement shall be governed by and construed in accordance with the laws of New York...", "LOW"),
        ("Auto-Renewal 90-Day Notice",        "Renewal",         "Renewal",    "This agreement shall automatically renew for successive one-year terms unless either party provides 90 days written notice...", "MEDIUM"),
        ("SLA Performance Standards",         "Service_Level",   "Service",    "Service provider guarantees 99.9% uptime. Compensation of 10% monthly fee per hour of excess downtime...", "HIGH"),
    ]
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM clauses")
        if cur.fetchone()["cnt"] > 0:
            conn.close()
            return
        for title, ctype, cat, content, risk in clauses:
            cur.execute(
                "INSERT INTO clauses (title, clause_type, category, content, risk_level) VALUES (%s,%s,%s,%s,%s)",
                (title, ctype, cat, content, risk)
            )
        conn.commit()
        logger.info("Clauses seeded.")
    finally:
        conn.close()


def seed_contracts():
    import json
    from datetime import date, timedelta
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM contracts")
        if cur.fetchone()["cnt"] > 0:
            conn.close()
            return
        cur.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
        admin = cur.fetchone()
        cur.execute("SELECT id FROM users WHERE role='contract_manager' LIMIT 1")
        mgr   = cur.fetchone()
        if not admin:
            conn.close()
            return
        admin_id = admin["id"]
        mgr_id   = mgr["id"] if mgr else admin_id
        today = date.today()
        contracts = [
            ("CIP-2026-0001","Microsoft Azure Services Agreement","MSA","ACTIVE","Acme Corp","Microsoft Corp","manager@contract.ai","azure@microsoft.com",180000,"USD",today-timedelta(days=180),today+timedelta(days=185),today+timedelta(days=155),"New York",25,'[]'),
            ("CIP-2026-0002","Salesforce CRM License Renewal","Vendor","REVIEW","Acme Corp","Salesforce Inc","manager@contract.ai","contracts@salesforce.com",48000,"USD",today+timedelta(days=30),today+timedelta(days=395),today+timedelta(days=305),"California",55,'[{"flag":"Price increase clause","severity":"MEDIUM"}]'),
            ("CIP-2026-0003","Employee NDA Engineering Team","NDA","ACTIVE","Acme Corp","Engineering Staff","legal@contract.ai","hr@acme.ai",0,"USD",today-timedelta(days=90),today+timedelta(days=275),None,"New York",10,'[]'),
            ("CIP-2026-0004","Office Lease HQ Building","Lease","ACTIVE","Acme Corp","City Properties LLC","manager@contract.ai","leasing@cityprops.com",240000,"USD",today-timedelta(days=365),today+timedelta(days=730),today+timedelta(days=640),"New York",35,'[{"flag":"Rent escalation clause","severity":"LOW"}]'),
            ("CIP-2026-0005","Marketing Agency SOW Q2 2026","SOW","APPROVAL","Acme Corp","Creative Agency Ltd","manager@contract.ai","contracts@creativeagency.com",85000,"USD",today+timedelta(days=15),today+timedelta(days=105),None,"California",40,'[{"flag":"IP ownership unclear","severity":"HIGH"}]'),
            ("CIP-2026-0006","AWS Enterprise Support Agreement","MSA","DRAFT","Acme Corp","Amazon Web Services","legal@contract.ai","enterprise@aws.com",96000,"USD",today+timedelta(days=60),today+timedelta(days=425),today+timedelta(days=335),"Washington",0,'[]'),
            ("CIP-2026-0007","HR Consulting Services Agreement","Employment","EXECUTION","Acme Corp","HR Consulting Partners","manager@contract.ai","info@hrconsult.com",36000,"USD",today+timedelta(days=1),today+timedelta(days=181),None,"New York",20,'[]'),
        ]
        for c in contracts:
            cur.execute("""
                INSERT INTO contracts (contract_number,title,contract_type,status,party_a_name,party_b_name,
                  party_a_email,party_b_email,value,currency,start_date,end_date,renewal_date,
                  jurisdiction,risk_score,risk_flags,created_by,owner_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
            """, (*c, admin_id, mgr_id))
            cid = cur.fetchone()["id"]
            # Seed an obligation for each contract
            cur.execute("""
                INSERT INTO obligations (contract_id, obligation_type, description, owner_email, due_date, status, priority)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
            """, (cid, "RENEWAL", f"Review and action renewal for {c[1]}", c[7],
                  c[11] if c[11] else today+timedelta(days=90), "PENDING", "HIGH"))
        conn.commit()
        logger.info("Sample contracts seeded.")
    finally:
        conn.close()


def log_audit(user_id, session_id, contract_id, intent_key, agent_used, mcp_tool,
              user_message, agent_response, duration_ms=0, status="success"):
    try:
        execute("""
            INSERT INTO audit_log
              (user_id,session_id,contract_id,intent_key,agent_used,mcp_tool,
               user_message,agent_response,duration_ms,status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (user_id, session_id, contract_id, intent_key, agent_used, mcp_tool,
              user_message, str(agent_response)[:4000], duration_ms, status))
    except Exception as e:
        logger.warning("Audit log write failed: %s", e)


def init_db():
    create_database_if_not_exists()
    create_schema()
    seed_users()
    seed_templates()
    seed_clauses()
    seed_contracts()
    logger.info("Database initialised successfully.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    print("Done.")
