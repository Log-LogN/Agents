"""Draft Agent tools — contract creation, templates, clauses."""
import json, random, logging
from datetime import datetime
logger = logging.getLogger(__name__)

def _next_contract_number() -> str:
    try:
        from database.db import fetch_one
        row = fetch_one("SELECT COUNT(*) AS cnt FROM contracts")
        n = (row["cnt"] if row else 0) + 1
        return f"CIP-{datetime.utcnow().year}-{n:04d}"
    except Exception:
        return f"CIP-{datetime.utcnow().year}-{random.randint(1000,9999)}"

def create_contract(contract_type: str, title: str, party_a: str, party_b: str,
                    party_a_email: str = "", party_b_email: str = "",
                    value: float = 0, currency: str = "USD",
                    jurisdiction: str = "New York", user_id: int = 1) -> dict:
    number = _next_contract_number()
    content = f"""CONTRACT AGREEMENT
Contract Number: {number}
Type: {contract_type}
Title: {title}

PARTIES:
Party A: {party_a} ({party_a_email})
Party B: {party_b} ({party_b_email})

CONTRACT VALUE: {currency} {value:,.2f}
JURISDICTION: {jurisdiction}

This agreement is entered into on {datetime.utcnow().strftime('%B %d, %Y')}.

[Standard terms and conditions apply. Legal review recommended before execution.]
"""
    try:
        from database.db import execute
        row = execute("""
            INSERT INTO contracts (contract_number,title,contract_type,status,party_a_name,party_b_name,
              party_a_email,party_b_email,value,currency,jurisdiction,content,created_by,owner_id)
            VALUES (%s,%s,%s,'DRAFT',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (number,title,contract_type,party_a,party_b,party_a_email,party_b_email,
              value,currency,jurisdiction,content,user_id,user_id))
        cid = row["id"] if row else None
        return {"status":"success","contract_id":cid,"contract_number":number,
                "title":title,"contract_type":contract_type,"message":f"Contract {number} created successfully."}
    except Exception as e:
        logger.error("create_contract error: %s", e)
        return {"status":"success","contract_number":number,"title":title,
                "contract_type":contract_type,"message":f"Contract {number} drafted (DB offline)."}

def get_templates(contract_type: str = "") -> dict:
    try:
        from database.db import fetch_all
        if contract_type:
            rows = fetch_all("SELECT id,name,contract_type FROM templates WHERE contract_type ILIKE %s AND is_active=TRUE", (f"%{contract_type}%",))
        else:
            rows = fetch_all("SELECT id,name,contract_type FROM templates WHERE is_active=TRUE")
        return {"status":"success","templates":[dict(r) for r in rows],"count":len(rows)}
    except Exception as e:
        return {"status":"error","message":str(e),"templates":[]}

def get_clause_library(category: str = "") -> dict:
    try:
        from database.db import fetch_all
        if category:
            rows = fetch_all("SELECT id,title,clause_type,category,risk_level FROM clauses WHERE category ILIKE %s", (f"%{category}%",))
        else:
            rows = fetch_all("SELECT id,title,clause_type,category,risk_level FROM clauses ORDER BY category")
        return {"status":"success","clauses":[dict(r) for r in rows],"count":len(rows)}
    except Exception as e:
        return {"status":"error","message":str(e),"clauses":[]}

def update_contract(contract_id: int, field: str, value: str) -> dict:
    allowed = {"title","status","party_b_name","party_b_email","value","end_date","content","jurisdiction"}
    if field not in allowed:
        return {"status":"error","message":f"Field '{field}' cannot be updated via this tool."}
    try:
        from database.db import execute
        execute(f"UPDATE contracts SET {field}=%s, updated_at=NOW() WHERE id=%s", (value, contract_id))
        return {"status":"success","message":f"Contract {contract_id} field '{field}' updated."}
    except Exception as e:
        return {"status":"error","message":str(e)}

def save_draft(contract_id: int, version_note: str = "Draft saved", user_id: int = 1) -> dict:
    try:
        from database.db import fetch_one, execute
        contract = fetch_one("SELECT content FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}
        row = fetch_one("SELECT MAX(version_number) AS v FROM contract_versions WHERE contract_id=%s", (contract_id,))
        next_v = (row["v"] or 0) + 1
        execute("INSERT INTO contract_versions (contract_id,version_number,content,changed_by,change_summary) VALUES (%s,%s,%s,%s,%s)",
                (contract_id, next_v, contract["content"], user_id, version_note))
        return {"status":"success","message":f"Draft saved as version {next_v}.","version":next_v}
    except Exception as e:
        return {"status":"error","message":str(e)}
