"""Obligation Agent tools — tracking, renewals, amendments."""
import json, logging
from datetime import datetime, timedelta, date
logger = logging.getLogger(__name__)

def extract_obligations(contract_id: int) -> dict:
    from datetime import date, timedelta
    try:
        from database.db import fetch_one, execute
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        c = dict(contract)
        obligations = [
            {"type": "RENEWAL",     "description": f"Review renewal for {c.get('title','contract')}",        "due_date": str(c.get("renewal_date") or date.today()+timedelta(days=90)), "priority": "HIGH"},
            {"type": "PAYMENT",     "description": "Quarterly payment milestone",                             "due_date": str(date.today()+timedelta(days=30)), "priority": "HIGH"},
            {"type": "COMPLIANCE",  "description": "Annual compliance certification required",                "due_date": str(date.today()+timedelta(days=60)), "priority": "MEDIUM"},
            {"type": "REPORT",      "description": "Quarterly performance report due to counterparty",       "due_date": str(date.today()+timedelta(days=45)), "priority": "MEDIUM"},
        ]
        created = []
        for o in obligations:
            row = execute("""
                INSERT INTO obligations (contract_id, obligation_type, description, owner_email, due_date, priority)
                VALUES (%s,%s,%s,%s,%s,%s) RETURNING id
            """, (contract_id, o["type"], o["description"], c.get("party_a_email",""), o["due_date"], o["priority"]))
            o["id"] = row["id"] if row else None
            created.append(o)
        return {"status": "success", "contract_id": contract_id, "obligations_created": len(created), "obligations": created}
    except Exception as e:
        logger.error("extract_obligations: %s", e)
        return {"status": "error", "message": str(e)}

def get_obligations(contract_id: int = 0, status: str = "") -> dict:
    try:
        from database.db import fetch_all
        if contract_id and status:
            rows = fetch_all("SELECT * FROM obligations WHERE contract_id=%s AND status=%s ORDER BY due_date", (contract_id, status.upper()))
        elif contract_id:
            rows = fetch_all("SELECT * FROM obligations WHERE contract_id=%s ORDER BY due_date", (contract_id,))
        elif status:
            rows = fetch_all("SELECT * FROM obligations WHERE status=%s ORDER BY due_date", (status.upper(),))
        else:
            rows = fetch_all("SELECT * FROM obligations ORDER BY due_date LIMIT 50")
        return {"status": "success", "obligations": [dict(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"status": "error", "message": str(e), "obligations": []}

def update_obligation_status(obligation_id: int, new_status: str) -> dict:
    try:
        from database.db import execute
        completed_at = "NOW()" if new_status.upper() == "COMPLETED" else "NULL"
        execute(f"UPDATE obligations SET status=%s, completed_at={'NOW()' if new_status.upper()=='COMPLETED' else 'NULL'} WHERE id=%s",
                (new_status.upper(), obligation_id))
        return {"status": "success", "obligation_id": obligation_id, "new_status": new_status.upper(),
                "message": f"Obligation {obligation_id} updated to {new_status.upper()}."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_upcoming_deadlines(days_ahead: int = 30) -> dict:
    try:
        from database.db import fetch_all
        cutoff = date.today() + timedelta(days=days_ahead)
        rows = fetch_all("""
            SELECT o.*, c.title as contract_title, c.contract_number
            FROM obligations o JOIN contracts c ON c.id=o.contract_id
            WHERE o.due_date <= %s AND o.status IN ('PENDING','IN_PROGRESS')
            ORDER BY o.due_date ASC
        """, (cutoff,))
        return {"status": "success", "days_ahead": days_ahead, "deadlines": [dict(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"status": "error", "message": str(e), "deadlines": []}

def create_renewal_alert(contract_id: int, notice_days: int = 90) -> dict:
    try:
        from database.db import fetch_one, execute
        contract = fetch_one("SELECT title, end_date, renewal_date FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        alert_date = contract["renewal_date"] or (contract["end_date"] - timedelta(days=notice_days) if contract["end_date"] else date.today()+timedelta(days=60))
        execute("""
            INSERT INTO obligations (contract_id, obligation_type, description, due_date, priority)
            VALUES (%s,'RENEWAL',%s,%s,'HIGH')
        """, (contract_id, f"Renewal action required for {contract['title']} — {notice_days}-day notice", alert_date))
        return {"status": "success", "contract_id": contract_id, "alert_date": str(alert_date),
                "message": f"Renewal alert set for {alert_date} ({notice_days} days notice)."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def process_amendment(contract_id: int, changes: str) -> dict:
    try:
        from database.db import execute, fetch_one
        contract = fetch_one("SELECT content FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        amendment_note = f"\n\n--- AMENDMENT {datetime.utcnow().strftime('%Y-%m-%d')} ---\n{changes}\n"
        new_content = (contract.get("content") or "") + amendment_note
        execute("UPDATE contracts SET content=%s, status='AMENDED', updated_at=NOW() WHERE id=%s", (new_content, contract_id))
        return {"status": "success", "contract_id": contract_id, "new_status": "AMENDED",
                "message": f"Amendment recorded for contract {contract_id}.", "changes": changes}
    except Exception as e:
        return {"status": "error", "message": str(e)}
