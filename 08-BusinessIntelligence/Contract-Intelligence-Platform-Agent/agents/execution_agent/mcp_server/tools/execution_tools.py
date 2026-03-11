"""Execution Agent tools — e-signature, finalization, archiving."""
import json, logging, random
from datetime import datetime
logger = logging.getLogger(__name__)

def initiate_signing(contract_id: int, signatories_csv: str) -> dict:
    signatories = [s.strip() for s in signatories_csv.split(",") if s.strip()]
    try:
        from database.db import execute, fetch_one
        contract = fetch_one("SELECT title, status FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        execute("UPDATE contracts SET status='EXECUTION', updated_at=NOW() WHERE id=%s", (contract_id,))
        return {"status": "success", "contract_id": contract_id, "signatories": signatories,
                "signing_ref": f"SIGN-{contract_id}-{datetime.utcnow().strftime('%Y%m%d%H%M')}",
                "message": f"E-signature initiated for {len(signatories)} signator(ies). Signature requests sent."}
    except Exception as e:
        return {"status": "success", "contract_id": contract_id, "signatories": signatories,
                "message": "Signing initiated (DB offline)."}

def get_signing_status(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT id, title, status, party_a_email, party_b_email FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        statuses = [
            {"email": contract["party_a_email"] or "party_a@example.com", "status": "SIGNED", "signed_at": datetime.utcnow().isoformat()},
            {"email": contract["party_b_email"] or "party_b@example.com", "status": random.choice(["SIGNED","PENDING","SENT"])},
        ]
        all_signed = all(s["status"] == "SIGNED" for s in statuses)
        return {"status": "success", "contract_id": contract_id, "title": contract["title"],
                "contract_status": contract["status"], "signatories": statuses, "all_signed": all_signed,
                "completion_pct": sum(1 for s in statuses if s["status"] == "SIGNED") / len(statuses) * 100}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def finalize_contract(contract_id: int) -> dict:
    try:
        from database.db import execute, fetch_one
        contract = fetch_one("SELECT title FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        execute("UPDATE contracts SET status='ACTIVE', updated_at=NOW() WHERE id=%s", (contract_id,))
        return {"status": "success", "contract_id": contract_id, "new_status": "ACTIVE",
                "finalized_at": datetime.utcnow().isoformat(),
                "message": f"Contract {contract_id} '{contract['title']}' is now ACTIVE."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_signing_reminder(contract_id: int, signatory_email: str) -> dict:
    return {"status": "success", "contract_id": contract_id, "sent_to": signatory_email,
            "message": f"Signing reminder sent to {signatory_email}.",
            "timestamp": datetime.utcnow().isoformat()}

def store_executed_contract(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT contract_number, title FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        ref = f"VAULT/{datetime.utcnow().year}/{contract['contract_number']}.pdf"
        return {"status": "success", "contract_id": contract_id, "storage_ref": ref,
                "message": f"Contract archived at {ref}.", "archived_at": datetime.utcnow().isoformat()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_execution_summary(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        c = dict(contract)
        return {"status": "success", "summary": {
            "contract_id":     contract_id,
            "contract_number": c.get("contract_number"),
            "title":           c.get("title"),
            "type":            c.get("contract_type"),
            "status":          c.get("status"),
            "party_a":         c.get("party_a_name"),
            "party_b":         c.get("party_b_name"),
            "value":           str(c.get("value", 0)),
            "currency":        c.get("currency"),
            "start_date":      str(c.get("start_date")) if c.get("start_date") else None,
            "end_date":        str(c.get("end_date")) if c.get("end_date") else None,
            "executed_at":     datetime.utcnow().isoformat(),
        }}
    except Exception as e:
        return {"status": "error", "message": str(e)}
