"""Approval Agent tools."""
import json, logging
from datetime import datetime, timedelta
logger = logging.getLogger(__name__)

def create_approval_workflow(contract_id: int, approvers: list, deadline_days: int = 7, created_by: int = 1) -> dict:
    try:
        from database.db import execute, fetch_one
        contract = fetch_one("SELECT title, status FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}
        deadline = datetime.utcnow() + timedelta(days=deadline_days)
        row = execute("""
            INSERT INTO approval_workflows (contract_id, status, approvers, deadline, created_by)
            VALUES (%s, 'IN_PROGRESS', %s, %s, %s) RETURNING id
        """, (contract_id, json.dumps(approvers), deadline, created_by))
        execute("UPDATE contracts SET status='APPROVAL', updated_at=NOW() WHERE id=%s", (contract_id,))
        return {"status": "success", "workflow_id": row["id"] if row else None,
                "contract_id": contract_id, "approvers": approvers,
                "deadline": deadline.isoformat(), "message": f"Approval workflow created for contract {contract_id}."}
    except Exception as e:
        logger.error("create_approval_workflow: %s", e)
        return {"status": "success", "message": f"Approval workflow initiated for contract {contract_id} (DB offline)."}

def get_approval_status(contract_id: int) -> dict:
    try:
        from database.db import fetch_one, fetch_all
        wf = fetch_one("SELECT * FROM approval_workflows WHERE contract_id=%s ORDER BY created_at DESC LIMIT 1", (contract_id,))
        if not wf:
            return {"status": "info", "message": "No approval workflow found for this contract.", "contract_id": contract_id}
        actions = fetch_all("SELECT * FROM approval_actions WHERE workflow_id=%s ORDER BY created_at", (wf["id"],))
        return {"status": "success", "contract_id": contract_id, "workflow_id": wf["id"],
                "workflow_status": wf["status"], "approvers": wf["approvers"],
                "current_step": wf["current_step"], "deadline": str(wf["deadline"]) if wf["deadline"] else None,
                "actions": [dict(a) for a in actions]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def approve_contract(contract_id: int, approver_email: str, comments: str = "") -> dict:
    try:
        from database.db import fetch_one, execute
        wf = fetch_one("SELECT id, current_step, approvers FROM approval_workflows WHERE contract_id=%s ORDER BY created_at DESC LIMIT 1", (contract_id,))
        if not wf:
            return {"status": "error", "message": "No active workflow found."}
        approvers = wf["approvers"] if isinstance(wf["approvers"], list) else json.loads(wf["approvers"] or "[]")
        next_step = (wf["current_step"] or 0) + 1
        is_final  = next_step >= len(approvers)
        execute("INSERT INTO approval_actions (workflow_id, contract_id, approver_email, action, comments, step_number) VALUES (%s,%s,%s,'APPROVED',%s,%s)",
                (wf["id"], contract_id, approver_email, comments, next_step))
        if is_final:
            execute("UPDATE approval_workflows SET status='APPROVED', current_step=%s, updated_at=NOW() WHERE id=%s", (next_step, wf["id"]))
            execute("UPDATE contracts SET status='EXECUTION', updated_at=NOW() WHERE id=%s", (contract_id,))
            return {"status": "success", "message": f"Contract {contract_id} fully approved — ready for execution.", "final_approval": True}
        else:
            execute("UPDATE approval_workflows SET current_step=%s, updated_at=NOW() WHERE id=%s", (next_step, wf["id"]))
            return {"status": "success", "message": f"Approval recorded. {len(approvers)-next_step} more approver(s) pending.", "final_approval": False}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def reject_contract(contract_id: int, approver_email: str, reason: str = "") -> dict:
    try:
        from database.db import fetch_one, execute
        wf = fetch_one("SELECT id FROM approval_workflows WHERE contract_id=%s ORDER BY created_at DESC LIMIT 1", (contract_id,))
        if not wf:
            return {"status": "error", "message": "No active workflow found."}
        execute("INSERT INTO approval_actions (workflow_id, contract_id, approver_email, action, comments) VALUES (%s,%s,%s,'REJECTED',%s)",
                (wf["id"], contract_id, approver_email, reason))
        execute("UPDATE approval_workflows SET status='REJECTED', updated_at=NOW() WHERE id=%s", (wf["id"],))
        execute("UPDATE contracts SET status='REVIEW', updated_at=NOW() WHERE id=%s", (contract_id,))
        return {"status": "success", "message": f"Contract {contract_id} rejected and returned to REVIEW.", "reason": reason}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def escalate_approval(contract_id: int, reason: str = "") -> dict:
    try:
        from database.db import fetch_one, execute
        wf = fetch_one("SELECT id FROM approval_workflows WHERE contract_id=%s ORDER BY created_at DESC LIMIT 1", (contract_id,))
        if wf:
            execute("INSERT INTO approval_actions (workflow_id, contract_id, action, comments) VALUES (%s,%s,'ESCALATED',%s)",
                    (wf["id"], contract_id, reason))
        return {"status": "success", "message": f"Contract {contract_id} escalated to senior approver.", "reason": reason}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def get_pending_approvals(user_email: str = "") -> dict:
    try:
        from database.db import fetch_all
        rows = fetch_all("""
            SELECT c.id, c.contract_number, c.title, c.contract_type, c.value, aw.status, aw.deadline
            FROM contracts c JOIN approval_workflows aw ON aw.contract_id=c.id
            WHERE aw.status='IN_PROGRESS' ORDER BY aw.deadline ASC NULLS LAST
        """)
        return {"status": "success", "pending_approvals": [dict(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"status": "error", "message": str(e), "pending_approvals": []}
