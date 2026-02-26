"""mcp_servers/comms_server.py — Candidate Communications Agent (port 8006 · 7 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import (
    send_application_confirmation, send_status_update,
    send_interview_invitation, send_rejection_email,
    send_offer_email, send_bulk_update
)

mcp = FastMCP("CommsServer", host="127.0.0.1", port=8006, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _log_comm(cur, candidate_id: int, comm_type: str, subject: str, preview: str, sent_by: str):
    cur.execute("""INSERT INTO communications (candidate_id, type, subject, body_preview, sent_by)
                   VALUES (%s,%s,%s,%s,%s)""", (candidate_id, comm_type, subject, preview, sent_by))


@mcp.tool()
def send_application_confirmation_email(candidate_id: int, sent_by: str = "system") -> dict:
    """Send application receipt confirmation to a candidate."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT c.name, c.email, j.title, c.job_id FROM candidates c
                   JOIN jobs j ON c.job_id=j.id WHERE c.id=%s""", (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    result = send_application_confirmation(row["name"], row["email"], row["title"], row["job_id"])
    _log_comm(cur, candidate_id, "application_confirmation",
              f"Application Received – {row['title']}", "Thank you for applying.", sent_by)
    conn.commit(); conn.close()
    return {"success": True, "email_result": result, "candidate": row["name"],
            "message": f"Application confirmation sent to {row['email']}."}


@mcp.tool()
def send_candidate_status_update(candidate_id: int, new_status: str,
                                  custom_message: str = "", sent_by: str = "system") -> dict:
    """Send a status update notification email to a candidate."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT c.name, c.email, j.title FROM candidates c
                   JOIN jobs j ON c.job_id=j.id WHERE c.id=%s""", (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    result = send_status_update(row["name"], row["email"], row["title"], new_status, custom_message)
    _log_comm(cur, candidate_id, "status_update",
              f"Status Update – {new_status.replace('_',' ').title()}", custom_message or new_status, sent_by)
    conn.commit(); conn.close()
    return {"success": True, "email_result": result, "candidate": row["name"],
            "message": f"Status update ({new_status}) sent to {row['email']}."}


@mcp.tool()
def send_interview_invite(candidate_id: int, interview_id: int, sent_by: str = "recruiter") -> dict:
    """Send an interview invitation email using an existing interview record."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT i.*, c.name as candidate_name, c.email as candidate_email,
                          j.title as job_title
                   FROM interviews i JOIN candidates c ON i.candidate_id=c.id
                   JOIN jobs j ON i.job_id=j.id
                   WHERE i.id=%s AND i.candidate_id=%s""", (interview_id, candidate_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Interview #{interview_id} not found for candidate #{candidate_id}."}
    result = send_interview_invitation(
        row["candidate_name"], row["candidate_email"], row["job_title"],
        str(row["scheduled_at"])[:16], row["duration_mins"], row["type"],
        row["round"], row["interviewer_name"], row["meeting_link"]
    )
    _log_comm(cur, candidate_id, "interview_invitation",
              f"Interview Invitation – Round {row['round']}", f"Scheduled: {str(row['scheduled_at'])[:16]}", sent_by)
    conn.commit(); conn.close()
    return {"success": True, "email_result": result,
            "message": f"Interview invitation re-sent to {row['candidate_email']}."}


@mcp.tool()
def send_rejection(candidate_id: int, feedback: str = "", sent_by: str = "recruiter") -> dict:
    """Send a professional rejection email to a candidate."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT c.name, c.email, j.title FROM candidates c
                   JOIN jobs j ON c.job_id=j.id WHERE c.id=%s""", (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    result = send_rejection_email(row["name"], row["email"], row["title"], feedback)
    _log_comm(cur, candidate_id, "rejection",
              f"Application Update – {row['title']}", f"Rejection sent. Feedback: {feedback}", sent_by)
    conn.commit(); conn.close()
    return {"success": True, "email_result": result, "candidate": row["name"],
            "message": f"Rejection email sent to {row['email']}."}


@mcp.tool()
def send_offer_notification(candidate_id: int, offer_id: int, sent_by: str = "hr_manager") -> dict:
    """Send the offer letter email to a candidate using an existing offer record."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT o.*, c.name, c.email, j.title as job_title
                   FROM offers o JOIN candidates c ON o.candidate_id=c.id
                   JOIN jobs j ON o.job_id=j.id WHERE o.id=%s AND o.candidate_id=%s""",
                (offer_id, candidate_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} not found for candidate #{candidate_id}."}
    result = send_offer_email(
        row["name"], row["email"], row["job_title"],
        float(row["salary"]), row["currency"],
        str(row["start_date"])[:10], row["benefits"] or "", row["equity"] or ""
    )
    _log_comm(cur, candidate_id, "offer", f"Offer Letter – {row['job_title']}", "Offer extended.", sent_by)
    conn.commit(); conn.close()
    return {"success": True, "email_result": result, "candidate": row["name"],
            "message": f"Offer notification sent to {row['email']}."}


@mcp.tool()
def send_bulk_status_update(job_id: int, subject: str, message: str, sent_by: str = "hr") -> dict:
    """Send a bulk email update to all candidates who applied to a specific job."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT id, name, email FROM candidates
                   WHERE job_id=%s AND status NOT IN ('hired','rejected')""", (job_id,))
    candidates = [dict(r) for r in cur.fetchall()]
    if not candidates:
        conn.close()
        return {"success": False, "message": f"No active candidates for job #{job_id}."}
    result = send_bulk_update(candidates, subject, message)
    for c in candidates:
        _log_comm(cur, c["id"], "bulk_update", subject, message[:100], sent_by)
    conn.commit(); conn.close()
    return {"success": True, "result": result,
            "message": f"Bulk email sent to {result['sent']} candidates for job #{job_id}."}


@mcp.tool()
def get_communication_history(candidate_id: int) -> list:
    """Retrieve full email communication log for a candidate."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""SELECT id, type, subject, body_preview, sent_at, sent_by, status
                   FROM communications WHERE candidate_id=%s ORDER BY sent_at DESC""", (candidate_id,))
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["sent_at"] = str(d["sent_at"])[:16] if d.get("sent_at") else None
        result.append(d)
    return result if result else [{"message": f"No communications found for candidate #{candidate_id}."}]


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()