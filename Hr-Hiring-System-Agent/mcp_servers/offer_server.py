"""mcp_servers/offer_server.py — Offer Management Agent (port 8004 · 7 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_offer_email, send_status_update

mcp = FastMCP("OfferServer", host="127.0.0.1", port=8004, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def generate_offer(candidate_id: int, job_id: int, salary: float, currency: str,
                    start_date: str, benefits: str, equity: str, created_by: str) -> dict:
    """
    Create a new offer record in draft/pending_approval state.
    salary is annual figure. start_date format: YYYY-MM-DD.
    """
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s AND c.job_id=%s
    """, (candidate_id, job_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found for job #{job_id}."}
    cur.execute("""
        INSERT INTO offers (candidate_id, job_id, salary, currency, start_date,
                            benefits, equity, status, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,'pending_approval',%s) RETURNING id
    """, (candidate_id, job_id, salary, currency, start_date, benefits, equity, created_by))
    oid = cur.fetchone()["id"]
    cur.execute("UPDATE candidates SET status='offer', updated_at=NOW() WHERE id=%s", (candidate_id,))
    conn.commit(); conn.close()
    return {"success": True, "offer_id": oid, "candidate": row["name"],
            "job_title": row["job_title"], "salary": salary, "currency": currency,
            "status": "pending_approval",
            "message": f"Offer #{oid} created for {row['name']}. Awaiting HR Manager approval."}


@mcp.tool()
def get_offer_details(offer_id: int) -> dict:
    """Get full offer letter details including approval status."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.*, c.name as candidate_name, c.email as candidate_email, j.title as job_title
        FROM offers o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.id=%s
    """, (offer_id,))
    row = cur.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Offer #{offer_id} not found."}
    d = dict(row)
    d["salary"] = float(d["salary"]) if d.get("salary") else 0
    for k in ("created_at","approved_at","sent_at","response_at","start_date"):
        if d.get(k): d[k] = str(d[k])[:16]
    return {**d, "found": True}


@mcp.tool()
def list_offers_by_status(status: str = "all") -> list:
    """List offers filtered by status: draft/pending_approval/approved/sent/accepted/declined/expired/all."""
    conn = get_connection(); cur = _cur(conn)
    q = """SELECT o.id, o.status, o.salary, o.currency, o.start_date, o.created_at,
                  c.name as candidate_name, j.title as job_title
           FROM offers o JOIN candidates c ON o.candidate_id=c.id
           JOIN jobs j ON o.job_id=j.id"""
    params = []
    if status != "all":
        q += " WHERE o.status=%s"; params.append(status)
    q += " ORDER BY o.created_at DESC"
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["salary"] = float(d["salary"]) if d.get("salary") else 0
        for k in ("created_at","start_date"):
            if d.get(k): d[k] = str(d[k])[:10]
        result.append(d)
    return result if result else [{"message": f"No offers found with status '{status}'."}]


@mcp.tool()
def approve_offer(offer_id: int, approved_by: str) -> dict:
    """HR Manager approves an offer. Changes status from pending_approval to approved."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT status FROM offers WHERE id=%s", (offer_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} not found."}
    if row["status"] != "pending_approval":
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} is '{row['status']}' — only 'pending_approval' offers can be approved."}
    cur.execute("""UPDATE offers SET status='approved', approved_by=%s, approved_at=NOW()
                   WHERE id=%s""", (approved_by, offer_id))
    conn.commit(); conn.close()
    return {"success": True, "offer_id": offer_id, "approved_by": approved_by,
            "message": f"Offer #{offer_id} approved by {approved_by}. Ready to send to candidate."}


@mcp.tool()
def send_offer_to_candidate(offer_id: int, sent_by: str) -> dict:
    """Send an approved offer letter to the candidate via email."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.*, c.name as candidate_name, c.email as candidate_email, j.title as job_title
        FROM offers o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.id=%s
    """, (offer_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} not found."}
    if row["status"] not in ("approved", "sent"):
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} must be 'approved' before sending. Current: {row['status']}"}
    cur.execute("UPDATE offers SET status='sent', sent_at=NOW() WHERE id=%s", (offer_id,))
    conn.commit(); conn.close()
    result = send_offer_email(
        row["candidate_name"], row["candidate_email"], row["job_title"],
        float(row["salary"]), row["currency"], str(row["start_date"])[:10],
        row["benefits"] or "", row["equity"] or ""
    )
    return {"success": True, "offer_id": offer_id, "candidate": row["candidate_name"],
            "email_result": result,
            "message": f"Offer #{offer_id} sent to {row['candidate_email']}."}


@mcp.tool()
def record_offer_response(offer_id: int, response: str, decline_reason: str = "") -> dict:
    """
    Record candidate's response to an offer.
    response: accepted / declined
    """
    if response not in ("accepted", "declined"):
        return {"success": False, "message": "Response must be 'accepted' or 'declined'."}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.candidate_id, c.name, c.email, j.title as job_title
        FROM offers o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.id=%s
    """, (offer_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Offer #{offer_id} not found."}
    cur.execute("""UPDATE offers SET status=%s, response_at=NOW(), decline_reason=%s
                   WHERE id=%s""", (response, decline_reason, offer_id))
    new_status = "hired" if response == "accepted" else "rejected"
    cur.execute("UPDATE candidates SET status=%s, updated_at=NOW() WHERE id=%s",
                (new_status, row["candidate_id"]))
    conn.commit(); conn.close()
    return {"success": True, "offer_id": offer_id, "response": response,
            "candidate": row["name"], "candidate_status_updated": new_status,
            "message": f"{row['name']} has {response} the offer for {row['job_title']}."}


@mcp.tool()
def get_offer_analytics() -> dict:
    """Offer acceptance rate, avg. days-to-decision, and declined reasons summary."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT
            COUNT(*) FILTER (WHERE status='sent')     as sent,
            COUNT(*) FILTER (WHERE status='accepted') as accepted,
            COUNT(*) FILTER (WHERE status='declined') as declined,
            COUNT(*) FILTER (WHERE status='expired')  as expired,
            AVG(EXTRACT(EPOCH FROM (response_at - sent_at))/86400)
              FILTER (WHERE response_at IS NOT NULL AND sent_at IS NOT NULL) as avg_days_to_decision
        FROM offers
    """)
    row = dict(cur.fetchone())
    cur.execute("SELECT decline_reason, COUNT(*) as cnt FROM offers WHERE status='declined' AND decline_reason != '' GROUP BY decline_reason ORDER BY cnt DESC LIMIT 5")
    reasons = [dict(r) for r in cur.fetchall()]
    conn.close()
    sent = row.get("sent") or 0
    accepted = row.get("accepted") or 0
    acceptance_rate = round((accepted / sent * 100), 1) if sent > 0 else 0
    return {
        "offers_sent":      sent,
        "accepted":         accepted,
        "declined":         row.get("declined") or 0,
        "expired":          row.get("expired") or 0,
        "acceptance_rate_pct": acceptance_rate,
        "avg_days_to_decision": round(float(row.get("avg_days_to_decision") or 0), 1),
        "top_decline_reasons": reasons,
    }


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()