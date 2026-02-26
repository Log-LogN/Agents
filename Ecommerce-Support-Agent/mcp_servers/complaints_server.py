"""mcp_servers/complaints_server.py — Reviews & Complaints tools (port 8005)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_complaint_email

mcp = FastMCP("ComplaintsServer", host="127.0.0.1", port=8005,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def submit_complaint(customer_email: str, order_id: int, complaint_type: str,
                     description: str, priority: str = "medium") -> dict:
    """
    Submit a customer complaint.
    complaint_type: product_defect | late_delivery | wrong_item | billing_issue | out_of_stock | return_rejected | other
    priority: low | medium | high | urgent
    Sends confirmation email automatically.
    """
    valid_types     = ("product_defect","late_delivery","wrong_item","billing_issue","out_of_stock","return_rejected","other")
    valid_priorities= ("low","medium","high","urgent")
    if complaint_type not in valid_types:
        return {"status": "error", "message": f"Invalid type. Choose: {valid_types}"}
    if priority not in valid_priorities:
        return {"status": "error", "message": f"Invalid priority. Choose: {valid_priorities}"}
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM customers WHERE email=%s", (customer_email,))
    cust = c.fetchone()
    if not cust:
        conn.close()
        return {"status": "error", "message": f"Customer '{customer_email}' not registered."}
    # Auto-escalate urgent/high
    escalated = priority in ("urgent",)
    c.execute("""
        INSERT INTO complaints(customer_email,order_id,type,description,status,priority,escalated)
        VALUES(%s,%s,%s,%s,'open',%s,%s) RETURNING id
    """, (customer_email, order_id, complaint_type, description, priority, escalated))
    cid = c.fetchone()["id"]
    conn.commit(); conn.close()
    send_complaint_email(cust["name"], customer_email, cid, complaint_type, priority)
    return {"status": "submitted", "complaint_id": cid,
            "escalated": escalated,
            "message": f"[OK] Complaint #{cid} filed ({'ESCALATED to senior team — ' if escalated else ''}response in {'1 hour' if priority == 'urgent' else '4 hours' if priority == 'high' else '24 hours'}). ✉️ Confirmation sent."}


@mcp.tool()
def get_complaint_status(customer_email: str) -> list:
    """Get all complaints filed by a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, order_id, type, description, status, priority, escalated, resolution, created_at, resolved_at
        FROM complaints WHERE customer_email=%s ORDER BY created_at DESC
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No complaints found for '{customer_email}'."}]
    return [{**dict(r), "created_at": str(r["created_at"])[:16],
             "resolved_at": str(r["resolved_at"])[:16] if r["resolved_at"] else None} for r in rows]


@mcp.tool()
def update_complaint_status(complaint_id: int, new_status: str, resolution: str = "") -> dict:
    """
    Update a complaint's status.
    new_status: open | in_progress | resolved | closed
    """
    valid = ("open","in_progress","resolved","closed")
    if new_status not in valid:
        return {"status": "error", "message": f"Invalid status. Choose: {valid}"}
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id FROM complaints WHERE id=%s", (complaint_id,))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": f"Complaint #{complaint_id} not found."}
    resolved_at = "NOW()" if new_status in ("resolved","closed") else "NULL"
    c.execute(f"UPDATE complaints SET status=%s, resolution=%s, resolved_at={'NOW()' if new_status in ('resolved','closed') else 'resolved_at'} WHERE id=%s",
              (new_status, resolution or None, complaint_id))
    conn.commit(); conn.close()
    return {"status": "updated", "complaint_id": complaint_id, "new_status": new_status,
            "message": f"[OK] Complaint #{complaint_id} status → '{new_status}'."}


@mcp.tool()
def request_replacement(customer_email: str, order_id: int, reason: str) -> dict:
    """
    Request a product replacement instead of a refund.
    Creates a replacement order and complaint record.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status FROM orders WHERE id=%s AND customer_email=%s", (order_id, customer_email))
    order = c.fetchone()
    if not order:
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} not found for '{customer_email}'."}
    if order["status"] not in ("delivered",):
        conn.close()
        return {"status": "error", "message": "Replacements are only available for delivered orders."}
    c.execute("SELECT name FROM customers WHERE email=%s", (customer_email,))
    cust = c.fetchone()
    c.execute("""
        INSERT INTO complaints(customer_email,order_id,type,description,status,priority)
        VALUES(%s,%s,'product_defect',%s,'in_progress','high') RETURNING id
    """, (customer_email, order_id, f"Replacement request: {reason}"))
    cid = c.fetchone()["id"]
    conn.commit(); conn.close()
    return {"status": "replacement_requested", "complaint_id": cid,
            "message": f"[OK] Replacement request #{cid} filed for Order #{order_id}. A replacement will be dispatched within 2–3 business days after verification."}


@mcp.tool()
def escalate_to_human(complaint_id: int, reason: str) -> dict:
    """Escalate a complaint to a human support agent for manual handling."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id, priority FROM complaints WHERE id=%s", (complaint_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Complaint #{complaint_id} not found."}
    c.execute("UPDATE complaints SET escalated=TRUE, priority='urgent', status='in_progress' WHERE id=%s", (complaint_id,))
    conn.commit(); conn.close()
    return {"status": "escalated", "complaint_id": complaint_id,
            "message": f"[ERROR] Complaint #{complaint_id} escalated to senior human agent. Reason: {reason}. Response within 1 hour."}


@mcp.tool()
def add_review(customer_email: str, product_id: int, order_id: int,
               rating: int, comment: str) -> dict:
    """Submit a product review (rating 1–5)."""
    if not 1 <= rating <= 5:
        return {"status": "error", "message": "Rating must be between 1 and 5."}
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT id FROM orders WHERE id=%s AND customer_email=%s AND status='delivered'", (order_id, customer_email))
    if not c.fetchone():
        conn.close()
        return {"status": "error", "message": "Reviews can only be submitted for delivered orders."}
    c.execute("SELECT id FROM reviews WHERE customer_email=%s AND product_id=%s AND order_id=%s", (customer_email, product_id, order_id))
    if c.fetchone():
        conn.close()
        return {"status": "error", "message": "You have already reviewed this product for this order."}
    c.execute("INSERT INTO reviews(customer_email,product_id,order_id,rating,comment) VALUES(%s,%s,%s,%s,%s) RETURNING id",
              (customer_email, product_id, order_id, rating, comment))
    rid = c.fetchone()["id"]
    # Award loyalty points for review
    points = 50
    c.execute("UPDATE customers SET loyalty_points=loyalty_points+%s WHERE email=%s", (points, customer_email))
    c.execute("INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) SELECT %s,%s,%s,loyalty_points FROM customers WHERE email=%s",
              (customer_email, points, f"Review submitted for product #{product_id}", customer_email))
    conn.commit(); conn.close()
    return {"status": "submitted", "review_id": rid, "rating": rating, "points_earned": points,
            "message": f"[OK] Review submitted! [STARS]{'⭐' * (rating-1)} You earned {points} loyalty points."}


@mcp.tool()
def get_product_reviews(product_id: int) -> dict:
    """Get all reviews for a product with average rating."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name FROM products WHERE id=%s", (product_id,))
    prod = c.fetchone()
    if not prod:
        conn.close()
        return {"found": False, "message": f"Product #{product_id} not found."}
    c.execute("""
        SELECT r.rating, r.comment, r.response, r.created_at, cu.name as reviewer
        FROM reviews r JOIN customers cu ON r.customer_email=cu.email
        WHERE r.product_id=%s ORDER BY r.created_at DESC
    """, (product_id,))
    rows = c.fetchall()
    if not rows:
        conn.close()
        return {"product": prod["name"], "review_count": 0, "average_rating": None, "reviews": []}
    avg = round(sum(r["rating"] for r in rows) / len(rows), 1)
    conn.close()
    return {
        "product": prod["name"], "review_count": len(rows), "average_rating": avg,
        "reviews": [{**dict(r), "created_at": str(r["created_at"])[:10]} for r in rows]
    }


if __name__ == "__main__":
    init_db()
    print("[RUN] Complaints MCP Server on http://127.0.0.1:8005/mcp")
    mcp.run(transport="streamable-http")