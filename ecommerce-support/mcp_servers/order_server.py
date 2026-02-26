"""mcp_servers/order_server.py — Order Tracking & Management tools (port 8001)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_order_status_email

mcp = FastMCP("OrderServer", host="127.0.0.1", port=8001,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def list_customer_orders(customer_email: str) -> list:
    """List all orders for a customer with their current status."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, status, total_amount, tracking_number, carrier, created_at, shipped_at, delivered_at
        FROM orders WHERE customer_email=%s ORDER BY created_at DESC
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No orders found for '{customer_email}'."}]
    return [{**dict(r), "total_amount": float(r["total_amount"]),
             "created_at": str(r["created_at"])[:16],
             "shipped_at": str(r["shipped_at"])[:16] if r["shipped_at"] else None,
             "delivered_at": str(r["delivered_at"])[:16] if r["delivered_at"] else None
             } for r in rows]


@mcp.tool()
def get_order_details(order_id: int) -> dict:
    """Get full details of a specific order including all items."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT o.*, cu.name as customer_name FROM orders o
        JOIN customers cu ON o.customer_email=cu.email
        WHERE o.id=%s
    """, (order_id,))
    order = c.fetchone()
    if not order:
        conn.close()
        return {"found": False, "message": f"Order #{order_id} not found."}
    c.execute("""
        SELECT p.name, p.sku, p.brand, oi.quantity, oi.unit_price, oi.subtotal
        FROM order_items oi JOIN products p ON oi.product_id=p.id
        WHERE oi.order_id=%s
    """, (order_id,))
    items = [dict(r) for r in c.fetchall()]
    conn.close()
    d = dict(order)
    d["total_amount"] = float(d["total_amount"])
    d["created_at"]   = str(d["created_at"])[:16]
    d["shipped_at"]   = str(d["shipped_at"])[:16] if d["shipped_at"] else None
    d["delivered_at"] = str(d["delivered_at"])[:16] if d["delivered_at"] else None
    for i in items:
        i["unit_price"] = float(i["unit_price"])
        i["subtotal"]   = float(i["subtotal"])
    return {"found": True, "order": d, "items": items}


@mcp.tool()
def get_order_status(order_id: int) -> dict:
    """Get the current status and tracking information for an order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status, tracking_number, carrier, shipped_at, delivered_at FROM orders WHERE id=%s", (order_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Order #{order_id} not found."}
    status_messages = {
        "processing":        "Your order is being prepared.",
        "shipped":           "Your order is on its way!",
        "out_for_delivery":  "Your order is out for delivery today!",
        "delivered":         "Your order has been delivered.",
        "cancelled":         "This order has been cancelled.",
    }
    return {
        "found": True, "order_id": order_id,
        "status": row["status"], "message": status_messages.get(row["status"], row["status"]),
        "tracking_number": row["tracking_number"], "carrier": row["carrier"],
        "shipped_at":   str(row["shipped_at"])[:16]   if row["shipped_at"]   else None,
        "delivered_at": str(row["delivered_at"])[:16] if row["delivered_at"] else None,
    }


@mcp.tool()
def get_delivery_estimate(order_id: int) -> dict:
    """Get the estimated delivery date for a shipped order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status, shipped_at, carrier, delivered_at FROM orders WHERE id=%s", (order_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Order #{order_id} not found."}
    if row["status"] == "delivered":
        return {"status": "delivered", "delivered_at": str(row["delivered_at"])[:16],
                "message": "This order has already been delivered."}
    if row["status"] == "processing":
        return {"status": "processing", "message": "Order is still being prepared. Will ship within 1–2 business days."}
    if row["status"] == "out_for_delivery":
        return {"status": "out_for_delivery", "message": "Out for delivery today — expected by 8 PM."}
    if row["shipped_at"]:
        from datetime import datetime, timedelta
        eta = datetime.fromisoformat(str(row["shipped_at"])) + timedelta(days=3)
        return {"status": "shipped", "carrier": row["carrier"],
                "estimated_delivery": str(eta.date()),
                "message": f"Expected delivery by {str(eta.date())} via {row['carrier']}."}
    return {"status": row["status"], "message": "Delivery estimate not available yet."}


@mcp.tool()
def cancel_order(order_id: int, customer_email: str) -> dict:
    """Cancel an order that has not yet been shipped."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status, customer_email FROM orders WHERE id=%s", (order_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} not found."}
    if row["customer_email"] != customer_email:
        conn.close()
        return {"status": "error", "message": "This order does not belong to this email address."}
    if row["status"] in ("shipped", "out_for_delivery", "delivered"):
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} cannot be cancelled — it is already '{row['status']}'."}
    if row["status"] == "cancelled":
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} is already cancelled."}
    c.execute("UPDATE orders SET status='cancelled' WHERE id=%s", (order_id,))
    conn.commit(); conn.close()
    return {"status": "cancelled", "order_id": order_id,
            "message": f"[OK] Order #{order_id} has been cancelled. Refund will be processed within 3–5 business days."}


@mcp.tool()
def update_shipping_address(order_id: int, customer_email: str, new_address: str) -> dict:
    """Update the shipping address for an unshipped order."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT status, customer_email FROM orders WHERE id=%s", (order_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Order #{order_id} not found."}
    if row["customer_email"] != customer_email:
        conn.close()
        return {"status": "error", "message": "Unauthorised — email does not match this order."}
    if row["status"] not in ("processing",):
        conn.close()
        return {"status": "error", "message": f"Cannot update address — order is already '{row['status']}'."}
    c.execute("UPDATE orders SET shipping_address=%s WHERE id=%s", (new_address, order_id))
    conn.commit(); conn.close()
    return {"status": "updated", "message": f"[OK] Shipping address updated for Order #{order_id}."}


@mcp.tool()
def send_order_update_email(order_id: int, customer_email: str) -> dict:
    """Send the latest order status email to the customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT o.status, o.tracking_number, o.carrier, cu.name FROM orders o JOIN customers cu ON o.customer_email=cu.email WHERE o.id=%s AND o.customer_email=%s", (order_id, customer_email))
    row = c.fetchone(); conn.close()
    if not row:
        return {"status": "error", "message": f"Order #{order_id} not found for '{customer_email}'."}
    r = send_order_status_email(row["name"], customer_email, order_id, row["status"], row["tracking_number"], row["carrier"])
    return {"status": "sent" if r["success"] else "failed", "message": r["message"]}


if __name__ == "__main__":
    init_db()
    print("[RUN] Order MCP Server on http://127.0.0.1:8001/mcp")
    mcp.run(transport="streamable-http")