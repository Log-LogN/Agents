"""mcp_servers/inventory_server.py — Inventory tools MCP server (port 8003)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("InventoryServer", host="127.0.0.1", port=8003, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

@mcp.tool()
def get_all_stock() -> list:
    """Get all inventory items with current stock levels."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,name,category,quantity,unit,reorder_level,expiry_date,cost_per_unit FROM inventory_items ORDER BY category,name")
    rows = c.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r); d["cost_per_unit"] = float(d["cost_per_unit"])
        d["status"] = "⚠️ LOW" if d["quantity"] <= d["reorder_level"] else "✅ OK"
        d["expiry_date"] = str(d["expiry_date"]) if d["expiry_date"] else None
        result.append(d)
    return result

@mcp.tool()
def get_low_stock_items() -> list:
    """Get items that are at or below their reorder level."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,name,category,quantity,unit,reorder_level FROM inventory_items WHERE quantity<=reorder_level ORDER BY quantity")
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "✅ All items are sufficiently stocked."}]
    return [dict(r) for r in rows]

@mcp.tool()
def check_item_stock(item_name: str) -> dict:
    """Check stock level for a specific item by name."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM inventory_items WHERE LOWER(name) LIKE LOWER(%s)", (f"%{item_name}%",))
    item = c.fetchone(); conn.close()
    if not item: return {"found": False, "message": f"Item '{item_name}' not found in inventory."}
    d = dict(item); d["cost_per_unit"] = float(d["cost_per_unit"])
    d["status"] = "⚠️ LOW — reorder needed" if d["quantity"] <= d["reorder_level"] else "✅ Sufficient stock"
    d["expiry_date"] = str(d["expiry_date"]) if d["expiry_date"] else None
    return {"found": True, **d}

@mcp.tool()
def update_stock(item_name: str, quantity_change: int, operation: str = "add") -> dict:
    """
    Update stock for an item.
    operation: 'add' to add stock, 'subtract' to use/consume stock.
    """
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM inventory_items WHERE LOWER(name) LIKE LOWER(%s)", (f"%{item_name}%",))
    item = c.fetchone()
    if not item: conn.close(); return {"status": "error", "message": f"Item '{item_name}' not found."}
    if operation == "add":
        new_qty = item["quantity"] + quantity_change
    elif operation == "subtract":
        if item["quantity"] < quantity_change:
            conn.close(); return {"status": "error", "message": f"Insufficient stock. Available: {item['quantity']} {item['unit']}."}
        new_qty = item["quantity"] - quantity_change
    else:
        conn.close(); return {"status": "error", "message": "operation must be 'add' or 'subtract'."}
    c.execute("UPDATE inventory_items SET quantity=%s WHERE id=%s", (new_qty, item["id"]))
    # Auto-create reorder alert if below threshold
    alert_msg = ""
    if new_qty <= item["reorder_level"]:
        c.execute("SELECT id FROM reorder_alerts WHERE item_id=%s AND status='open'", (item["id"],))
        if not c.fetchone():
            c.execute("INSERT INTO reorder_alerts (item_id,quantity_at_trigger) VALUES (%s,%s)", (item["id"], new_qty))
            alert_msg = f" ⚠️ REORDER ALERT created — stock is low ({new_qty} {item['unit']})."
    conn.commit(); conn.close()
    return {"status": "updated", "item": item["name"], "previous_qty": item["quantity"],
            "new_qty": new_qty, "unit": item["unit"], "message": f"✅ Stock updated.{alert_msg}"}

@mcp.tool()
def create_reorder_alert(item_name: str) -> dict:
    """Manually create a reorder alert for an item."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM inventory_items WHERE LOWER(name) LIKE LOWER(%s)", (f"%{item_name}%",))
    item = c.fetchone()
    if not item: conn.close(); return {"status": "error", "message": f"Item '{item_name}' not found."}
    c.execute("SELECT id FROM reorder_alerts WHERE item_id=%s AND status='open'", (item["id"],))
    if c.fetchone(): conn.close(); return {"status": "exists", "message": f"⚠️ Reorder alert already open for '{item['name']}'."}
    c.execute("INSERT INTO reorder_alerts (item_id,quantity_at_trigger) VALUES (%s,%s)", (item["id"], item["quantity"]))
    conn.commit(); conn.close()
    return {"status": "created", "message": f"✅ Reorder alert created for '{item['name']}' (current stock: {item['quantity']} {item['unit']})."}

@mcp.tool()
def get_open_reorder_alerts() -> list:
    """Get all open (unresolved) reorder alerts."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT r.id,i.name,i.quantity,i.unit,i.reorder_level,r.quantity_at_trigger,r.triggered_at
                 FROM reorder_alerts r JOIN inventory_items i ON r.item_id=i.id
                 WHERE r.status='open' ORDER BY r.triggered_at""")
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "✅ No open reorder alerts."}]
    return [{**dict(r), "triggered_at": str(r["triggered_at"])} for r in rows]

@mcp.tool()
def resolve_reorder_alert(alert_id: int) -> dict:
    """Mark a reorder alert as resolved (after restock)."""
    conn = get_connection(); c = cur(conn)
    c.execute("UPDATE reorder_alerts SET status='resolved', resolved_at=NOW() WHERE id=%s RETURNING id", (alert_id,))
    if not c.fetchone(): conn.close(); return {"status": "error", "message": f"Alert {alert_id} not found."}
    conn.commit(); conn.close()
    return {"status": "resolved", "message": f"✅ Reorder alert #{alert_id} resolved."}

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Inventory MCP Server on http://127.0.0.1:8003/mcp")
    mcp.run(transport="streamable-http")