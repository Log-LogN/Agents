"""mcp_servers/product_server.py — Product & Inventory tools (port 8003)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("ProductServer", host="127.0.0.1", port=8003,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def search_products(query: str) -> list:
    """Search products by name, brand, or category (case-insensitive)."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, name, sku, category, brand, price, stock_qty, description
        FROM products
        WHERE LOWER(name) LIKE %s OR LOWER(brand) LIKE %s OR LOWER(category) LIKE %s
        ORDER BY stock_qty DESC LIMIT 10
    """, (f"%{query.lower()}%", f"%{query.lower()}%", f"%{query.lower()}%"))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No products found matching '{query}'."}]
    return [{**dict(r), "price": float(r["price"]),
             "availability": "In Stock" if r["stock_qty"] > 0 else "Out of Stock"} for r in rows]


@mcp.tool()
def get_product_info(product_id: int) -> dict:
    """Get full information about a specific product."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT * FROM products WHERE id=%s", (product_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Product #{product_id} not found."}
    d = dict(row)
    d["price"] = float(d["price"])
    d["availability"] = "In Stock" if d["stock_qty"] > 0 else "Out of Stock"
    d["stock_status"] = ("Plenty in stock" if d["stock_qty"] > 20
                         else "Low stock" if d["stock_qty"] > 0 else "Out of stock")
    return {"found": True, **d}


@mcp.tool()
def check_stock_level(product_id: int) -> dict:
    """Check the current stock level for a product."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, sku, stock_qty, reorder_level FROM products WHERE id=%s", (product_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Product #{product_id} not found."}
    qty = row["stock_qty"]
    return {
        "product_id": product_id, "name": row["name"], "sku": row["sku"],
        "stock_qty": qty, "reorder_level": row["reorder_level"],
        "availability": "In Stock" if qty > 0 else "Out of Stock",
        "status": ("Well stocked" if qty > row["reorder_level"] * 2
                   else "Low stock" if qty > 0 else "Out of stock — reorder needed"),
        "message": f"{'[OK]' if qty > 0 else '[STOP]'} {row['name']}: {qty} units available."
    }


@mcp.tool()
def get_category_products(category: str) -> list:
    """Get all products in a specific category with availability."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, name, brand, price, stock_qty, description
        FROM products WHERE LOWER(category)=LOWER(%s) ORDER BY price
    """, (category,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No products found in category '{category}'."}]
    return [{**dict(r), "price": float(r["price"]),
             "availability": "In Stock" if r["stock_qty"] > 0 else "Out of Stock"} for r in rows]


@mcp.tool()
def get_low_stock_items(threshold: int = 10) -> list:
    """Get all products with stock below the given threshold. Useful for restock alerts."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT id, name, sku, category, stock_qty, reorder_level
        FROM products WHERE stock_qty <= %s ORDER BY stock_qty
    """, (threshold,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No products below stock threshold of {threshold}."}]
    return [dict(r) for r in rows]


@mcp.tool()
def get_price(product_id: int) -> dict:
    """Get the current price and any active discount for a product."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, price, stock_qty FROM products WHERE id=%s", (product_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Product #{product_id} not found."}
    price = float(row["price"])
    return {
        "product_id": product_id, "name": row["name"],
        "price": price, "currency": "INR",
        "availability": "In Stock" if row["stock_qty"] > 0 else "Out of Stock",
        "message": f"₹{price:,.0f} for {row['name']}."
    }


@mcp.tool()
def update_stock(product_id: int, quantity_change: int, reason: str) -> dict:
    """
    Update stock quantity for a product.
    quantity_change: positive to add stock, negative to reduce.
    """
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, stock_qty FROM products WHERE id=%s", (product_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Product #{product_id} not found."}
    new_qty = max(0, row["stock_qty"] + quantity_change)
    c.execute("UPDATE products SET stock_qty=%s WHERE id=%s", (new_qty, product_id))
    conn.commit(); conn.close()
    return {"status": "updated", "product": row["name"],
            "old_qty": row["stock_qty"], "new_qty": new_qty, "reason": reason,
            "message": f"[OK] Stock updated: {row['name']} — {row['stock_qty']} → {new_qty} units."}


@mcp.tool()
def check_restock_date(product_id: int) -> dict:
    """Get restock information for an out-of-stock product."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, stock_qty, sku FROM products WHERE id=%s", (product_id,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Product #{product_id} not found."}
    if row["stock_qty"] > 0:
        return {"in_stock": True, "stock_qty": row["stock_qty"],
                "message": f"'{row['name']}' is currently in stock ({row['stock_qty']} units)."}
    # Simulate restock ETA based on SKU
    from datetime import date, timedelta
    eta = date.today() + timedelta(days=7)
    return {
        "in_stock": False, "product": row["name"], "sku": row["sku"],
        "estimated_restock": str(eta),
        "message": f"[PENDING] '{row['name']}' is out of stock. Expected restock by {eta}. We can notify you when available."
    }


if __name__ == "__main__":
    init_db()
    print("[RUN] Product MCP Server on http://127.0.0.1:8003/mcp")
    mcp.run(transport="streamable-http")