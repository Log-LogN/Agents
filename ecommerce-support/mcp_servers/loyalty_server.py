"""mcp_servers/loyalty_server.py — Loyalty & Promotions tools (port 8006)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_loyalty_points_email

mcp = FastMCP("LoyaltyServer", host="127.0.0.1", port=8006,
              stateless_http=True, json_response=True)

def _cur(c): return c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# Tier thresholds
TIERS = {
    "bronze":   {"min_points": 0,     "max_points": 999,   "perks": ["5% birthday discount"]},
    "silver":   {"min_points": 1000,  "max_points": 2999,  "perks": ["10% discount", "Free standard shipping on orders ₹500+"]},
    "gold":     {"min_points": 3000,  "max_points": 9999,  "perks": ["15% discount", "Free express shipping", "Priority support"]},
    "platinum": {"min_points": 10000, "max_points": 999999,"perks": ["20% discount", "Free same-day shipping", "Dedicated support agent", "Early access to sales"]},
}

ACTIVE_PROMOS = [
    {"code": "SAVE10",    "discount_pct": 10, "min_order": 500,   "description": "10% off on orders above ₹500",               "valid_until": "2025-12-31"},
    {"code": "WELCOME20", "discount_pct": 20, "min_order": 1000,  "description": "20% off for new customers",                  "valid_until": "2025-12-31"},
    {"code": "FLASH50",   "discount_pct": 50, "min_order": 5000,  "description": "50% off flash sale on orders above ₹5000",   "valid_until": "2025-06-30"},
    {"code": "GOLD15",    "discount_pct": 15, "min_order": 2000,  "description": "15% off for Gold & Platinum members",        "valid_until": "2025-12-31"},
]


@mcp.tool()
def get_loyalty_points(customer_email: str) -> dict:
    """Get current loyalty points balance and tier for a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, loyalty_points, loyalty_tier FROM customers WHERE email=%s", (customer_email,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Customer '{customer_email}' not found."}
    tier      = row["loyalty_tier"]
    points    = row["loyalty_points"]
    tier_info = TIERS.get(tier, TIERS["bronze"])
    # Next tier progress
    tiers_ordered = ["bronze","silver","gold","platinum"]
    curr_idx = tiers_ordered.index(tier)
    next_tier = tiers_ordered[curr_idx + 1] if curr_idx < 3 else None
    points_to_next = (TIERS[next_tier]["min_points"] - points) if next_tier else 0
    return {
        "found": True, "name": row["name"], "email": customer_email,
        "points": points, "tier": tier.title(),
        "tier_perks": tier_info["perks"],
        "monetary_value": f"₹{points:,}",
        "next_tier": next_tier.title() if next_tier else "Already at highest tier",
        "points_to_next_tier": max(0, points_to_next),
        "message": f"[STARS] {points:,} points (₹{points:,} value) — {tier.title()} member. {f'Need {max(0,points_to_next):,} more points for {next_tier.title()}!' if next_tier and points_to_next > 0 else 'Highest tier reached!'}"
    }


@mcp.tool()
def get_tier_status(customer_email: str) -> dict:
    """Get full tier status, perks, and upgrade requirements."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, loyalty_tier, loyalty_points FROM customers WHERE email=%s", (customer_email,))
    row = c.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Customer '{customer_email}' not found."}
    tier = row["loyalty_tier"]
    return {
        "name": row["name"], "current_tier": tier.title(),
        "points": row["loyalty_points"],
        "current_perks": TIERS[tier]["perks"],
        "all_tiers": {t: {"min_points": d["min_points"], "perks": d["perks"]} for t, d in TIERS.items()},
        "message": f"{row['name']} is a {tier.title()} member with {row['loyalty_points']:,} points."
    }


@mcp.tool()
def redeem_points(customer_email: str, points_to_redeem: int) -> dict:
    """
    Redeem loyalty points for store credit.
    1 point = ₹1 discount. Minimum redemption: 100 points.
    """
    if points_to_redeem < 100:
        return {"status": "error", "message": "Minimum redemption is 100 points."}
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, loyalty_points FROM customers WHERE email=%s", (customer_email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Customer '{customer_email}' not found."}
    if row["loyalty_points"] < points_to_redeem:
        conn.close()
        return {"status": "error",
                "message": f"Insufficient points. You have {row['loyalty_points']:,} points, trying to redeem {points_to_redeem:,}."}
    new_balance = row["loyalty_points"] - points_to_redeem
    c.execute("UPDATE customers SET loyalty_points=%s WHERE email=%s", (new_balance, customer_email))
    c.execute("INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) VALUES(%s,%s,%s,%s)",
              (customer_email, -points_to_redeem, f"Redeemed {points_to_redeem} points for store credit", new_balance))
    conn.commit(); conn.close()
    return {
        "status": "redeemed", "points_redeemed": points_to_redeem,
        "credit_value": f"₹{points_to_redeem:,}",
        "remaining_points": new_balance,
        "message": f"[OK] {points_to_redeem:,} points redeemed for ₹{points_to_redeem:,} store credit. Remaining balance: {new_balance:,} points."
    }


@mcp.tool()
def add_loyalty_points(customer_email: str, points: int, reason: str) -> dict:
    """Add loyalty points to a customer account (for purchases, reviews, referrals)."""
    conn = get_connection(); c = _cur(conn)
    c.execute("SELECT name, loyalty_points, loyalty_tier FROM customers WHERE email=%s", (customer_email,))
    row = c.fetchone()
    if not row:
        conn.close()
        return {"status": "error", "message": f"Customer '{customer_email}' not found."}
    new_balance = row["loyalty_points"] + points
    # Check for tier upgrade
    old_tier = row["loyalty_tier"]
    new_tier = old_tier
    for tier_name, tier_data in sorted(TIERS.items(), key=lambda x: x[1]["min_points"], reverse=True):
        if new_balance >= tier_data["min_points"]:
            new_tier = tier_name
            break
    c.execute("UPDATE customers SET loyalty_points=%s, loyalty_tier=%s WHERE email=%s", (new_balance, new_tier, customer_email))
    c.execute("INSERT INTO loyalty_history(customer_email,points_change,reason,balance_after) VALUES(%s,%s,%s,%s)",
              (customer_email, points, reason, new_balance))
    conn.commit(); conn.close()
    tier_upgrade = new_tier != old_tier
    send_loyalty_points_email(row["name"], customer_email, points, new_balance, reason)
    return {
        "status": "added", "points_added": points, "new_balance": new_balance,
        "tier": new_tier.title(),
        "tier_upgraded": tier_upgrade,
        "message": f"[OK] {points:,} points added. New balance: {new_balance:,}. Tier: {new_tier.title()}.{' 🎉 Tier upgraded!' if tier_upgrade else ''}"
    }


@mcp.tool()
def validate_promo_code(code: str, customer_email: str, order_total: float) -> dict:
    """
    Validate a promo/voucher code for a customer.
    Checks: code exists, not expired, minimum order met, not already used.
    """
    code = code.upper().strip()
    promo = next((p for p in ACTIVE_PROMOS if p["code"] == code), None)
    if not promo:
        return {"valid": False, "message": f"Code '{code}' is invalid or does not exist."}
    # Check min order
    if order_total < promo["min_order"]:
        return {"valid": False,
                "message": f"Minimum order ₹{promo['min_order']:,} required for '{code}'. Your order: ₹{order_total:,.0f}."}
    # Check if GOLD15 is for gold/platinum only
    if code == "GOLD15":
        conn = get_connection(); c = _cur(conn)
        c.execute("SELECT loyalty_tier FROM customers WHERE email=%s", (customer_email,))
        row = c.fetchone(); conn.close()
        if not row or row["loyalty_tier"] not in ("gold","platinum"):
            return {"valid": False, "message": "Code 'GOLD15' is only for Gold and Platinum members."}
    discount = round(order_total * promo["discount_pct"] / 100, 2)
    final    = round(order_total - discount, 2)
    return {
        "valid": True, "code": code,
        "discount_pct": promo["discount_pct"], "discount_amount": discount,
        "original_total": order_total, "final_total": final,
        "valid_until": promo["valid_until"],
        "message": f"[OK] Code '{code}' valid! Save ₹{discount:,.0f} ({promo['discount_pct']}% off). Pay ₹{final:,.0f}."
    }


@mcp.tool()
def get_active_promotions() -> list:
    """Get all currently active promotions and discount codes."""
    return [{
        "code": p["code"], "discount": f"{p['discount_pct']}% off",
        "min_order": f"₹{p['min_order']:,}", "description": p["description"],
        "valid_until": p["valid_until"]
    } for p in ACTIVE_PROMOS]


@mcp.tool()
def get_rewards_history(customer_email: str) -> list:
    """Get full loyalty points history for a customer."""
    conn = get_connection(); c = _cur(conn)
    c.execute("""
        SELECT points_change, reason, balance_after, created_at
        FROM loyalty_history WHERE customer_email=%s ORDER BY created_at DESC LIMIT 20
    """, (customer_email,))
    rows = c.fetchall(); conn.close()
    if not rows:
        return [{"message": f"No loyalty history found for '{customer_email}'."}]
    return [{**dict(r), "created_at": str(r["created_at"])[:16]} for r in rows]


if __name__ == "__main__":
    init_db()
    print("[RUN] Loyalty MCP Server on http://127.0.0.1:8006/mcp")
    mcp.run(transport="streamable-http")