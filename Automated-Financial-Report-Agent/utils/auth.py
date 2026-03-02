"""
utils/auth.py
═════════════
RBAC authentication helpers for the Financial Report Generator.
"""

import psycopg2.extras
from database.db import get_connection, verify_password

# ── Role → visible agents ──────────────────────────────────────────────────────
ROLE_AGENTS: dict[str, list[str]] = {
    "admin": [
        "GL / Transactions",
        "Profit & Loss",
        "Balance Sheet",
        "Cash Flow",
        "Budget & Variance",
        "KPI & Analytics",
        "Report Delivery",
        "General Finance",
    ],
    "cfo": [
        "Profit & Loss",
        "Balance Sheet",
        "Cash Flow",
        "KPI & Analytics",
        "Report Delivery",
        "General Finance",
    ],
    "analyst": [
        "GL / Transactions",
        "Profit & Loss",
        "Budget & Variance",
        "KPI & Analytics",
        "General Finance",
    ],
    "controller": [
        "GL / Transactions",
        "Balance Sheet",
        "Cash Flow",
        "Report Delivery",
        "General Finance",
    ],
}

ROLE_LABELS = {
    "admin":      "🛡️  Admin",
    "cfo":        "💼  CFO",
    "analyst":    "📊  FP&A Analyst",
    "controller": "🏦  Controller",
}

ROLE_COLORS = {
    "admin":      "#f59e0b",
    "cfo":        "#1d4ed8",
    "analyst":    "#15803d",
    "controller": "#5b21b6",
}


def authenticate(email: str, password: str) -> dict | None:
    """Return user dict on success, None on failure."""
    try:
        conn = get_connection()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id,name,email,password_hash,role,department "
            "FROM users WHERE email=%s AND is_active=TRUE",
            (email.strip().lower(),),
        )
        user = cur.fetchone()
        conn.close()
        if user and verify_password(password, user["password_hash"]):
            return {
                "id":         user["id"],
                "name":       user["name"],
                "email":      user["email"],
                "role":       user["role"],
                "department": user["department"],
            }
        return None
    except Exception:
        return None