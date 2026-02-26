"""
utils/auth.py
═════════════
Authentication helpers for the HR Hiring System.

Uses SHA-256 + salt for demo. In production, replace with bcrypt.
"""

import hashlib
import os
import psycopg2.extras

SALT = "hr_salt_2026"


def hash_password(password: str) -> str:
    """Hash a plain-text password."""
    return hashlib.sha256((password + SALT).encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against its hash."""
    return hash_password(plain) == hashed


def authenticate(email: str, password: str) -> dict | None:
    """
    Look up the user by email, verify password.
    Returns user dict on success, None on failure.
    """
    from database.db import get_connection
    try:
        conn = get_connection()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            "SELECT id, name, email, password_hash, role, department FROM users "
            "WHERE email = %s AND is_active = TRUE",
            (email.strip().lower(),)
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
    except Exception as e:
        return None


# ── Role → visible agents mapping ────────────────────────────────────────────
ROLE_AGENTS = {
    "admin": [
        "Job Management",
        "Resume Screening",
        "Interview Scheduling",
        "Offer Management",
        "Onboarding",
        "Candidate Comms",
        "Analytics",
    ],
    "hr_manager": [
        "Job Management",
        "Resume Screening",
        "Interview Scheduling",
        "Offer Management",
        "Analytics",
    ],
    "recruiter": [
        "Job Management",
        "Resume Screening",
        "Interview Scheduling",
        "Candidate Comms",
    ],
    "hiring_manager": [
        "Interview Scheduling",
        "Analytics",
    ],
}

ROLE_LABELS = {
    "admin":          "🛡️ Admin",
    "hr_manager":     "👔 HR Manager",
    "recruiter":      "🔍 Recruiter",
    "hiring_manager": "🏢 Hiring Manager",
}

ROLE_COLORS = {
    "admin":          "#f59e0b",
    "hr_manager":     "#1d4ed8",
    "recruiter":      "#15803d",
    "hiring_manager": "#5b21b6",
}