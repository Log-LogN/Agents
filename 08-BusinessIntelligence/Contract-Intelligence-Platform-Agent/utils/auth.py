"""utils/auth.py — JWT tokens, bcrypt passwords, RBAC."""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

SECRET_KEY       = os.getenv("SECRET_KEY", "change-me-in-production")
JWT_ALGORITHM    = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "8"))


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user_id: int, email: str, role: str) -> str:
    payload = {
        "sub":   str(user_id),
        "email": email,
        "role":  role,
        "iat":   datetime.now(timezone.utc),
        "exp":   datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning("JWT invalid: %s", e)
        return None


def authenticate_user(email: str, password: str) -> Optional[dict]:
    try:
        from database.db import fetch_one, execute
        user = fetch_one(
            "SELECT id,email,password_hash,role,full_name,is_active FROM users WHERE email=%s",
            (email.lower().strip(),)
        )
        if not user or not user["is_active"]:
            return None
        if not verify_password(password, user["password_hash"]):
            return None
        execute("UPDATE users SET last_login=NOW() WHERE id=%s", (user["id"],))
        return dict(user)
    except Exception as e:
        logger.error("Auth error: %s", e)
        return None


def has_permission(role: str, permission: str) -> bool:
    if not permission:
        return True
    from shared.constants import ROLE_PERMISSIONS
    perms  = ROLE_PERMISSIONS.get(role, [])
    domain = permission.split(":")[0]
    return permission in perms or f"{domain}:full" in perms


def can_access_intent(role: str, intent: str) -> bool:
    from shared.constants import INTENT_PERMISSION
    required = INTENT_PERMISSION.get(intent, "")
    return has_permission(role, required)


def get_allowed_pages(role: str) -> list:
    from shared.constants import ROLE_PAGES
    return ROLE_PAGES.get(role, ["🏠 Dashboard"])
