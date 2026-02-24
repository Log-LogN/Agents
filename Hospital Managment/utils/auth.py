import hashlib
import hmac
import json
import os
import secrets
from typing import Dict, Optional

VALID_ROLES = {
    "patient",
    "frontdesk",
    "billing",
    "inventory",
    "pharmacy",
    "lab",
    "ward",
    "admin",
}


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password: str, stored_password: str) -> bool:
    if "$" not in stored_password:
        # Backward compatibility for plain text passwords in local demos.
        return hmac.compare_digest(password, stored_password)

    try:
        salt, expected_hex = stored_password.split("$", 1)
    except ValueError:
        return False

    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return hmac.compare_digest(digest.hex(), expected_hex)


def _default_users() -> Dict[str, dict]:
    defaults = [
        {
            "username": "patient_demo",
            "password": "patient123",
            "role": "patient",
            "email": "hardikloglogn@gmail.com",
        },
        {"username": "frontdesk_demo", "password": "frontdesk123", "role": "frontdesk"},
        {"username": "billing_demo", "password": "billing123", "role": "billing"},
        {"username": "inventory_demo", "password": "inventory123", "role": "inventory"},
        {"username": "pharmacy_demo", "password": "pharmacy123", "role": "pharmacy"},
        {"username": "lab_demo", "password": "lab123", "role": "lab"},
        {"username": "ward_demo", "password": "ward123", "role": "ward"},
        {"username": "admin_demo", "password": "admin123", "role": "admin"},
    ]

    users: Dict[str, dict] = {}
    for entry in defaults:
        users[entry["username"]] = {
            "username": entry["username"],
            "role": entry["role"],
            "email": entry.get("email"),
            "password_hash": hash_password(entry["password"]),
        }
    return users


def load_users() -> Dict[str, dict]:
    raw = os.getenv("APP_USERS_JSON", "").strip()
    if not raw:
        return _default_users()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"APP_USERS_JSON is not valid JSON: {exc}") from exc

    if not isinstance(parsed, list):
        raise ValueError("APP_USERS_JSON must be a JSON array of user objects")

    users: Dict[str, dict] = {}
    for idx, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            raise ValueError(f"APP_USERS_JSON[{idx}] must be an object")

        username = str(entry.get("username", "")).strip()
        role = str(entry.get("role", "")).strip().lower()
        email = entry.get("email")
        password = entry.get("password")
        password_hash = entry.get("password_hash")

        if not username:
            raise ValueError(f"APP_USERS_JSON[{idx}] missing 'username'")
        if role not in VALID_ROLES:
            raise ValueError(f"APP_USERS_JSON[{idx}] has invalid role '{role}'")

        if password_hash:
            final_hash = str(password_hash)
        elif password:
            final_hash = hash_password(str(password))
        else:
            raise ValueError(
                f"APP_USERS_JSON[{idx}] must contain either 'password' or 'password_hash'"
            )

        users[username] = {
            "username": username,
            "role": role,
            "email": str(email).strip() if email else None,
            "password_hash": final_hash,
        }

    return users


def authenticate_user(username: str, password: str) -> Optional[dict]:
    users = load_users()
    record = users.get(username)
    if not record:
        return None
    if not verify_password(password, record["password_hash"]):
        return None

    return {
        "username": record["username"],
        "role": record["role"],
        "email": record.get("email"),
    }
