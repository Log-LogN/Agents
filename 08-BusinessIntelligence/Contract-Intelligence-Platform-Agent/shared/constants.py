"""shared/constants.py — System-wide constants, enums, and mappings."""

# ── Intent keys ───────────────────────────────────────────────────────────────
INTENT_KEYS = ["draft", "review", "approve", "execute", "obligation", "compliance", "analytics", "UNKNOWN"]

# ── Agent ports ───────────────────────────────────────────────────────────────
AGENT_PORTS = {
    "draft":       8001,
    "review":      8002,
    "approve":     8003,
    "execute":     8004,
    "obligation":  8005,
    "compliance":  8006,
    "analytics":   8007,
}

AGENT_NAMES = {
    "draft":       "Contract Draft Agent",
    "review":      "Review & Risk Agent",
    "approve":     "Approval Agent",
    "execute":     "Execution Agent",
    "obligation":  "Obligation Agent",
    "compliance":  "Compliance Agent",
    "analytics":   "Analytics Agent",
    "UNKNOWN":     "Default Answering Agent",
}

# ── Contract statuses ─────────────────────────────────────────────────────────
CONTRACT_STATUSES = ["DRAFT","REVIEW","APPROVAL","EXECUTION","ACTIVE","EXPIRED","TERMINATED","AMENDED"]

CONTRACT_TYPES = ["NDA","MSA","SOW","Vendor","Employment","SaaS","Lease","Service","Partnership","Other"]

# ── Role → permissions ────────────────────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": [
        "contracts:create","contracts:review","contracts:approve",
        "contracts:execute","obligations:manage","compliance:run",
        "analytics:full","users:manage","audit:read",
    ],
    "legal_counsel": [
        "contracts:create","contracts:review","compliance:run","analytics:read",
    ],
    "contract_manager": [
        "contracts:create","contracts:review","contracts:approve",
        "contracts:execute","obligations:manage","analytics:full",
    ],
    "procurement": [
        "contracts:create","contracts:execute","obligations:manage","analytics:read",
    ],
    "finance": [
        "obligations:manage","analytics:read",
    ],
    "viewer": [
        "analytics:read",
    ],
}

# ── Intent → required permission ──────────────────────────────────────────────
INTENT_PERMISSION = {
    "draft":       "contracts:create",
    "review":      "contracts:review",
    "approve":     "contracts:approve",
    "execute":     "contracts:execute",
    "obligation":  "obligations:manage",
    "compliance":  "compliance:run",
    "analytics":   "analytics:read",
    "UNKNOWN":     "",
}

# ── Role → allowed UI pages ───────────────────────────────────────────────────
ROLE_PAGES = {
    "admin": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📝 Draft Contract",
        "🔍 Review & Risk","✅ Approvals","📋 Obligations",
        "🛡️ Compliance","📊 Analytics","👥 Admin",
    ],
    "legal_counsel": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📝 Draft Contract",
        "🔍 Review & Risk","🛡️ Compliance","📊 Analytics",
    ],
    "contract_manager": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📝 Draft Contract",
        "🔍 Review & Risk","✅ Approvals","📋 Obligations","📊 Analytics",
    ],
    "procurement": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📝 Draft Contract",
        "📋 Obligations","📊 Analytics",
    ],
    "finance": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📋 Obligations","📊 Analytics",
    ],
    "viewer": [
        "🏠 Dashboard","💬 Assistant","📂 Contracts","📊 Analytics",
    ],
}

# ── Risk score colours ────────────────────────────────────────────────────────
def risk_color(score: int) -> str:
    if score <= 25:   return "#1E7E34"  # green
    if score <= 50:   return "#B88600"  # amber
    if score <= 75:   return "#C85000"  # orange
    return "#C0392B"                    # red

def risk_label(score: int) -> str:
    if score <= 25:   return "Low"
    if score <= 50:   return "Medium"
    if score <= 75:   return "High"
    return "Critical"

STATUS_EMOJI = {
    "DRAFT": "📝", "REVIEW": "🔍", "APPROVAL": "⏳",
    "EXECUTION": "✍️", "ACTIVE": "✅", "EXPIRED": "⌛",
    "TERMINATED": "❌", "AMENDED": "🔄",
}
