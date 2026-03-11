"""Review Agent resolver."""
def resolve_risk_level(user_input: str) -> str:
    u = user_input.upper()
    if "CRITICAL" in u: return "CRITICAL"
    if "HIGH" in u:     return "HIGH"
    if "MEDIUM" in u or "MED" in u: return "MEDIUM"
    if "LOW" in u:      return "LOW"
    return "MEDIUM"
