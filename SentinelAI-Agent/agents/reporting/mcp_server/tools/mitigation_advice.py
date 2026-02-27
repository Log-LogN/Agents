def mitigation_advice(risk_level: str) -> dict:
    advice_map = {
        "CRITICAL": "Immediate patching required. Restrict access and monitor for exploitation.",
        "HIGH": "Patch as soon as possible and review exposed services.",
        "MEDIUM": "Schedule patching in next maintenance window.",
        "LOW": "Monitor and patch during routine updates."
    }

    return {
        "risk_level": risk_level,
        "recommendation": advice_map.get(risk_level, "Review security posture.")
    }