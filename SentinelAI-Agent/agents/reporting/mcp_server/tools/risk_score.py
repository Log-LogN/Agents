def risk_score(cve_list: list) -> dict:
    """
    Calculate overall risk level based on CVE severities.
    """
    critical = sum(1 for c in cve_list if c.get("severity") == "CRITICAL")
    high = sum(1 for c in cve_list if c.get("severity") == "HIGH")

    if critical >= 2:
        level = "CRITICAL"
    elif critical == 1 or high >= 2:
        level = "HIGH"
    elif high == 1:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_level": level,
        "critical_count": critical,
        "high_count": high,
    }