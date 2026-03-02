from __future__ import annotations

from typing import Any, Iterable


def _success(data: Any) -> dict:
    return {"status": "success", "data": data, "error": None}


def _failure(message: str) -> dict:
    return {"status": "error", "data": None, "error": message}


def _severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _priority(severity: str) -> str:
    if severity == "Critical":
        return "Patch immediately"
    if severity == "High":
        return "Patch ASAP"
    if severity == "Medium":
        return "Patch soon"
    return "Monitor / schedule fix"


def calculate_risk(
    *,
    cvss: float,
    epss: float | None = None,
    exploit_available: bool = False,
    internet_exposed: bool = False,
    open_ports: Iterable[int] | None = None,
    in_kev: bool = False,
) -> dict:
    """
    Deterministic Phase-1 risk scoring model.
    """
    try:
        base = float(cvss)
    except Exception:
        return _failure("Invalid cvss value.")

    if base < 0 or base > 10:
        return _failure("cvss must be between 0.0 and 10.0.")

    ports = list(open_ports or [])
    score = base
    reasons: list[str] = []

    if epss is not None:
        try:
            epss_f = float(epss)
        except Exception:
            return _failure("Invalid epss value.")

        if epss_f > 0.7:
            score += 1.0
            pct = int(round(epss_f * 100))
            reasons.append(f"High EPSS ({pct}%)")

    if exploit_available:
        score += 1.0
        reasons.append("Public exploit available")

    if in_kev:
        score += 1.0
        reasons.append("Listed in CISA KEV")

    if internet_exposed:
        score += 0.5
        reasons.append("Internet exposed")

    if any(p in (80, 443) for p in ports):
        score += 0.3
        if 443 in ports:
            reasons.append("Port 443 open")
        elif 80 in ports:
            reasons.append("Port 80 open")

    score = min(10.0, round(score, 1))
    severity = _severity(score)

    if not reasons:
        reasons.append("CVSS-driven baseline risk")

    return _success(
        {
            "overall_score": score,
            "severity": severity,
            "reasons": reasons,
            "recommended_priority": _priority(severity),
        }
    )

