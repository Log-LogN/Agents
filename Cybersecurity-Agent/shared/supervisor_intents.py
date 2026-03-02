from __future__ import annotations

import re
from dataclasses import dataclass

INTENTS = {
    "risk_assessment",
    "threat_only",
    "session_analysis",
    "report_generation",
    "recon_only",
    "direct_answer",
}

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_cve(text: str) -> str | None:
    m = _CVE_RE.search(text or "")
    return m.group(0).upper() if m else None


def extract_domain(text: str) -> str | None:
    if not text:
        return None
    # Prefer URL hostnames.
    m = re.search(r"https?://([^/\s]+)", text, flags=re.IGNORECASE)
    if m:
        return m.group(1).strip().strip(".,;:()[]{}<>\"'")
    d = _DOMAIN_RE.search(text)
    if d:
        return d.group(0).strip().strip(".,;:()[]{}<>\"'")
    return None


@dataclass(frozen=True)
class IntentMatch:
    intent: str
    cve: str | None = None
    domain: str | None = None


def detect_intent(message: str) -> IntentMatch:
    """
    Deterministic Phase-1 intent detection (SOC-grade, keyword based).
    """
    msg = (message or "").lower()
    cve = extract_cve(message)
    domain = extract_domain(message)

    # report_generation
    if "generate report" in msg:
        return IntentMatch("report_generation", cve=cve, domain=domain)

    # session_analysis
    if any(
        k in msg
        for k in (
            "which vulnerability",
            "most critical",
            "highest risk",
            "fix first",
            "what should we fix first",
        )
    ):
        return IntentMatch("session_analysis", cve=cve, domain=domain)

    # threat_only (must NOT require domain)
    if any(k in msg for k in ("actively exploited", "exploit available", "is this exploited")):
        return IntentMatch("threat_only", cve=cve, domain=domain)

    # risk_assessment
    if any(k in msg for k in ("analyze risk", "risk for cve", "affected by")):
        return IntentMatch("risk_assessment", cve=cve, domain=domain)
    if cve and domain:
        return IntentMatch("risk_assessment", cve=cve, domain=domain)

    # recon_only (basic)
    if any(k in msg for k in ("scan ports", "port scan", "dns", "whois", "recon")):
        return IntentMatch("recon_only", cve=cve, domain=domain)

    return IntentMatch("direct_answer", cve=cve, domain=domain)

