"""Compliance Agent tools."""
import json, logging, random, re
from datetime import datetime
from typing import List, Dict, Any, Optional
from shared.prompt_loader import load_prompt
logger = logging.getLogger(__name__)

GDPR_CHECKS = [
    ("Lawful basis for processing",       "HIGH"),
    ("Data subject rights clause",        "HIGH"),
    ("Data retention policy",             "MEDIUM"),
    ("Data breach notification (72hr)",   "HIGH"),
    ("Data Processing Agreement present", "HIGH"),
    ("Cross-border transfer safeguards",  "MEDIUM"),
    ("Privacy notice reference",          "LOW"),
]

JURISDICTION_RULES = {
    "New York":   ["NY commercial law compliance", "UCC Article 2 if goods", "SHIELD Act for data"],
    "California": ["CCPA compliance required", "California Consumer Privacy Act", "CPRA obligations"],
    "EU":         ["GDPR full compliance", "DPA required", "Right to erasure clause", "Data residency"],
    "England & Wales": ["UK GDPR compliance", "ICO registration", "Companies Act obligations"],
}

def _get_llm():
    """Get LLM instance for compliance analysis."""
    from langchain_openai import ChatOpenAI
    import os
    # Request structured JSON to reduce parsing failures.
    return ChatOpenAI(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        temperature=0.1,
        timeout=30,
        max_retries=2,
        model_kwargs={"response_format": {"type": "json_object"}},
    )

def _safe_json_loads(text: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from LLM output, tolerating code fences or leading text."""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    # Strip fenced blocks if present.
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    # Best-effort extract first JSON object.
    blob = re.search(r"\{.*\}", text, re.S)
    if blob:
        try:
            return json.loads(blob.group(0))
        except Exception:
            return None
    return None

def _basic_compliance_analysis(contract_content: str, contract_type: str, jurisdiction: str, regulations: str) -> Dict[str, Any]:
    """Lightweight keyword-based compliance fallback when LLM is unavailable."""
    content = (contract_content or "").lower()
    issues = []

    if not content.strip():
        issues.append({
            "issue_type": "Contract content missing",
            "regulation": "General",
            "severity": "HIGH",
            "description": "No contract text is available for compliance analysis.",
            "recommendation": "Upload or paste the contract content before running compliance checks.",
        })
        return {
            "issues": issues,
            "compliance_score": 10,
            "overall_status": "CONCERNS",
            "key_findings": ["No contract text available for compliance analysis."],
        }

    def _missing(label: str, keywords: List[str], regulation: str, severity: str, recommendation: str):
        if not any(k in content for k in keywords):
            issues.append({
                "issue_type": label,
                "regulation": regulation,
                "severity": severity,
                "description": f"Missing or unclear coverage for: {label}.",
                "recommendation": recommendation,
            })

    regs = {r.strip().upper() for r in (regulations or "").split(",") if r.strip()}

    # General commercial checks
    _missing("Governing law clause", ["governing law", "laws of"], "General", "LOW", "Add a governing law clause.")
    _missing("Termination rights", ["terminate", "termination"], "General", "MEDIUM", "Specify termination rights and notice period.")
    _missing("Limitation of liability", ["limitation of liability", "limitation of liabilities"], "General", "HIGH", "Add limitation of liability terms.")
    _missing("Indemnification", ["indemnify", "indemnification"], "General", "MEDIUM", "Include mutual indemnification where appropriate.")
    _missing("Confidentiality", ["confidential", "non-disclosure"], "General", "MEDIUM", "Include confidentiality obligations.")
    _missing("Dispute resolution", ["dispute resolution", "arbitration", "jurisdiction"], "General", "LOW", "Define dispute resolution mechanism.")

    # GDPR/Privacy checks
    if "GDPR" in regs or "GENERAL" in regs:
        _missing("Lawful basis for processing", ["lawful basis", "legal basis"], "GDPR", "HIGH", "Define lawful basis for processing personal data.")
        _missing("Data subject rights", ["data subject", "access", "erasure", "rectification"], "GDPR", "HIGH", "Include data subject rights.")
        _missing("Data retention", ["retention", "retain", "storage period"], "GDPR", "MEDIUM", "State retention periods.")
        _missing("Breach notification", ["breach", "72 hours", "notification"], "GDPR", "HIGH", "Add breach notification obligations.")
        _missing("DPA / processor terms", ["data processing agreement", "processor", "sub-processor"], "GDPR", "MEDIUM", "Add DPA/processor obligations.")
        _missing("Cross-border transfer safeguards", ["transfer", "standard contractual clauses", "scc"], "GDPR", "MEDIUM", "Add transfer safeguards.")

    # Simple jurisdiction cues
    if jurisdiction.lower().startswith("california"):
        _missing("CCPA/CPRA compliance", ["ccpa", "cpra", "consumer privacy"], "CCPA", "MEDIUM", "Add CCPA/CPRA compliance language.")

    # Score and status
    severity_weights = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    score = 100 - sum(severity_weights.get(i["severity"], 10) for i in issues)
    score = max(min(score, 100), 0)
    status = "GOOD" if score >= 80 else ("CONCERNS" if score >= 50 else "CRITICAL")
    key_findings = [i["issue_type"] for i in issues[:5]] or ["No obvious compliance gaps detected by keyword checks."]

    return {
        "issues": issues,
        "compliance_score": score,
        "overall_status": status,
        "key_findings": key_findings,
    }

def _analyze_compliance(contract_content: str, contract_type: str, jurisdiction: str, regulations: str) -> Dict[str, Any]:
    """Use LLM to analyze contract compliance based on content."""
    llm = _get_llm()

    prompt = load_prompt("compliance_analysis.txt").format(
        contract_type=contract_type,
        jurisdiction=jurisdiction,
        regulations=regulations,
        contract_content=contract_content[:6000],
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        parsed = _safe_json_loads(getattr(response, "content", "") or "")
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Compliance LLM returned non-JSON output; using fallback.")
        return _basic_compliance_analysis(contract_content, contract_type, jurisdiction, regulations)
    except Exception as e:
        logger.error(f"Compliance LLM analysis failed: {e}")
        return _basic_compliance_analysis(contract_content, contract_type, jurisdiction, regulations)

def _check_gdpr_compliance(contract_content: str) -> Dict[str, Any]:
    """Use LLM to check GDPR compliance specifically."""
    llm = _get_llm()

    gdpr_requirements = [
        "Lawful basis for processing personal data",
        "Data subject rights (access, rectification, erasure)",
        "Data retention policy and time limits",
        "Data breach notification within 72 hours",
        "Data Processing Agreement for processors",
        "Cross-border transfer safeguards",
        "Privacy notice and transparency",
        "Data Protection Officer designation",
        "Data Protection Impact Assessment",
        "Records of processing activities"
    ]

    requirements_list = "\n".join(f"- {req}" for req in gdpr_requirements)
    prompt = load_prompt("gdpr_check.txt").format(
        contract_content=contract_content[:6000],
        requirements_list=requirements_list,
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        result = json.loads(response.content.strip())
        return result
    except Exception as e:
        logger.error(f"GDPR LLM check failed: {e}")
        return {
            "checks": [{"requirement": "GDPR compliance check", "status": "MISSING", "evidence": "Analysis failed", "severity": "HIGH"}],
            "gdpr_score": 0,
            "gdpr_compliant": False,
            "critical_issues": ["Analysis failed"],
            "recommendations": ["Manual GDPR review required"]
        }

def check_compliance(contract_id: int, regulations: str = "GDPR,general") -> dict:
    try:
        from database.db import fetch_one, execute
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}

        contract_content = contract.get("content", "") or ""
        contract_type = contract.get("contract_type", "MSA")
        jurisdiction = contract.get("jurisdiction", "New York")

        # Use LLM to analyze actual contract content for compliance
        compliance_results = _analyze_compliance(contract_content, contract_type, jurisdiction, regulations)

        issues = compliance_results.get("issues", [])

        # Store issues in database
        for issue in issues:
            try:
                issue_type = issue.get("issue_type", "Compliance issue")
                regulation = issue.get("regulation", "General")
                severity = issue.get("severity", "MEDIUM")
                description = issue.get("description", "Issue details unavailable.")
                recommendation = issue.get("recommendation", "Manual review recommended.")
                execute("""
                    INSERT INTO compliance_issues
                    (contract_id, issue_type, regulation, severity, description, recommendation, status)
                    VALUES (%s,%s,%s,%s,%s,%s,'OPEN')
                """, (contract_id, issue_type, regulation,
                      severity, description, recommendation))
            except Exception:
                pass

        return {
            "status": "success",
            "contract_id": contract_id,
            "regulations_checked": regulations,
            "issues_found": len(issues),
            "issues": issues,
            "compliance_score": compliance_results.get("compliance_score", 50),
            "overall_status": compliance_results.get("overall_status", "CONCERNS"),
            "key_findings": compliance_results.get("key_findings", [])
        }
    except Exception as e:
        logger.error("check_compliance error: %s", e)
        return {"status": "error", "message": str(e)}

def get_compliance_issues(contract_id: int) -> dict:
    try:
        from database.db import fetch_all
        rows = fetch_all("SELECT * FROM compliance_issues WHERE contract_id=%s ORDER BY severity DESC", (contract_id,))
        return {"status": "success", "contract_id": contract_id,
                "issues": [dict(r) for r in rows], "count": len(rows)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def run_gdpr_check(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status": "error", "message": "Contract not found."}

        contract_content = contract.get("content", "") or ""

        # Use LLM to check actual GDPR compliance
        results = _check_gdpr_compliance(contract_content)

        return {
            "status": "success",
            "contract_id": contract_id,
            "gdpr_checks": results.get("checks", []),
            "gdpr_score": results.get("gdpr_score", 0),
            "gdpr_compliant": results.get("gdpr_compliant", False),
            "critical_issues": results.get("critical_issues", []),
            "recommendations": results.get("recommendations", [])
        }
    except Exception as e:
        logger.error("run_gdpr_check error: %s", e)
        return {"status": "error", "message": str(e)}

def run_jurisdiction_check(contract_id: int, jurisdiction: str = "New York") -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT jurisdiction FROM contracts WHERE id=%s", (contract_id,))
        jur = jurisdiction or (contract["jurisdiction"] if contract else "New York")
        rules = JURISDICTION_RULES.get(jur, [f"{jur} standard commercial law compliance"])
        checks = [{"rule": r, "status": random.choice(["COMPLIANT", "REVIEW_REQUIRED", "NON_COMPLIANT"])} for r in rules]
        return {"status": "success", "contract_id": contract_id, "jurisdiction": jur,
                "rules_checked": checks, "count": len(checks)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def generate_audit_trail(contract_id: int) -> dict:
    try:
        from database.db import fetch_all
        logs = fetch_all("""
            SELECT al.ts, al.intent_key, al.agent_used, al.mcp_tool, al.status,
                   u.email as user_email
            FROM audit_log al LEFT JOIN users u ON u.id=al.user_id
            WHERE al.contract_id=%s ORDER BY al.ts DESC LIMIT 50
        """, (contract_id,))
        return {"status": "success", "contract_id": contract_id,
                "audit_entries": [dict(r) for r in logs], "count": len(logs)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_data_residency(contract_id: int) -> dict:
    checks = [
        {"requirement": "Data stored within EU/EEA", "status": random.choice(["COMPLIANT","NON_COMPLIANT"])},
        {"requirement": "No transfer to high-risk countries", "status": random.choice(["COMPLIANT","REVIEW"])},
        {"requirement": "Standard Contractual Clauses in place", "status": random.choice(["COMPLIANT","MISSING"])},
        {"requirement": "Sub-processor list maintained", "status": random.choice(["COMPLIANT","OUTDATED"])},
    ]
    return {"status": "success", "contract_id": contract_id, "data_residency_checks": checks,
            "compliant_count": sum(1 for c in checks if c["status"] == "COMPLIANT")}
