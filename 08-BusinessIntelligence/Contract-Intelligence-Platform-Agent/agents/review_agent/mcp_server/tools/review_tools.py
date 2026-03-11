"""Review & Risk Agent tools."""
import json, logging, re
from datetime import datetime
from typing import List, Dict, Any, Optional
from shared.prompt_loader import load_prompt
logger = logging.getLogger(__name__)

# LLM-powered contract analysis functions

def _get_llm():
    """Get LLM instance for analysis."""
    from langchain_openai import ChatOpenAI
    import os
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
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fenced:
        try:
            return json.loads(fenced.group(1))
        except Exception:
            pass
    blob = re.search(r"\{.*\}", text, re.S)
    if blob:
        try:
            return json.loads(blob.group(0))
        except Exception:
            return None
    return None

def _basic_missing_clauses(contract_content: str, contract_type: str) -> Dict[str, Any]:
    """Keyword-based missing clause checks when LLM is unavailable."""
    content = (contract_content or "").lower()
    if not content.strip():
        return {
            "clause_analysis": [
                {
                    "clause": "Contract content",
                    "status": "MISSING",
                    "details": "No contract text available for analysis.",
                    "severity": "HIGH",
                }
            ],
            "missing_critical": ["Contract text missing"],
            "completeness_score": 0,
            "recommendations": ["Upload or paste the contract content before running clause checks."],
        }

    required_clauses = {
        "MSA": [
            "Limitation of Liability", "Payment Terms", "Confidentiality",
            "Termination", "Governing Law", "IP Ownership",
            "Force Majeure", "Indemnification", "Warranties", "Dispute Resolution",
        ],
        "NDA": [
            "Definition of Confidential Information", "Exceptions", "Term",
            "Return of Information", "Remedies", "Non-Disclosure Obligations",
        ],
        "SOW": [
            "Scope of Work", "Deliverables", "Timeline", "Payment Milestones",
            "Change Management", "Acceptance Criteria", "Responsibilities",
        ],
        "Vendor": [
            "Product Specifications", "Delivery Terms", "Warranty",
            "Indemnification", "Price", "Payment", "Support Terms",
        ],
    }

    clause_keywords = {
        "Limitation of Liability": ["limitation of liability", "limit of liability"],
        "Payment Terms": ["payment terms", "payment", "invoice", "due date"],
        "Confidentiality": ["confidential", "non-disclosure"],
        "Termination": ["terminate", "termination"],
        "Governing Law": ["governing law", "laws of"],
        "IP Ownership": ["intellectual property", "ip ownership", "ownership of"],
        "Force Majeure": ["force majeure"],
        "Indemnification": ["indemnify", "indemnification"],
        "Warranties": ["warranty", "warranties"],
        "Dispute Resolution": ["dispute resolution", "arbitration", "jurisdiction"],
        "Definition of Confidential Information": ["confidential information", "definition of confidential"],
        "Exceptions": ["exceptions", "not include", "exclusions"],
        "Term": ["term", "duration"],
        "Return of Information": ["return", "destroy", "destruction of"],
        "Remedies": ["remedy", "injunctive"],
        "Non-Disclosure Obligations": ["non-disclosure", "nondisclosure"],
        "Scope of Work": ["scope of work", "scope"],
        "Deliverables": ["deliverable", "deliverables"],
        "Timeline": ["timeline", "schedule", "milestone"],
        "Payment Milestones": ["milestone payment", "payment milestone"],
        "Change Management": ["change management", "change order"],
        "Acceptance Criteria": ["acceptance criteria", "acceptance"],
        "Responsibilities": ["responsibilities", "obligations"],
        "Product Specifications": ["specifications", "specification"],
        "Delivery Terms": ["delivery", "shipping", "incoterms"],
        "Warranty": ["warranty", "warranties"],
        "Price": ["price", "pricing", "fees"],
        "Payment": ["payment terms", "payment", "invoice"],
        "Support Terms": ["support", "sla", "service level"],
    }

    clauses = required_clauses.get(contract_type.upper(), required_clauses["MSA"])
    analysis = []
    missing = []
    for clause in clauses:
        keywords = clause_keywords.get(clause, [])
        present = any(k in content for k in keywords) if keywords else False
        status = "PRESENT" if present else "MISSING"
        severity = "HIGH" if status == "MISSING" else "LOW"
        analysis.append({
            "clause": clause,
            "status": status,
            "details": "Found by keyword scan." if present else "Not detected by keyword scan.",
            "severity": severity,
        })
        if status == "MISSING":
            missing.append(clause)

    total = len(clauses) or 1
    missing_count = len(missing)
    completeness_score = round(((total - missing_count) / total) * 100)
    recommendations = [f"Add or clarify the {c} clause." for c in missing[:5]] or ["No obvious missing clauses detected by keyword checks."]

    return {
        "clause_analysis": analysis,
        "missing_critical": missing[:5],
        "completeness_score": completeness_score,
        "recommendations": recommendations,
    }

def _analyze_contract_content(contract_content: str, contract_type: str, title: str) -> Dict[str, Any]:
    """Use LLM to analyze contract content and identify real risks."""
    llm = _get_llm()

    prompt = load_prompt("contract_risk_analysis.txt").format(
        contract_type=contract_type,
        title=title,
        contract_content=contract_content[:8000],
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        result = json.loads(response.content.strip())
        return result
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}")
        # Fallback to basic analysis
        return {
            "risks": [
                {
                    "issue": "Contract content analysis unavailable",
                    "severity": "MEDIUM",
                    "recommendation": "Manual review recommended",
                    "evidence": "LLM analysis failed"
                }
            ],
            "overall_risk_score": 50,
            "key_findings": ["LLM analysis failed - manual review needed"],
            "compliance_status": "CONCERNS"
        }

def _generate_redline_suggestions(contract_content: str, contract_type: str, identified_risks: List[Dict]) -> List[Dict]:
    """Use LLM to generate specific redline suggestions based on identified risks."""
    llm = _get_llm()

    risks_text = "\n".join([f"- {r['issue']} ({r['severity']})" for r in identified_risks[:5]])

    prompt = load_prompt("redline_suggestions.txt").format(
        contract_type=contract_type,
        risks_text=risks_text,
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        parsed = _safe_json_loads(getattr(response, "content", "") or "")
        if isinstance(parsed, dict):
            suggestions = parsed.get("suggestions", [])
            if isinstance(suggestions, list):
                return suggestions
        logger.warning("Redline suggestions LLM returned non-JSON output.")
        return _fallback_redlines(contract_content, contract_type, identified_risks)
    except Exception as e:
        logger.error(f"Redline generation failed: {e}")
        return _fallback_redlines(contract_content, contract_type, identified_risks)

def _fallback_redlines(contract_content: str, contract_type: str, identified_risks: List[Dict]) -> List[Dict]:
    """Fallback redline suggestions when LLM is unavailable."""
    if not (contract_content or "").strip():
        return [{
            "clause": "Contract content",
            "current": "No contract text available.",
            "suggested": "Upload or paste the contract content before requesting redlines.",
            "rationale": "Redline suggestions require contract text.",
            "priority": "HIGH",
        }]

    suggestions: List[Dict[str, Any]] = []
    for r in (identified_risks or [])[:3]:
        issue = r.get("issue") or "Risk identified"
        severity = r.get("severity", "MEDIUM").upper()
        suggestions.append({
            "clause": issue,
            "current": "Clause missing or unclear.",
            "suggested": f"Add or clarify language to address: {issue}.",
            "rationale": r.get("recommendation") or issue,
            "priority": severity if severity in ["HIGH", "MEDIUM", "LOW"] else "MEDIUM",
        })

    if suggestions:
        return suggestions

    generic_by_type = {
        "MSA": [
            ("Limitation of Liability", "Add a reasonable cap and exclusions."),
            ("Termination", "Clarify termination for cause and convenience."),
            ("Data Privacy", "Add GDPR/CCPA handling obligations if applicable."),
        ],
        "NDA": [
            ("Confidential Information", "Clarify definition and exclusions."),
            ("Term and Survival", "Define term and survival of obligations."),
            ("Return/Destruction", "Require return or destruction on request."),
        ],
        "SOW": [
            ("Scope/Deliverables", "Define detailed scope and deliverables."),
            ("Acceptance Criteria", "Add objective acceptance criteria."),
            ("Change Control", "Add change order and pricing process."),
        ],
        "VENDOR": [
            ("Warranty", "Add warranty scope and duration."),
            ("Support/SLA", "Define support terms and service levels."),
            ("Indemnification", "Add vendor indemnity for IP/data claims."),
        ],
    }

    for clause, tip in generic_by_type.get(contract_type.upper(), generic_by_type["MSA"]):
        suggestions.append({
            "clause": clause,
            "current": "Clause missing or unclear.",
            "suggested": tip,
            "rationale": "Standard protection for this contract type.",
            "priority": "MEDIUM",
        })
    return suggestions

def _check_playbook_compliance(contract_content: str, contract_type: str) -> Dict[str, Any]:
    """Use LLM to check contract against playbook requirements."""
    llm = _get_llm()

    playbook_rules = {
        "MSA": [
            "Limitation of liability must be present and reasonable",
            "Governing law must be specified clearly",
            "Payment terms must be defined with due dates",
            "Data privacy/GDPR clause required if handling personal data",
            "Auto-renewal notice minimum 60 days",
            "Termination rights for cause and convenience",
            "Force majeure clause present",
            "IP ownership clearly defined",
            "Dispute resolution mechanism specified",
            "Confidentiality obligations defined"
        ],
        "NDA": [
            "Definition of Confidential Information is clear",
            "Permitted exceptions are reasonable",
            "Term duration is specified",
            "Return/destruction of information required",
            "Remedies for breach are defined",
            "Non-disclosure obligations survive termination"
        ],
        "SOW": [
            "Scope of Work is clearly defined",
            "Deliverables are specific and measurable",
            "Timeline/milestones are realistic",
            "Payment milestones are tied to deliverables",
            "Change management process defined",
            "Acceptance criteria are objective"
        ]
    }

    rules = playbook_rules.get(contract_type.upper(), playbook_rules["MSA"])

    rules_list = "\n".join(f"- {rule}" for rule in rules)
    prompt = load_prompt("playbook_check.txt").format(
        contract_type=contract_type,
        contract_content=contract_content[:6000],
        rules_list=rules_list,
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        result = json.loads(response.content.strip())
        return result
    except Exception as e:
        logger.error(f"Playbook compliance check failed: {e}")
        return {
            "checks": [{"requirement": "Playbook compliance check", "status": "MISSING", "evidence": "Analysis failed", "recommendation": "Manual review required"}],
            "overall_compliance": "UNKNOWN",
            "critical_issues": ["Analysis failed"],
            "summary": "Unable to complete automated compliance check"
        }

def _identify_missing_clauses(contract_content: str, contract_type: str) -> Dict[str, Any]:
    """Use LLM to identify actually missing clauses based on contract content."""
    llm = _get_llm()

    required_clauses = {
        "MSA": ["Limitation of Liability", "Payment Terms", "Confidentiality", "Termination", "Governing Law", "IP Ownership", "Force Majeure", "Indemnification", "Warranties", "Dispute Resolution"],
        "NDA": ["Definition of Confidential Information", "Exceptions", "Term", "Return of Information", "Remedies", "Non-Disclosure Obligations"],
        "SOW": ["Scope of Work", "Deliverables", "Timeline", "Payment Milestones", "Change Management", "Acceptance Criteria", "Responsibilities"],
        "Vendor": ["Product Specifications", "Delivery Terms", "Warranty", "Indemnification", "Price", "Payment", "Support Terms"]
    }

    clauses = required_clauses.get(contract_type.upper(), required_clauses["MSA"])

    clauses_list = "\n".join(f"- {clause}" for clause in clauses)
    prompt = load_prompt("missing_clauses.txt").format(
        contract_type=contract_type,
        contract_content=contract_content[:6000],
        clauses_list=clauses_list,
    )

    try:
        response = llm.invoke([{"role": "user", "content": prompt}])
        parsed = _safe_json_loads(getattr(response, "content", "") or "")
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Missing clauses LLM returned non-JSON output; using fallback.")
        return _basic_missing_clauses(contract_content, contract_type)
    except Exception as e:
        logger.error(f"Missing clauses analysis failed: {e}")
        return _basic_missing_clauses(contract_content, contract_type)

def analyze_contract(contract_id: int) -> dict:
    try:
        from database.db import fetch_one, execute
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        content = contract.get("content","") or ""
        contract_type = contract.get("contract_type", "MSA")
        title = contract.get("title", "Unknown Contract")

        # Use LLM to analyze actual contract content
        analysis = _analyze_contract_content(content, contract_type, title)

        flags = analysis.get("risks", [])
        score = analysis.get("overall_risk_score", 50)
        score = min(max(score, 0), 100)  # Ensure 0-100 range

        # Store results in database
        execute("UPDATE contracts SET risk_score=%s, risk_flags=%s, updated_at=NOW() WHERE id=%s",
                (score, json.dumps(flags), contract_id))

        # Determine risk level
        risk_level = ("Low" if score <= 25 else
                     "Medium" if score <= 50 else
                     "High" if score <= 75 else "Critical")

        return {
            "status": "success",
            "contract_id": contract_id,
            "risk_score": score,
            "risk_level": risk_level,
            "issues_found": len(flags),
            "flags": flags,
            "key_findings": analysis.get("key_findings", []),
            "compliance_status": analysis.get("compliance_status", "CONCERNS")
        }
    except Exception as e:
        logger.error("analyze_contract error: %s", e)
        # Enhanced fallback with more context
        return {
            "status": "error",
            "message": f"Contract analysis failed: {str(e)}",
            "contract_id": contract_id,
            "risk_score": 50,
            "risk_level": "Medium",
            "issues_found": 1,
            "flags": [{"issue": "Analysis failed", "severity": "HIGH", "recommendation": "Manual review required", "evidence": str(e)}],
            "key_findings": ["Automated analysis unavailable"],
            "compliance_status": "UNKNOWN"
        }

def suggest_redlines(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        content = contract.get("content","") or ""
        contract_type = contract.get("contract_type", "MSA")
        title = contract.get("title", "Unknown Contract")

        # Get existing risk flags to base suggestions on
        risk_flags = contract.get("risk_flags") or []

        # Use LLM to generate specific redline suggestions
        suggestions = _generate_redline_suggestions(content, contract_type, risk_flags)
        if not suggestions:
            suggestions = _fallback_redlines(content, contract_type, risk_flags)

        return {
            "status": "success",
            "contract_id": contract_id,
            "redlines": suggestions,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "based_on_risks": len(risk_flags)
        }
    except Exception as e:
        logger.error("suggest_redlines error: %s", e)
        # Fallback suggestions
        return {
            "status": "error",
            "message": f"Redline generation failed: {str(e)}",
            "contract_id": contract_id,
            "redlines": [
                {
                    "clause": "General Review",
                    "current": "Contract requires manual review",
                    "suggested": "Conduct thorough legal review",
                    "rationale": "Automated analysis unavailable",
                    "priority": "HIGH"
                }
            ],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "based_on_risks": 0
        }

def compare_to_playbook(contract_id: int) -> dict:
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        content = contract.get("content","") or ""
        contract_type = contract.get("contract_type", "MSA")

        # Use LLM to check actual compliance against playbook
        compliance_result = _check_playbook_compliance(content, contract_type)

        checks = compliance_result.get("checks", [])
        passed = sum(1 for c in checks if c.get("status") == "COMPLIANT")
        total = len(checks)
        compliance_pct = round((passed / total * 100) if total > 0 else 0)

        return {
            "status": "success",
            "contract_id": contract_id,
            "playbook": f"Standard {contract_type.upper()} Playbook",
            "checks_passed": passed,
            "checks_total": total,
            "compliance_pct": compliance_pct,
            "results": checks,
            "critical_issues": compliance_result.get("critical_issues", []),
            "summary": compliance_result.get("summary", "Compliance check completed")
        }
    except Exception as e:
        logger.error("compare_to_playbook error: %s", e)
        return {
            "status": "error",
            "message": f"Playbook comparison failed: {str(e)}",
            "contract_id": contract_id,
            "playbook": "Standard Playbook",
            "checks_passed": 0,
            "checks_total": 1,
            "compliance_pct": 0,
            "results": [{"rule": "Playbook compliance check", "passed": False, "note": "Analysis failed"}],
            "critical_issues": ["Manual review required"],
            "summary": "Unable to complete automated compliance check"
        }

def check_missing_clauses(contract_id: int, contract_type: str = "MSA") -> dict:
    """Check and identify missing clauses in the contract using LLM analysis."""
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT * FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        content = contract.get("content","") or ""
        actual_contract_type = contract.get("contract_type", contract_type)

        # Use LLM to identify actually missing clauses
        analysis = _identify_missing_clauses(content, actual_contract_type)

        clause_analysis = analysis.get("clause_analysis", [])
        missing_critical = analysis.get("missing_critical", [])
        completeness_score = analysis.get("completeness_score", "UNKNOWN")
        recommendations = analysis.get("recommendations", [])

        # Calculate missing count
        missing_count = sum(1 for c in clause_analysis if c.get("status") in ["MISSING", "INADEQUATE"])

        return {
            "status": "success",
            "contract_id": contract_id,
            "contract_type": actual_contract_type,
            "clause_analysis": clause_analysis,
            "missing_critical": missing_critical,
            "missing_count": missing_count,
            "completeness_score": completeness_score,
            "recommendations": recommendations
        }
    except Exception as e:
        logger.error("check_missing_clauses error: %s", e)
        return {
            "status": "error",
            "message": f"Missing clauses analysis failed: {str(e)}",
            "contract_id": contract_id,
            "contract_type": contract_type,
            "clause_analysis": [{"clause": "Analysis failed", "status": "UNKNOWN", "details": "LLM analysis unavailable", "severity": "HIGH"}],
            "missing_critical": ["Manual review required"],
            "missing_count": 1,
            "completeness_score": "UNKNOWN",
            "recommendations": ["Conduct manual contract review"]
        }

def get_risk_score(contract_id: int) -> dict:
    """Get current risk score and flags for a contract."""
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT risk_score, risk_flags, title FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        score = contract.get("risk_score") or 0
        flags = contract.get("risk_flags") or []

        # Determine risk level
        risk_level = ("Low" if score <= 25 else
                     "Medium" if score <= 50 else
                     "High" if score <= 75 else "Critical")

        return {
            "status": "success",
            "contract_id": contract_id,
            "title": contract.get("title"),
            "risk_score": score,
            "risk_level": risk_level,
            "flags": flags,
            "flags_count": len(flags) if isinstance(flags, list) else 0
        }
    except Exception as e:
        logger.error("get_risk_score error: %s", e)
        return {"status": "error", "message": str(e)}

def flag_clauses(contract_id: int, risk_level: str = "HIGH") -> dict:
    """Filter and return flagged clauses by risk level."""
    try:
        from database.db import fetch_one
        contract = fetch_one("SELECT risk_flags FROM contracts WHERE id=%s", (contract_id,))
        if not contract:
            return {"status":"error","message":"Contract not found."}

        all_flags = contract.get("risk_flags") or []

        # Filter by risk level
        filtered = []
        if isinstance(all_flags, list):
            filtered = [f for f in all_flags if isinstance(f, dict) and f.get("severity", "").upper() == risk_level.upper()]

        return {
            "status": "success",
            "contract_id": contract_id,
            "risk_level": risk_level,
            "flagged_clauses": filtered,
            "count": len(filtered)
        }
    except Exception as e:
        logger.error("flag_clauses error: %s", e)
        return {"status": "error", "message": str(e)}
