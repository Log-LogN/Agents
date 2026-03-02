"""mcp_servers/report_server.py — Report Delivery Agent (port 8007 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import time
import uuid
import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_report_email, send_board_pack, send_executive_alert

mcp = FastMCP("ReportServer", host="127.0.0.1", port=8007, stateless_http=True, json_response=True)
APPROVAL_TTL_SEC = int(os.getenv("EMAIL_APPROVAL_TTL_SEC", "900"))
PENDING_EMAIL_APPROVALS: dict[str, dict] = {}


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _cleanup_pending() -> None:
    now = time.time()
    expired = [k for k, v in PENDING_EMAIL_APPROVALS.items() if now - float(v.get("created_at", 0)) > APPROVAL_TTL_SEC]
    for k in expired:
        PENDING_EMAIL_APPROVALS.pop(k, None)


def _create_email_approval(tool_name: str, args: dict, preview: dict) -> dict:
    _cleanup_pending()
    token = str(uuid.uuid4())
    PENDING_EMAIL_APPROVALS[token] = {
        "tool_name": tool_name,
        "args": args,
        "preview": preview,
        "created_at": time.time(),
    }
    return {
        "success": False,
        "requires_approval": True,
        "approval_token": token,
        "tool_name": tool_name,
        "approval_ttl_seconds": APPROVAL_TTL_SEC,
        "email_preview": preview,
        "message": "Approval required before sending this email.",
    }


def _consume_email_approval(tool_name: str, approval_token: str) -> dict:
    _cleanup_pending()
    pending = PENDING_EMAIL_APPROVALS.get(approval_token)
    if not pending:
        return {"success": False, "message": "Approval token is invalid or expired."}
    if pending.get("tool_name") != tool_name:
        return {"success": False, "message": "Approval token does not match this email action."}
    PENDING_EMAIL_APPROVALS.pop(approval_token, None)
    return {"success": True, "pending": pending}


@mcp.tool()
def generate_report_summary(report_data: str, report_type: str = "Financial Report", period: str = "2026-02") -> dict:
    """Create a formatted plain-text summary from a JSON data dict string."""
    try:
        data = json.loads(report_data) if isinstance(report_data, str) else report_data
    except Exception:
        data = {"raw": str(report_data)}
    lines = [f"{'='*50}", f"  {report_type.upper()}", f"  Period: {period}", f"{'='*50}", ""]
    def _fmt_scalar(key: str, value, indent: int) -> None:
        label = str(key).replace("_", " ").title() if key else "Value"
        val = f"₹{value:,.2f}" if isinstance(value, float) and "_pct" not in str(key) and "ratio" not in str(key) else value
        lines.append(f"{'  '*indent}{label}: {val}")

    def _fmt_any(value, indent: int = 0, key: str = "") -> None:
        if isinstance(value, dict):
            if key:
                lines.append(f"{'  '*indent}{str(key).replace('_',' ').title()}:")
                indent += 1
            for k, v in value.items():
                _fmt_any(v, indent, str(k))
            return
        if isinstance(value, list):
            if key:
                lines.append(f"{'  '*indent}{str(key).replace('_',' ').title()}:")
                indent += 1
            if not value:
                lines.append(f"{'  '*indent}- (empty)")
                return
            for idx, item in enumerate(value, start=1):
                if isinstance(item, (dict, list)):
                    lines.append(f"{'  '*indent}- Item {idx}:")
                    _fmt_any(item, indent + 1)
                else:
                    lines.append(f"{'  '*indent}- {item}")
            return
        _fmt_scalar(key or "value", value, indent)

    _fmt_any(data)
    lines.append(f"\n{'='*50}")
    summary = "\n".join(lines)
    log_report_delivery(report_type, "system", "internal", period, "generated")
    return {"success": True, "report_type": report_type, "period": period, "summary": summary}


@mcp.tool()
def send_financial_report_email(
    recipients: str = "", report_type: str = "", period: str = "", summary: str = "", approval_token: str = ""
) -> dict:
    """Email a financial report to a recipient list."""
    if approval_token:
        approved = _consume_email_approval("send_financial_report_email", approval_token)
        if not approved["success"]:
            return approved
        args = approved["pending"]["args"]
        recipients = args["recipients"]
        report_type = args["report_type"]
        period = args["period"]
        summary = args["summary"]
    else:
        if not (recipients and report_type and period and summary):
            return {"success": False, "message": "recipients, report_type, period, and summary are required."}
        preview = {
            "title": "Financial Report Email",
            "to": recipients,
            "subject": f"{report_type} — {period}",
            "period": period,
            "report_type": report_type,
            "summary_full": summary,
            "summary_preview": summary[:800],
        }
        return _create_email_approval(
            "send_financial_report_email",
            {"recipients": recipients, "report_type": report_type, "period": period, "summary": summary},
            preview,
        )

    result = send_report_email(recipients, report_type, period, summary)
    log_report_delivery(report_type, "report_agent", recipients, period,
                        "sent" if result["success"] else "failed")
    return {"success": result["success"], "recipients": recipients,
            "report_type": report_type, "period": period, "message": result["message"]}


@mcp.tool()
def send_board_pack_email(
    recipients: str = "", period: str = "",
    pl_summary: str = "", bs_summary: str = "", cf_summary: str = "", approval_token: str = ""
) -> dict:
    """Compile and send the monthly board pack to board members."""
    if approval_token:
        approved = _consume_email_approval("send_board_pack_email", approval_token)
        if not approved["success"]:
            return approved
        args = approved["pending"]["args"]
        recipients = args["recipients"]
        period = args["period"]
        pl_summary = args["pl_summary"]
        bs_summary = args["bs_summary"]
        cf_summary = args["cf_summary"]
    else:
        if not (recipients and period and pl_summary and bs_summary and cf_summary):
            return {"success": False, "message": "recipients, period, pl_summary, bs_summary, and cf_summary are required."}
        preview = {
            "title": "Board Pack Email",
            "to": recipients,
            "subject": f"Board Pack — {period}",
            "period": period,
            "sections": ["P&L", "Balance Sheet", "Cash Flow"],
            "full_sections": {
                "pl": pl_summary,
                "bs": bs_summary,
                "cf": cf_summary,
            },
            "summary_preview": {
                "pl": pl_summary[:350],
                "bs": bs_summary[:350],
                "cf": cf_summary[:350],
            },
        }
        return _create_email_approval(
            "send_board_pack_email",
            {
                "recipients": recipients,
                "period": period,
                "pl_summary": pl_summary,
                "bs_summary": bs_summary,
                "cf_summary": cf_summary,
            },
            preview,
        )

    result = send_board_pack(recipients, period, pl_summary, bs_summary, cf_summary)
    log_report_delivery("board_pack", "report_agent", recipients, period,
                        "sent" if result["success"] else "failed")
    return {"success": result["success"], "recipients": recipients, "period": period,
            "message": result["message"]}


@mcp.tool()
def get_report_history(limit: int = 20, report_type: str = "") -> list:
    """Return the full report audit trail from report_log."""
    conn = get_connection(); cur = _cur(conn)
    q = "SELECT id,report_type,generated_by,recipients,sent_at,period,status FROM report_log"
    params = []
    if report_type:
        q += " WHERE report_type ILIKE %s"; params.append(f"%{report_type}%")
    q += " ORDER BY sent_at DESC LIMIT %s"; params.append(limit)
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["sent_at"] = str(d["sent_at"])[:19]
        result.append(d)
    return result if result else [{"message": "No report history found."}]


@mcp.tool()
def schedule_report(
    report_type: str, frequency: str,
    recipients: str, created_by: str = ""
) -> dict:
    """Create a recurring report schedule (daily/weekly/monthly)."""
    if frequency not in ("daily","weekly","monthly"):
        return {"success": False, "message": "frequency must be 'daily', 'weekly', or 'monthly'"}
    conn = get_connection(); cur = _cur(conn)
    delta = {"daily": "INTERVAL '1 day'", "weekly": "INTERVAL '7 days'", "monthly": "INTERVAL '30 days'"}[frequency]
    cur.execute(f"""
        INSERT INTO report_schedules (report_type,frequency,recipients,next_run,is_active)
        VALUES (%s,%s,%s,NOW()+{delta},TRUE) RETURNING id
    """, (report_type, frequency, recipients))
    sid = cur.fetchone()["id"]; conn.commit(); conn.close()
    return {"success": True, "schedule_id": sid, "report_type": report_type,
            "frequency": frequency, "recipients": recipients,
            "message": f"'{report_type}' scheduled {frequency} → {recipients}"}


@mcp.tool()
def send_executive_alert_email(
    recipients: str = "", title: str = "", message: str = "", severity: str = "warning", approval_token: str = ""
) -> dict:
    """Send an urgent financial alert email to the executive team."""
    if approval_token:
        approved = _consume_email_approval("send_executive_alert_email", approval_token)
        if not approved["success"]:
            return approved
        args = approved["pending"]["args"]
        recipients = args["recipients"]
        title = args["title"]
        message = args["message"]
        severity = args["severity"]
    else:
        if not (recipients and title and message):
            return {"success": False, "message": "recipients, title, and message are required."}
        preview = {
            "title": "Executive Alert Email",
            "to": recipients,
            "subject": f"Executive Alert: {title}",
            "severity": severity,
            "message_full": message,
            "message_preview": message[:800],
        }
        return _create_email_approval(
            "send_executive_alert_email",
            {"recipients": recipients, "title": title, "message": message, "severity": severity},
            preview,
        )

    result = send_executive_alert(recipients, title, message, severity)
    log_report_delivery("executive_alert", "report_agent", recipients, "now",
                        "sent" if result["success"] else "failed")
    return {"success": result["success"], "recipients": recipients,
            "title": title, "severity": severity, "message": result["message"]}


@mcp.tool()
def get_report_recipients(report_type: str = "") -> list:
    """List all configured report recipients from report_schedules."""
    conn = get_connection(); cur = _cur(conn)
    q = "SELECT report_type,frequency,recipients,next_run,is_active FROM report_schedules"
    params = []
    if report_type:
        q += " WHERE report_type ILIKE %s"; params.append(f"%{report_type}%")
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["next_run"] = str(d["next_run"])[:16]
        result.append(d)
    return result if result else [{"message": "No report schedules configured."}]


@mcp.tool()
def log_report_delivery(
    report_type: str, generated_by: str,
    recipients: str, period: str, status: str = "sent"
) -> dict:
    """Write a delivery record to report_log for compliance."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        INSERT INTO report_log (report_type,generated_by,recipients,period,status)
        VALUES (%s,%s,%s,%s,%s) RETURNING id
    """, (report_type, generated_by, recipients, period, status))
    lid = cur.fetchone()["id"]; conn.commit(); conn.close()
    return {"success": True, "log_id": lid, "report_type": report_type,
            "status": status, "message": f"Report delivery logged (ID #{lid})"}


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
