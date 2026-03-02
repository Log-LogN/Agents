"""
utils/email_service.py
══════════════════════
HTML email templates for the Financial Report Generator.
All emails use a consistent dark-navy financial theme.
"""

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()


def _send(to_emails: list[str] | str, subject: str, html: str) -> dict:
    sender   = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_APP_PASSWORD")
    if not sender or not password:
        return {"success": False, "message": "Email credentials not configured in .env — skipping send."}
    if isinstance(to_emails, str):
        to_emails = [e.strip() for e in to_emails.split(",") if e.strip()]
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"FinReport AI <{sender}>"
        msg["To"]      = ", ".join(to_emails)
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender, password)
            s.sendmail(sender, to_emails, msg.as_string())
        return {"success": True, "message": f"Email sent to {', '.join(to_emails)}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _wrap(content: str, badge: str, badge_color: str) -> str:
    return f"""
<div style="font-family:Arial,sans-serif;background:#0f172a;padding:28px;max-width:640px;margin:auto;border-radius:12px">
  <div style="background:linear-gradient(135deg,#1e3a5f,#1d4ed8);padding:22px;border-radius:8px;text-align:center;margin-bottom:16px">
    <h2 style="color:#fff;margin:0;font-size:20px">📊 FinReport AI — Financial Intelligence</h2>
    <span style="background:{badge_color};color:#fff;padding:4px 18px;border-radius:20px;font-size:12px;margin-top:8px;display:inline-block;font-weight:600">{badge}</span>
  </div>
  <div style="background:#1e293b;padding:22px;border-radius:8px;color:#e2e8f0;line-height:1.8">{content}</div>
  <p style="color:#475569;font-size:11px;text-align:center;margin-top:12px">FinReport AI — Automated Financial Notification. Contact admin@finapp.com for queries.</p>
</div>"""


def _row(label: str, value: str, highlight: bool = False) -> str:
    color = "#fbbf24" if highlight else "#e2e8f0"
    return (f'<tr><td style="padding:8px 10px;color:#94a3b8;border-bottom:1px solid #334155;width:45%">{label}</td>'
            f'<td style="padding:8px 10px;color:{color};font-weight:{"700" if highlight else "400"};border-bottom:1px solid #334155">{value}</td></tr>')


# ── 1. Cash Alert ─────────────────────────────────────────────────────────────
def send_cash_alert(recipients: str, current_cash: float, threshold: float, runway_days: int) -> dict:
    content = f"""<p>⚠️ <b>Cash Position Alert</b></p>
<p>The company's cash balance has dropped below the configured threshold.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Current Cash Balance", f"₹{current_cash:,.0f}", True)}
  {_row("Alert Threshold", f"₹{threshold:,.0f}")}
  {_row("Estimated Runway", f"{runway_days} days")}
  {_row("Status", "⚠️ BELOW THRESHOLD — Immediate action required", True)}
</table>
<p style="color:#94a3b8;font-size:13px">Please review cash flow and AR collections immediately.</p>"""
    return _send(recipients, "🚨 Cash Alert — Balance Below Threshold", _wrap(content, "CASH ALERT", "#c2410c"))


# ── 2. Budget Variance Alert ──────────────────────────────────────────────────
def send_variance_alert(recipients: str, department: str, budget: float, actual: float, variance_pct: float) -> dict:
    content = f"""<p>📊 <b>Budget Variance Alert — {department}</b></p>
<p>A department has exceeded its approved budget by more than the configured threshold.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Department", department)}
  {_row("Approved Budget", f"₹{budget:,.0f}")}
  {_row("Actual Spend", f"₹{actual:,.0f}", True)}
  {_row("Variance", f"₹{actual-budget:,.0f} ({variance_pct:.1f}% over)", True)}
</table>
<p style="color:#94a3b8;font-size:13px">Please review department spend and update the forecast accordingly.</p>"""
    return _send(recipients, f"📊 Budget Overspend Alert — {department}", _wrap(content, "VARIANCE ALERT", "#b45309"))


# ── 3. Weekly KPI Digest ──────────────────────────────────────────────────────
def send_kpi_digest(recipients: str, period: str, kpis: dict) -> dict:
    rows = "".join(_row(k.replace("_", " ").title(), str(v)) for k, v in kpis.items())
    content = f"""<p>📈 <b>Weekly KPI Digest — {period}</b></p>
<p>Here is your automated financial KPI summary for the period.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {rows}
</table>
<p style="color:#94a3b8;font-size:13px">All figures calculated from live transaction data.</p>"""
    return _send(recipients, f"📈 Weekly KPI Digest — {period}", _wrap(content, "KPI DIGEST", "#15803d"))


# ── 4. Financial Report Email ─────────────────────────────────────────────────
def send_report_email(recipients: str, report_type: str, period: str, summary: str) -> dict:
    content = f"""<p>📄 <b>{report_type} — {period}</b></p>
<p>Your automated financial report is ready.</p>
<div style="background:#162032;border:1px solid #1d4ed8;border-left:5px solid #1d4ed8;
            border-radius:8px;padding:14px;margin:12px 0;white-space:pre-wrap;
            font-family:monospace;font-size:13px;color:#cbd5e1">{summary}</div>
<p style="color:#94a3b8;font-size:13px">Generated automatically by FinReport AI.</p>"""
    return _send(recipients, f"📄 {report_type} — {period}", _wrap(content, report_type.upper(), "#1d4ed8"))


# ── 5. Board Pack ─────────────────────────────────────────────────────────────
def send_board_pack(recipients: str, period: str, pl_summary: str, bs_summary: str, cf_summary: str) -> dict:
    content = f"""<p>📋 <b>Board Pack — {period}</b></p>
<p>Please find the quarterly board pack containing P&amp;L, Balance Sheet, and Cash Flow summaries.</p>

<p><b style="color:#60a5fa">Profit & Loss Summary</b></p>
<div style="background:#162032;border-left:4px solid #1d4ed8;padding:10px;border-radius:6px;margin-bottom:10px;
            font-size:12px;white-space:pre-wrap;font-family:monospace;color:#cbd5e1">{pl_summary}</div>

<p><b style="color:#4ade80">Balance Sheet Summary</b></p>
<div style="background:#162032;border-left:4px solid #15803d;padding:10px;border-radius:6px;margin-bottom:10px;
            font-size:12px;white-space:pre-wrap;font-family:monospace;color:#cbd5e1">{bs_summary}</div>

<p><b style="color:#fbbf24">Cash Flow Summary</b></p>
<div style="background:#162032;border-left:4px solid #b45309;padding:10px;border-radius:6px;margin-bottom:10px;
            font-size:12px;white-space:pre-wrap;font-family:monospace;color:#cbd5e1">{cf_summary}</div>

<p style="color:#94a3b8;font-size:13px">Confidential — For Board Members Only.</p>"""
    return _send(recipients, f"📋 Board Pack — {period}", _wrap(content, "BOARD PACK", "#1e3a5f"))


# ── 6. Executive Alert ────────────────────────────────────────────────────────
def send_executive_alert(recipients: str, title: str, message: str, severity: str = "warning") -> dict:
    colors = {"critical": "#c2410c", "warning": "#b45309", "info": "#1d4ed8"}
    color  = colors.get(severity, "#b45309")
    content = f"""<p>🔔 <b>{title}</b></p>
<div style="background:#162032;border-left:5px solid {color};padding:14px;border-radius:8px;margin:12px 0">
  <p style="color:#e2e8f0;margin:0">{message}</p>
</div>
<p style="color:#94a3b8;font-size:13px">Sent by FinReport AI automated monitoring system.</p>"""
    return _send(recipients, f"🔔 Executive Alert: {title}", _wrap(content, severity.upper(), color))