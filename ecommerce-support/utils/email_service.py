"""utils/email_service.py — HTML email notifications for the E-Commerce Support System."""
import os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()


def _send(to_email: str, subject: str, html: str) -> dict:
    sender   = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_APP_PASSWORD")
    if not sender or not password:
        return {"success": False, "message": "Email credentials not configured in .env"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"ShopAI Support <{sender}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender, password)
            s.sendmail(sender, to_email, msg.as_string())
        return {"success": True, "message": f"Email sent to {to_email}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _wrap(content: str, badge: str, badge_color: str) -> str:
    return f"""
<div style="font-family:Arial,sans-serif;background:#0f172a;padding:28px;max-width:600px;margin:auto;border-radius:12px">
  <div style="background:linear-gradient(135deg,#1e3a5f,#1d4ed8);padding:20px;border-radius:8px;text-align:center;margin-bottom:14px">
    <h2 style="color:#fff;margin:0;font-size:18px">🛒 ShopAI Customer Support</h2>
    <span style="background:{badge_color};color:#fff;padding:3px 16px;border-radius:20px;font-size:12px;margin-top:6px;display:inline-block">{badge}</span>
  </div>
  <div style="background:#1e293b;padding:20px;border-radius:8px;color:#e2e8f0">{content}</div>
  <p style="color:#475569;font-size:11px;text-align:center;margin-top:10px">ShopAI Automated Notification — reply to this email to reach a human agent.</p>
</div>"""


def send_order_status_email(name: str, email: str, order_id: int, status: str, tracking: str, carrier: str) -> dict:
    content = f"""<p>Hello <b>{name}</b>,</p>
<p>Here is the latest update for your order.</p>
<table width="100%" style="border-collapse:collapse;margin:10px 0">
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Order ID</td><td style="color:#60a5fa;font-weight:bold">#{order_id}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Status</td><td style="color:#4ade80;font-weight:bold">{status.replace('_',' ').title()}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Tracking No.</td><td>{tracking or 'Not yet assigned'}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8">Carrier</td><td>{carrier or 'TBD'}</td></tr>
</table>"""
    return _send(email, f"📦 Order #{order_id} Update — {status.title()}", _wrap(content, "ORDER UPDATE", "#1d4ed8"))


def send_return_confirmation_email(name: str, email: str, return_id: int, order_id: int, reason: str) -> dict:
    content = f"""<p>Hello <b>{name}</b>,</p>
<p>Your return request has been received.</p>
<table width="100%" style="border-collapse:collapse;margin:10px 0">
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Return ID</td><td style="color:#fb923c;font-weight:bold">#{return_id}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Order ID</td><td>#{order_id}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8">Reason</td><td>{reason}</td></tr>
</table>
<p style="background:#431407;border:1px solid #c2410c;padding:10px;border-radius:6px;color:#fdba74">💡 We will review your return within 24–48 hours and email you the outcome.</p>"""
    return _send(email, f"🔄 Return Request #{return_id} Received", _wrap(content, "RETURN INITIATED", "#c2410c"))


def send_refund_email(name: str, email: str, refund_id: int, amount: float, method: str) -> dict:
    content = f"""<p>Hello <b>{name}</b>,</p>
<p style="color:#4ade80;font-weight:bold">✅ Your refund has been processed!</p>
<table width="100%" style="border-collapse:collapse;margin:10px 0">
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Refund ID</td><td style="color:#60a5fa;font-weight:bold">#{refund_id}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Amount</td><td style="color:#4ade80;font-weight:bold">₹{amount:,.0f}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8">Refund Method</td><td>{method.replace('_',' ').title()}</td></tr>
</table>
<p style="background:#14532d;border:1px solid #15803d;padding:10px;border-radius:6px;color:#86efac">💡 Expect funds within 3–5 business days for bank refunds, or instant for store credit.</p>"""
    return _send(email, f"💚 Refund of ₹{amount:,.0f} Processed", _wrap(content, "REFUND PROCESSED", "#15803d"))


def send_complaint_email(name: str, email: str, complaint_id: int, complaint_type: str, priority: str) -> dict:
    priority_color = {"urgent": "#9b1c1c", "high": "#c2410c", "medium": "#b45309", "low": "#15803d"}.get(priority, "#1d4ed8")
    content = f"""<p>Hello <b>{name}</b>,</p>
<p>Your complaint has been registered and our team is on it.</p>
<table width="100%" style="border-collapse:collapse;margin:10px 0">
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Complaint ID</td><td style="color:#60a5fa;font-weight:bold">#{complaint_id}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Type</td><td>{complaint_type.replace('_',' ').title()}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8">Priority</td><td style="color:{priority_color};font-weight:bold">{priority.upper()}</td></tr>
</table>
<p style="background:#1e3a5f;border:1px solid #1d4ed8;padding:10px;border-radius:6px;color:#93c5fd">💡 Our team will respond within {'1 hour' if priority == 'urgent' else '4 hours' if priority == 'high' else '24 hours'}.</p>"""
    return _send(email, f"⭐ Complaint #{complaint_id} Filed — {priority.title()} Priority", _wrap(content, f"{priority.upper()} PRIORITY", priority_color))


def send_loyalty_points_email(name: str, email: str, points_added: int, new_balance: int, reason: str) -> dict:
    content = f"""<p>Hello <b>{name}</b>,</p>
<p style="color:#4ade80;font-weight:bold">🎁 Your loyalty points have been updated!</p>
<table width="100%" style="border-collapse:collapse;margin:10px 0">
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">Points Added</td><td style="color:#4ade80;font-weight:bold">+{points_added:,}</td></tr>
  <tr><td style="padding:7px;color:#94a3b8;border-bottom:1px solid #334155">New Balance</td><td style="font-weight:bold">⭐ {new_balance:,} points</td></tr>
  <tr><td style="padding:7px;color:#94a3b8">Reason</td><td>{reason}</td></tr>
</table>"""
    return _send(email, f"🎁 +{points_added:,} Loyalty Points Earned!", _wrap(content, "POINTS UPDATED", "#15803d"))