"""utils/email_service.py — HTML email notifications for the loan system."""
import os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

def _send(to_email: str, subject: str, html: str) -> dict:
    sender   = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_APP_PASSWORD")
    if not sender or not password:
        return {"success": False, "message": "Email credentials not set in .env"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Loan System <{sender}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender, password)
            s.sendmail(sender, to_email, msg.as_string())
        return {"success": True, "message": f"Email sent to {to_email}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def _base(content: str, badge_color: str, badge_text: str) -> str:
    return f"""
<div style="font-family:Arial,sans-serif;background:#0f172a;padding:32px;max-width:620px;margin:auto;border-radius:14px">
  <div style="background:linear-gradient(135deg,#1e3a5f,#1d4ed8);padding:24px 28px;border-radius:10px;text-align:center;margin-bottom:16px">
    <h2 style="color:#fff;margin:0;font-size:20px">🏦 Loan & Credit System</h2>
    <span style="background:{badge_color};color:#fff;padding:4px 18px;border-radius:20px;font-size:13px;margin-top:8px;display:inline-block">{badge_text}</span>
  </div>
  <div style="background:#1e293b;padding:24px 28px;border-radius:10px;color:#e2e8f0">{content}</div>
  <p style="color:#475569;font-size:12px;text-align:center;margin-top:14px">This is an automated notification from the Loan & Credit Processing System.</p>
</div>"""

def send_application_confirmation(name: str, email: str, app_id: int, loan_type: str, amount: float, purpose: str) -> dict:
    content = f"""
<p>Hello <b>{name}</b>,</p>
<p>Your loan application has been received and is under review.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0">
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Application ID</td><td style="color:#60a5fa;font-weight:bold">#{app_id}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Loan Type</td><td>{loan_type.title()}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Amount Requested</td><td style="font-weight:bold">₹{amount:,.0f}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Purpose</td><td>{purpose}</td></tr>
</table>
<p style="background:#1e3a5f;border:1px solid #1d4ed8;padding:12px;border-radius:8px;color:#93c5fd">💡 Next step: Our team will verify your KYC documents. You will be notified at each stage.</p>"""
    return _send(email, f"✅ Loan Application #{app_id} Received", _base(content, "#1d4ed8", "APPLICATION RECEIVED"))

def send_approval_email(name: str, email: str, app_id: int, amount: float, rate: float, months: int, emi: float) -> dict:
    content = f"""
<p>Hello <b>{name}</b>,</p>
<p style="color:#4ade80;font-weight:bold;font-size:16px">🎉 Congratulations! Your loan has been approved.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0">
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Application ID</td><td style="color:#60a5fa;font-weight:bold">#{app_id}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Approved Amount</td><td style="color:#4ade80;font-weight:bold">₹{amount:,.0f}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Interest Rate</td><td>{rate}% per annum</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Loan Term</td><td>{months} months</td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Monthly EMI</td><td style="font-weight:bold;color:#4ade80">₹{emi:,.0f}</td></tr>
</table>
<p style="background:#14532d;border:1px solid #15803d;padding:12px;border-radius:8px;color:#86efac">💡 Funds will be disbursed to your registered bank account within 24–48 hours.</p>"""
    return _send(email, f"🎉 Loan Approved — ₹{amount:,.0f} @ {rate}%", _base(content, "#15803d", "✅ APPROVED"))

def send_rejection_email(name: str, email: str, app_id: int, reason: str) -> dict:
    content = f"""
<p>Hello <b>{name}</b>,</p>
<p>We regret to inform you that your loan application has not been approved at this time.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0">
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Application ID</td><td style="color:#f87171;font-weight:bold">#{app_id}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Decision Reason</td><td>{reason}</td></tr>
</table>
<p style="background:#450a0a;border:1px solid #9b1c1c;padding:12px;border-radius:8px;color:#fca5a5">💡 You may re-apply after 6 months or contact our helpdesk for guidance on improving your profile.</p>"""
    return _send(email, f"❌ Loan Application #{app_id} — Decision", _base(content, "#9b1c1c", "NOT APPROVED"))

def send_payment_reminder(name: str, email: str, loan_id: int, due_date: str, amount: float, installment_no: int) -> dict:
    content = f"""
<p>Hello <b>{name}</b>,</p>
<p>This is a friendly reminder that your loan installment is due soon.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0">
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Loan ID</td><td style="color:#60a5fa;font-weight:bold">#{loan_id}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Installment No.</td><td>#{installment_no}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8;border-bottom:1px solid #334155">Due Date</td><td style="color:#fb923c;font-weight:bold">{due_date}</td></tr>
  <tr><td style="padding:8px;color:#94a3b8">Amount Due</td><td style="font-weight:bold;color:#fb923c">₹{amount:,.0f}</td></tr>
</table>
<p style="background:#431407;border:1px solid #c2410c;padding:12px;border-radius:8px;color:#fdba74">💡 Please ensure sufficient funds in your account. Late payments attract a 2% penalty.</p>"""
    return _send(email, f"⏰ EMI Reminder — ₹{amount:,.0f} due on {due_date}", _base(content, "#c2410c", "PAYMENT DUE"))

def send_kyc_approved_email(name: str, email: str) -> dict:
    content = f"""
<p>Hello <b>{name}</b>,</p>
<p style="color:#4ade80;font-weight:bold">✅ Your KYC verification has been successfully completed.</p>
<p>Your identity, documents, employment, and AML checks have all passed. Your application is now moving to the credit assessment stage.</p>
<p style="background:#14532d;border:1px solid #15803d;padding:12px;border-radius:8px;color:#86efac">💡 You will receive the final loan decision within 1–2 business days.</p>"""
    return _send(email, "✅ KYC Verification Approved", _base(content, "#15803d", "KYC APPROVED"))