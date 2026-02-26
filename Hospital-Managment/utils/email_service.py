"""utils/email_service.py — HTML email sender via Gmail SMTP"""
import smtplib, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
load_dotenv()

def send_email(to_email: str, subject: str, html_body: str) -> dict:
    sender = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_APP_PASSWORD")
    if not sender or not password:
        return {"success": False, "message": "Email credentials not set in .env"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Hospital System <{sender}>"
        msg["To"] = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as s:
            s.login(sender, password)
            s.sendmail(sender, to_email, msg.as_string())
        return {"success": True, "message": f"Email sent to {to_email}"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def send_booking_confirmation(patient_name, patient_email, doctor_name, specialization, appointment_date, appointment_time, reason, appointment_id):
    subject = f"✅ Appointment Confirmed — {appointment_date} at {appointment_time}"
    html = f"""<div style="font-family:Arial;background:#0d1117;padding:30px;border-radius:12px;max-width:600px;margin:auto">
    <div style="background:linear-gradient(135deg,#1a3a5c,#1f6feb);padding:24px;border-radius:8px;text-align:center">
      <h2 style="color:#fff;margin:0">🏥 Hospital Appointment System</h2>
      <span style="background:#238636;color:#fff;padding:4px 16px;border-radius:20px;font-size:13px">✅ CONFIRMED</span>
    </div>
    <div style="background:#161b22;padding:24px;border-radius:8px;margin-top:12px;color:#e6edf3">
      <p>Hello <b>{patient_name}</b>,</p>
      <table width="100%" style="border-collapse:collapse">
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Appointment ID</td><td style="color:#58a6ff;font-weight:bold">#{appointment_id}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Doctor</td><td>{doctor_name}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Specialization</td><td>{specialization}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Date</td><td>{appointment_date}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Time</td><td>{appointment_time}</td></tr>
        <tr><td style="padding:8px;color:#8b949e">Reason</td><td>{reason}</td></tr>
      </table>
      <p style="background:#1c2a1c;border:1px solid #238636;padding:12px;border-radius:8px;color:#3fb950">💡 Please arrive 10 minutes early. Keep Appointment ID <b>#{appointment_id}</b> handy.</p>
    </div></div>"""
    return send_email(patient_email, subject, html)

def send_cancellation_notice(patient_name, patient_email, doctor_name, appointment_date, appointment_time, appointment_id):
    subject = f"❌ Appointment Cancelled — #{appointment_id}"
    html = f"""<div style="font-family:Arial;background:#0d1117;padding:30px;border-radius:12px;max-width:600px;margin:auto">
    <div style="background:linear-gradient(135deg,#3a1a1a,#b91c1c);padding:24px;border-radius:8px;text-align:center">
      <h2 style="color:#fff;margin:0">🏥 Hospital Appointment System</h2>
      <span style="background:#b91c1c;color:#fff;padding:4px 16px;border-radius:20px;font-size:13px">❌ CANCELLED</span>
    </div>
    <div style="background:#161b22;padding:24px;border-radius:8px;margin-top:12px;color:#e6edf3">
      <p>Hello <b>{patient_name}</b>, your appointment has been cancelled.</p>
      <table width="100%" style="border-collapse:collapse">
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Appointment ID</td><td style="color:#f85149">#{appointment_id}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Doctor</td><td>{doctor_name}</td></tr>
        <tr><td style="padding:8px;color:#8b949e;border-bottom:1px solid #30363d">Date</td><td>{appointment_date}</td></tr>
        <tr><td style="padding:8px;color:#8b949e">Time</td><td>{appointment_time}</td></tr>
      </table>
      <p style="background:#2a1c1c;border:1px solid #b91c1c;padding:12px;border-radius:8px;color:#f85149">💡 You can book a new appointment anytime.</p>
    </div></div>"""
    return send_email(patient_email, subject, html)