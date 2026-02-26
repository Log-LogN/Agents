"""
utils/email_service.py
══════════════════════
HTML email notification templates for the HR Hiring System.
All emails share a consistent dark-navy brand theme.
"""

import os, smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()


def _send(to_email: str, subject: str, html: str) -> dict:
    sender   = os.getenv("EMAIL_SENDER")
    password = os.getenv("EMAIL_APP_PASSWORD")
    if not sender or not password:
        return {"success": False, "message": "Email credentials not configured in .env — skipping send."}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"HireSmart AI <{sender}>"
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
<div style="font-family:Arial,sans-serif;background:#0f172a;padding:28px;max-width:620px;margin:auto;border-radius:12px">
  <div style="background:linear-gradient(135deg,#1e3a5f,#1d4ed8);padding:22px;border-radius:8px;text-align:center;margin-bottom:16px">
    <h2 style="color:#fff;margin:0;font-size:20px">📄 HireSmart Hiring System</h2>
    <span style="background:{badge_color};color:#fff;padding:4px 18px;border-radius:20px;font-size:12px;margin-top:8px;display:inline-block;font-weight:600">{badge}</span>
  </div>
  <div style="background:#1e293b;padding:22px;border-radius:8px;color:#e2e8f0;line-height:1.7">{content}</div>
  <p style="color:#475569;font-size:11px;text-align:center;margin-top:12px">HireSmart AI — Automated HR Notification. Contact hr@hrapp.com for queries.</p>
</div>"""


def _row(label: str, value: str) -> str:
    return f'<tr><td style="padding:8px 10px;color:#94a3b8;border-bottom:1px solid #334155;width:40%">{label}</td><td style="padding:8px 10px;color:#e2e8f0;font-weight:500;border-bottom:1px solid #334155">{value}</td></tr>'


# ── 1. Application Confirmation ───────────────────────────────────────────────
def send_application_confirmation(name: str, email: str, job_title: str, job_id: int) -> dict:
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>Thank you for applying to <b>{job_title}</b>. We have received your application and our team will review it shortly.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Job Title", job_title)}
  {_row("Application ID", f"APP-{job_id}-{email[:3].upper()}")}
  {_row("Status", "Under Review")}
  {_row("Next Step", "Our recruiter will contact you within 5 business days")}
</table>
<p style="color:#94a3b8;font-size:13px">We review every application carefully. You will receive an update regardless of the outcome.</p>"""
    return _send(email, f"✅ Application Received — {job_title}", _wrap(content, "APPLICATION CONFIRMED", "#15803d"))


# ── 2. Status Update ──────────────────────────────────────────────────────────
def send_status_update(name: str, email: str, job_title: str, new_status: str, message: str = "") -> dict:
    status_colors = {
        "shortlisted": "#15803d", "screening": "#1d4ed8",
        "interview": "#0e7490",   "offer": "#b45309",
        "hired": "#15803d",       "rejected": "#c2410c",
    }
    color = status_colors.get(new_status, "#334155")
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>We have an update on your application for <b>{job_title}</b>.</p>
<div style="background:#162032;padding:14px;border-radius:6px;border-left:4px solid {color};margin:12px 0">
  <span style="color:{color};font-weight:700;font-size:16px">Status: {new_status.replace('_',' ').title()}</span>
</div>
{f'<p>{message}</p>' if message else ''}
<p style="color:#94a3b8;font-size:13px">If you have any questions, reply to this email or contact your recruiter.</p>"""
    return _send(email, f"📋 Application Update — {new_status.replace('_',' ').title()}", _wrap(content, "STATUS UPDATE", color))


# ── 3. Interview Invitation ───────────────────────────────────────────────────
def send_interview_invitation(name: str, email: str, job_title: str, scheduled_at: str,
                               duration_mins: int, interview_type: str, round_num: int,
                               interviewer_name: str, meeting_link: str) -> dict:
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>We are pleased to invite you for an interview for the <b>{job_title}</b> position.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Interview Type", interview_type.replace('_',' ').title())}
  {_row("Round", f"Round {round_num}")}
  {_row("Date & Time", scheduled_at)}
  {_row("Duration", f"{duration_mins} minutes")}
  {_row("Interviewer", interviewer_name)}
  {_row("Meeting Link", f'<a href="{meeting_link}" style="color:#60a5fa">{meeting_link}</a>')}
</table>
<p style="color:#94a3b8;font-size:13px">Please confirm your availability by replying to this email. If you need to reschedule, contact us at least 24 hours in advance.</p>"""
    return _send(email, f"📅 Interview Invitation — {job_title} (Round {round_num})", _wrap(content, "INTERVIEW SCHEDULED", "#0e7490"))


# ── 4. Rejection Email ────────────────────────────────────────────────────────
def send_rejection_email(name: str, email: str, job_title: str, feedback: str = "") -> dict:
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>Thank you for your time and interest in the <b>{job_title}</b> position at HireSmart.</p>
<p>After careful consideration, we have decided to move forward with other candidates whose experience more closely matches our current requirements.</p>
{f'<div style="background:#162032;padding:12px;border-radius:6px;border-left:4px solid #475569;margin:12px 0"><p style="color:#94a3b8;margin:0"><b>Feedback:</b> {feedback}</p></div>' if feedback else ''}
<p>We encourage you to apply for future openings that match your profile. We will keep your details on file for 6 months.</p>
<p style="color:#94a3b8;font-size:13px">We appreciate the time you invested in our hiring process.</p>"""
    return _send(email, f"Application Update — {job_title}", _wrap(content, "APPLICATION UPDATE", "#475569"))


# ── 5. Offer Letter Email ─────────────────────────────────────────────────────
def send_offer_email(name: str, email: str, job_title: str, salary: float,
                      currency: str, start_date: str, benefits: str, equity: str = "") -> dict:
    salary_fmt = f"{currency} {salary:,.0f} per annum"
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>We are thrilled to extend an official offer of employment for the position of <b>{job_title}</b> at HireSmart.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Position", job_title)}
  {_row("Compensation", salary_fmt)}
  {_row("Start Date", start_date)}
  {_row("Benefits", benefits)}
  {_row("Equity", equity or "N/A")}
</table>
<p>Please review the offer and respond within <b>5 business days</b>. Reply to this email to accept or request a call to discuss.</p>
<p style="color:#94a3b8;font-size:13px">We look forward to welcoming you to our team!</p>"""
    return _send(email, f"🎉 Offer Letter — {job_title} at HireSmart", _wrap(content, "OFFER EXTENDED", "#b45309"))


# ── 6. Welcome / Onboarding Email ─────────────────────────────────────────────
def send_welcome_email(name: str, email: str, job_title: str, start_date: str,
                        buddy_name: str, buddy_email: str) -> dict:
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>Welcome to HireSmart! We are so excited to have you join us as <b>{job_title}</b>.</p>
<table width="100%" style="border-collapse:collapse;margin:12px 0;background:#162032;border-radius:6px">
  {_row("Start Date", start_date)}
  {_row("Reporting Time", "9:30 AM")}
  {_row("Your Buddy", f"{buddy_name} ({buddy_email})")}
  {_row("First Day Location", "HireSmart HQ, Tower B, Ground Floor Reception")}
</table>
<div style="background:#162032;padding:14px;border-radius:6px;border-left:4px solid #15803d;margin:12px 0">
  <p style="margin:0;color:#4ade80;font-weight:600">📋 Before Day 1 Checklist</p>
  <ul style="color:#94a3b8;margin:8px 0;padding-left:20px">
    <li>Check your work email (being set up by IT)</li>
    <li>Complete the online HR forms sent separately</li>
    <li>Contact your buddy {buddy_name} to introduce yourself</li>
  </ul>
</div>
<p style="color:#94a3b8;font-size:13px">Questions? Email hr@hrapp.com or reply to this message.</p>"""
    return _send(email, f"🎉 Welcome to HireSmart — Your Journey Starts {start_date}", _wrap(content, "WELCOME ABOARD", "#15803d"))


# ── 7. Check-in Email (30/60/90 day) ─────────────────────────────────────────
def send_checkin_email(name: str, email: str, job_title: str, day_milestone: int) -> dict:
    milestone_msgs = {
        30: ("30-Day Check-In", "You have completed your first month! We hope you are settling in well."),
        60: ("60-Day Check-In", "You are two months in — half way through your formal onboarding period!"),
        90: ("90-Day Review",   "Congratulations on completing 90 days! This marks the end of your onboarding."),
    }
    label, msg = milestone_msgs.get(day_milestone, (f"{day_milestone}-Day Check-In", "Time for a check-in!"))
    content = f"""<p>Dear <b>{name}</b>,</p>
<p>{msg}</p>
<p>As part of our structured onboarding, we would love to hear how things are going in your role as <b>{job_title}</b>.</p>
<div style="background:#162032;padding:14px;border-radius:6px;border-left:4px solid #1d4ed8;margin:12px 0">
  <p style="margin:0;color:#60a5fa;font-weight:600">Questions for your check-in:</p>
  <ul style="color:#94a3b8;margin:8px 0;padding-left:20px">
    <li>How are you finding the role so far?</li>
    <li>Do you have everything you need to do your work?</li>
    <li>Any blockers or support you need from HR or your manager?</li>
    <li>Are the goals for your role clear?</li>
  </ul>
</div>
<p>Please reply to this email or book a 30-minute call with your HR partner.</p>"""
    return _send(email, f"📋 {label} — {job_title}", _wrap(content, label.upper(), "#1d4ed8"))


# ── 8. Buddy Introduction ─────────────────────────────────────────────────────
def send_buddy_intro_email(new_hire_name: str, new_hire_email: str,
                            buddy_name: str, buddy_email: str, job_title: str, start_date: str) -> dict:
    content_buddy = f"""<p>Dear <b>{buddy_name}</b>,</p>
<p>You have been assigned as the onboarding buddy for <b>{new_hire_name}</b>, who joins as <b>{job_title}</b> on <b>{start_date}</b>.</p>
<p>As their buddy, please reach out before their start date to introduce yourself and answer any questions they have about the team and culture.</p>
<p style="color:#94a3b8;font-size:13px">New hire email: {new_hire_email}</p>"""
    return _send(buddy_email, f"🤝 Onboarding Buddy Assignment — {new_hire_name}", _wrap(content_buddy, "BUDDY ASSIGNED", "#0e7490"))


# ── 9. Bulk Status Update ─────────────────────────────────────────────────────
def send_bulk_update(candidates: list, subject: str, message: str) -> dict:
    """Send the same message to multiple candidates."""
    results = []
    for c in candidates:
        content = f"""<p>Dear <b>{c['name']}</b>,</p><p>{message}</p>"""
        r = _send(c["email"], subject, _wrap(content, "IMPORTANT UPDATE", "#334155"))
        results.append({"email": c["email"], **r})
    sent    = sum(1 for r in results if r.get("success"))
    failed  = len(results) - sent
    return {"total": len(results), "sent": sent, "failed": failed, "details": results}