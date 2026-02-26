"""mcp_servers/appointment_server.py — Appointment tools MCP server (port 8001)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2
import psycopg2.extras
from database.db import get_connection, init_db
from utils.email_service import send_booking_confirmation, send_cancellation_notice

mcp = FastMCP("AppointmentServer", host="127.0.0.1", port=8001, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

def _doctor_slot_conflict(c, doctor_id: int, appointment_date: str, appointment_time: str, exclude_id: int | None = None):
    if exclude_id is None:
        c.execute(
            "SELECT id FROM appointments WHERE doctor_id=%s AND appointment_date=%s AND appointment_time=%s AND status='scheduled'",
            (doctor_id, appointment_date, appointment_time),
        )
    else:
        c.execute(
            "SELECT id FROM appointments WHERE doctor_id=%s AND appointment_date=%s AND appointment_time=%s AND status='scheduled' AND id!=%s",
            (doctor_id, appointment_date, appointment_time, exclude_id),
        )
    return c.fetchone()

def _patient_slot_conflict(c, patient_email: str, appointment_date: str, appointment_time: str, exclude_id: int | None = None):
    if exclude_id is None:
        c.execute(
            "SELECT id FROM appointments WHERE patient_email=%s AND appointment_date=%s AND appointment_time=%s AND status='scheduled'",
            (patient_email, appointment_date, appointment_time),
        )
    else:
        c.execute(
            "SELECT id FROM appointments WHERE patient_email=%s AND appointment_date=%s AND appointment_time=%s AND status='scheduled' AND id!=%s",
            (patient_email, appointment_date, appointment_time, exclude_id),
        )
    return c.fetchone()

@mcp.tool()
def validate_patient_info(name: str, email: str, age: int) -> dict:
    """Validate patient information. Returns valid (bool) and issues list."""
    issues = []
    if not name or len(name.strip()) < 2: issues.append("Name too short.")
    if not email or "@" not in email: issues.append("Invalid email.")
    if not isinstance(age, int) or age <= 0 or age > 120: issues.append("Invalid age.")
    return {"valid": len(issues) == 0, "issues": issues}

@mcp.tool()
def register_patient(name: str, email: str, age: int) -> dict:
    """Register a new patient. Returns existing record if email already used."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM patients WHERE email=%s", (email,))
    existing = c.fetchone()
    if existing:
        conn.close()
        return {"status": "already_exists", "message": f"Patient '{email}' already registered.", "patient_id": existing["id"]}
    c.execute("INSERT INTO patients (name,email,age) VALUES (%s,%s,%s) RETURNING id", (name, email, age))
    pid = c.fetchone()["id"]; conn.commit(); conn.close()
    return {"status": "registered", "message": f"Patient '{name}' registered.", "patient_id": pid}

@mcp.tool()
def get_doctors() -> list:
    """Get all doctors with id, name, specialization, email."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,name,specialization,email FROM doctors ORDER BY id")
    rows = c.fetchall(); conn.close()
    return [dict(r) for r in rows]

@mcp.tool()
def check_doctor_availability(doctor_id: int, appointment_date: str, appointment_time: str) -> dict:
    """Check if a doctor is free at the given date (YYYY-MM-DD) and time (HH:MM)."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,name FROM doctors WHERE id=%s", (doctor_id,))
    doc = c.fetchone()
    if not doc: conn.close(); return {"available": False, "message": f"Doctor {doctor_id} not found."}
    conflict = _doctor_slot_conflict(c, doctor_id, appointment_date, appointment_time); conn.close()
    if conflict: return {"available": False, "message": f"Dr. {doc['name']} is booked at that time."}
    return {"available": True, "message": f"Dr. {doc['name']} is available."}

@mcp.tool()
def book_appointment(patient_email: str, doctor_id: int, appointment_date: str, appointment_time: str, reason: str) -> dict:
    """Book an appointment. Sends confirmation email automatically."""
    conn = get_connection(); c = cur(conn)
    try:
        c.execute("SELECT id,name FROM patients WHERE email=%s", (patient_email,))
        patient = c.fetchone()
        if not patient:
            return {"status": "error", "message": f"Patient '{patient_email}' not found. Register first."}

        c.execute("SELECT id,name,specialization FROM doctors WHERE id=%s", (doctor_id,))
        doctor = c.fetchone()
        if not doctor:
            return {"status": "error", "message": f"Doctor {doctor_id} not found."}

        if _doctor_slot_conflict(c, doctor_id, appointment_date, appointment_time):
            return {"status": "error", "message": f"Dr. {doctor['name']} already booked at that time."}
        if _patient_slot_conflict(c, patient_email, appointment_date, appointment_time):
            return {"status": "error", "message": "You already have another appointment at that time."}

        try:
            c.execute(
                "INSERT INTO appointments (patient_email,doctor_id,appointment_date,appointment_time,reason) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (patient_email, doctor_id, appointment_date, appointment_time, reason),
            )
            appt_id = c.fetchone()["id"]
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            if _doctor_slot_conflict(c, doctor_id, appointment_date, appointment_time):
                return {"status": "error", "message": f"Dr. {doctor['name']} already booked at that time."}
            if _patient_slot_conflict(c, patient_email, appointment_date, appointment_time):
                return {"status": "error", "message": "You already have another appointment at that time."}
            return {"status": "error", "message": "Could not book this slot because it was taken. Please choose another time."}
    finally:
        conn.close()

    email_r = send_booking_confirmation(patient["name"], patient_email, doctor["name"], doctor["specialization"],
                                        str(appointment_date), str(appointment_time), reason, appt_id)
    note = "✉️ Confirmation email sent." if email_r["success"] else f"⚠️ Email failed: {email_r['message']}"
    return {"status": "booked", "appointment_id": appt_id,
            "message": f"✅ Booked! Dr. {doctor['name']} on {appointment_date} at {appointment_time}. {note}"}

@mcp.tool()
def cancel_appointment(appointment_id: int, patient_email: str) -> dict:
    """Cancel an appointment. Sends cancellation email automatically."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT a.*,d.name AS doctor_name FROM appointments a JOIN doctors d ON a.doctor_id=d.id WHERE a.id=%s", (appointment_id,))
    appt = c.fetchone()
    if not appt: conn.close(); return {"status": "error", "message": f"Appointment {appointment_id} not found."}
    if appt["patient_email"] != patient_email: conn.close(); return {"status": "error", "message": "You can only cancel your own appointments."}
    if appt["status"] == "cancelled": conn.close(); return {"status": "error", "message": "Already cancelled."}
    c.execute("UPDATE appointments SET status='cancelled' WHERE id=%s", (appointment_id,))
    conn.commit()
    c.execute("SELECT name FROM patients WHERE email=%s", (patient_email,))
    patient = c.fetchone(); conn.close()
    email_r = send_cancellation_notice(patient["name"] if patient else patient_email, patient_email,
                                       appt["doctor_name"], str(appt["appointment_date"]), str(appt["appointment_time"]), appointment_id)
    note = "✉️ Cancellation email sent." if email_r["success"] else f"⚠️ Email failed: {email_r['message']}"
    return {"status": "cancelled", "message": f"❌ Appointment #{appointment_id} cancelled. {note}"}

@mcp.tool()
def edit_appointment(appointment_id: int, patient_email: str, new_date: str, new_time: str) -> dict:
    """Reschedule an appointment to a new date (YYYY-MM-DD) and time (HH:MM)."""
    conn = get_connection(); c = cur(conn)
    try:
        c.execute("SELECT * FROM appointments WHERE id=%s", (appointment_id,))
        appt = c.fetchone()
        if not appt:
            return {"status": "error", "message": f"Appointment {appointment_id} not found."}
        if appt["patient_email"] != patient_email:
            return {"status": "error", "message": "Not your appointment."}
        if appt["status"] == "cancelled":
            return {"status": "error", "message": "Cannot edit a cancelled appointment."}

        if _doctor_slot_conflict(c, appt["doctor_id"], new_date, new_time, exclude_id=appointment_id):
            return {"status": "error", "message": f"Doctor booked at {new_date} {new_time}."}
        if _patient_slot_conflict(c, patient_email, new_date, new_time, exclude_id=appointment_id):
            return {"status": "error", "message": "You already have another appointment at that time."}

        try:
            c.execute("UPDATE appointments SET appointment_date=%s, appointment_time=%s WHERE id=%s",
                      (new_date, new_time, appointment_id))
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            if _doctor_slot_conflict(c, appt["doctor_id"], new_date, new_time, exclude_id=appointment_id):
                return {"status": "error", "message": f"Doctor booked at {new_date} {new_time}."}
            if _patient_slot_conflict(c, patient_email, new_date, new_time, exclude_id=appointment_id):
                return {"status": "error", "message": "You already have another appointment at that time."}
            return {"status": "error", "message": "Could not reschedule because the slot was taken. Please choose another time."}
    finally:
        conn.close()
    return {"status": "updated", "message": f"📅 Appointment #{appointment_id} rescheduled to {new_date} at {new_time}."}

@mcp.tool()
def get_patient_appointments(patient_email: str) -> list:
    """Get all appointments for a patient by email."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT a.id,a.appointment_date,a.appointment_time,a.reason,a.status,d.name AS doctor_name,d.specialization
                 FROM appointments a JOIN doctors d ON a.doctor_id=d.id
                 WHERE a.patient_email=%s ORDER BY a.appointment_date,a.appointment_time""", (patient_email,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": f"No appointments for '{patient_email}'."}]
    return [dict(r) for r in rows]

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Appointment MCP Server on http://127.0.0.1:8001/mcp")
    mcp.run(transport="streamable-http")
