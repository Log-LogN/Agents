"""mcp_servers/pharmacy_server.py — Pharmacy tools MCP server (port 8004)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("PharmacyServer", host="127.0.0.1", port=8004, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# Known drug interactions (simplified knowledge base)
DRUG_INTERACTIONS = {
    ("warfarin", "aspirin"): "HIGH RISK: Increased bleeding risk.",
    ("aspirin", "warfarin"): "HIGH RISK: Increased bleeding risk.",
    ("metformin", "alcohol"): "MODERATE: Risk of lactic acidosis.",
    ("ssri", "maoi"): "HIGH RISK: Serotonin syndrome risk.",
    ("simvastatin", "amiodarone"): "HIGH RISK: Myopathy risk.",
}

@mcp.tool()
def create_prescription(patient_email: str, doctor_id: int, medication: str, dosage: str, frequency: str, duration_days: int, notes: str = "") -> dict:
    """Create a new prescription for a patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT name FROM patients WHERE email=%s", (patient_email,))
    patient = c.fetchone()
    if not patient: conn.close(); return {"status": "error", "message": f"Patient '{patient_email}' not found."}
    c.execute("SELECT name FROM doctors WHERE id=%s", (doctor_id,))
    doctor = c.fetchone()
    if not doctor: conn.close(); return {"status": "error", "message": f"Doctor {doctor_id} not found."}
    c.execute("""INSERT INTO prescriptions (patient_email,doctor_id,medication,dosage,frequency,duration_days,notes)
                 VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
              (patient_email, doctor_id, medication, dosage, frequency, duration_days, notes))
    presc_id = c.fetchone()["id"]; conn.commit(); conn.close()
    return {"status": "created", "prescription_id": presc_id,
            "message": f"✅ Prescription #{presc_id} created for {patient['name']}: {medication} {dosage}, {frequency} for {duration_days} days."}

@mcp.tool()
def get_patient_prescriptions(patient_email: str) -> list:
    """Get all prescriptions for a patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT p.id,p.medication,p.dosage,p.frequency,p.duration_days,p.status,p.created_at,d.name AS doctor_name
                 FROM prescriptions p JOIN doctors d ON p.doctor_id=d.id
                 WHERE p.patient_email=%s ORDER BY p.created_at DESC""", (patient_email,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": f"No prescriptions for '{patient_email}'."}]
    return [{**dict(r), "created_at": str(r["created_at"])} for r in rows]

@mcp.tool()
def check_drug_interactions(drug1: str, drug2: str) -> dict:
    """Check for known interactions between two drugs."""
    key1 = (drug1.lower(), drug2.lower())
    key2 = (drug2.lower(), drug1.lower())
    interaction = DRUG_INTERACTIONS.get(key1) or DRUG_INTERACTIONS.get(key2)
    if interaction:
        return {"interaction_found": True, "drug1": drug1, "drug2": drug2,
                "severity": interaction, "recommendation": "Consult prescribing doctor before dispensing."}
    return {"interaction_found": False, "drug1": drug1, "drug2": drug2,
            "message": f"✅ No known interaction between {drug1} and {drug2} in the database."}

@mcp.tool()
def check_dosage_safety(medication: str, dosage_mg: float, patient_weight_kg: float, patient_age: int) -> dict:
    """Check if a dosage is safe for a patient based on weight and age."""
    # Simplified safety checks
    warnings = []
    if patient_age > 65 and dosage_mg > 500:
        warnings.append("Elderly patient — consider dose reduction.")
    if patient_age < 12 and dosage_mg > 200:
        warnings.append("Pediatric patient — dose may be too high.")
    if patient_weight_kg < 50 and dosage_mg > 400:
        warnings.append("Low body weight — consider dose adjustment.")
    if warnings:
        return {"safe": False, "warnings": warnings, "medication": medication,
                "dosage_mg": dosage_mg, "recommendation": "Review dose with prescribing physician."}
    return {"safe": True, "medication": medication, "dosage_mg": dosage_mg,
            "message": f"✅ Dosage appears appropriate for patient profile."}

@mcp.tool()
def dispense_medication(prescription_id: int) -> dict:
    """Mark a prescription as dispensed (fulfilled)."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM prescriptions WHERE id=%s", (prescription_id,))
    presc = c.fetchone()
    if not presc: conn.close(); return {"status": "error", "message": f"Prescription {prescription_id} not found."}
    if presc["status"] == "dispensed": conn.close(); return {"status": "error", "message": "Already dispensed."}
    if presc["status"] == "cancelled": conn.close(); return {"status": "error", "message": "Prescription is cancelled."}
    c.execute("UPDATE prescriptions SET status='dispensed' WHERE id=%s", (prescription_id,))
    conn.commit(); conn.close()
    return {"status": "dispensed", "message": f"✅ Prescription #{prescription_id} ({presc['medication']}) dispensed to patient."}

@mcp.tool()
def cancel_prescription(prescription_id: int, reason: str = "") -> dict:
    """Cancel an active prescription."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM prescriptions WHERE id=%s", (prescription_id,))
    presc = c.fetchone()
    if not presc: conn.close(); return {"status": "error", "message": f"Prescription {prescription_id} not found."}
    if presc["status"] in ("cancelled", "dispensed"):
        conn.close(); return {"status": "error", "message": f"Cannot cancel — status is '{presc['status']}'."}
    c.execute("UPDATE prescriptions SET status='cancelled' WHERE id=%s", (prescription_id,))
    conn.commit(); conn.close()
    return {"status": "cancelled", "message": f"❌ Prescription #{prescription_id} ({presc['medication']}) cancelled. Reason: {reason or 'Not provided'}"}

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Pharmacy MCP Server on http://127.0.0.1:8004/mcp")
    mcp.run(transport="streamable-http")