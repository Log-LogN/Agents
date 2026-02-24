"""mcp_servers/ward_server.py — Ward/Bed tools MCP server (port 8006)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("WardServer", host="127.0.0.1", port=8006, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

@mcp.tool()
def get_bed_availability() -> dict:
    """Get bed availability summary across all wards."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT ward_name, status, COUNT(*) as count FROM beds GROUP BY ward_name,status ORDER BY ward_name,status")
    rows = c.fetchall()
    c.execute("SELECT COUNT(*) as total FROM beds")
    total = c.fetchone()["total"]
    c.execute("SELECT COUNT(*) as available FROM beds WHERE status='available'")
    available = c.fetchone()["available"]
    conn.close()
    wards = {}
    for r in rows:
        w = r["ward_name"]
        if w not in wards: wards[w] = {}
        wards[w][r["status"]] = r["count"]
    return {"total_beds": total, "available_beds": available, "occupied_beds": total - available, "by_ward": wards}

@mcp.tool()
def get_ward_beds(ward_name: str) -> list:
    """Get all beds and their status in a specific ward."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,bed_number,status,patient_email,assigned_at FROM beds WHERE LOWER(ward_name)=LOWER(%s) ORDER BY bed_number", (ward_name,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": f"Ward '{ward_name}' not found or has no beds."}]
    return [{**dict(r), "assigned_at": str(r["assigned_at"]) if r["assigned_at"] else None} for r in rows]

@mcp.tool()
def assign_bed(patient_email: str, ward_name: str) -> dict:
    """Assign the first available bed in a ward to a patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT name FROM patients WHERE email=%s", (patient_email,))
    patient = c.fetchone()
    if not patient: conn.close(); return {"status": "error", "message": f"Patient '{patient_email}' not found."}
    c.execute("SELECT * FROM beds WHERE LOWER(ward_name)=LOWER(%s) AND status='available' ORDER BY bed_number LIMIT 1", (ward_name,))
    bed = c.fetchone()
    if not bed: conn.close(); return {"status": "error", "message": f"No available beds in {ward_name}. Ward is full."}
    c.execute("UPDATE beds SET status='occupied', patient_email=%s, assigned_at=NOW() WHERE id=%s", (patient_email, bed["id"]))
    c.execute("INSERT INTO ward_events (bed_id,event_type,patient_email,notes) VALUES (%s,'admit',%s,%s)",
              (bed["id"], patient_email, f"Patient {patient['name']} admitted to {bed['bed_number']}"))
    conn.commit(); conn.close()
    return {"status": "assigned", "bed_number": bed["bed_number"], "ward": ward_name,
            "message": f"✅ Bed {bed['bed_number']} in {ward_name} assigned to {patient['name']}."}

@mcp.tool()
def discharge_patient(patient_email: str) -> dict:
    """Discharge a patient and free their bed for cleaning."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM beds WHERE patient_email=%s AND status='occupied'", (patient_email,))
    bed = c.fetchone()
    if not bed: conn.close(); return {"status": "error", "message": f"No occupied bed found for '{patient_email}'."}
    c.execute("UPDATE beds SET status='cleaning', patient_email=NULL, assigned_at=NULL WHERE id=%s", (bed["id"],))
    c.execute("INSERT INTO ward_events (bed_id,event_type,patient_email,notes) VALUES (%s,'discharge',%s,%s)",
              (bed["id"], patient_email, f"Patient discharged from {bed['bed_number']}. Bed queued for cleaning."))
    conn.commit(); conn.close()
    return {"status": "discharged", "bed_number": bed["bed_number"], "ward": bed["ward_name"],
            "message": f"✅ Patient discharged. Bed {bed['bed_number']} is now being cleaned and will be available shortly."}

@mcp.tool()
def mark_bed_cleaned(bed_number: str) -> dict:
    """Mark a bed as cleaned and ready for the next patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM beds WHERE LOWER(bed_number)=LOWER(%s)", (bed_number,))
    bed = c.fetchone()
    if not bed: conn.close(); return {"status": "error", "message": f"Bed '{bed_number}' not found."}
    if bed["status"] != "cleaning": conn.close(); return {"status": "error", "message": f"Bed {bed_number} is not in 'cleaning' status (current: {bed['status']})."}
    c.execute("UPDATE beds SET status='available' WHERE id=%s", (bed["id"],))
    c.execute("INSERT INTO ward_events (bed_id,event_type,notes) VALUES (%s,'clean',%s)",
              (bed["id"], f"Bed {bed_number} cleaned and marked available."))
    conn.commit(); conn.close()
    return {"status": "available", "bed_number": bed_number, "ward": bed["ward_name"],
            "message": f"✅ Bed {bed_number} in {bed['ward_name']} is now clean and available."}

@mcp.tool()
def transfer_patient(patient_email: str, target_ward: str) -> dict:
    """Transfer a patient from their current bed to a bed in a different ward."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM beds WHERE patient_email=%s AND status='occupied'", (patient_email,))
    current_bed = c.fetchone()
    if not current_bed: conn.close(); return {"status": "error", "message": f"Patient '{patient_email}' is not currently admitted."}
    c.execute("SELECT * FROM beds WHERE LOWER(ward_name)=LOWER(%s) AND status='available' ORDER BY bed_number LIMIT 1", (target_ward,))
    new_bed = c.fetchone()
    if not new_bed: conn.close(); return {"status": "error", "message": f"No available beds in {target_ward}."}
    c.execute("UPDATE beds SET status='cleaning', patient_email=NULL, assigned_at=NULL WHERE id=%s", (current_bed["id"],))
    c.execute("UPDATE beds SET status='occupied', patient_email=%s, assigned_at=NOW() WHERE id=%s", (patient_email, new_bed["id"]))
    c.execute("INSERT INTO ward_events (bed_id,event_type,patient_email,notes) VALUES (%s,'transfer',%s,%s)",
              (new_bed["id"], patient_email, f"Transferred from {current_bed['bed_number']} to {new_bed['bed_number']} ({target_ward})"))
    conn.commit(); conn.close()
    return {"status": "transferred", "from_bed": current_bed["bed_number"], "from_ward": current_bed["ward_name"],
            "to_bed": new_bed["bed_number"], "to_ward": target_ward,
            "message": f"✅ Patient transferred from {current_bed['bed_number']} ({current_bed['ward_name']}) to {new_bed['bed_number']} ({target_ward})."}

@mcp.tool()
def get_ward_events(limit: int = 20) -> list:
    """Get recent ward events (admissions, discharges, transfers, cleaning)."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT e.id,e.event_type,e.patient_email,e.notes,e.performed_at,b.bed_number,b.ward_name
                 FROM ward_events e JOIN beds b ON e.bed_id=b.id
                 ORDER BY e.performed_at DESC LIMIT %s""", (limit,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "No ward events recorded yet."}]
    return [{**dict(r), "performed_at": str(r["performed_at"])} for r in rows]

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Ward MCP Server on http://127.0.0.1:8006/mcp")
    mcp.run(transport="streamable-http")