"""mcp_servers/billing_server.py — Billing tools MCP server (port 8002)"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("BillingServer", host="127.0.0.1", port=8002, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

@mcp.tool()
def get_patient_bill(patient_email: str) -> list:
    """Get all invoices for a patient by email."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM invoices WHERE patient_email=%s ORDER BY created_at DESC", (patient_email,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": f"No invoices found for {patient_email}."}]
    result = []
    for r in rows:
        d = dict(r)
        d["subtotal"] = float(d["subtotal"]); d["insurance_covered"] = float(d["insurance_covered"]); d["total_due"] = float(d["total_due"])
        result.append(d)
    return result

@mcp.tool()
def generate_invoice(patient_email: str, appointment_id: int, items: str, insurance_covered: float = 0.0) -> dict:
    """
    Generate an invoice for a patient.
    items: JSON string like '[{"name":"Consultation","cost":200},{"name":"ECG","cost":100}]'
    insurance_covered: amount covered by insurance.
    """
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,name FROM patients WHERE email=%s", (patient_email,))
    patient = c.fetchone()
    if not patient: conn.close(); return {"status": "error", "message": f"Patient '{patient_email}' not found."}
    try:
        items_list = json.loads(items)
        subtotal = sum(item.get("cost", 0) for item in items_list)
    except Exception as e:
        conn.close(); return {"status": "error", "message": f"Invalid items JSON: {e}"}
    total_due = max(0, subtotal - insurance_covered)
    c.execute("""INSERT INTO invoices (patient_email,appointment_id,items,subtotal,insurance_covered,total_due,status)
                 VALUES (%s,%s,%s,%s,%s,%s,'pending') RETURNING id""",
              (patient_email, appointment_id, json.dumps(items_list), subtotal, insurance_covered, total_due))
    inv_id = c.fetchone()["id"]; conn.commit(); conn.close()
    return {"status": "created", "invoice_id": inv_id, "patient": patient["name"],
            "subtotal": subtotal, "insurance_covered": insurance_covered, "total_due": total_due,
            "message": f"✅ Invoice #{inv_id} created. Subtotal: ${subtotal:.2f}, Insurance: ${insurance_covered:.2f}, Due: ${total_due:.2f}"}

@mcp.tool()
def update_invoice_status(invoice_id: int, status: str) -> dict:
    """Update invoice status. Valid statuses: pending, paid, cancelled."""
    valid = ["pending", "paid", "cancelled"]
    if status not in valid: return {"status": "error", "message": f"Invalid status. Use: {valid}"}
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id FROM invoices WHERE id=%s", (invoice_id,))
    if not c.fetchone(): conn.close(); return {"status": "error", "message": f"Invoice {invoice_id} not found."}
    c.execute("UPDATE invoices SET status=%s WHERE id=%s", (status, invoice_id))
    conn.commit(); conn.close()
    return {"status": "updated", "message": f"✅ Invoice #{invoice_id} marked as '{status}'."}

@mcp.tool()
def calculate_charges(consultation_fee: float, procedures: str = "[]", lab_tests: str = "[]") -> dict:
    """
    Calculate total charges before generating invoice.
    procedures: JSON list like '[{"name":"X-Ray","cost":150}]'
    lab_tests: JSON list like '[{"name":"Blood Test","cost":80}]'
    """
    try:
        procs = json.loads(procedures); labs = json.loads(lab_tests)
        proc_total = sum(p.get("cost", 0) for p in procs)
        lab_total  = sum(l.get("cost", 0) for l in labs)
        total = consultation_fee + proc_total + lab_total
        return {"consultation_fee": consultation_fee, "procedures_total": proc_total,
                "lab_tests_total": lab_total, "grand_total": total,
                "breakdown": {"procedures": procs, "lab_tests": labs}}
    except Exception as e:
        return {"status": "error", "message": f"Invalid JSON: {e}"}

@mcp.tool()
def get_pending_invoices() -> list:
    """Get all unpaid (pending) invoices across all patients."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT i.id,i.patient_email,i.total_due,i.created_at,p.name AS patient_name
                 FROM invoices i LEFT JOIN patients p ON i.patient_email=p.email
                 WHERE i.status='pending' ORDER BY i.created_at""")
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "No pending invoices."}]
    result = []
    for r in rows:
        d = dict(r); d["total_due"] = float(d["total_due"]); result.append(d)
    return result

@mcp.tool()
def get_revenue_summary() -> dict:
    """Get total revenue summary: total billed, collected, outstanding."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT SUM(subtotal) as billed, SUM(CASE WHEN status='paid' THEN total_due ELSE 0 END) as collected, SUM(CASE WHEN status='pending' THEN total_due ELSE 0 END) as outstanding FROM invoices")
    row = c.fetchone(); conn.close()
    return {"total_billed": float(row["billed"] or 0), "total_collected": float(row["collected"] or 0),
            "total_outstanding": float(row["outstanding"] or 0)}

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Billing MCP Server on http://127.0.0.1:8002/mcp")
    mcp.run(transport="streamable-http")