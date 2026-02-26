"""mcp_servers/lab_server.py — Lab tools MCP server (port 8005)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from mcp.server.fastmcp import FastMCP
import psycopg2.extras
from database.db import get_connection, init_db

mcp = FastMCP("LabServer", host="127.0.0.1", port=8005, stateless_http=True, json_response=True)

def cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# Critical value thresholds (simplified)
CRITICAL_TESTS = ["potassium", "hemoglobin", "glucose", "troponin", "creatinine", "sodium"]

@mcp.tool()
def order_lab_test(patient_email: str, doctor_id: int, test_name: str) -> dict:
    """Order a new lab test for a patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT name FROM patients WHERE email=%s", (patient_email,))
    patient = c.fetchone()
    if not patient: conn.close(); return {"status": "error", "message": f"Patient '{patient_email}' not found."}
    c.execute("SELECT name FROM doctors WHERE id=%s", (doctor_id,))
    doctor = c.fetchone()
    if not doctor: conn.close(); return {"status": "error", "message": f"Doctor {doctor_id} not found."}
    c.execute("INSERT INTO lab_tests (patient_email,doctor_id,test_name) VALUES (%s,%s,%s) RETURNING id",
              (patient_email, doctor_id, test_name))
    test_id = c.fetchone()["id"]; conn.commit(); conn.close()
    return {"status": "ordered", "test_id": test_id,
            "message": f"🧪 Lab test '{test_name}' ordered for {patient['name']}. Test ID: #{test_id}"}

@mcp.tool()
def get_patient_lab_results(patient_email: str) -> list:
    """Get all lab tests and results for a patient."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT l.id,l.test_name,l.status,l.result,l.critical_flag,l.ordered_at,l.notified_at,d.name AS doctor_name
                 FROM lab_tests l JOIN doctors d ON l.doctor_id=d.id
                 WHERE l.patient_email=%s ORDER BY l.ordered_at DESC""", (patient_email,))
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": f"No lab tests for '{patient_email}'."}]
    return [{**dict(r), "ordered_at": str(r["ordered_at"]), "notified_at": str(r["notified_at"]) if r["notified_at"] else None} for r in rows]

@mcp.tool()
def update_lab_result(test_id: int, result: str) -> dict:
    """
    Enter a result for a completed lab test.
    Automatically flags critical values based on test name.
    """
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT * FROM lab_tests WHERE id=%s", (test_id,))
    test = c.fetchone()
    if not test: conn.close(); return {"status": "error", "message": f"Test {test_id} not found."}
    if test["status"] == "completed": conn.close(); return {"status": "error", "message": "Result already entered."}

    # Auto-detect critical values
    is_critical = any(name in test["test_name"].lower() for name in CRITICAL_TESTS) and any(
        word in result.lower() for word in ["critical", "high", "low", "abnormal", "danger"]
    )
    c.execute("UPDATE lab_tests SET result=%s, status='completed', critical_flag=%s WHERE id=%s",
              (result, is_critical, test_id))
    conn.commit(); conn.close()
    critical_msg = " 🚨 CRITICAL VALUE FLAGGED — doctor notification required!" if is_critical else ""
    return {"status": "completed", "test_id": test_id, "test_name": test["test_name"],
            "result": result, "critical": is_critical,
            "message": f"✅ Result recorded for Test #{test_id} ({test['test_name']}).{critical_msg}"}

@mcp.tool()
def get_pending_lab_tests() -> list:
    """Get all lab tests that are still pending (no result yet)."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT l.id,l.test_name,l.patient_email,l.ordered_at,d.name AS doctor_name
                 FROM lab_tests l JOIN doctors d ON l.doctor_id=d.id
                 WHERE l.status='pending' ORDER BY l.ordered_at""")
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "✅ No pending lab tests."}]
    return [{**dict(r), "ordered_at": str(r["ordered_at"])} for r in rows]

@mcp.tool()
def get_critical_flags() -> list:
    """Get all lab tests with critical flags that have not been notified yet."""
    conn = get_connection(); c = cur(conn)
    c.execute("""SELECT l.id,l.test_name,l.result,l.patient_email,l.ordered_at,d.name AS doctor_name
                 FROM lab_tests l JOIN doctors d ON l.doctor_id=d.id
                 WHERE l.critical_flag=TRUE AND l.notified_at IS NULL ORDER BY l.ordered_at""")
    rows = c.fetchall(); conn.close()
    if not rows: return [{"message": "✅ No unnotified critical results."}]
    return [{**dict(r), "ordered_at": str(r["ordered_at"])} for r in rows]

@mcp.tool()
def mark_doctor_notified(test_id: int) -> dict:
    """Mark a critical test result as having been communicated to the doctor."""
    conn = get_connection(); c = cur(conn)
    c.execute("SELECT id,test_name FROM lab_tests WHERE id=%s AND critical_flag=TRUE", (test_id,))
    test = c.fetchone()
    if not test: conn.close(); return {"status": "error", "message": f"Critical test {test_id} not found."}
    c.execute("UPDATE lab_tests SET notified_at=NOW() WHERE id=%s", (test_id,))
    conn.commit(); conn.close()
    return {"status": "notified", "message": f"✅ Doctor notified for critical Test #{test_id} ({test['test_name']})."}

if __name__ == "__main__":
    init_db()
    # Note: Keep print statements plain text to avoid Windows encoding crashes
    print("[READY] Lab MCP Server on http://127.0.0.1:8005/mcp")
    mcp.run(transport="streamable-http")