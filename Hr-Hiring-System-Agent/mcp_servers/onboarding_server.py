"""mcp_servers/onboarding_server.py — Onboarding Agent (port 8005 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_welcome_email, send_checkin_email, send_buddy_intro_email

mcp = FastMCP("OnboardingServer", host="127.0.0.1", port=8005, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def create_onboarding_record(candidate_id: int, job_id: int, start_date: str) -> dict:
    """Initialize onboarding record for a newly hired candidate. start_date: YYYY-MM-DD."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s AND c.status='hired'
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found or not in 'hired' status. Only hired candidates can be onboarded."}
    cur.execute("SELECT id FROM onboarding WHERE candidate_id=%s", (candidate_id,))
    if cur.fetchone():
        conn.close()
        return {"success": False, "message": f"Onboarding record already exists for candidate #{candidate_id}."}
    cur.execute("""
        INSERT INTO onboarding (candidate_id, job_id, start_date, status)
        VALUES (%s,%s,%s,'pending') RETURNING id
    """, (candidate_id, job_id, start_date))
    oid = cur.fetchone()["id"]
    conn.commit(); conn.close()
    return {"success": True, "onboarding_id": oid, "candidate": row["name"],
            "job_title": row["job_title"], "start_date": start_date,
            "message": f"Onboarding record created for {row['name']} (ID {oid}). Add checklist tasks next."}


@mcp.tool()
def get_onboarding_status(candidate_id: int) -> dict:
    """Check completion percentage and all tasks for a new hire's onboarding."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.*, c.name as candidate_name, c.email as candidate_email, j.title as job_title
        FROM onboarding o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.candidate_id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"found": False, "message": f"No onboarding record for candidate #{candidate_id}."}
    cur.execute("""
        SELECT id, task_name, category, assigned_to, due_date, completed, completed_at
        FROM onboarding_tasks WHERE onboarding_id=%s ORDER BY category, due_date
    """, (row["id"],))
    tasks = [dict(t) for t in cur.fetchall()]
    conn.close()
    for t in tasks:
        if t.get("due_date"): t["due_date"] = str(t["due_date"])[:10]
        if t.get("completed_at"): t["completed_at"] = str(t["completed_at"])[:16]
    d = dict(row)
    d["completion_pct"] = float(d["completion_pct"]) if d.get("completion_pct") else 0
    d["start_date"] = str(d["start_date"])[:10] if d.get("start_date") else None
    return {**d, "found": True, "tasks": tasks,
            "total_tasks": len(tasks),
            "completed_tasks": sum(1 for t in tasks if t["completed"]),
            "pending_tasks": sum(1 for t in tasks if not t["completed"])}


@mcp.tool()
def create_checklist_item(candidate_id: int, task_name: str, category: str,
                           assigned_to: str, due_date: str) -> dict:
    """
    Add a task to a new hire's onboarding checklist.
    category: it_setup / documentation / training / access / orientation / other
    """
    valid_cats = ["it_setup","documentation","training","access","orientation","other"]
    if category not in valid_cats:
        return {"success": False, "message": f"Invalid category. Valid: {', '.join(valid_cats)}"}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT id FROM onboarding WHERE candidate_id=%s", (candidate_id,))
    ob = cur.fetchone()
    if not ob:
        conn.close()
        return {"success": False, "message": f"No onboarding record for candidate #{candidate_id}. Create onboarding record first."}
    cur.execute("""
        INSERT INTO onboarding_tasks (onboarding_id, task_name, category, assigned_to, due_date)
        VALUES (%s,%s,%s,%s,%s) RETURNING id
    """, (ob["id"], task_name, category, assigned_to, due_date))
    tid = cur.fetchone()["id"]
    # Recalculate completion pct
    cur.execute("SELECT COUNT(*) as total, SUM(CASE WHEN completed THEN 1 ELSE 0 END) as done FROM onboarding_tasks WHERE onboarding_id=%s", (ob["id"],))
    counts = cur.fetchone()
    pct = round(float(counts["done"] or 0) / float(counts["total"]) * 100, 1) if counts["total"] else 0
    cur.execute("UPDATE onboarding SET completion_pct=%s WHERE id=%s", (pct, ob["id"]))
    conn.commit(); conn.close()
    return {"success": True, "task_id": tid, "task_name": task_name, "category": category,
            "due_date": due_date, "message": f"Task '{task_name}' added to onboarding checklist."}


@mcp.tool()
def complete_checklist_item(task_id: int, completed_by: str = "system") -> dict:
    """Mark an onboarding checklist item as completed and update overall completion percentage."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        UPDATE onboarding_tasks SET completed=TRUE, completed_at=NOW()
        WHERE id=%s RETURNING onboarding_id, task_name
    """, (task_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Task #{task_id} not found."}
    ob_id = row["onboarding_id"]
    cur.execute("""SELECT COUNT(*) as total, SUM(CASE WHEN completed THEN 1 ELSE 0 END) as done
                   FROM onboarding_tasks WHERE onboarding_id=%s""", (ob_id,))
    counts = cur.fetchone()
    pct = round(float(counts["done"]) / float(counts["total"]) * 100, 1) if counts["total"] else 0
    new_status = "completed" if pct >= 100 else "in_progress"
    cur.execute("UPDATE onboarding SET completion_pct=%s, status=%s WHERE id=%s", (pct, new_status, ob_id))
    conn.commit(); conn.close()
    return {"success": True, "task_id": task_id, "task_name": row["task_name"],
            "completion_pct": pct, "onboarding_status": new_status,
            "message": f"Task '{row['task_name']}' marked complete. Overall progress: {pct}%"}


@mcp.tool()
def send_welcome_email_tool(candidate_id: int) -> dict:
    """Send the Day-1 welcome email to the new hire with schedule, buddy, and location info."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.start_date, o.buddy_email, o.buddy_name, o.id as ob_id,
               c.name, c.email, j.title as job_title
        FROM onboarding o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.candidate_id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"No onboarding record for candidate #{candidate_id}."}
    result = send_welcome_email(
        row["name"], row["email"], row["job_title"],
        str(row["start_date"])[:10],
        row["buddy_name"] or "Your HR Partner",
        row["buddy_email"] or "hr@hrapp.com"
    )
    cur.execute("UPDATE onboarding SET welcome_sent=TRUE WHERE id=%s", (row["ob_id"],))
    conn.commit(); conn.close()
    return {"success": True, "email_result": result, "candidate": row["name"],
            "message": f"Welcome email sent to {row['email']}."}


@mcp.tool()
def send_checkin_email_tool(candidate_id: int, day_milestone: int) -> dict:
    """
    Send a 30/60/90-day check-in email to the new hire.
    day_milestone: 30, 60, or 90
    """
    if day_milestone not in (30, 60, 90):
        return {"success": False, "message": "day_milestone must be 30, 60, or 90."}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title
        FROM onboarding o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.candidate_id=%s
    """, (candidate_id,))
    row = cur.fetchone(); conn.close()
    if not row:
        return {"success": False, "message": f"No onboarding record for candidate #{candidate_id}."}
    result = send_checkin_email(row["name"], row["email"], row["job_title"], day_milestone)
    return {"success": True, "email_result": result, "milestone": f"{day_milestone}-day",
            "message": f"{day_milestone}-day check-in email sent to {row['email']}."}


@mcp.tool()
def get_pending_onboardings() -> list:
    """List all new hires with incomplete onboarding tasks."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.id, o.start_date, o.completion_pct, o.status, o.welcome_sent,
               c.name as candidate_name, c.email as candidate_email, j.title as job_title
        FROM onboarding o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id
        WHERE o.status != 'completed'
        ORDER BY o.start_date
    """)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["completion_pct"] = float(d["completion_pct"]) if d.get("completion_pct") else 0
        d["start_date"] = str(d["start_date"])[:10] if d.get("start_date") else None
        result.append(d)
    return result if result else [{"message": "All onboarding records are complete!"}]


@mcp.tool()
def assign_buddy(candidate_id: int, buddy_email: str, buddy_name: str) -> dict:
    """Assign an onboarding buddy/mentor to a new hire. Sends introduction email to both."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT o.id as ob_id, c.name, c.email, j.title as job_title, o.start_date
        FROM onboarding o JOIN candidates c ON o.candidate_id=c.id
        JOIN jobs j ON o.job_id=j.id WHERE o.candidate_id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"No onboarding record for candidate #{candidate_id}."}
    cur.execute("UPDATE onboarding SET buddy_email=%s, buddy_name=%s WHERE id=%s",
                (buddy_email, buddy_name, row["ob_id"]))
    conn.commit(); conn.close()
    send_buddy_intro_email(row["name"], row["email"], buddy_name, buddy_email,
                            row["job_title"], str(row["start_date"])[:10])
    return {"success": True, "candidate": row["name"], "buddy_name": buddy_name,
            "buddy_email": buddy_email,
            "message": f"{buddy_name} assigned as buddy for {row['name']}. Introduction emails sent."}


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()