"""mcp_servers/job_server.py — Job Management Agent (port 8001 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db

mcp = FastMCP("JobServer", host="127.0.0.1", port=8001, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def create_job_posting(title: str, department: str, description: str, required_skills: str,
                        experience_years: int, salary_min: float, salary_max: float,
                        location: str, deadline: str, created_by: str) -> dict:
    """Create a new job posting. deadline format: YYYY-MM-DD."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        INSERT INTO jobs (title, department, description, required_skills, experience_years,
                          salary_min, salary_max, location, deadline, created_by, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'open') RETURNING id
    """, (title, department, description, required_skills, experience_years,
          salary_min, salary_max, location, deadline, created_by))
    job_id = cur.fetchone()["id"]
    conn.commit(); conn.close()
    return {"success": True, "job_id": job_id, "title": title, "status": "open",
            "message": f"Job posting '{title}' created successfully with ID {job_id}."}


@mcp.tool()
def get_job_posting(job_id: int) -> dict:
    """Get full details of a job posting by ID."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT * FROM jobs WHERE id=%s", (job_id,))
    row = cur.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Job #{job_id} not found."}
    d = dict(row)
    for k in ("salary_min", "salary_max"):
        if d.get(k): d[k] = float(d[k])
    for k in ("created_at", "updated_at", "deadline"):
        if d.get(k): d[k] = str(d[k])[:10]
    return {**d, "found": True}


@mcp.tool()
def list_all_jobs(status: str = "all", department: str = "all") -> list:
    """List job postings. status: open/closed/on_hold/draft/all. department: name or 'all'."""
    conn = get_connection(); cur = _cur(conn)
    q = "SELECT id, title, department, status, location, salary_min, salary_max, deadline, created_at FROM jobs WHERE 1=1"
    params = []
    if status != "all":
        q += " AND status=%s"; params.append(status)
    if department != "all":
        q += " AND department ILIKE %s"; params.append(f"%{department}%")
    q += " ORDER BY created_at DESC"
    cur.execute(q, params)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("salary_min", "salary_max"):
            if d.get(k): d[k] = float(d[k])
        for k in ("created_at", "deadline"):
            if d.get(k): d[k] = str(d[k])[:10]
        result.append(d)
    return result if result else [{"message": "No jobs found matching filters."}]


@mcp.tool()
def update_job_posting(job_id: int, title: str = "", department: str = "",
                        required_skills: str = "", salary_min: float = 0,
                        salary_max: float = 0, deadline: str = "", status: str = "") -> dict:
    """Update fields of an existing job posting. Only non-empty fields are updated."""
    conn = get_connection(); cur = _cur(conn)
    updates, params = [], []
    if title:          updates.append("title=%s");          params.append(title)
    if department:     updates.append("department=%s");     params.append(department)
    if required_skills:updates.append("required_skills=%s");params.append(required_skills)
    if salary_min:     updates.append("salary_min=%s");     params.append(salary_min)
    if salary_max:     updates.append("salary_max=%s");     params.append(salary_max)
    if deadline:       updates.append("deadline=%s");       params.append(deadline)
    if status:         updates.append("status=%s");         params.append(status)
    if not updates:
        conn.close()
        return {"success": False, "message": "No fields to update."}
    updates.append("updated_at=NOW()")
    params.append(job_id)
    cur.execute(f"UPDATE jobs SET {','.join(updates)} WHERE id=%s RETURNING id, title, status", params)
    row = cur.fetchone(); conn.commit(); conn.close()
    if not row:
        return {"success": False, "message": f"Job #{job_id} not found."}
    return {"success": True, "job_id": job_id, "message": f"Job #{job_id} updated successfully."}


@mcp.tool()
def close_job_posting(job_id: int, reason: str = "Position filled") -> dict:
    """Close a job posting. Marks it as closed and records the reason."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("UPDATE jobs SET status='closed', updated_at=NOW() WHERE id=%s RETURNING title", (job_id,))
    row = cur.fetchone(); conn.commit(); conn.close()
    if not row:
        return {"success": False, "message": f"Job #{job_id} not found."}
    return {"success": True, "job_id": job_id, "title": row["title"],
            "message": f"Job '{row['title']}' closed. Reason: {reason}"}


@mcp.tool()
def get_job_applications_count(job_id: int) -> dict:
    """Get application pipeline counts for a specific job."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT title FROM jobs WHERE id=%s", (job_id,))
    job = cur.fetchone()
    if not job:
        conn.close()
        return {"found": False, "message": f"Job #{job_id} not found."}
    cur.execute("""
        SELECT status, COUNT(*) as count FROM candidates
        WHERE job_id=%s GROUP BY status
    """, (job_id,))
    rows = {r["status"]: r["count"] for r in cur.fetchall()}
    conn.close()
    return {
        "job_id": job_id, "title": job["title"],
        "applied":       rows.get("applied", 0),
        "screening":     rows.get("screening", 0),
        "shortlisted":   rows.get("shortlisted", 0),
        "interview":     rows.get("interview", 0),
        "offer":         rows.get("offer", 0),
        "hired":         rows.get("hired", 0),
        "rejected":      rows.get("rejected", 0),
        "total":         sum(rows.values()),
    }


@mcp.tool()
def search_jobs_by_skill(skill_keyword: str) -> list:
    """Find open job postings that require a specific skill or keyword."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT id, title, department, required_skills, salary_min, salary_max, location, deadline
        FROM jobs WHERE status='open'
        AND (required_skills ILIKE %s OR title ILIKE %s OR description ILIKE %s)
        ORDER BY created_at DESC
    """, (f"%{skill_keyword}%",)*3)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("salary_min", "salary_max"):
            if d.get(k): d[k] = float(d[k])
        if d.get("deadline"): d["deadline"] = str(d["deadline"])[:10]
        result.append(d)
    return result if result else [{"message": f"No open jobs found matching '{skill_keyword}'."}]


@mcp.tool()
def get_department_jobs(department: str) -> list:
    """Get all open job postings for a specific department."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT id, title, status, location, salary_min, salary_max, deadline, required_skills
        FROM jobs WHERE department ILIKE %s ORDER BY status, created_at DESC
    """, (f"%{department}%",))
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        for k in ("salary_min", "salary_max"):
            if d.get(k): d[k] = float(d[k])
        if d.get("deadline"): d["deadline"] = str(d["deadline"])[:10]
        result.append(d)
    return result if result else [{"message": f"No jobs found for department '{department}'."}]


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()