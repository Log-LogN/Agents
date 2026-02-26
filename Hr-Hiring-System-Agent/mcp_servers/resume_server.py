"""mcp_servers/resume_server.py — Resume Screening Agent (port 8002 · 9 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_application_confirmation, send_status_update, send_rejection_email

mcp = FastMCP("ResumeServer", host="127.0.0.1", port=8002, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def submit_candidate(name: str, email: str, job_id: int, resume_text: str,
                      source: str, experience_years: int, current_role: str,
                      skills: str, education: str) -> dict:
    """Register a new candidate application. Sends confirmation email."""
    conn = get_connection(); cur = _cur(conn)
    # Check duplicate
    cur.execute("SELECT id FROM candidates WHERE email=%s AND job_id=%s", (email, job_id))
    if cur.fetchone():
        conn.close()
        return {"success": False, "message": f"{email} has already applied for job #{job_id}."}
    cur.execute("SELECT title FROM jobs WHERE id=%s", (job_id,))
    job = cur.fetchone()
    if not job:
        conn.close()
        return {"success": False, "message": f"Job #{job_id} not found."}
    cur.execute("""
        INSERT INTO candidates (name, email, job_id, resume_text, source, experience_years,
                                "current_role", skills, education, status)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'applied') RETURNING id
    """, (name, email, job_id, resume_text, source, experience_years, current_role, skills, education))
    cid = cur.fetchone()["id"]
    # Log communication
    cur.execute("""INSERT INTO communications (candidate_id, type, subject, body_preview, sent_by)
                   VALUES (%s,'application_confirmation',%s,'Application received.',%s)""",
                (cid, f"Application Received – {job['title']}", "system"))
    conn.commit(); conn.close()
    send_application_confirmation(name, email, job["title"], job_id)
    return {"success": True, "candidate_id": cid, "name": name, "job_title": job["title"],
            "message": f"Candidate {name} registered (ID {cid}). Confirmation email sent."}


@mcp.tool()
def get_candidate_profile(candidate_id: int) -> dict:
    """Retrieve full candidate profile including status, score, and notes."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.*, j.title as job_title FROM candidates c
        LEFT JOIN jobs j ON c.job_id=j.id WHERE c.id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"found": False, "message": f"Candidate #{candidate_id} not found."}
    cur.execute("SELECT note, created_by, created_at FROM screening_notes WHERE candidate_id=%s ORDER BY created_at DESC", (candidate_id,))
    notes = [dict(n) for n in cur.fetchall()]
    conn.close()
    d = dict(row)
    d["score"] = float(d["score"]) if d.get("score") else 0
    d["created_at"] = str(d["created_at"])[:16] if d.get("created_at") else None
    d["screening_notes"] = notes
    return {**d, "found": True}


@mcp.tool()
def list_candidates_for_job(job_id: int, status: str = "all") -> list:
    """List all candidates who applied to a specific job, optionally filtered by status."""
    conn = get_connection(); cur = _cur(conn)
    q = """SELECT id, name, email, status, score, source, experience_years,
                  "current_role", shortlisted, created_at
           FROM candidates WHERE job_id=%s"""
    params = [job_id]
    if status != "all":
        q += " AND status=%s"; params.append(status)
    q += " ORDER BY score DESC, created_at ASC"
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["score"] = float(d["score"]) if d.get("score") else 0
        d["created_at"] = str(d["created_at"])[:10]
        result.append(d)
    return result if result else [{"message": f"No candidates found for job #{job_id}."}]


@mcp.tool()
def score_resume(candidate_id: int) -> dict:
    """
    Score a candidate's resume against their applied job requirements.
    Calculates match score based on skills overlap, experience, and education.
    Updates the score in the database.
    """
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.*, j.required_skills, j.experience_years as req_exp, j.title as job_title
        FROM candidates c JOIN jobs j ON c.job_id=j.id WHERE c.id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"found": False, "message": f"Candidate #{candidate_id} not found."}
    d = dict(row)

    # Skills match scoring
    req_skills = [s.strip().lower() for s in (d.get("required_skills") or "").split(",")]
    cand_skills = [s.strip().lower() for s in (d.get("skills") or "").split(",")]
    matched = sum(1 for s in req_skills if any(s in c or c in s for c in cand_skills))
    skill_score = (matched / max(len(req_skills), 1)) * 50

    # Experience scoring (max 30 pts)
    req_exp = d.get("req_exp", 0) or 0
    cand_exp = d.get("experience_years", 0) or 0
    exp_score = min(30, (cand_exp / max(req_exp, 1)) * 30)

    # Education scoring (max 20 pts)
    edu = (d.get("education") or "").lower()
    edu_score = 20 if any(k in edu for k in ["iit","iim","bits","nid","nit"]) else \
                15 if any(k in edu for k in ["b.tech","m.tech","mba","b.des"]) else 10

    final_score = round(min(100, skill_score + exp_score + edu_score), 2)

    cur.execute("UPDATE candidates SET score=%s, updated_at=NOW() WHERE id=%s", (final_score, candidate_id))
    conn.commit(); conn.close()
    return {
        "candidate_id": candidate_id, "name": d["name"], "job_title": d["job_title"],
        "final_score": final_score, "skill_score": round(skill_score, 1),
        "experience_score": round(exp_score, 1), "education_score": edu_score,
        "matched_skills": matched, "total_required_skills": len(req_skills),
        "message": f"Resume scored: {final_score}/100"
    }


@mcp.tool()
def update_candidate_status(candidate_id: int, new_status: str, updated_by: str = "system") -> dict:
    """Move candidate through pipeline: applied→screening→shortlisted→interview→offer→hired/rejected."""
    valid = ["applied","screening","shortlisted","interview","offer","hired","rejected"]
    if new_status not in valid:
        return {"success": False, "message": f"Invalid status. Valid: {', '.join(valid)}"}
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    cur.execute("UPDATE candidates SET status=%s, updated_at=NOW() WHERE id=%s", (new_status, candidate_id))
    cur.execute("""INSERT INTO audit_log (user_email, role, action, entity_type, entity_id, details)
                   VALUES (%s,'system','update_status','candidate',%s,%s)""",
                (updated_by, candidate_id, f"Status changed to {new_status}"))
    conn.commit(); conn.close()
    return {"success": True, "candidate_id": candidate_id, "name": row["name"],
            "new_status": new_status, "message": f"{row['name']} status updated to '{new_status}'."}


@mcp.tool()
def shortlist_candidate(candidate_id: int, shortlisted_by: str = "recruiter") -> dict:
    """Mark candidate as shortlisted and send notification email."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    cur.execute("""UPDATE candidates SET shortlisted=TRUE, status='shortlisted', updated_at=NOW()
                   WHERE id=%s""", (candidate_id,))
    conn.commit(); conn.close()
    send_status_update(row["name"], row["email"], row["job_title"], "shortlisted",
                       "Congratulations! You have been shortlisted for the next stage.")
    return {"success": True, "candidate_id": candidate_id, "name": row["name"],
            "message": f"{row['name']} shortlisted. Notification email sent."}


@mcp.tool()
def reject_candidate(candidate_id: int, reason: str = "", rejected_by: str = "recruiter") -> dict:
    """Reject a candidate and send a professional rejection email."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s
    """, (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    cur.execute("UPDATE candidates SET status='rejected', updated_at=NOW() WHERE id=%s", (candidate_id,))
    cur.execute("""INSERT INTO communications (candidate_id, type, subject, body_preview, sent_by)
                   VALUES (%s,'rejection',%s,%s,%s)""",
                (candidate_id, f"Application Update – {row['job_title']}", f"Rejection sent. Reason: {reason}", rejected_by))
    conn.commit(); conn.close()
    send_rejection_email(row["name"], row["email"], row["job_title"], reason)
    return {"success": True, "candidate_id": candidate_id, "name": row["name"],
            "message": f"{row['name']} rejected. Professional email sent."}


@mcp.tool()
def get_top_candidates(job_id: int, top_n: int = 5) -> list:
    """Return top-N ranked candidates for a job posting, sorted by score descending."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT id, name, email, score, status, experience_years, "current_role",
               skills, education, shortlisted
        FROM candidates WHERE job_id=%s AND status != 'rejected'
        ORDER BY score DESC LIMIT %s
    """, (job_id, top_n))
    rows = cur.fetchall(); conn.close()
    result = []
    for i, r in enumerate(rows):
        d = dict(r)
        d["score"] = float(d["score"]) if d.get("score") else 0
        d["rank"] = i + 1
        result.append(d)
    return result if result else [{"message": f"No active candidates for job #{job_id}."}]


@mcp.tool()
def add_screening_note(candidate_id: int, note: str, created_by: str) -> dict:
    """Add an internal recruiter note to a candidate profile."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("SELECT name FROM candidates WHERE id=%s", (candidate_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found."}
    cur.execute("""INSERT INTO screening_notes (candidate_id, note, created_by)
                   VALUES (%s,%s,%s) RETURNING id""", (candidate_id, note, created_by))
    note_id = cur.fetchone()["id"]
    conn.commit(); conn.close()
    return {"success": True, "note_id": note_id, "candidate_id": candidate_id,
            "name": row["name"], "message": "Note added successfully."}


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()
