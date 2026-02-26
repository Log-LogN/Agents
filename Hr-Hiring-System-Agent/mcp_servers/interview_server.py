"""mcp_servers/interview_server.py — Interview Scheduling Agent (port 8003 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_interview_invitation

mcp = FastMCP("InterviewServer", host="127.0.0.1", port=8003, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def schedule_interview(candidate_id: int, job_id: int, interviewer_email: str,
                        interviewer_name: str, scheduled_at: str, duration_mins: int,
                        interview_type: str, round_num: int, meeting_link: str) -> dict:
    """
    Schedule an interview. scheduled_at format: YYYY-MM-DD HH:MM.
    interview_type: technical / hr / culture_fit / final / panel
    Sends invitation emails to candidate and interviewer.
    """
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT c.name, c.email, j.title as job_title FROM candidates c
        JOIN jobs j ON c.job_id=j.id WHERE c.id=%s AND c.job_id=%s
    """, (candidate_id, job_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Candidate #{candidate_id} not found for job #{job_id}."}
    cur.execute("""
        INSERT INTO interviews (candidate_id, job_id, interviewer_email, interviewer_name,
                                scheduled_at, duration_mins, type, round, status, meeting_link)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,'scheduled',%s) RETURNING id
    """, (candidate_id, job_id, interviewer_email, interviewer_name,
          scheduled_at, duration_mins, interview_type, round_num, meeting_link))
    iid = cur.fetchone()["id"]
    cur.execute("UPDATE candidates SET status='interview', updated_at=NOW() WHERE id=%s", (candidate_id,))
    conn.commit(); conn.close()
    send_interview_invitation(row["name"], row["email"], row["job_title"],
                               scheduled_at, duration_mins, interview_type, round_num,
                               interviewer_name, meeting_link)
    return {"success": True, "interview_id": iid, "candidate": row["name"],
            "scheduled_at": scheduled_at, "type": interview_type, "round": round_num,
            "message": f"Interview #{iid} scheduled. Invitation emails sent to candidate and interviewer."}


@mcp.tool()
def get_interview_details(interview_id: int) -> dict:
    """Get full details of an interview including candidate and job info."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT i.*, c.name as candidate_name, c.email as candidate_email, j.title as job_title
        FROM interviews i
        JOIN candidates c ON i.candidate_id=c.id
        JOIN jobs j ON i.job_id=j.id
        WHERE i.id=%s
    """, (interview_id,))
    row = cur.fetchone(); conn.close()
    if not row:
        return {"found": False, "message": f"Interview #{interview_id} not found."}
    d = dict(row)
    d["scheduled_at"] = str(d["scheduled_at"])[:16] if d.get("scheduled_at") else None
    d["created_at"]   = str(d["created_at"])[:16] if d.get("created_at") else None
    return {**d, "found": True}


@mcp.tool()
def list_interviews_for_job(job_id: int, status: str = "all") -> list:
    """Get all scheduled interviews for a specific job, optionally filtered by status."""
    conn = get_connection(); cur = _cur(conn)
    q = """SELECT i.id, i.type, i.round, i.status, i.scheduled_at, i.duration_mins,
                  i.interviewer_name, i.meeting_link,
                  c.name as candidate_name, c.email as candidate_email
           FROM interviews i JOIN candidates c ON i.candidate_id=c.id
           WHERE i.job_id=%s"""
    params = [job_id]
    if status != "all":
        q += " AND i.status=%s"; params.append(status)
    q += " ORDER BY i.scheduled_at"
    cur.execute(q, params); rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["scheduled_at"] = str(d["scheduled_at"])[:16] if d.get("scheduled_at") else None
        result.append(d)
    return result if result else [{"message": f"No interviews found for job #{job_id}."}]


@mcp.tool()
def list_upcoming_interviews(days_ahead: int = 7) -> list:
    """List all interviews scheduled in the next N days."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT i.id, i.type, i.round, i.status, i.scheduled_at, i.duration_mins,
               i.interviewer_name, i.interviewer_email, i.meeting_link,
               c.name as candidate_name, j.title as job_title
        FROM interviews i
        JOIN candidates c ON i.candidate_id=c.id
        JOIN jobs j ON i.job_id=j.id
        WHERE i.scheduled_at BETWEEN NOW() AND NOW() + INTERVAL '%s days'
          AND i.status='scheduled'
        ORDER BY i.scheduled_at
    """, (days_ahead,))
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["scheduled_at"] = str(d["scheduled_at"])[:16] if d.get("scheduled_at") else None
        result.append(d)
    return result if result else [{"message": f"No interviews scheduled in the next {days_ahead} days."}]


@mcp.tool()
def reschedule_interview(interview_id: int, new_scheduled_at: str, reason: str = "") -> dict:
    """Reschedule an interview to a new date/time. Sends updated invitation via email."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT i.*, c.name as candidate_name, c.email as candidate_email,
               j.title as job_title
        FROM interviews i JOIN candidates c ON i.candidate_id=c.id
        JOIN jobs j ON i.job_id=j.id WHERE i.id=%s
    """, (interview_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Interview #{interview_id} not found."}
    cur.execute("""UPDATE interviews SET scheduled_at=%s, status='rescheduled'
                   WHERE id=%s""", (new_scheduled_at, interview_id))
    conn.commit(); conn.close()
    send_interview_invitation(row["candidate_name"], row["candidate_email"], row["job_title"],
                               new_scheduled_at, row["duration_mins"], row["type"],
                               row["round"], row["interviewer_name"], row["meeting_link"])
    return {"success": True, "interview_id": interview_id,
            "new_scheduled_at": new_scheduled_at,
            "message": f"Interview #{interview_id} rescheduled. Updated invite sent."}


@mcp.tool()
def cancel_interview(interview_id: int, reason: str = "Position on hold") -> dict:
    """Cancel an interview and update its status."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT i.id, c.name as candidate_name FROM interviews i
        JOIN candidates c ON i.candidate_id=c.id WHERE i.id=%s
    """, (interview_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"success": False, "message": f"Interview #{interview_id} not found."}
    cur.execute("UPDATE interviews SET status='cancelled', notes=%s WHERE id=%s",
                (f"Cancelled: {reason}", interview_id))
    conn.commit(); conn.close()
    return {"success": True, "interview_id": interview_id,
            "message": f"Interview #{interview_id} for {row['candidate_name']} cancelled. Reason: {reason}"}


@mcp.tool()
def submit_interview_feedback(interview_id: int, candidate_id: int, rating: int,
                               technical_score: int, culture_fit: int, communication: int,
                               notes: str, recommendation: str, submitted_by: str) -> dict:
    """
    Record post-interview feedback.
    rating: 1-5, technical_score/culture_fit/communication: 1-10
    recommendation: strong_yes / yes / maybe / no / strong_no
    """
    def _in_range(name: str, value: int, lo: int, hi: int) -> str | None:
        if not isinstance(value, int):
            return f"{name} must be an integer between {lo} and {hi}."
        if value < lo or value > hi:
            return f"{name} must be between {lo} and {hi}. You gave {value}."
        return None

    valid_rec = ["strong_yes","yes","maybe","no","strong_no"]
    if recommendation not in valid_rec:
        return {"success": False, "message": f"Invalid recommendation. Valid: {', '.join(valid_rec)}"}
    for err in [
        _in_range("rating", rating, 1, 5),
        _in_range("technical_score", technical_score, 1, 10),
        _in_range("culture_fit", culture_fit, 1, 10),
        _in_range("communication", communication, 1, 10),
    ]:
        if err:
            return {"success": False, "message": err}

    conn = None
    try:
        conn = get_connection()
        cur = _cur(conn)

        cur.execute(
            """
            SELECT id FROM interviews WHERE id=%s AND candidate_id=%s
            """,
            (interview_id, candidate_id),
        )
        if not cur.fetchone():
            return {
                "success": False,
                "message": f"Interview #{interview_id} was not found for candidate #{candidate_id}.",
            }

        cur.execute("""
            INSERT INTO interview_feedback
              (interview_id, candidate_id, rating, technical_score, culture_fit,
               communication, notes, recommendation, submitted_by)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (interview_id, candidate_id, rating, technical_score, culture_fit,
              communication, notes, recommendation, submitted_by))
        fid = cur.fetchone()["id"]
        cur.execute("UPDATE interviews SET status='completed' WHERE id=%s", (interview_id,))
        conn.commit()
        return {
            "success": True,
            "feedback_id": fid,
            "interview_id": interview_id,
            "recommendation": recommendation,
            "rating": rating,
            "message": f"Feedback submitted for interview #{interview_id}. Recommendation: {recommendation}",
        }
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        return {
            "success": False,
            "message": f"Could not submit interview feedback: {e}",
        }
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


@mcp.tool()
def get_interview_feedback(candidate_id: int) -> list:
    """Retrieve all feedback submitted for a candidate across all interview rounds."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT f.*, i.type as interview_type, i.round, i.scheduled_at
        FROM interview_feedback f
        JOIN interviews i ON f.interview_id=i.id
        WHERE f.candidate_id=%s ORDER BY i.round
    """, (candidate_id,))
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["scheduled_at"] = str(d["scheduled_at"])[:16] if d.get("scheduled_at") else None
        d["created_at"]   = str(d["created_at"])[:16] if d.get("created_at") else None
        result.append(d)
    return result if result else [{"message": f"No feedback found for candidate #{candidate_id}."}]


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()
