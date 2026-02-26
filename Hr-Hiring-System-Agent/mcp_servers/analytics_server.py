"""mcp_servers/analytics_server.py — Analytics Agent (port 8007 · 9 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db

mcp = FastMCP("AnalyticsServer", host="127.0.0.1", port=8007, stateless_http=True, json_response=True)


def _cur(conn): return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@mcp.tool()
def get_pipeline_summary() -> dict:
    """Overall hiring funnel: applied→screened→interviewed→offered→hired counts."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT
            COUNT(*) as total_applications,
            COUNT(*) FILTER (WHERE status='applied')     as applied,
            COUNT(*) FILTER (WHERE status='screening')   as screening,
            COUNT(*) FILTER (WHERE status='shortlisted') as shortlisted,
            COUNT(*) FILTER (WHERE status='interview')   as interview,
            COUNT(*) FILTER (WHERE status='offer')       as offer,
            COUNT(*) FILTER (WHERE status='hired')       as hired,
            COUNT(*) FILTER (WHERE status='rejected')    as rejected
        FROM candidates
    """)
    row = dict(cur.fetchone())
    cur.execute("SELECT COUNT(*) as open_jobs FROM jobs WHERE status='open'")
    row["open_jobs"] = cur.fetchone()["open_jobs"]
    cur.execute("SELECT COUNT(*) as total_jobs FROM jobs")
    row["total_jobs"] = cur.fetchone()["total_jobs"]
    conn.close()
    # Compute funnel conversion rates
    total = row["total_applications"] or 1
    row["shortlist_rate_pct"] = round((row["shortlisted"] / total) * 100, 1)
    row["interview_rate_pct"] = round((row["interview"] / total) * 100, 1)
    row["offer_rate_pct"]     = round((row["offer"] / total) * 100, 1)
    row["hire_rate_pct"]      = round((row["hired"] / total) * 100, 1)
    return row


@mcp.tool()
def get_time_to_hire_report() -> dict:
    """Average days per pipeline stage and total time-to-hire analysis."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT
            AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='hired') as avg_days_total,
            AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='shortlisted') as avg_days_to_shortlist,
            AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='interview') as avg_days_to_interview,
            AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='offer') as avg_days_to_offer,
            MIN(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='hired') as min_days_hired,
            MAX(EXTRACT(EPOCH FROM (updated_at - created_at))/86400)
              FILTER (WHERE status='hired') as max_days_hired
        FROM candidates
    """)
    row = dict(cur.fetchone())
    conn.close()
    return {k: round(float(v), 1) if v else 0 for k, v in row.items()}


@mcp.tool()
def get_source_effectiveness() -> list:
    """Which job boards/sources produce the most applications and hires."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT source,
               COUNT(*) as total_applications,
               COUNT(*) FILTER (WHERE status='hired') as hired,
               COUNT(*) FILTER (WHERE status='shortlisted' OR status='interview' OR status='offer' OR status='hired') as progressed,
               AVG(score) as avg_score
        FROM candidates
        GROUP BY source ORDER BY hired DESC, total_applications DESC
    """)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["avg_score"] = round(float(d["avg_score"]), 1) if d.get("avg_score") else 0
        total = d["total_applications"] or 1
        d["hire_rate_pct"] = round(d["hired"] / total * 100, 1)
        d["progression_rate_pct"] = round(d["progressed"] / total * 100, 1)
        result.append(d)
    return result if result else [{"message": "No source data available."}]


@mcp.tool()
def get_open_positions_report() -> list:
    """All open roles with age in days, applicant counts, and pipeline progress."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT j.id, j.title, j.department, j.location, j.status, j.deadline,
               j.salary_min, j.salary_max,
               EXTRACT(EPOCH FROM (NOW()-j.created_at))/86400 as age_days,
               COUNT(c.id) as total_applicants,
               COUNT(c.id) FILTER (WHERE c.status='shortlisted') as shortlisted,
               COUNT(c.id) FILTER (WHERE c.status='interview') as in_interview,
               COUNT(c.id) FILTER (WHERE c.status='hired') as hired
        FROM jobs j LEFT JOIN candidates c ON j.id=c.job_id
        WHERE j.status='open'
        GROUP BY j.id ORDER BY age_days DESC
    """)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["age_days"] = round(float(d["age_days"]), 0) if d.get("age_days") else 0
        for k in ("salary_min", "salary_max"):
            if d.get(k): d[k] = float(d[k])
        if d.get("deadline"): d["deadline"] = str(d["deadline"])[:10]
        result.append(d)
    return result if result else [{"message": "No open positions currently."}]


@mcp.tool()
def get_department_hiring_stats() -> list:
    """Hiring velocity and headcount per department."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT j.department,
               COUNT(DISTINCT j.id) as open_jobs,
               COUNT(c.id) as total_applicants,
               COUNT(c.id) FILTER (WHERE c.status='hired') as hired,
               AVG(c.score) FILTER (WHERE c.score > 0) as avg_candidate_score
        FROM jobs j LEFT JOIN candidates c ON j.id=c.job_id
        GROUP BY j.department ORDER BY total_applicants DESC
    """)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["avg_candidate_score"] = round(float(d["avg_candidate_score"]), 1) if d.get("avg_candidate_score") else 0
        result.append(d)
    return result if result else [{"message": "No department data available."}]


@mcp.tool()
def get_interviewer_stats() -> list:
    """Interviews conducted, offer conversion rate, and avg score per interviewer."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT i.interviewer_name, i.interviewer_email,
               COUNT(i.id) as interviews_conducted,
               COUNT(f.id) as feedback_submitted,
               AVG(f.rating) as avg_rating,
               AVG(f.technical_score) as avg_technical_score,
               COUNT(f.id) FILTER (WHERE f.recommendation IN ('yes','strong_yes')) as recommended
        FROM interviews i LEFT JOIN interview_feedback f ON i.id=f.interview_id
        WHERE i.status='completed'
        GROUP BY i.interviewer_name, i.interviewer_email
        ORDER BY interviews_conducted DESC
    """)
    rows = cur.fetchall(); conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["avg_rating"] = round(float(d["avg_rating"]), 2) if d.get("avg_rating") else 0
        d["avg_technical_score"] = round(float(d["avg_technical_score"]), 2) if d.get("avg_technical_score") else 0
        total = d["feedback_submitted"] or 1
        d["recommendation_rate_pct"] = round(d["recommended"] / total * 100, 1)
        result.append(d)
    return result if result else [{"message": "No interviewer data available."}]


@mcp.tool()
def get_diversity_funnel() -> dict:
    """Candidate count and progression at each pipeline stage for diversity tracking."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT status, COUNT(*) as count, AVG(score) as avg_score
        FROM candidates GROUP BY status ORDER BY
        CASE status
            WHEN 'applied' THEN 1 WHEN 'screening' THEN 2 WHEN 'shortlisted' THEN 3
            WHEN 'interview' THEN 4 WHEN 'offer' THEN 5 WHEN 'hired' THEN 6
            WHEN 'rejected' THEN 7 END
    """)
    rows = cur.fetchall()
    cur.execute("SELECT source, COUNT(*) as count FROM candidates GROUP BY source ORDER BY count DESC")
    sources = [dict(r) for r in cur.fetchall()]
    conn.close()
    funnel = []
    for r in rows:
        d = dict(r)
        d["avg_score"] = round(float(d["avg_score"]), 1) if d.get("avg_score") else 0
        funnel.append(d)
    return {"pipeline_funnel": funnel, "application_sources": sources,
            "note": "Full gender/diversity analytics require demographic fields in candidate profiles."}


@mcp.tool()
def get_rejection_reasons() -> list:
    """Most common rejection reasons — identifies screening criteria gaps."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT note as reason, COUNT(*) as occurrences
        FROM screening_notes
        WHERE note ILIKE '%reject%' OR note ILIKE '%not suitable%' OR note ILIKE '%overqualified%'
           OR note ILIKE '%underqualified%' OR note ILIKE '%missing%'
        GROUP BY note ORDER BY occurrences DESC LIMIT 10
    """)
    notes = [dict(r) for r in cur.fetchall()]
    cur.execute("""
        SELECT decline_reason as reason, COUNT(*) as occurrences
        FROM offers WHERE decline_reason IS NOT NULL AND decline_reason != ''
        GROUP BY decline_reason ORDER BY occurrences DESC LIMIT 5
    """)
    offer_declines = [dict(r) for r in cur.fetchall()]
    conn.close()
    return [
        {"category": "Screening Rejections", "items": notes or [{"message": "No screening rejection notes found."}]},
        {"category": "Offer Declines",        "items": offer_declines or [{"message": "No offer decline reasons recorded."}]},
    ]


@mcp.tool()
def get_offer_acceptance_rate() -> dict:
    """Offer acceptance rate, average days-to-decision, and trend data."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT
            COUNT(*) as total_offers,
            COUNT(*) FILTER (WHERE status='sent')     as pending,
            COUNT(*) FILTER (WHERE status='accepted') as accepted,
            COUNT(*) FILTER (WHERE status='declined') as declined,
            COUNT(*) FILTER (WHERE status='expired')  as expired,
            AVG(EXTRACT(EPOCH FROM (response_at - sent_at))/86400)
              FILTER (WHERE response_at IS NOT NULL) as avg_response_days,
            AVG(salary) FILTER (WHERE status='accepted') as avg_accepted_salary,
            AVG(salary) FILTER (WHERE status='declined') as avg_declined_salary
        FROM offers
    """)
    row = dict(cur.fetchone())
    conn.close()
    total = row.get("total_offers") or 1
    accepted = row.get("accepted") or 0
    declined = row.get("declined") or 0
    responded = accepted + declined
    return {
        "total_offers":           total,
        "pending_response":       row.get("pending") or 0,
        "accepted":               accepted,
        "declined":               declined,
        "expired":                row.get("expired") or 0,
        "acceptance_rate_pct":    round(accepted / max(responded, 1) * 100, 1),
        "avg_days_to_response":   round(float(row.get("avg_response_days") or 0), 1),
        "avg_accepted_salary":    round(float(row.get("avg_accepted_salary") or 0), 0),
        "avg_declined_salary":    round(float(row.get("avg_declined_salary") or 0), 0),
        "insight": "Higher declined salary vs accepted may indicate compensation competitiveness issues."
        if (row.get("avg_declined_salary") or 0) > (row.get("avg_accepted_salary") or 0) else
        "Compensation appears competitive relative to declined offers."
    }


def main():
    init_db()
    mcp.run(transport="streamable-http")

if __name__ == "__main__":
    main()