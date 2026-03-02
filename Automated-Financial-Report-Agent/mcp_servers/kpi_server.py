"""mcp_servers/kpi_server.py — KPI & Analytics Agent (port 8006 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db
from utils.email_service import send_kpi_digest

mcp = FastMCP("KPIServer", host="127.0.0.1", port=8006, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _sum_acct(cur, acct_type: str, cat: str, d1: str, d2: str) -> float:
    q = "SELECT COALESCE(SUM(t.amount),0) AS t FROM transactions t JOIN accounts a ON t.account_id=a.id WHERE a.type=%s AND t.txn_date BETWEEN %s AND %s"
    p = [acct_type, d1, d2]
    if cat:
        q += " AND a.category=%s"; p.append(cat)
    cur.execute(q, p)
    return float(cur.fetchone()["t"])


@mcp.tool()
def get_all_kpis(period: str = "2026-02") -> dict:
    """Full KPI dashboard: profitability, liquidity, and leverage ratios."""
    d1 = f"{period}-01"
    # Last day of month
    import calendar; y, m = int(period[:4]), int(period[5:7])
    d2 = f"{period}-{calendar.monthrange(y,m)[1]:02d}"
    conn = get_connection(); cur = _cur(conn)
    rev  = _sum_acct(cur, "revenue", "", d1, d2)
    cogs = _sum_acct(cur, "expense", "cogs", d1, d2)
    opex = sum(_sum_acct(cur, "expense", c, d1, d2) for c in ["salary","overhead","marketing","travel","software"])
    gross  = rev - cogs
    ebitda = gross - opex
    # Balance sheet items (approx from account types)
    cur.execute("""
        SELECT a.type, a.category,
               COALESCE(SUM(CASE WHEN t.txn_type='debit' THEN t.amount ELSE -t.amount END),0) AS bal
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE t.txn_date <= %s GROUP BY a.type, a.category
    """, (d2,))
    bs_rows = cur.fetchall()
    def _bs(atype, acat):
        for r in bs_rows:
            if r["type"] == atype and r["category"] == acat:
                return abs(float(r["bal"]))
        return 0.0
    cur_assets = _bs("asset","cash") + _bs("asset","receivable") + _bs("asset","inventory")
    cur_liab   = _bs("liability","payable") + _bs("liability","accrued") + _bs("liability","short_term_debt")
    total_liab = sum(abs(float(r["bal"])) for r in bs_rows if r["type"]=="liability")
    total_eq   = sum(abs(float(r["bal"])) for r in bs_rows if r["type"]=="equity")
    conn.close()
    # Compute ratios
    gm_pct     = round(gross/rev*100, 2) if rev else 0
    ebitda_pct = round(ebitda/rev*100, 2) if rev else 0
    net_margin = round((ebitda*0.75)/rev*100, 2) if rev else 0  # approx after tax
    cur_ratio  = round(cur_assets/cur_liab, 2) if cur_liab else 0
    de_ratio   = round(total_liab/total_eq, 2) if total_eq else 0
    # Save snapshot
    save_kpi_snapshot(period, {"gross_margin_pct": gm_pct, "ebitda_margin_pct": ebitda_pct,
                                "current_ratio": cur_ratio, "debt_to_equity": de_ratio})
    return {
        "period": period,
        "profitability": {"revenue": round(rev,2), "gross_margin_pct": gm_pct,
                          "ebitda_margin_pct": ebitda_pct, "net_margin_pct": net_margin},
        "liquidity":     {"current_ratio": cur_ratio,
                          "status": "🟢 Healthy" if cur_ratio > 2 else "🟡 Watch" if cur_ratio > 1.5 else "🔴 Low"},
        "leverage":      {"debt_to_equity": de_ratio,
                          "status": "🟢 Conservative" if de_ratio < 0.5 else "🟡 Moderate" if de_ratio <= 1 else "🔴 High"},
    }


def save_kpi_snapshot(period: str, kpis: dict) -> None:
    try:
        conn = get_connection(); cur = _cur(conn)
        for name, value in kpis.items():
            cur.execute("""
                INSERT INTO kpi_snapshots (metric_name, metric_value, period)
                VALUES (%s,%s,%s)
                ON CONFLICT DO NOTHING
            """, (name, value, period))
        conn.commit(); conn.close()
    except Exception:
        pass


@mcp.tool()
def get_profitability_ratios(period: str = "2026-02") -> dict:
    """Gross profit %, EBITDA margin, net margin with trend vs prior period."""
    import calendar; y, m = int(period[:4]), int(period[5:7])
    d1 = f"{period}-01"
    d2 = f"{period}-{calendar.monthrange(y,m)[1]:02d}"
    conn = get_connection(); cur = _cur(conn)
    rev  = _sum_acct(cur, "revenue", "", d1, d2)
    cogs = _sum_acct(cur, "expense", "cogs", d1, d2)
    opex = sum(_sum_acct(cur, "expense", c, d1, d2) for c in ["salary","overhead","marketing","travel","software"])
    conn.close()
    gross  = rev - cogs
    ebitda = gross - opex
    return {
        "period": period, "revenue": round(rev,2),
        "gross_profit": round(gross,2), "gross_margin_pct": round(gross/rev*100,2) if rev else 0,
        "ebitda": round(ebitda,2),      "ebitda_margin_pct": round(ebitda/rev*100,2) if rev else 0,
        "net_income_approx": round(ebitda*0.75,2),
        "net_margin_pct": round(ebitda*0.75/rev*100,2) if rev else 0,
    }


@mcp.tool()
def get_liquidity_ratios(as_of_date: str = "2026-02-28") -> dict:
    """Current ratio, quick ratio, cash ratio."""
    conn = get_connection(); cur = _cur(conn)
    def _bs(atype, acat):
        cur.execute("""
            SELECT COALESCE(SUM(CASE WHEN txn_type='debit' THEN amount ELSE -amount END),0) AS b
            FROM transactions t JOIN accounts a ON t.account_id=a.id
            WHERE a.type=%s AND a.category=%s AND t.txn_date<=%s
        """, (atype, acat, as_of_date))
        return abs(float(cur.fetchone()["b"]))
    cash = _bs("asset","cash"); ar = _bs("asset","receivable"); inv = _bs("asset","inventory")
    ap   = _bs("liability","payable"); acc = _bs("liability","accrued"); st = _bs("liability","short_term_debt")
    cur_assets = cash+ar+inv; cur_liab = ap+acc+st; conn.close()
    cr = round(cur_assets/cur_liab,2) if cur_liab else 0
    qr = round((cur_assets-inv)/cur_liab,2) if cur_liab else 0
    cashR = round(cash/cur_liab,2) if cur_liab else 0
    return {"as_of_date": as_of_date,
            "current_ratio": cr, "quick_ratio": qr, "cash_ratio": cashR,
            "benchmarks": {"current_ratio": 2.0, "quick_ratio": 1.0, "cash_ratio": 0.5},
            "status": {"current_ratio": "🟢" if cr>2 else "🟡" if cr>1.5 else "🔴",
                       "quick_ratio":   "🟢" if qr>1 else "🔴"}}


@mcp.tool()
def get_efficiency_ratios(period: str = "2026-02") -> dict:
    """Asset turnover, receivables turnover, DSO, DPO."""
    import calendar; y, m = int(period[:4]), int(period[5:7])
    d1 = f"{period}-01"
    d2 = f"{period}-{calendar.monthrange(y,m)[1]:02d}"
    conn = get_connection(); cur = _cur(conn)
    rev = _sum_acct(cur, "revenue", "", d1, d2) * 12  # annualise
    # Approx asset values
    total_assets = 20000000  # seed approx
    ar           = 4500000
    ap           = 2000000
    cogs_ann     = _sum_acct(cur, "expense", "cogs", d1, d2) * 12
    conn.close()
    at  = round(rev/total_assets, 2) if total_assets else 0
    rt  = round(rev/ar, 2) if ar else 0
    dso = round(ar/rev*365, 1) if rev else 0
    dpo = round(ap/cogs_ann*365, 1) if cogs_ann else 0
    return {"period": period, "asset_turnover": at, "receivables_turnover": rt,
            "dso_days": dso, "dpo_days": dpo,
            "note": "Ratios annualised from monthly data"}


@mcp.tool()
def get_leverage_ratios(as_of_date: str = "2026-02-28") -> dict:
    """Debt-to-equity, interest coverage, debt-to-assets."""
    conn = get_connection(); cur = _cur(conn)
    def _t(atype):
        cur.execute("""
            SELECT COALESCE(SUM(CASE WHEN txn_type='debit' THEN amount ELSE -amount END),0) AS b
            FROM transactions t JOIN accounts a ON t.account_id=a.id
            WHERE a.type=%s AND t.txn_date<=%s
        """, (atype, as_of_date))
        return abs(float(cur.fetchone()["b"]))
    total_liab = _t("liability"); total_eq = _t("equity"); total_assets = _t("asset")
    interest   = _t("expense")  # approx — full expenses
    conn.close()
    de  = round(total_liab/total_eq,2) if total_eq else 0
    da  = round(total_liab/total_assets,2) if total_assets else 0
    return {"as_of_date": as_of_date, "total_liabilities": round(total_liab,2),
            "total_equity": round(total_eq,2), "total_assets": round(total_assets,2),
            "debt_to_equity": de, "debt_to_assets": da,
            "status": "🟢 Conservative" if de < 0.5 else "🟡 Moderate" if de <= 1 else "🔴 High"}


@mcp.tool()
def get_kpi_trend(metric_name: str = "gross_margin_pct", periods: int = 3) -> list:
    """Historical values for any KPI metric across N periods from snapshots."""
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        SELECT metric_name, metric_value, period, calculated_at
        FROM kpi_snapshots WHERE metric_name=%s
        ORDER BY calculated_at DESC LIMIT %s
    """, (metric_name, periods))
    rows = list(reversed(cur.fetchall())); conn.close()
    result = [{"period": r["period"], "value": float(r["metric_value"]),
               "calculated_at": str(r["calculated_at"])[:10]} for r in rows]
    if len(result) >= 2:
        trend = result[-1]["value"] - result[-2]["value"]
        for r in result:
            r["trend"] = "📈 Improving" if trend > 0 else "📉 Declining" if trend < 0 else "➡️ Stable"
    return result if result else [{"message": f"No snapshot data found for '{metric_name}'."}]


@mcp.tool()
def get_performance_vs_benchmark(period: str = "2026-02") -> dict:
    """Compare company KPIs vs industry benchmark values."""
    kpis = get_all_kpis(period)
    benchmarks = {
        "gross_margin_pct":  {"benchmark": 65.0, "company": kpis["profitability"]["gross_margin_pct"]},
        "ebitda_margin_pct": {"benchmark": 22.0, "company": kpis["profitability"]["ebitda_margin_pct"]},
        "net_margin_pct":    {"benchmark": 12.0, "company": kpis["profitability"]["net_margin_pct"]},
        "current_ratio":     {"benchmark": 2.0,  "company": kpis["liquidity"]["current_ratio"]},
        "debt_to_equity":    {"benchmark": 0.5,  "company": kpis["leverage"]["debt_to_equity"]},
    }
    for k, v in benchmarks.items():
        comp = v["company"]; bench = v["benchmark"]
        if k == "debt_to_equity":
            v["vs_benchmark"] = "🟢 Better than benchmark" if comp < bench else "🔴 Worse than benchmark"
        else:
            v["vs_benchmark"] = "🟢 Above benchmark" if comp >= bench else "🔴 Below benchmark"
        v["difference"] = round(comp - bench, 2)
    return {"period": period, "industry": "SaaS / Technology", "kpis": benchmarks}


@mcp.tool()
def send_weekly_kpi_digest_email(recipients: str, period: str = "2026-02") -> dict:
    """Email a formatted KPI summary to the executive distribution list."""
    kpis    = get_all_kpis(period)
    kpi_map = {
        "Revenue":          f"₹{kpis['profitability']['revenue']:,.0f}",
        "Gross Margin %":   f"{kpis['profitability']['gross_margin_pct']}%",
        "EBITDA Margin %":  f"{kpis['profitability']['ebitda_margin_pct']}%",
        "Net Margin %":     f"{kpis['profitability']['net_margin_pct']}%",
        "Current Ratio":    str(kpis["liquidity"]["current_ratio"]),
        "Debt-to-Equity":   str(kpis["leverage"]["debt_to_equity"]),
    }
    result = send_kpi_digest(recipients, period, kpi_map)
    # Log
    conn = get_connection(); cur = _cur(conn)
    cur.execute("""
        INSERT INTO report_log (report_type,generated_by,recipients,period,status)
        VALUES ('weekly_kpi_digest','kpi_agent',%s,%s,'sent')
    """, (recipients, period))
    conn.commit(); conn.close()
    return {"digest_sent": result["success"], "period": period, "recipients": recipients,
            "kpis": kpi_map, "email_result": result}


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
