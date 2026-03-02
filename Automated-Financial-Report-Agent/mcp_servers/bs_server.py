"""mcp_servers/bs_server.py — Balance Sheet Agent (port 8003 · 8 tools)"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psycopg2.extras
from mcp.server.fastmcp import FastMCP
from database.db import get_connection, init_db

mcp = FastMCP("BSServer", host="127.0.0.1", port=8003, stateless_http=True, json_response=True)


def _cur(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def _sum_category(cur, account_type: str, category: str, as_of: str) -> float:
    cur.execute("""
        SELECT COALESCE(SUM(CASE WHEN txn_type='debit' THEN amount ELSE -amount END),0) AS bal
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type=%s AND a.category=%s AND t.txn_date<=%s
    """, (account_type, category, as_of))
    return float(cur.fetchone()["bal"])


def _sum_type(cur, account_type: str, as_of: str) -> float:
    cur.execute("""
        SELECT COALESCE(SUM(CASE WHEN txn_type='debit' THEN amount ELSE -amount END),0) AS bal
        FROM transactions t JOIN accounts a ON t.account_id=a.id
        WHERE a.type=%s AND t.txn_date<=%s
    """, (account_type, as_of))
    return abs(float(cur.fetchone()["bal"]))


@mcp.tool()
def get_balance_sheet(as_of_date: str = "2026-02-28") -> dict:
    """Full balance sheet as of a date: assets, liabilities, equity."""
    conn = get_connection(); cur = _cur(conn)
    # Assets
    cash      = _sum_category(cur, "asset", "cash", as_of_date)
    ar        = _sum_category(cur, "asset", "receivable", as_of_date)
    inventory = _sum_category(cur, "asset", "inventory", as_of_date)
    prepaid   = _sum_category(cur, "asset", "prepaid", as_of_date)
    cur_assets = cash + ar + inventory + prepaid
    fixed     = _sum_category(cur, "asset", "fixed_asset", as_of_date)
    depr      = abs(_sum_category(cur, "asset", "depreciation", as_of_date))
    net_fixed = fixed - depr
    total_assets = cur_assets + net_fixed
    # Liabilities
    ap        = abs(_sum_category(cur, "liability", "payable", as_of_date))
    accrued   = abs(_sum_category(cur, "liability", "accrued", as_of_date))
    st_debt   = abs(_sum_category(cur, "liability", "short_term_debt", as_of_date))
    cur_liab  = ap + accrued + st_debt
    lt_debt   = abs(_sum_category(cur, "liability", "long_term_debt", as_of_date))
    deferred  = abs(_sum_category(cur, "liability", "deferred_revenue", as_of_date))
    total_liab = cur_liab + lt_debt + deferred
    # Equity
    capital   = _sum_category(cur, "equity", "capital", as_of_date)
    retained  = _sum_category(cur, "equity", "retained", as_of_date)
    total_eq  = abs(capital) + abs(retained)
    conn.close()
    balanced  = abs(total_assets - (total_liab + total_eq)) < 1000
    return {
        "as_of_date": as_of_date,
        "assets": {
            "current_assets": {"cash": round(cash,2), "accounts_receivable": round(ar,2),
                               "inventory": round(inventory,2), "prepaid": round(prepaid,2),
                               "total": round(cur_assets,2)},
            "fixed_assets": {"gross": round(fixed,2), "accumulated_depreciation": round(depr,2),
                             "net": round(net_fixed,2)},
            "total_assets": round(total_assets,2),
        },
        "liabilities": {
            "current_liabilities": {"accounts_payable": round(ap,2), "accrued_salaries": round(accrued,2),
                                    "short_term_debt": round(st_debt,2), "total": round(cur_liab,2)},
            "long_term": {"long_term_debt": round(lt_debt,2), "deferred_revenue": round(deferred,2)},
            "total_liabilities": round(total_liab,2),
        },
        "equity": {"share_capital": round(abs(capital),2), "retained_earnings": round(abs(retained),2),
                   "total_equity": round(total_eq,2)},
        "total_liabilities_and_equity": round(total_liab + total_eq, 2),
        "balanced": balanced,
        "accounting_check": "✅ A = L + E (balanced)" if balanced else "⚠️ Balance sheet does not balance!",
    }


@mcp.tool()
def get_current_assets(as_of_date: str = "2026-02-28") -> dict:
    """Detail of current assets: cash, AR, inventory, prepaid."""
    conn = get_connection(); cur = _cur(conn)
    cash = _sum_category(cur, "asset", "cash", as_of_date)
    ar   = _sum_category(cur, "asset", "receivable", as_of_date)
    inv  = _sum_category(cur, "asset", "inventory", as_of_date)
    pre  = _sum_category(cur, "asset", "prepaid", as_of_date)
    conn.close()
    total = cash + ar + inv + pre
    return {"as_of_date": as_of_date, "cash": round(cash,2), "accounts_receivable": round(ar,2),
            "inventory": round(inv,2), "prepaid": round(pre,2), "total_current_assets": round(total,2)}


@mcp.tool()
def get_current_liabilities(as_of_date: str = "2026-02-28") -> dict:
    """Detail of current liabilities: AP, accrued, short-term debt."""
    conn = get_connection(); cur = _cur(conn)
    ap      = abs(_sum_category(cur, "liability", "payable", as_of_date))
    accrued = abs(_sum_category(cur, "liability", "accrued", as_of_date))
    st_debt = abs(_sum_category(cur, "liability", "short_term_debt", as_of_date))
    conn.close()
    total = ap + accrued + st_debt
    return {"as_of_date": as_of_date, "accounts_payable": round(ap,2),
            "accrued_salaries": round(accrued,2), "short_term_debt": round(st_debt,2),
            "total_current_liabilities": round(total,2)}


@mcp.tool()
def get_long_term_items(as_of_date: str = "2026-02-28") -> dict:
    """Fixed assets, long-term debt, retained earnings."""
    conn = get_connection(); cur = _cur(conn)
    fixed   = _sum_category(cur, "asset", "fixed_asset", as_of_date)
    depr    = abs(_sum_category(cur, "asset", "depreciation", as_of_date))
    lt_debt = abs(_sum_category(cur, "liability", "long_term_debt", as_of_date))
    retained= _sum_category(cur, "equity", "retained", as_of_date)
    conn.close()
    return {"as_of_date": as_of_date, "gross_fixed_assets": round(fixed,2),
            "accumulated_depreciation": round(depr,2), "net_fixed_assets": round(fixed-depr,2),
            "long_term_debt": round(lt_debt,2), "retained_earnings": round(abs(retained),2)}


@mcp.tool()
def get_current_ratio(as_of_date: str = "2026-02-28") -> dict:
    """Current ratio = current assets / current liabilities with status."""
    ca = get_current_assets(as_of_date)
    cl = get_current_liabilities(as_of_date)
    cur_assets = ca["total_current_assets"]
    cur_liab   = cl["total_current_liabilities"]
    ratio = round(cur_assets / cur_liab, 2) if cur_liab else 0
    status = ("🟢 Healthy (>2.0)" if ratio > 2.0 else
              "🟡 Acceptable (1.5–2.0)" if ratio >= 1.5 else
              "🔴 Low — watch carefully (<1.5)")
    return {"as_of_date": as_of_date, "current_assets": cur_assets,
            "current_liabilities": cur_liab, "current_ratio": ratio,
            "benchmark": 2.0, "status": status}


@mcp.tool()
def get_working_capital(as_of_date: str = "2026-02-28") -> dict:
    """Working capital = current assets − current liabilities."""
    ca = get_current_assets(as_of_date)
    cl = get_current_liabilities(as_of_date)
    wc = ca["total_current_assets"] - cl["total_current_liabilities"]
    return {"as_of_date": as_of_date, "current_assets": ca["total_current_assets"],
            "current_liabilities": cl["total_current_liabilities"],
            "working_capital": round(wc, 2),
            "status": "✅ Positive — sufficient short-term liquidity" if wc > 0 else "⚠️ Negative working capital"}


@mcp.tool()
def get_debt_to_equity(as_of_date: str = "2026-02-28") -> dict:
    """Debt-to-equity ratio with status."""
    conn = get_connection(); cur = _cur(conn)
    total_liab = _sum_type(cur, "liability", as_of_date)
    total_eq   = _sum_type(cur, "equity", as_of_date)
    conn.close()
    de = round(total_liab / total_eq, 2) if total_eq else 0
    status = ("🟢 Conservative (<0.5)" if de < 0.5 else
              "🟡 Moderate (0.5–1.0)" if de <= 1.0 else
              "🔴 High leverage (>1.0)")
    return {"as_of_date": as_of_date, "total_liabilities": round(total_liab,2),
            "total_equity": round(total_eq,2), "debt_to_equity": de,
            "benchmark": 0.5, "status": status}


@mcp.tool()
def check_balance_sheet_equation(as_of_date: str = "2026-02-28") -> dict:
    """Verify Assets = Liabilities + Equity — flag discrepancy."""
    bs = get_balance_sheet(as_of_date)
    assets  = bs["assets"]["total_assets"]
    liab_eq = bs["total_liabilities_and_equity"]
    diff    = round(abs(assets - liab_eq), 2)
    return {"as_of_date": as_of_date, "total_assets": assets,
            "total_liabilities_plus_equity": liab_eq, "discrepancy": diff,
            "balanced": diff < 1.0,
            "result": "✅ Balance sheet equation holds." if diff < 1.0 else f"⚠️ Out of balance by ₹{diff:,.2f}"}


def main():
    init_db()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
