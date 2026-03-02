"""Static UI constants and quick action helpers."""

ROLE_QUICK_ACTIONS: dict[str, list[tuple[str, str]]] = {
    "admin": [
        ("📊 Full P&L February 2026", "Show me the complete income statement for February 2026 with all margins"),
        ("💰 Live Cash Position", "What is our current cash position and runway across all accounts?"),
        ("📈 All KPIs Dashboard", "Show me the full KPI dashboard with benchmark comparison for February 2026"),
        ("🎯 Top Overspend Departments", "Which departments are most over budget this month? Show top 5"),
        ("📋 Send Board Pack", "Generate and send the monthly board pack for February 2026"),
        ("📚 Chart of Accounts", "Show me the full chart of accounts"),
    ],
    "cfo": [
        ("📊 February 2026 P&L", "Show the complete P&L for February 2026 with EBITDA breakdown"),
        ("💰 Cash Runway", "What is our cash runway and current burn rate?"),
        ("📈 KPI Dashboard", "Show the full KPI dashboard with industry benchmark comparison"),
        ("📋 Board Pack", "Prepare and send the February 2026 board pack"),
        ("⚖️ Balance Sheet", "Show the balance sheet as of February 28, 2026"),
        ("💡 What is Free Cash Flow?", "Explain the difference between EBITDA and free cash flow"),
    ],
    "analyst": [
        ("📊 Income Statement Feb 2026", "Show the P&L for February 2026"),
        ("🎯 Budget Variance Report", "Show the full budget variance report for February 2026"),
        ("📈 KPI Trends", "Show KPI trends for the last 3 months"),
        ("💸 Revenue Breakdown", "Break down revenue by category for February 2026"),
        ("📉 Top Overspend", "Which departments exceeded budget most this month?"),
        ("📚 Post a GL Entry", "Post a sample journal entry to the GL"),
    ],
    "controller": [
        ("📚 Trial Balance", "Generate the trial balance as of February 28, 2026"),
        ("⚖️ Balance Sheet Check", "Show the balance sheet and verify it balances"),
        ("💰 Cash Position", "Show cash position across all accounts"),
        ("📋 Report History", "Show the last 10 financial reports sent"),
        ("🔄 Reconcile Accounts Receivable", "Reconcile the accounts receivable account"),
        ("📤 Send Cash Flow Report", "Send the cash flow summary for February 2026"),
    ],
}

AGENT_ACTION_KEYWORDS: dict[str, list[str]] = {
    "GL / Transactions": ["gl", "journal", "trial balance", "chart of accounts", "reconcile", "revenue breakdown", "post"],
    "Profit & Loss": ["p&l", "income statement", "ebitda", "revenue", "margin"],
    "Balance Sheet": ["balance sheet"],
    "Cash Flow": ["cash", "runway", "burn rate"],
    "Budget & Variance": ["budget", "variance", "overspend", "forecast"],
    "KPI & Analytics": ["kpi", "benchmark", "trend"],
    "Report Delivery": ["board pack", "send", "report history", "report"],
    "General Finance": ["explain", "difference", "what is", "free cash flow"],
}

AGENT_ICONS = {
    "GL / Transactions": "📚",
    "Profit & Loss": "📊",
    "Balance Sheet": "⚖️",
    "Cash Flow": "💰",
    "Budget & Variance": "🎯",
    "KPI & Analytics": "📈",
    "Report Delivery": "📋",
    "General Finance": "💡",
}


def actions_for_agent(role: str, agent: str) -> list[tuple[str, str]]:
    actions = ROLE_QUICK_ACTIONS.get(role, [])
    keys = [k.lower() for k in AGENT_ACTION_KEYWORDS.get(agent, [])]
    if not keys:
        return actions[:4]
    out = []
    for label, prompt in actions:
        hay = f"{label} {prompt}".lower()
        if any(k in hay for k in keys):
            out.append((label, prompt))
    return out[:6] if out else actions[:4]

