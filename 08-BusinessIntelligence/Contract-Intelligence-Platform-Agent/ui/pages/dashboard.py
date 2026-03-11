"""Dashboard page — portfolio KPIs, alerts, recent activity."""
import streamlit as st

def render_dashboard():
    st.title("🏠 Dashboard")
    user = st.session_state.get("user", {})
    st.markdown(f"Welcome back, **{user.get('full_name') or user.get('email','')}** — *{user.get('role','').replace('_',' ').title()}*")
    st.markdown("---")

    try:
        from agents.analytics_agent.mcp_server.tools.analytics_tools import get_portfolio_summary, get_expiry_report
        from agents.obligation_agent.mcp_server.tools.obligation_tools  import get_upcoming_deadlines as ob_deadlines

        summary = get_portfolio_summary()
        p = summary.get("portfolio", {})

        # KPI row
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("📄 Total Contracts",    p.get("total_contracts", 0))
        c2.metric("✅ Active",             p.get("active", 0))
        c3.metric("🔍 Under Review",       p.get("under_review", 0))
        c4.metric("⏰ Expiring (90d)",     p.get("expiring_90_days", 0))
        c5.metric("⚠️ Overdue Obligations",p.get("overdue_obligations", 0))

        st.markdown("---")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📊 Portfolio Value")
            val = p.get("active_value_usd", 0)
            st.markdown(f"### ${val:,.0f}")
            st.caption("Total active contract value (USD)")

            st.subheader("📋 By Contract Type")
            by_type = p.get("by_type", [])
            if by_type:
                import pandas as pd
                df = pd.DataFrame(by_type)
                st.bar_chart(df.set_index("contract_type")["count"])

        with col2:
            st.subheader("🚨 Upcoming Deadlines (30 days)")
            try:
                dead = ob_deadlines(30)
                items = dead.get("deadlines", [])
                if items:
                    import pandas as pd
                    df = pd.DataFrame(items)[["due_date","description","priority","status"]]
                    df.columns = ["Due Date","Description","Priority","Status"]
                    st.dataframe(df, use_container_width=True, hide_index=True)
                else:
                    st.success("✅ No upcoming deadlines in the next 30 days.")
            except Exception:
                st.info("Deadline data unavailable.")

            st.subheader("📉 Risk Overview")
            risk = p.get("avg_risk_score", 0)
            col_a, col_b = st.columns(2)
            col_a.metric("Avg Risk Score", f"{risk}/100")
            level = "🟢 Low" if risk <= 25 else ("🟡 Medium" if risk <= 50 else ("🟠 High" if risk <= 75 else "🔴 Critical"))
            col_b.metric("Risk Level", level)

    except Exception as e:
        st.warning(f"Dashboard data loading... ({e})")
        st.info("Make sure the database is running and initialised.")
