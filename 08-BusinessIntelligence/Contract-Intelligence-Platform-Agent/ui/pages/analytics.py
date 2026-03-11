"""Analytics & Reports page."""
import streamlit as st
import pandas as pd

def render_analytics():
    st.title("📊 Analytics & Reports")

    tab1, tab2, tab3, tab4 = st.tabs(["📈 Portfolio", "💰 Spend", "⚠️ Risk", "🔍 Search"])

    with tab1:
        from agents.analytics_agent.mcp_server.tools.analytics_tools import get_portfolio_summary, get_expiry_report, get_cycle_time_report
        summary = get_portfolio_summary()
        p = summary.get("portfolio",{})
        c1,c2,c3,c4 = st.columns(4)
        c1.metric("Total",         p.get("total_contracts",0))
        c2.metric("Active",        p.get("active",0))
        c3.metric("Active Value",  f"${p.get('active_value_usd',0):,.0f}")
        c4.metric("Expiring 90d",  p.get("expiring_90_days",0))

        st.subheader("Contracts by Type")
        by_type = p.get("by_type",[])
        if by_type:
            df = pd.DataFrame(by_type)
            st.bar_chart(df.set_index("contract_type")["count"])

        st.subheader("Expiring Contracts (next 90 days)")
        days = st.slider("Days ahead", 30, 365, 90, key="exp_days")
        exp  = get_expiry_report(days)
        items = exp.get("contracts",[])
        if items:
            df = pd.DataFrame(items)[["contract_number","title","contract_type","end_date","value","party_b_name"]]
            df.columns = ["Number","Title","Type","Expires","Value","Counterparty"]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.success(f"No contracts expiring in {days} days.")

        st.subheader("Cycle Times")
        ct = get_cycle_time_report()
        ct_data = ct.get("cycle_times",{})
        cols = st.columns(3)
        cols[0].metric("Draft → Review",     f"{ct_data.get('draft_to_review_avg_days',0)} days")
        cols[1].metric("Review → Approval",  f"{ct_data.get('review_to_approval_avg_days',0)} days")
        cols[2].metric("End-to-End Average", f"{ct_data.get('total_end_to_end_avg_days',0)} days")
        st.caption(f"Industry benchmark: {ct_data.get('benchmark_industry_days',22)} days | Our improvement: {ct_data.get('improvement_vs_benchmark','N/A')}")

    with tab2:
        from agents.analytics_agent.mcp_server.tools.analytics_tools import get_spend_analytics
        period = st.selectbox("Period", [90, 180, 365], format_func=lambda x: f"{x} days", index=2)
        spend  = get_spend_analytics(period)
        items  = spend.get("spend_breakdown",[])
        total  = spend.get("total_active_value",0)
        st.metric("Total Active Contract Value", f"${total:,.0f}")
        if items:
            df = pd.DataFrame(items)
            df["total_value"] = df["total_value"].astype(float)
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.subheader("Top Vendors by Value")
            top = df.nlargest(8,"total_value")[["party_b_name","total_value","contract_count"]]
            st.bar_chart(top.set_index("party_b_name")["total_value"])

    with tab3:
        from agents.analytics_agent.mcp_server.tools.analytics_tools import get_risk_dashboard
        rd = get_risk_dashboard().get("risk_dashboard",{})
        summary_r = rd.get("summary",{})
        c1,c2,c3 = st.columns(3)
        c1.metric("🔴 Critical Risk", summary_r.get("critical",0))
        c2.metric("🟠 High Risk",     summary_r.get("high",0))
        c3.metric("🟡 Medium Risk",   summary_r.get("medium",0))

        for label, key in [("🔴 Critical Risk Contracts","critical_risk"),("🟠 High Risk Contracts","high_risk")]:
            items = rd.get(key,[])
            if items:
                st.subheader(label)
                df = pd.DataFrame(items)[["contract_number","title","contract_type","risk_score","status"]]
                st.dataframe(df, use_container_width=True, hide_index=True)

    with tab4:
        query  = st.text_input("Search contracts", placeholder="Search by title, party, or keyword...")
        ct     = st.selectbox("Type filter", ["All","NDA","MSA","SOW","Vendor","Employment"], key="search_type")
        st_fil = st.selectbox("Status filter", ["All","ACTIVE","DRAFT","REVIEW","EXPIRED"], key="search_status")
        if st.button("Search", type="primary") and query:
            from agents.analytics_agent.mcp_server.tools.analytics_tools import search_contracts
            result = search_contracts(query, "" if ct=="All" else ct, "" if st_fil=="All" else st_fil)
            items  = result.get("results",[])
            st.metric("Results", len(items))
            if items:
                df = pd.DataFrame(items)[["contract_number","title","contract_type","status","value","party_b_name","risk_score"]]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No contracts found matching your search.")
