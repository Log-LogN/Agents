"""Obligations & Renewals page."""
import streamlit as st
import pandas as pd

def render_obligations():
    st.title("📋 Obligations & Renewals")

    tab1, tab2, tab3 = st.tabs(["📋 All Obligations", "⏰ Upcoming Deadlines", "🔄 Renewals"])

    with tab1:
        col1, col2 = st.columns(2)
        status_filter = col1.selectbox("Status", ["All","PENDING","IN_PROGRESS","COMPLETED","OVERDUE","WAIVED"])
        from agents.obligation_agent.mcp_server.tools.obligation_tools import get_obligations
        result = get_obligations(0, "" if status_filter=="All" else status_filter)
        items  = result.get("obligations",[])
        st.metric("Obligations", len(items))
        if items:
            df = pd.DataFrame(items)
            cols = [c for c in ["id","contract_id","obligation_type","description","due_date","status","priority"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
            st.subheader("Update Status")
            ob_ids = df["id"].tolist()
            if ob_ids:
                sel_id     = col2.selectbox("Obligation ID", ob_ids)
                new_status = st.selectbox("New Status", ["PENDING","IN_PROGRESS","COMPLETED","OVERDUE","WAIVED"])
                if st.button("Update", type="primary"):
                    from agents.obligation_agent.mcp_server.tools.obligation_tools import update_obligation_status
                    r = update_obligation_status(sel_id, new_status)
                    st.success(r.get("message","Updated."))
                    st.rerun()
        else:
            st.info("No obligations found.")

    with tab2:
        days = st.slider("Days ahead", 7, 180, 30)
        from agents.obligation_agent.mcp_server.tools.obligation_tools import get_upcoming_deadlines
        result = get_upcoming_deadlines(days)
        items  = result.get("deadlines",[])
        st.metric(f"Deadlines in {days} days", len(items))
        if items:
            df = pd.DataFrame(items)
            cols = [c for c in ["due_date","description","obligation_type","priority","status","contract_title"] if c in df.columns]
            st.dataframe(df[cols], use_container_width=True, hide_index=True)
        else:
            st.success(f"✅ No deadlines in the next {days} days.")

    with tab3:
        st.subheader("Create Renewal Alert")
        try:
            from database.db import fetch_all
            contracts = fetch_all("SELECT id,contract_number,title FROM contracts WHERE status='ACTIVE' ORDER BY end_date")
            opts = {f"{c['contract_number']} — {c['title']}": c["id"] for c in contracts}
        except Exception:
            opts = {}
        if opts:
            sel          = st.selectbox("Contract", list(opts.keys()))
            cid          = opts[sel]
            notice_days  = st.number_input("Notice period (days)", 30, 180, 90)
            if st.button("Set Renewal Alert", type="primary"):
                from agents.obligation_agent.mcp_server.tools.obligation_tools import create_renewal_alert
                r = create_renewal_alert(cid, notice_days)
                st.success(r.get("message","Alert created."))
        else:
            st.info("No active contracts found.")
