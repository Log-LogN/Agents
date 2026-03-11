"""Approvals page."""
import streamlit as st
import pandas as pd

def render_approvals():
    st.title("✅ Approval Workflows")

    tab1, tab2 = st.tabs(["⏳ Pending Approvals", "🔄 Create Workflow"])

    with tab1:
        from agents.approval_agent.mcp_server.tools.approval_tools import get_pending_approvals
        result   = get_pending_approvals()
        pending  = result.get("pending_approvals", [])
        st.metric("Pending Approvals", len(pending))
        if pending:
            for item in pending:
                item = dict(item)
                with st.expander(f"⏳ {item.get('contract_number','N/A')} — {item.get('title','N/A')}"):
                    c1, c2 = st.columns(2)
                    c1.markdown(f"**Type:** {item.get('contract_type','')}")
                    c1.markdown(f"**Value:** ${float(item.get('value',0)):,.0f}")
                    c2.markdown(f"**Status:** {item.get('status','')}")
                    c2.markdown(f"**Deadline:** {item.get('deadline','—')}")
                    cid = item.get("id")
                    col_a, col_b, col_c = st.columns(3)
                    user = st.session_state.get("user",{})
                    email = user.get("email","")
                    if col_a.button("✅ Approve", key=f"app_{cid}"):
                        from agents.approval_agent.mcp_server.tools.approval_tools import approve_contract
                        r = approve_contract(cid, email, "Approved via platform")
                        st.success(r.get("message",""))
                        st.rerun()
                    if col_b.button("❌ Reject", key=f"rej_{cid}"):
                        from agents.approval_agent.mcp_server.tools.approval_tools import reject_contract
                        r = reject_contract(cid, email, "Rejected via platform")
                        st.warning(r.get("message",""))
                        st.rerun()
                    if col_c.button("🔺 Escalate", key=f"esc_{cid}"):
                        from agents.approval_agent.mcp_server.tools.approval_tools import escalate_approval
                        r = escalate_approval(cid, "Escalated for senior review")
                        st.info(r.get("message",""))
        else:
            st.success("✅ No pending approvals.")

    with tab2:
        st.subheader("Create Approval Workflow")
        try:
            from database.db import fetch_all
            contracts = fetch_all("SELECT id,contract_number,title FROM contracts WHERE status IN ('DRAFT','REVIEW') ORDER BY created_at DESC")
            opts = {f"{c['contract_number']} — {c['title']}": c["id"] for c in contracts}
        except Exception:
            opts = {}
        if opts:
            sel      = st.selectbox("Select Contract", list(opts.keys()))
            cid      = opts[sel]
            approvers= st.text_input("Approvers (comma-separated emails)", "manager@contract.ai, admin@contract.ai")
            deadline = st.number_input("Deadline (days)", 1, 30, 7)
            if st.button("Create Workflow", type="primary"):
                from agents.approval_agent.mcp_server.tools.approval_tools import create_approval_workflow
                user = st.session_state.get("user",{})
                result = create_approval_workflow(cid, [a.strip() for a in approvers.split(",")], deadline, user.get("id",1))
                st.success(result.get("message","Workflow created."))
        else:
            st.info("No contracts in DRAFT or REVIEW status available.")
