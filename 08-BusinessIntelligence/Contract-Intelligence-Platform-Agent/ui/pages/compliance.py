"""Compliance page."""
import streamlit as st
import pandas as pd

def render_compliance():
    st.title("🛡️ Compliance")

    try:
        from database.db import fetch_all
        contracts = fetch_all("SELECT id,contract_number,title FROM contracts ORDER BY created_at DESC")
        opts = {f"{c['contract_number']} — {c['title']}": c["id"] for c in contracts}
    except Exception:
        opts = {}

    if not opts:
        st.info("No contracts available.")
        return

    selected = st.selectbox("Select Contract", list(opts.keys()))
    cid      = opts[selected]

    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Full Check", "🇪🇺 GDPR", "⚖️ Jurisdiction", "📜 Audit Trail"])

    with tab1:
        regs = st.multiselect("Regulations", ["GDPR","CCPA","SOX","HIPAA","General"], default=["GDPR","General"])
        if st.button("Run Compliance Check", type="primary"):
            from agents.compliance_agent.mcp_server.tools.compliance_tools import check_compliance
            result = check_compliance(cid, ",".join(regs))
            col1, col2 = st.columns(2)
            col1.metric("Issues Found",     result.get("issues_found",0))
            col2.metric("Compliance Score", f"{result.get('compliance_score',0)}%")
            issues = result.get("issues",[])
            if issues:
                df = pd.DataFrame(issues)[["issue_type","regulation","severity","description","recommendation"]]
                st.dataframe(df, use_container_width=True, hide_index=True)

    with tab2:
        if st.button("Run GDPR Check", type="primary"):
            from agents.compliance_agent.mcp_server.tools.compliance_tools import run_gdpr_check
            result = run_gdpr_check(cid)
            col1, col2 = st.columns(2)
            col1.metric("GDPR Score",   f"{result.get('gdpr_score',0)}%")
            col2.metric("Status", "✅ Compliant" if result.get("gdpr_compliant") else "⚠️ Issues Found")
            checks = result.get("gdpr_checks",[])
            if checks:
                df = pd.DataFrame(checks)
                # Map status to visual indicator
                df["result"] = df["status"].map({
                    "COMPLIANT": "✅",
                    "PARTIAL": "⚠️",
                    "MISSING": "❌"
                }).fillna("❓")
                # Display relevant columns
                display_cols = ["requirement", "severity", "result"]
                if all(col in df.columns for col in display_cols):
                    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No GDPR checks available.")

    with tab3:
        jur = st.selectbox("Jurisdiction", ["New York","California","England & Wales","EU","Texas"])
        if st.button("Check Jurisdiction Rules", type="primary"):
            from agents.compliance_agent.mcp_server.tools.compliance_tools import run_jurisdiction_check
            result = run_jurisdiction_check(cid, jur)
            checks = result.get("rules_checked",[])
            if checks:
                df = pd.DataFrame(checks)
                st.dataframe(df, use_container_width=True, hide_index=True)

    with tab4:
        if st.button("Generate Audit Trail", type="primary"):
            from agents.compliance_agent.mcp_server.tools.compliance_tools import generate_audit_trail
            result = generate_audit_trail(cid)
            entries = result.get("audit_entries",[])
            st.metric("Audit Entries", len(entries))
            if entries:
                df = pd.DataFrame(entries)
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No audit entries found for this contract.")
