"""Review & Risk page."""
import streamlit as st
import pandas as pd

def render_review():
    st.title("🔍 Review & Risk Analysis")

    try:
        from database.db import fetch_all
        contracts = fetch_all("SELECT id, contract_number, title, status FROM contracts ORDER BY created_at DESC")
        options   = {f"{c['contract_number']} — {c['title']}": c["id"] for c in contracts}
    except Exception:
        options = {}

    if not options:
        st.info("No contracts available. Create a contract first.")
        return

    selected = st.selectbox("Select Contract", list(options.keys()))
    cid      = options[selected]

    tab1, tab2, tab3, tab4 = st.tabs(["⚡ Risk Analysis", "🔴 Flag Clauses", "📋 Playbook Check", "✏️ Redlines"])

    with tab1:
        if st.button("🔍 Run Full Analysis", type="primary"):
            with st.spinner("Analysing contract..."):
                from agents.review_agent.mcp_server.tools.review_tools import analyze_contract
                result = analyze_contract(cid)
            
            # Display metrics
            score  = result.get("risk_score", 0)
            level  = result.get("risk_level", "")
            flags  = result.get("flags", [])
            colors = {"Low":"🟢","Medium":"🟡","High":"🟠","Critical":"🔴"}
            
            col1, col2 = st.columns(2)
            col1.metric("Risk Score", f"{score}/100")
            col2.metric("Risk Level",  f"{colors.get(level,'•')} {level}")
            
            # Display key findings
            key_findings = result.get("key_findings", [])
            if key_findings:
                st.subheader("📌 Key Findings")
                for i, finding in enumerate(key_findings, 1):
                    st.markdown(f"**{i}.** {finding}")
            
            # Display flags in table
            if flags:
                st.subheader("🚩 Risk Flags")
                df = pd.DataFrame(flags)
                # Ensure we only display available columns
                available_cols = [col for col in ["issue", "severity", "recommendation"] if col in df.columns]
                st.dataframe(df[available_cols], use_container_width=True, hide_index=True)
            else:
                st.success("✅ No risk flags identified.")
            
            # Display compliance status
            compliance_status = result.get("compliance_status", "UNKNOWN")
            if compliance_status == "GOOD":
                st.success(f"✅ Compliance Status: {compliance_status}")
            elif compliance_status == "CONCERNS":
                st.warning(f"⚠️ Compliance Status: {compliance_status}")
            else:
                st.error(f"❌ Compliance Status: {compliance_status}")

        st.subheader("Missing Clauses")
        ctype = st.selectbox("Contract Type for Check", ["MSA","NDA","SOW","Vendor"])
        if st.button("Check Missing Clauses"):
            from agents.review_agent.mcp_server.tools.review_tools import check_missing_clauses
            result = check_missing_clauses(cid, ctype)
            
            completeness = result.get('completeness_score', 'UNKNOWN')
            if isinstance(completeness, str) and completeness.isdigit():
                st.metric("Completeness", f"{completeness}%")
            else:
                st.metric("Completeness", str(completeness))
            
            # Display clause analysis
            clause_analysis = result.get("clause_analysis", [])
            if clause_analysis:
                st.subheader("📋 Clause Analysis")
                df = pd.DataFrame(clause_analysis)
                # Map status to visual indicator
                if "status" in df.columns:
                    df["result"] = df["status"].map({
                        "PRESENT": "✅ Present",
                        "MISSING": "❌ Missing",
                        "INADEQUATE": "⚠️ Inadequate",
                        "UNKNOWN": "❓ Unknown"
                    }).fillna("❓")
                    display_cols = ["clause", "result", "severity"]
                    available_cols = [col for col in display_cols if col in df.columns]
                    st.dataframe(df[available_cols], use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Display missing critical items
            missing_critical = result.get("missing_critical", [])
            if missing_critical:
                st.warning(f"🚩 Missing Critical Clauses: {', '.join(missing_critical)}")
            
            # Display recommendations
            recommendations = result.get("recommendations", [])
            if recommendations:
                st.subheader("💡 Recommendations")
                for rec in recommendations:
                    st.markdown(f"• {rec}")

    with tab2:
        risk_filter = st.radio("Show risk level", ["HIGH","MEDIUM","LOW"], horizontal=True)
        if st.button("Flag Clauses", type="primary"):
            from agents.review_agent.mcp_server.tools.review_tools import flag_clauses
            result = flag_clauses(cid, risk_filter)
            items  = result.get("flagged_clauses", [])
            st.metric("Flagged Clauses", len(items))
            if items:
                st.dataframe(pd.DataFrame(items), use_container_width=True, hide_index=True)
            else:
                st.success(f"No {risk_filter} risk clauses found.")

    with tab3:
        if st.button("Run Playbook Check", type="primary"):
            from agents.review_agent.mcp_server.tools.review_tools import compare_to_playbook
            result = compare_to_playbook(cid)
            
            col1, col2 = st.columns(2)
            col1.metric("Playbook Score", f"{result.get('compliance_pct',0)}%")
            col2.metric("Checks Passed",  f"{result.get('checks_passed',0)}/{result.get('checks_total',0)}")
            
            # Display critical issues if any
            critical_issues = result.get("critical_issues", [])
            if critical_issues:
                st.subheader("⚠️ Critical Issues")
                for issue in critical_issues:
                    st.error(f"• {issue}")
            
            # Display check results
            checks = result.get("results",[])
            if checks:
                st.subheader("📋 Playbook Requirements")
                df = pd.DataFrame(checks)
                # Map status to visual indicator
                if "status" in df.columns:
                    df["result"] = df["status"].map({
                        "COMPLIANT": "✅ Compliant",
                        "PARTIAL": "⚠️ Partial",
                        "MISSING": "❌ Missing"
                    }).fillna("❓ Unknown")
                    # Display relevant columns
                    display_cols = ["requirement", "result"]
                    if "evidence" in df.columns:
                        display_cols.append("evidence")
                    st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
                else:
                    st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Display summary
            summary = result.get("summary", "")
            if summary:
                st.info(f"📝 Summary: {summary}")

    with tab4:
        if st.button("Generate Redline Suggestions", type="primary"):
            from agents.review_agent.mcp_server.tools.review_tools import suggest_redlines
            result  = suggest_redlines(cid)
            redlines= result.get("redlines",[])
            if not redlines:
                st.info("No redline suggestions generated.")
            for r in redlines:
                with st.expander(f"📝 {r.get('clause','Clause')}"):
                    st.markdown(f"**Current:** {r.get('current','—')}")
                    st.markdown(f"**Suggested:** {r.get('suggested','—')}")
                    st.markdown(f"**Rationale:** {r.get('rationale','—')}")
