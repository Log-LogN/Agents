"""Contract Repository page."""
import streamlit as st
import pandas as pd

def render_contracts():
    st.title("📂 Contract Repository")

    # Filters
    col1, col2, col3 = st.columns(3)
    search  = col1.text_input("🔍 Search", placeholder="Title, party, or number...")
    ctype   = col2.selectbox("Type", ["All","NDA","MSA","SOW","Vendor","Employment","SaaS","Lease"])
    cstatus = col3.selectbox("Status", ["All","DRAFT","REVIEW","APPROVAL","EXECUTION","ACTIVE","EXPIRED","TERMINATED"])

    try:
        from database.db import fetch_all
        sql    = """SELECT id, contract_number, title, contract_type, status,
                           party_b_name, value, currency, end_date, risk_score
                    FROM contracts WHERE 1=1"""
        params = []
        if search:
            sql += " AND (title ILIKE %s OR contract_number ILIKE %s OR party_b_name ILIKE %s)"
            params += [f"%{search}%", f"%{search}%", f"%{search}%"]
        if ctype != "All":
            sql += " AND contract_type=%s"; params.append(ctype)
        if cstatus != "All":
            sql += " AND status=%s"; params.append(cstatus)
        sql += " ORDER BY created_at DESC"
        rows = fetch_all(sql, tuple(params))

        if not rows:
            st.info("No contracts found matching your filters.")
            return

        st.markdown(f"**{len(rows)} contract(s) found**")
        for r in rows:
            r = dict(r)
            risk    = r.get("risk_score", 0)
            risk_c  = "🟢" if risk <= 25 else ("🟡" if risk <= 50 else ("🟠" if risk <= 75 else "🔴"))
            status_badges = {
                "ACTIVE":"✅","DRAFT":"📝","REVIEW":"🔍","APPROVAL":"⏳",
                "EXECUTION":"✍️","EXPIRED":"⌛","TERMINATED":"❌","AMENDED":"🔄"
            }
            badge = status_badges.get(r["status"], "•")

            with st.expander(f"{badge} **{r['contract_number']}** — {r['title']}  {risk_c} Risk {risk}"):
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**Type:** {r['contract_type']}")
                c1.markdown(f"**Status:** {r['status']}")
                c2.markdown(f"**Counterparty:** {r.get('party_b_name','—')}")
                c2.markdown(f"**Value:** {r.get('currency','USD')} {float(r.get('value',0)):,.2f}")
                c3.markdown(f"**Expires:** {r.get('end_date','—')}")
                c3.markdown(f"**Risk Score:** {risk}/100")

                col_a, col_b, col_c = st.columns(3)
                if col_a.button("🔍 Analyze Risk", key=f"risk_{r['id']}"):
                    from agents.review_agent.mcp_server.tools.review_tools import analyze_contract
                    result = analyze_contract(r["id"])
                    # Display metrics
                    score  = result.get("risk_score", 0)
                    level  = result.get("risk_level", "")
                    flags  = result.get("flags", [])
                    colors = {"Low":"🟢","Medium":"🟡","High":"🟠","Critical":"🔴"}
                    st.markdown(f"**Risk Score:** {score}/100")
                    st.markdown(f"**Risk Level:** {colors.get(level,'•')} {level}")
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
                if col_b.button("📋 Obligations", key=f"obl_{r['id']}"):
                    from agents.obligation_agent.mcp_server.tools.obligation_tools import get_obligations
                    result = get_obligations(r["id"])
                    obs = result.get("obligations", [])
                    if obs:
                        st.dataframe(pd.DataFrame(obs)[["obligation_type","description","due_date","status","priority"]], hide_index=True)
                    else:
                        st.info("No obligations recorded.")
                if col_c.button("🛡️ Compliance", key=f"comp_{r['id']}"):
                    from agents.compliance_agent.mcp_server.tools.compliance_tools import check_compliance
                    result = check_compliance(r["id"])
                    # Display metrics
                    score = result.get("compliance_score", 0)
                    issues_found = result.get("issues_found", 0)
                    overall_status = result.get("overall_status", "UNKNOWN")
                    key_findings = result.get("key_findings", [])
                    issues = result.get("issues", [])
                    st.markdown(f"**Compliance Score:** {score}%")
                    st.markdown(f"**Issues Found:** {issues_found}")
                    # Display overall status
                    if overall_status == "GOOD":
                        st.success(f"✅ Overall Status: {overall_status}")
                    elif overall_status == "CONCERNS":
                        st.warning(f"⚠️ Overall Status: {overall_status}")
                    else:
                        st.error(f"❌ Overall Status: {overall_status}")
                    # Display key findings
                    if key_findings:
                        st.subheader("📌 Key Findings")
                        for i, finding in enumerate(key_findings, 1):
                            st.markdown(f"**{i}.** {finding}")
                    # Display issues in table
                    if issues:
                        st.subheader("🛡️ Compliance Issues")
                        df = pd.DataFrame(issues)
                        available_cols = [col for col in ["issue_type", "regulation", "severity", "description", "recommendation"] if col in df.columns]
                        st.dataframe(df[available_cols], use_container_width=True, hide_index=True)
                    else:
                        st.success("✅ No compliance issues found.")
    except Exception as e:
        st.error(f"Error loading contracts: {e}")
