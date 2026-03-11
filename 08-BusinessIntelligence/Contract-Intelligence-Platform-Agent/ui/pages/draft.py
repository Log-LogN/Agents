"""Draft Contract page."""
import streamlit as st

def render_draft():
    st.title("📝 Draft New Contract")
    user = st.session_state.get("user", {})

    tab1, tab2, tab3 = st.tabs(["📋 Create Contract", "📚 Template Library", "🔖 Clause Library"])

    with tab1:
        st.subheader("Create New Contract")
        with st.form("create_contract_form"):
            c1, c2 = st.columns(2)
            title      = c1.text_input("Contract Title *", placeholder="e.g. Microsoft Azure MSA 2026")
            ctype      = c2.selectbox("Contract Type *", ["NDA","MSA","SOW","Vendor","Employment","SaaS","Lease","Service","Other"])
            party_a    = c1.text_input("Party A (Your Company) *", value="Acme Corp")
            party_b    = c2.text_input("Party B (Counterparty) *")
            party_a_em = c1.text_input("Party A Email", value=user.get("email",""))
            party_b_em = c2.text_input("Party B Email")
            value      = c1.number_input("Contract Value (USD)", min_value=0.0, step=1000.0)
            jurisdiction = c2.selectbox("Governing Jurisdiction", ["New York","California","Texas","England & Wales","European Union","Other"])
            submitted  = st.form_submit_button("🚀 Create Draft", type="primary")

        if submitted:
            if not title or not party_b:
                st.error("Title and Counterparty are required.")
            else:
                with st.spinner("Creating contract..."):
                    from agents.draft_agent.mcp_server.tools.draft_tools import create_contract
                    result = create_contract(ctype, title, party_a, party_b, party_a_em, party_b_em,
                                            value, "USD", jurisdiction, user.get("id", 1))
                if result.get("status") == "success":
                    st.success(f"✅ Contract **{result.get('contract_number')}** created successfully!")
                    st.json(result)
                else:
                    st.error(result.get("message","Creation failed."))

    with tab2:
        st.subheader("Available Templates")
        filter_type = st.selectbox("Filter by type", ["All","NDA","MSA","SOW","Vendor","Employment","SaaS","Lease"])
        from agents.draft_agent.mcp_server.tools.draft_tools import get_templates
        result = get_templates("" if filter_type == "All" else filter_type)
        templates = result.get("templates", [])
        if templates:
            for t in templates:
                with st.expander(f"📄 {t['name']} — {t['contract_type']}"):
                    st.markdown(f"**Template ID:** {t['id']}")
                    st.markdown(f"**Type:** {t['contract_type']}")
        else:
            st.info("No templates found.")

    with tab3:
        st.subheader("Clause Library")
        cat = st.selectbox("Category", ["All","Risk","Compliance","Finance","IP","Security","Exit","Legal","Renewal","Service"])
        from agents.draft_agent.mcp_server.tools.draft_tools import get_clause_library
        result = get_clause_library("" if cat == "All" else cat)
        clauses = result.get("clauses", [])
        if clauses:
            import pandas as pd
            df = pd.DataFrame(clauses)[["title","clause_type","category","risk_level"]]
            df.columns = ["Clause","Type","Category","Risk Level"]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No clauses found.")
