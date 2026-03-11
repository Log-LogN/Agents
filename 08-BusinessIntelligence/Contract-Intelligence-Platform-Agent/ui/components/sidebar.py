"""Sidebar navigation component."""
import streamlit as st

def render_sidebar(pages: list) -> str:
    with st.sidebar:
        st.markdown("""
        <div class='sidebar-logo'>
            <h2>⚖️ ContractAI</h2>
            <p>Intelligence Platform</p>
        </div>
        """, unsafe_allow_html=True)
        st.markdown("---")

        user  = st.session_state.get("user", {})
        name  = user.get("full_name") or user.get("email","User")
        role  = user.get("role","viewer").replace("_"," ").title()
        email = user.get("email","")

        st.markdown(f"**👤 {name}**")
        st.markdown(f"*{role}*")
        st.markdown(f"`{email}`", unsafe_allow_html=True)
        st.markdown("---")

        page = st.radio("Navigation", pages, label_visibility="collapsed")
        st.markdown("---")

        if st.button("🚪 Sign Out", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

    return page
