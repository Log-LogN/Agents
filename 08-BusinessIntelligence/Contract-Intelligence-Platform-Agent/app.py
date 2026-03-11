"""
app.py - Contract Intelligence Platform UI
Run with: streamlit run app.py --server.port 9001
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import nest_asyncio
import streamlit as st

nest_asyncio.apply()

st.set_page_config(
    page_title="Contract Intelligence Platform",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from ui.styles.theme import apply_theme


def main():
    apply_theme()

    if not st.session_state.get("authenticated"):
        from ui.pages.login import render_login

        render_login()
        return

    user = st.session_state.get("user", {})
    role = user.get("role", "viewer")

    from utils.auth import get_allowed_pages

    pages = get_allowed_pages(role)

    from ui.components.sidebar import render_sidebar

    page = render_sidebar(pages)

    if "Dashboard" in page:
        from ui.pages.dashboard import render_dashboard

        render_dashboard()
    elif "Assistant" in page:
        from ui.pages.assistant import render_assistant

        render_assistant()
    elif "Contracts" in page and "Draft" not in page:
        from ui.pages.contracts import render_contracts

        render_contracts()
    elif "Draft" in page:
        from ui.pages.draft import render_draft

        render_draft()
    elif "Review" in page:
        from ui.pages.review import render_review

        render_review()
    elif "Approvals" in page:
        from ui.pages.approvals import render_approvals

        render_approvals()
    elif "Obligations" in page:
        from ui.pages.obligations import render_obligations

        render_obligations()
    elif "Compliance" in page:
        from ui.pages.compliance import render_compliance

        render_compliance()
    elif "Analytics" in page:
        from ui.pages.analytics import render_analytics

        render_analytics()
    elif "Admin" in page:
        from ui.pages.admin import render_admin

        render_admin()
    else:
        st.info(f"Page '{page}' coming soon.")


if __name__ == "__main__":
    main()
