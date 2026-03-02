"""UI configuration values and page setup."""

import streamlit as st

SUPERVISOR_URL = "http://127.0.0.1:9001/mcp"
REPORT_URL = "http://127.0.0.1:8007/mcp"
HTTP_TIMEOUT = 120


def configure_page() -> None:
    st.set_page_config(
        page_title="FinReport AI",
        page_icon="📊",
        layout="wide",
        initial_sidebar_state="expanded",
    )

