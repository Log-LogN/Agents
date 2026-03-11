"""UI theme and CSS aligned with Streamlit built-in light/dark mode."""
import streamlit as st


def get_theme_css() -> str:
    return """
<style>
    .stApp {
        font-family: "Segoe UI Variable", "Trebuchet MS", "Calibri", sans-serif;
    }

    .block-container {
        border: 1px solid var(--secondary-background-color);
        border-radius: 16px;
        padding-top: 1.2rem;
        padding-bottom: 1rem;
        box-shadow: 0 10px 30px color-mix(in srgb, var(--text-color) 16%, transparent);
    }

    h1, h2, h3, h4, h5, h6, p, li, label, span {
        color: var(--text-color) !important;
    }

    small, .stCaption, .stMarkdown p {
        color: color-mix(in srgb, var(--text-color) 62%, transparent) !important;
    }

    section[data-testid="stSidebar"] {
        border-right: 1px solid color-mix(in srgb, var(--text-color) 18%, transparent);
    }

    .sidebar-logo {
        text-align: center;
        padding: 18px 0 8px;
    }

    .sidebar-logo h2 {
        margin: 0;
        letter-spacing: 0.2px;
    }

    .sidebar-logo p {
        margin: 0;
        font-size: 12px;
        color: color-mix(in srgb, var(--text-color) 70%, transparent) !important;
    }

    .login-hero {
        text-align: center;
        padding: 34px 0 18px;
    }

    .login-hero .logo {
        font-size: 48px;
        margin-bottom: 6px;
    }

    .login-hero .title {
        font-size: 30px;
        margin: 0;
    }

    .login-hero .subtitle {
        margin-top: 8px;
        color: color-mix(in srgb, var(--text-color) 65%, transparent) !important;
    }

    .stButton > button {
        border-radius: 10px !important;
        font-weight: 600 !important;
        transition: all 0.18s ease-in-out;
    }

    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 8px 18px color-mix(in srgb, var(--text-color) 20%, transparent);
    }

    .stTextInput > div > div > input,
    .stTextArea textarea,
    .stSelectbox [data-baseweb="select"] > div,
    .stMultiSelect [data-baseweb="select"] > div,
    .stDateInput input,
    .stNumberInput input {
        border-radius: 10px !important;
    }

    div[data-testid="stDataFrame"],
    .stExpander,
    div[data-testid="stMetric"] {
        border: 1px solid color-mix(in srgb, var(--text-color) 18%, transparent);
        border-radius: 12px;
    }

    .chat-user {
        background: var(--primary-color);
        color: #fff;
        border-radius: 18px 18px 4px 18px;
        padding: 12px 16px;
        margin: 4px 0;
        max-width: 80%;
        margin-left: auto;
    }

    .chat-bot {
        background: var(--secondary-background-color);
        color: var(--text-color);
        border-radius: 18px 18px 18px 4px;
        border: 1px solid color-mix(in srgb, var(--text-color) 18%, transparent);
        padding: 12px 16px;
        margin: 4px 0;
        max-width: 85%;
    }

    .agent-tag {
        background: var(--secondary-background-color);
        color: var(--primary-color);
        border-radius: 6px;
        border: 1px solid color-mix(in srgb, var(--text-color) 18%, transparent);
        padding: 2px 8px;
        font-size: 11px;
        font-weight: 600;
    }
</style>
"""


def apply_theme() -> None:
    st.markdown(get_theme_css(), unsafe_allow_html=True)
