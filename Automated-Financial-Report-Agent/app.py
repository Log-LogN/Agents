"""Streamlit entrypoint for FinReport AI."""

import os
import sys

import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.db import init_db
from ui.config import configure_page
from ui.pages import render_chat_page, render_login_page


def main() -> None:
    configure_page()
    init_db()

    user = st.session_state.get("user")
    if not user:
        render_login_page()
        return
    render_chat_page(user)


if __name__ == "__main__":
    main()

