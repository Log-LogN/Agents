"""Login page."""
import streamlit as st


def render_login():
    st.markdown(
        """
    <div class='login-hero'>
        <div class='logo'>⚖️</div>
        <h2 class='title'>Contract Intelligence Platform</h2>
        <p class='subtitle'>AI-Powered Multi-Agent Contract Management</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        with st.container():
            st.markdown("### Sign In")
            email = st.text_input("Email Address", placeholder="you@company.com")
            password = st.text_input("Password", type="password")

            if st.button("Sign In", use_container_width=True, type="primary"):
                if not email or not password:
                    st.error("Please enter both email and password.")
                    return
                try:
                    from utils.auth import authenticate_user

                    user = authenticate_user(email, password)
                    if user:
                        st.session_state["user"] = user
                        st.session_state["authenticated"] = True
                        st.session_state["chat_history"] = []
                        st.success(f"Welcome back, {user.get('full_name') or email}!")
                        st.rerun()
                    else:
                        st.error("Invalid email or password.")
                except Exception as e:
                    st.error(f"Login error: {e}")

            st.markdown("---")
            st.markdown("**Demo Accounts:**")
            demo_users = [
                ("admin@contract.ai", "Admin@123", "Admin - Full Access"),
                ("legal@contract.ai", "Legal@123", "Legal Counsel"),
                ("manager@contract.ai", "Manager@123", "Contract Manager"),
                ("procure@contract.ai", "Procure@123", "Procurement"),
                ("finance@contract.ai", "Finance@123", "Finance"),
                ("viewer@contract.ai", "Viewer@123", "Viewer - Read Only"),
            ]
            for email_d, pwd_d, label in demo_users:
                with st.expander(f"Key {label}"):
                    st.code(f"Email: {email_d}\nPassword: {pwd_d}")
