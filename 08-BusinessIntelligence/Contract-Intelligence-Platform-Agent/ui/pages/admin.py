"""Admin panel — users, audit log, agent health."""
import streamlit as st
import pandas as pd

def render_admin():
    st.title("👥 Admin Panel")

    tab1, tab2, tab3 = st.tabs(["👤 Users", "📜 Audit Log", "🔌 Agent Health"])

    with tab1:
        try:
            from database.db import fetch_all, execute
            users = fetch_all("SELECT id,email,full_name,role,department,is_active,last_login,created_at FROM users ORDER BY id")
            df = pd.DataFrame([dict(u) for u in users])
            st.metric("Total Users", len(df))
            st.dataframe(df, use_container_width=True, hide_index=True)

            st.subheader("Add New User")
            with st.form("add_user"):
                c1, c2 = st.columns(2)
                email    = c1.text_input("Email *")
                name     = c2.text_input("Full Name")
                password = c1.text_input("Password *", type="password")
                role     = c2.selectbox("Role", ["viewer","finance","procurement","legal_counsel","contract_manager","admin"])
                dept     = c1.text_input("Department")
                if st.form_submit_button("Create User", type="primary"):
                    if email and password:
                        from utils.auth import hash_password
                        try:
                            execute("INSERT INTO users (email,password_hash,role,full_name,department) VALUES (%s,%s,%s,%s,%s)",
                                    (email.lower(), hash_password(password), role, name, dept))
                            st.success(f"User {email} created.")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Error: {e}")
                    else:
                        st.error("Email and password are required.")
        except Exception as e:
            st.error(f"Error loading users: {e}")

    with tab2:
        try:
            from database.db import fetch_all
            logs = fetch_all("""
                SELECT al.ts, u.email, al.intent_key, al.agent_used, al.status, al.duration_ms
                FROM audit_log al LEFT JOIN users u ON u.id=al.user_id
                ORDER BY al.ts DESC LIMIT 100
            """)
            if logs:
                df = pd.DataFrame([dict(l) for l in logs])
                st.metric("Log Entries (last 100)", len(df))
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.info("No audit log entries yet.")
        except Exception as e:
            st.error(f"Error: {e}")

    with tab3:
        import socket, os
        agents = {
            "Draft Agent":      int(os.getenv("DRAFT_PORT","8001")),
            "Review Agent":     int(os.getenv("REVIEW_PORT","8002")),
            "Approval Agent":   int(os.getenv("APPROVAL_PORT","8003")),
            "Execution Agent":  int(os.getenv("EXECUTION_PORT","8004")),
            "Obligation Agent": int(os.getenv("OBLIGATION_PORT","8005")),
            "Compliance Agent": int(os.getenv("COMPLIANCE_PORT","8006")),
            "Analytics Agent":  int(os.getenv("ANALYTICS_PORT","8007")),
            "Supervisor API":   int(os.getenv("SUPERVISOR_PORT","8000")),
        }
        st.subheader("MCP Server Health")
        cols = st.columns(4)
        for i, (name, port) in enumerate(agents.items()):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                s.close()
                status, color = "🟢 UP", "green"
            except OSError:
                status, color = "🔴 DOWN", "red"
            cols[i % 4].markdown(f"**{name}**  \n:{color}[{status}] :{color}[port {port}]")

        if st.button("🔄 Refresh Health"):
            st.rerun()
