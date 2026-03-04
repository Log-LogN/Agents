import streamlit as st


def inject_custom_styles() -> None: st.markdown(
    """ <style> :root { 
        --bg-base: #070b14;
        --bg-soft: #0f1628; 
        --bg-panel: #121b30; 
        --bg-panel-2: #1a2540; 
        --text-primary: #e8eefc; 
        --text-secondary: #9fb0d5; 
        --border-soft: #2a3658; 
        --accent: #2f6bff; 
        --success-bg: #123028; 
        --success-border: #265746; 
        --success-text: #9fe4c4; 
    } 
    [data-testid="stAppViewContainer"] { 
        background: radial-gradient(1000px 500px at 75% -10%, #20305d 0%, rgba(32, 48, 93, 0) 70%), 
        radial-gradient(800px 400px at 15% 10%, #1a2a52 0%, rgba(26, 42, 82, 0) 72%), 
        linear-gradient(160deg, var(--bg-base) 0%, #0b1222 45%, #0e1830 100%); 
        color: var(--text-primary); 
    }
    [data-testid="stHeader"] {
        background: rgba(6, 11, 20, 0.7); 
    }
    [data-testid="stSidebar"] { 
        background: linear-gradient(180deg, #101729 0%, #0e1525 100%); 
        border-right: 1px solid var(--border-soft);
    } 
    [data-testid="stSidebar"] * {
           color: var(--text-primary); 
    } 
    .main .block-container { 
        background: rgba(13, 21, 38, 0.72); 
        border: 1px solid var(--border-soft); 
        border-radius: 14px; 
        padding: 1.6rem 1.8rem 5.5rem 1.8rem; 
        backdrop-filter: blur(2px); 
    } 
    .main-title { 
        font-size: 2rem; 
        font-weight: 700; 
        color: var(--text-primary); 
        margin-bottom: 0.4rem; 
    } 
    .subtitle { 
        color: var(--text-secondary); 
        margin-bottom: 1.2rem; 
    } 
    .section-title { 
        font-size: 0.95rem; 
        font-weight: 600; 
        color: #7f95c7; 
        margin-top: 0.35rem; 
        margin-bottom: 0.2rem; 
    } 
    .agent-chip { 
        background: #18233d; 
        border: 1px solid #324468; 
        border-radius: 10px; 
        padding: 0.45rem 0.6rem; 
        margin-bottom: 0.35rem; 
        color: #d6e2ff; 
        font-size: 0.86rem; 
        font-weight: 500; 
    } 
    .session-badge { 
        background: var(--success-bg); 
        border: 1px solid var(--success-border); 
        border-radius: 8px; 
        color: var(--success-text); 
        font-size: 0.8rem; 
        padding: 0.4rem 0.5rem; 
        margin: 0.4rem 0 0.55rem 0; 
    } 
    .session-badge code { 
        background: #0e1f3a; 
        color: #8ce8bc; 
        border-radius: 6px; 
        padding: 0.08rem 0.3rem; 
    } 
    h1, h2, h3, h4, h5, h6 { 
        color: var(--text-primary) !important; 
    } 
    [data-testid="stExpander"] { 
        border: 1px solid var(--border-soft) !important; 
        border-radius: 10px !important; 
        background: rgba(20, 31, 56, 0.65) !important; 
    } 
    [data-testid="stTextInput"] input { 
        background: #0f1830 !important; 
        color: var(--text-primary) !important; 
        border: 1px solid #34476f !important; 
    } 
    [data-testid="stChatMessage"] { 
        background: rgba(14, 24, 46, 0.9); 
        border: 1px solid #2e4168; 
        border-radius: 12px; 
        margin-bottom: 0.6rem; 
    } 
    [data-testid="stChatMessage"] p, [data-testid="stChatMessage"] span, [data-testid="stChatMessage"] div { 
        color: var(--text-primary) !important; 
    } 
    [data-testid="stChatInput"] { 
        background: rgba(12, 20, 38, 0.95); 
        border-top: 1px solid var(--border-soft); 
    } 
    .trace-wrapper { 
        border: 1px solid #2d4470; 
        border-radius: 12px; 
        background: linear-gradient(180deg, rgba(18, 33, 62, 0.9) 0%, rgba(13, 25, 49, 0.9) 100%); 
        padding: 0.8rem 0.9rem; 
        margin-bottom: 0.8rem; 
    } 
    .trace-badges { 
        display: flex; 
        gap: 0.5rem; 
        flex-wrap: wrap; 
    } 
    .trace-badge { 
        font-size: 0.82rem; 
        color: #9ed0ff; 
        background: rgba(35, 71, 123, 0.5); 
        border: 1px solid #325a95; 
        border-radius: 999px; 
        padding: 0.28rem 0.6rem; 
        font-weight: 600; 
    } 
    .trace-step { 
        border: 1px solid #2d4876; 
        border-radius: 12px; 
        padding: 0.9rem 1rem; 
        margin-bottom: 0.6rem; 
        background: linear-gradient(180deg, rgba(28, 52, 94, 0.92) 0%, rgba(24, 45, 83, 0.92) 100%); 
    } 
    .trace-step.tool { 
        background: linear-gradient(180deg, rgba(22, 46, 86, 0.95) 0%, rgba(19, 39, 73, 0.95) 100%); 
        border-color: #2c5a96; 
    } 
    .trace-step.result { 
        background: linear-gradient(180deg, rgba(16, 57, 53, 0.94) 0%, rgba(11, 45, 42, 0.94) 100%); 
        border-color: #297d74; 
    } 
    .trace-step.result.success { 
        box-shadow: 0 0 0 1px rgba(59, 154, 139, 0.22) inset; 
    } 
    .trace-step-head { 
        display: flex; 
        align-items: center; 
        gap: 0.6rem; 
        margin-bottom: 0.55rem; 
    } 
    .trace-pill { 
        font-size: 0.78rem; 
        font-weight: 700; 
        color: #9fd0ff; 
        border: 1px solid #3767a5; 
        border-radius: 999px; 
        padding: 0.14rem 0.52rem; 
        background: rgba(9, 27, 54, 0.8); 
    } 
    .trace-kind { 
        font-size: 0.8rem; 
        letter-spacing: 0.06em; 
        font-weight: 700; 
        color: #5da6ff; 
    } 
    .trace-title { 
        font-size: 1.05rem; 
        font-weight: 700; 
        color: #f2f7ff; 
        margin-bottom: 0.25rem; 
    } 
    .trace-note { 
        color: #c4d5f4; 
        font-size: 0.92rem; 
    } 
    </style> """,
unsafe_allow_html=True, )
