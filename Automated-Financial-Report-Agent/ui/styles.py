"""CSS styles for Streamlit UI."""

import streamlit as st

CSS = """
<style>
.stApp,[data-testid="stAppViewContainer"]{background:#0f172a!important}
.stApp *{color:#e2e8f0!important}
[data-testid="stSidebar"]{background:#1e293b!important;border-right:1px solid #334155}
[data-testid="stSidebar"] .stButton>button{
  background:#1e3a5f!important;color:#e2e8f0!important;border:1px solid #334155!important;
  border-radius:8px!important;width:100%!important;margin-bottom:5px!important;
  padding:9px 14px!important;font-size:13px!important;text-align:left!important}
[data-testid="stSidebar"] .stButton>button:hover{background:#1d4ed8!important;border-color:#1d4ed8!important}
[data-testid="stChatMessage"]{
  background:#1e293b!important;border:1px solid #334155!important;
  border-radius:12px!important;padding:12px 16px!important;margin-bottom:10px!important}
[data-testid="stChatInput"] textarea{
  background:#1e293b!important;color:#e2e8f0!important;
  border:1px solid #334155!important;border-radius:10px!important}
[data-testid="stChatInput"]{background:#0f172a!important;border-top:1px solid #334155!important}
.header-card{
  background:linear-gradient(135deg,#1e3a5f,#1d4ed8);
  padding:18px 24px;border-radius:12px;margin-bottom:16px;border:1px solid #334155}
.header-card h1{margin:0;font-size:20px;color:#fff!important}
.header-card p{margin:4px 0 0;font-size:12px;color:#93c5fd!important}
.role-badge{
  display:inline-block;padding:4px 14px;border-radius:20px;
  font-size:12px;font-weight:700;margin-bottom:10px}
.trace-shell{
  background:linear-gradient(180deg,#0f1a33,#0e162b);
  border:1px solid #24406d;border-radius:14px;padding:14px;margin-top:6px}
.trace-badges{display:flex;gap:10px;flex-wrap:wrap}
.trace-pill{
  background:#12284c;border:1px solid #2a4f86;color:#93c5fd!important;
  border-radius:999px;padding:6px 12px;font-size:10px;font-weight:700}
.trace-card{
  border-radius:14px;padding:14px 16px;margin-bottom:10px;border:1px solid #314a72;
  background:#172847}
.trace-card.route{background:#203b66;border-color:#2b5cb1}
.trace-card.tool_call{background:#192f52;border-color:#2b4f84}
.trace-card.tool_result{background:#0c3a2f;border-color:#17895e}
.trace-card.reply{background:#2e2349;border-color:#6f47b8}
.trace-card.error{background:#4a1f27;border-color:#9f3645}
.trace-step-top{display:flex;align-items:center;gap:10px;margin-bottom:7px}
.trace-step-num{
  background:#0b1c36;border:1px solid #2c5b99;color:#93c5fd!important;
  border-radius:999px;padding:4px 10px;font-size:10px;font-weight:700}
.trace-step-kind{
  color:#60a5fa!important;font-size:12px;font-weight:800;letter-spacing:.8px;text-transform:uppercase}
.trace-step-title{font-size:10px;font-weight:700;line-height:1.3;color:#fff!important}
.trace-step-note{color:#93c5fd!important;font-size:10px;margin-top:3px}
.trace-details{margin-top:6px}
.trace-details summary{color:#93c5fd!important;font-size:10px;cursor:pointer}
.trace-details pre{
  background:#0b1324;border:1px solid #263750;border-radius:8px;
  padding:10px;white-space:pre-wrap;word-break:break-word;font-size:11px;color:#cbd5e1!important}
.login-card{
  background:#1e293b;border:1px solid #334155;border-radius:12px;
  padding:32px;max-width:420px;margin:60px auto 0}
.stTextInput>div>div>input{
  background:#0f172a!important;color:#e2e8f0!important;
  border:1px solid #334155!important;border-radius:8px!important}
.stTextInput label{color:#94a3b8!important;font-size:13px!important}
div[data-testid="stForm"] .stButton>button{
  background:linear-gradient(135deg,#1d4ed8,#1e3a5f)!important;
  color:#fff!important;border:none!important;border-radius:8px!important;
  width:100%!important;padding:12px!important;font-size:15px!important;font-weight:700!important}
div[data-testid="stForm"] .stButton>button:hover{background:#2563eb!important}
.stExpander{background:#1e293b!important;border:1px solid #334155!important;border-radius:8px!important}
.metric-card{
  background:#1e293b;border:1px solid #334155;border-radius:10px;
  padding:14px;text-align:center;margin-bottom:8px}
button[aria-label="Approve & Send"]{
  background:#15803d!important;
  border:1px solid #16a34a!important;
  color:#ffffff!important;
}
button[aria-label="Approve & Send"]:hover{
  background:#15803d!important;
  border:1px solid #16a34a!important;
}
button[aria-label="Reject"]{
  background:#b91c1c!important;
  border:1px solid #dc2626!important;
  color:#ffffff!important;
}
button[aria-label="Reject"]:hover{
  background:#b91c1c!important;
  border:1px solid #dc2626!important;
}
.approval-shell{
  background:#111b31;border:1px solid #36598f;border-radius:12px;
  padding:16px;margin:8px 0 16px}
.approval-title{font-size:14px;font-weight:800;color:#93c5fd!important;margin-bottom:6px}
.approval-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px}
.approval-cell{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:8px 10px}
.approval-label{font-size:10px;color:#94a3b8!important;text-transform:uppercase;letter-spacing:.6px}
.approval-value{font-size:12px;color:#e2e8f0!important;word-break:break-word}
.agent-hub{
  background:#111b31;border:1px solid #2a3f66;border-radius:12px;
  padding:14px 14px 10px;margin-bottom:14px}
.agent-hub-title{font-size:13px;font-weight:800;letter-spacing:.8px;color:#93c5fd!important;margin-bottom:10px;text-transform:uppercase}
.agent-hub-sub{font-size:12px;color:#94a3b8!important;margin:-4px 0 10px}
</style>
"""


def apply_styles() -> None:
    st.markdown(CSS, unsafe_allow_html=True)

