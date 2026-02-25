"""
start_servers.py
----------------
Starts all 5 MCP servers for the Loan & Credit System.

Usage:
  Terminal 1:  python start_servers.py
  Terminal 2:  streamlit run app.py
"""
import subprocess, sys, os, time, signal, atexit

BASE = os.path.dirname(os.path.abspath(__file__))

SERVERS = [
    ("Application",  "mcp_servers/application_server.py",  8001),
    ("KYC",          "mcp_servers/kyc_server.py",           8002),
    ("Credit Risk",  "mcp_servers/credit_risk_server.py",   8003),
    ("Underwriting", "mcp_servers/underwriting_server.py",  8004),
    ("Repayment",    "mcp_servers/repayment_server.py",     8005),
]

processes = []

def shutdown(sig=None, frame=None):
    print("\n[STOP] Shutting down all MCP servers...")
    for p in processes:
        try: p.terminate()
        except: pass
    sys.exit(0)

signal.signal(signal.SIGINT,  shutdown)
signal.signal(signal.SIGTERM, shutdown)
atexit.register(shutdown)

print("=" * 60)
print("  🏦 Loan & Credit Multi-Agent System — MCP Servers")
print("=" * 60)
print()

for name, script, port in SERVERS:
    path = os.path.join(BASE, script)
    p = subprocess.Popen(
        [sys.executable, path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    processes.append(p)
    print(f"  [OK]  {name:<14} -> http://127.0.0.1:{port}/mcp   (PID: {p.pid})")
    time.sleep(0.6)

print()
print("  [READY]  All 5 MCP servers are running!")
print()
print("  ->  Open a NEW terminal and run:   streamlit run app.py")
print()
print("  Press Ctrl+C here to stop all servers.")
print("=" * 60)
print()

# Keep running — monitor for crashes
while True:
    for i, (name, _, port) in enumerate(SERVERS):
        p = processes[i]
        if p.poll() is not None:
            err = ""
            if p.stderr:
                try: err = p.stderr.read(400).decode()
                except: pass
            print(f"\n[ERROR] {name} Server (port {port}) crashed!")
            if err: print(f"   {err}")
            print(f"   Restarting {name}...")
            path = os.path.join(BASE, SERVERS[i][1])
            processes[i] = subprocess.Popen([sys.executable, path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            print(f"   [OK] {name} restarted (PID: {processes[i].pid})")
    time.sleep(5)