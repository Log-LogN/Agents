"""
start_servers.py
----------------
Starts all 6 MCP servers in parallel background processes.
Run this ONCE, then: streamlit run app.py

Usage:  python start_servers.py
"""
import subprocess, sys, os, time, signal, atexit

BASE = os.path.dirname(os.path.abspath(__file__))

SERVERS = [
    ("Appointment",  "mcp_servers/appointment_server.py", 8001),
    ("Billing",      "mcp_servers/billing_server.py",     8002),
    ("Inventory",    "mcp_servers/inventory_server.py",   8003),
    ("Pharmacy",     "mcp_servers/pharmacy_server.py",    8004),
    ("Lab",          "mcp_servers/lab_server.py",         8005),
    ("Ward",         "mcp_servers/ward_server.py",        8006),
]

processes = []

def shutdown(sig=None, frame=None):
    # Use plain text to avoid UnicodeEncodeError on Windows
    print("\n[STOP] Shutting down all MCP servers...")
    for p in processes:
        p.terminate()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)
atexit.register(shutdown)

from database.db import init_db

print("[INIT] Initializing Hospital Database...")
try:
    init_db()
except Exception as e:
    print(f"[ERROR] Database initialization failed: {e}")
    sys.exit(1)

print("\n[START] Starting all Hospital MCP Servers...\n")
for name, script, port in SERVERS:
    script_path = os.path.join(BASE, script)
    p = subprocess.Popen(
        [sys.executable, script_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    processes.append(p)
    print(f"  [OK] {name:12} Agent MCP Server -> http://127.0.0.1:{port}/mcp  (PID: {p.pid})")
    time.sleep(0.5)

print(f"\n[READY] All 6 MCP servers running!")
print(f"   Now open a NEW terminal and run: streamlit run app.py\n")
print("   Press Ctrl+C here to stop all servers.\n")

# Keep alive and print any server errors
while True:
    for i, (name, _, port) in enumerate(SERVERS):
        p = processes[i]
        if p.poll() is not None:
            stderr = p.stderr.read().decode(errors="replace") if p.stderr else ""
            print(f"\n[FAIL] {name} Server (port {port}) crashed!")
            if stderr: print(f"   Error: {stderr[:300]}")
    time.sleep(5)