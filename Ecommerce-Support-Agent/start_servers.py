"""
start_servers.py
════════════════
Launch all 7 servers for the ShopAI Customer Support System.

Server map
──────────
  Port 8001  Order Tracking       mcp_servers/order_server.py
  Port 8002  Returns & Refunds    mcp_servers/returns_server.py
  Port 8003  Product & Inventory  mcp_servers/product_server.py
  Port 8004  Payment & Billing    mcp_servers/payment_server.py
  Port 8005  Complaints           mcp_servers/complaints_server.py
  Port 8006  Loyalty & Promos     mcp_servers/loyalty_server.py
  Port 9001  Supervisor Agent     supervisor/supervisor_server.py

Usage
─────
    python start_servers.py     # start all 7 servers
    Ctrl+C                      # stop all servers cleanly
"""

import subprocess
import sys
import os
import time
import signal
import atexit


# ── Server registry ───────────────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))

SERVERS = [
    # Specialist MCP servers (8001–8006) — must start BEFORE Supervisor
    ("Order Tracking",      "mcp_servers/order_server.py",      8001),
    ("Returns & Refunds",   "mcp_servers/returns_server.py",     8002),
    ("Product & Inventory", "mcp_servers/product_server.py",     8003),
    ("Payment & Billing",   "mcp_servers/payment_server.py",     8004),
    ("Complaints",          "mcp_servers/complaints_server.py",  8005),
    ("Loyalty & Promos",    "mcp_servers/loyalty_server.py",     8006),
    # Supervisor HTTP API (9001) — routes to specialists above
    ("Supervisor Agent",    "supervisor/supervisor_server.py",   9001),
]

# Populated inside main(); kept module-level so shutdown() can reach it
_processes: list = []


# ── Graceful shutdown ─────────────────────────────────────────────────────────
def shutdown(sig=None, frame=None) -> None:
    """Terminate every child process on Ctrl+C or SIGTERM."""
    print("\n")
    print("  [STOP]  Stopping all servers...")
    for proc in _processes:
        try:
            proc.terminate()
        except Exception:
            pass
    time.sleep(1)
    for proc in _processes:
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
    print("  [OK]  All servers stopped.")
    sys.exit(0)


# ── Crash-restart watcher ─────────────────────────────────────────────────────
def _watch_loop() -> None:
    """Poll all processes every 5 s; restart any that have exited."""
    while True:
        for i, (name, script, port) in enumerate(SERVERS):
            proc = _processes[i]
            if proc.poll() is not None:
                print(f"\n  [STOP]  {name} (port {port}) exited unexpectedly.")
                print(f"  [RESTART]  Restarting {name}...")
                new_proc = subprocess.Popen(
                    [sys.executable, os.path.join(BASE, script)],
                    stdout=subprocess.DEVNULL,
                    # Avoid deadlocks from unread PIPE buffers on long-running servers.
                    stderr=subprocess.DEVNULL,
                )
                _processes[i] = new_proc
                print(f"  [OK]  {name} restarted (PID: {new_proc.pid})")
        time.sleep(5)


# ── Main ──────────────────────────────────────────────────────────────────────
def main() -> None:
    """
    Start all 7 MCP servers in the correct order, then watch them.

    Order:
      1. Specialist servers (8001–8006) — started first, staggered 0.6 s apart.
      2. 2-second pause — lets specialists finish binding their ports.
      3. Supervisor server (9001) — connects to specialists on startup.

    Keeps running until Ctrl+C, auto-restarting any server that crashes.
    """
    # Register signal handlers before spawning any children
    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    atexit.register(shutdown)

    print()
    print("  " + "=" * 60)
    print("    ShopAI Customer Support - Server Launcher")
    print("  " + "=" * 60)
    print()

    # ── Step 1: Start specialist servers ─────────────────────────────
    print("  -- Specialist MCP Servers (ports 8001-8006) --")
    for name, script, port in SERVERS[:-1]:       # all except Supervisor
        proc = subprocess.Popen(
            [sys.executable, os.path.join(BASE, script)],
            stdout=subprocess.DEVNULL,
            # Avoid blocking child processes if stderr output grows.
            stderr=subprocess.DEVNULL,
        )
        _processes.append(proc)
        print(f"  [OK]  {name:<24} ->  http://127.0.0.1:{port}/mcp   PID {proc.pid}")
        time.sleep(0.6)

    # ── Step 2: Brief pause so specialists are ready ──────────────────
    print()
    print("  [WAIT]  Waiting 2 s for specialist servers to be ready...")
    time.sleep(2)

    # ── Step 3: Start Supervisor server ──────────────────────────────
    print()
    print("  -- Supervisor HTTP Server (port 9001) --")
    sup_name, sup_script, sup_port = SERVERS[-1]
    sup_proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE, sup_script)],
        stdout=subprocess.DEVNULL,
        # Avoid blocking child processes if stderr output grows.
        stderr=subprocess.DEVNULL,
    )
    _processes.append(sup_proc)
    print(f"  [OK]  {sup_name:<24} ->  http://127.0.0.1:{sup_port}/chat   PID {sup_proc.pid}")
    print()

    # ── Summary ───────────────────────────────────────────────────────
    print("  " + "=" * 60)
    print(f"  [RUN]  All {len(SERVERS)} servers are running!")
    print()
    print("  ➜  Open a NEW terminal and launch the UI:")
    print("        streamlit run app.py")
    print()
    print("  Ctrl+C here to stop everything.")
    print("  " + "=" * 60)
    print()

    # ── Watch loop — blocks until Ctrl+C ─────────────────────────────
    _watch_loop()


if __name__ == "__main__":
    main()
