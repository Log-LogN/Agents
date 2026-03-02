"""
start_servers.py
════════════════
Launch all 8 servers for the FinReport AI system.

Usage:
    python start_servers.py            # start all servers
    python start_servers.py --stop     # stop all running servers

Servers:
    GL / Transaction Agent   → port 8001
    P&L Agent                → port 8002
    Balance Sheet Agent      → port 8003
    Cash Flow Agent          → port 8004
    Budget & Variance Agent  → port 8005
    KPI & Analytics Agent    → port 8006
    Report Delivery Agent    → port 8007
    Supervisor               → port 9001
"""

import sys
import os
import time
import signal
import subprocess
import argparse
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [ServerManager]  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")


# ── Server manifest ───────────────────────────────────────────────────────────
SERVERS = [
    {"name": "GL / Transaction Agent",   "module": "mcp_servers.gl_server",      "port": 8001},
    {"name": "P&L Agent",                "module": "mcp_servers.pl_server",      "port": 8002},
    {"name": "Balance Sheet Agent",      "module": "mcp_servers.bs_server",      "port": 8003},
    {"name": "Cash Flow Agent",          "module": "mcp_servers.cf_server",      "port": 8004},
    {"name": "Budget & Variance Agent",  "module": "mcp_servers.budget_server",  "port": 8005},
    {"name": "KPI & Analytics Agent",    "module": "mcp_servers.kpi_server",     "port": 8006},
    {"name": "Report Delivery Agent",    "module": "mcp_servers.report_server",  "port": 8007},
    {"name": "Supervisor Agent",         "module": "supervisor.supervisor_server","port": 9001},
]

_processes: list[subprocess.Popen] = []
_log_files: list = []


def _start_server(server: dict) -> subprocess.Popen | None:
    """Launch a single server as a subprocess."""
    bootstrap = (
        "import importlib, uvicorn; "
        f"mod=importlib.import_module('{server['module']}'); "
        "app=mod.mcp.streamable_http_app(); "
        f"uvicorn.run(app, host='127.0.0.1', port={server['port']}, log_level='info')"
    )
    cmd = [sys.executable, "-c", bootstrap]
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        log_name = (
            server["module"]
            .replace(".", "_")
            .replace("/", "_")
            .replace("\\", "_")
        )
        log_path = os.path.join(LOG_DIR, f"{log_name}.log")
        lf = open(log_path, "a", encoding="utf-8")
        p = subprocess.Popen(
            cmd,
            cwd=os.path.dirname(os.path.abspath(__file__)),
            stdout=lf,
            stderr=lf,
        )
        _log_files.append(lf)
        log.info(
            "✅  %-30s  port %-5d  PID %d  log %s",
            server["name"], server["port"], p.pid, log_path
        )
        return p
    except Exception as exc:
        log.error("❌  Failed to start %s: %s", server["name"], exc)
        return None


def _stop_all():
    """Terminate all running server subprocesses."""
    if not _processes:
        log.info("No running servers to stop.")
        return
    log.info("Stopping %d servers…", len(_processes))
    for p in _processes:
        try:
            p.terminate()
        except Exception:
            pass
    time.sleep(1.5)
    for p in _processes:
        try:
            if p.poll() is None:
                p.kill()
        except Exception:
            pass
    for lf in _log_files:
        try:
            lf.close()
        except Exception:
            pass
    log.info("All servers stopped.")


def _sig_handler(sig, frame):
    log.info("\n🛑  Interrupt received — shutting down all servers…")
    _stop_all()
    sys.exit(0)


def start():
    """Start all servers and block until Ctrl-C."""
    from database.db import init_db
    log.info("Initialising database…")
    init_db()

    log.info("Starting %d servers…\n", len(SERVERS))

    # Specialist agents first (8001-8007)
    for server in SERVERS[:-1]:
        p = _start_server(server)
        if p:
            _processes.append(p)
        time.sleep(0.4)  # slight stagger

    # Supervisor last (9001) — needs specialists ready
    log.info("Waiting 3s for specialist agents to be ready…")
    time.sleep(3)
    p = _start_server(SERVERS[-1])
    if p:
        _processes.append(p)

    log.info(
        "\n══════════════════════════════════════════════\n"
        "  FinReport AI — All servers running!\n"
        "  Streamlit UI:  streamlit run app.py\n"
        "  UI URL:        http://localhost:8501\n"
        "  Supervisor:    http://127.0.0.1:9001/mcp\n"
        "  Press Ctrl-C to stop all servers.\n"
        "══════════════════════════════════════════════"
    )

    # Register signal handler for clean shutdown
    signal.signal(signal.SIGINT,  _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    # Keep alive — monitor processes
    while True:
        time.sleep(5)
        dead = [s for s, p in zip(SERVERS, _processes) if p.poll() is not None]
        if dead:
            for s in dead:
                log.warning("⚠️  Server '%s' (port %d) has exited unexpectedly.", s["name"], s["port"])


def stop():
    """Stop all servers (reads PIDs from running processes)."""
    import psutil
    ports = {s["port"] for s in SERVERS}
    killed = 0
    target_pids: set[int] = set()

    for conn in psutil.net_connections(kind="inet"):
        try:
            if conn.laddr and conn.laddr.port in ports and conn.pid:
                target_pids.add(conn.pid)
        except Exception:
            pass

    for pid in sorted(target_pids):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            log.info("Stopped PID %d", pid)
            killed += 1
        except Exception:
            pass

    if killed == 0:
        log.info("No FinReport servers found running.")
    else:
        log.info("Stopped %d server(s).", killed)


def main():
    parser = argparse.ArgumentParser(description="FinReport AI — Server Manager")
    parser.add_argument("--stop", action="store_true", help="Stop all running servers")
    args = parser.parse_args()

    if args.stop:
        stop()
    else:
        start()


if __name__ == "__main__":
    main()
