"""
start_servers.py
Starts all 7 MCP agent servers (ports 8001-8007).
Run with: python start_servers.py

The Streamlit UI is started separately:
    streamlit run app.py --server.port 9001
The Supervisor API is started separately:
    python start_supervisor.py
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger   = logging.getLogger("start_servers")
ROOT     = Path(__file__).parent
LOGS_DIR = ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)
PYTHON   = sys.executable
RESET    = "\033[0m"

SERVERS = [
    {"name": "DraftAgent",      "script": "agents/draft_agent/mcp_server/server.py",       "port": int(os.getenv("DRAFT_PORT","8001")),      "color": "\033[36m"},
    {"name": "ReviewAgent",     "script": "agents/review_agent/mcp_server/server.py",       "port": int(os.getenv("REVIEW_PORT","8002")),     "color": "\033[32m"},
    {"name": "ApprovalAgent",   "script": "agents/approval_agent/mcp_server/server.py",     "port": int(os.getenv("APPROVAL_PORT","8003")),   "color": "\033[33m"},
    {"name": "ExecutionAgent",  "script": "agents/execution_agent/mcp_server/server.py",    "port": int(os.getenv("EXECUTION_PORT","8004")),  "color": "\033[31m"},
    {"name": "ObligationAgent", "script": "agents/obligation_agent/mcp_server/server.py",   "port": int(os.getenv("OBLIGATION_PORT","8005")), "color": "\033[34m"},
    {"name": "ComplianceAgent", "script": "agents/compliance_agent/mcp_server/server.py",   "port": int(os.getenv("COMPLIANCE_PORT","8006")), "color": "\033[35m"},
    {"name": "AnalyticsAgent",  "script": "agents/analytics_agent/mcp_server/server.py",    "port": int(os.getenv("ANALYTICS_PORT","8007")),  "color": "\033[37m"},
]

_processes: dict = {}
_stop_event = threading.Event()


def _start(server: dict) -> subprocess.Popen:
    name   = server["name"]
    log_fh = open(LOGS_DIR / f"{name.lower()}.log", "a", buffering=1)
    
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    env["PYTHONPATH"] = f"{ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)
    
    proc   = subprocess.Popen(
        [PYTHON, str(ROOT / server["script"])],
        cwd=str(ROOT),
        stdout=log_fh, stderr=log_fh,
        env=env,
    )
    logger.info("%s[%s]%s  PID %-6d  port %d  (logs/%s.log)",
                server["color"], name, RESET, proc.pid, server["port"], name.lower())
    return proc


def _healthy(port: int) -> bool:
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1.5)
        s.close(); return True
    except OSError:
        return False


def _monitor():
    while not _stop_event.is_set():
        for srv in SERVERS:
            proc = _processes.get(srv["name"])
            if proc and proc.poll() is not None:
                logger.warning("[%s] crashed (exit %d) — restarting…", srv["name"], proc.returncode)
                try:
                    _processes[srv["name"]] = _start(srv)
                except Exception as e:
                    logger.error("[%s] restart failed: %s", srv["name"], e)
        _stop_event.wait(10)


def _shutdown(sig, frame):
    logger.info("Shutting down all servers…")
    _stop_event.set()
    for name, proc in _processes.items():
        if proc.poll() is None:
            proc.terminate()
            logger.info("[%s] terminated.", name)
    sys.exit(0)


def main():
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("\n" + "=" * 60)
    print("   ⚖️  Contract Intelligence Platform — Server Manager")
    print("=" * 60)

    # DB init
    try:
        from database.db import init_db
        logger.info("Initialising database…")
        init_db()
        logger.info("Database ready ✅")
    except Exception as e:
        logger.warning("DB init skipped: %s", e)

    # Start servers
    print("\n[ Starting MCP Agent Servers ]\n")
    for srv in SERVERS:
        try:
            _processes[srv["name"]] = _start(srv)
        except Exception as e:
            logger.error("Failed to start [%s]: %s", srv["name"], e)

    logger.info("Waiting for servers to bind (4s)…")
    time.sleep(4)

    # Health table
    print("\n" + "-" * 60)
    print(f"  {'Server':<20} {'Port':<8} {'Status'}")
    print("-" * 60)
    all_ok = True
    for srv in SERVERS:
        ok     = _healthy(srv["port"])
        status = "UP ✅" if ok else "STARTING ⏳"
        if not ok: all_ok = False
        print(f"  {srv['color']}{srv['name']:<20}{RESET}  :{srv['port']}  {status}")
    print("-" * 60)
    print("\n✅ All servers running!\n" if all_ok else "\n⏳ Some servers still starting — check logs/\n")

    print("-" * 60)
    print("  MCP Agents      →  ports 8001–8007")
    print("  Logs            →  ./logs/")
    print()
    print("  To start the Supervisor API (separate terminal):")
    print("  \033[95m  python start_supervisor.py\033[0m")
    print()
    print("  To start the UI (separate terminal):")
    print("  \033[96m  streamlit run app.py --server.port 9001\033[0m")
    print("-" * 60)
    print("\n  Press Ctrl+C to stop all servers.\n")

    threading.Thread(target=_monitor, daemon=True).start()

    try:
        while not _stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()
