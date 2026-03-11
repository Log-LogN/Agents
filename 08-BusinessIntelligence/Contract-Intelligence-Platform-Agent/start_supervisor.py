"""
start_supervisor.py
Starts the Supervisor API (port 8000).
Run with: python start_supervisor.py

The MCP agent servers are started separately:
    python start_servers.py
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
logger   = logging.getLogger("start_supervisor")
ROOT     = Path(__file__).parent
LOGS_DIR = ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)
PYTHON   = sys.executable

SERVER = {
    "name": "SupervisorAPI",
    "script": "supervisor/api.py",
    "port": int(os.getenv("SUPERVISOR_PORT", "8000")),
}

_process: Optional[subprocess.Popen] = None
_stop_event = threading.Event()


def _start(server: dict) -> subprocess.Popen:
    name   = server["name"]
    log_fh = open(LOGS_DIR / f"{name.lower()}.log", "a", buffering=1)

    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    env["PYTHONPATH"] = f"{ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)

    proc = subprocess.Popen(
        [PYTHON, str(ROOT / server["script"])],
        cwd=str(ROOT),
        stdout=log_fh, stderr=log_fh,
        env=env,
    )
    logger.info("[%s] PID %-6d  port %d  (logs/%s.log)", name, proc.pid, server["port"], name.lower())
    return proc


def _healthy(port: int) -> bool:
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1.5)
        s.close()
        return True
    except OSError:
        return False


def _monitor():
    global _process
    while not _stop_event.is_set():
        if _process and _process.poll() is not None:
            logger.warning("[%s] crashed (exit %d) - restarting...", SERVER["name"], _process.returncode)
            try:
                _process = _start(SERVER)
            except Exception as e:
                logger.error("[%s] restart failed: %s", SERVER["name"], e)
        _stop_event.wait(10)


def _shutdown(sig, frame):
    logger.info("Shutting down supervisor...")
    _stop_event.set()
    if _process and _process.poll() is None:
        _process.terminate()
        logger.info("[%s] terminated.", SERVER["name"])
    sys.exit(0)


def main():
    global _process
    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("\n" + "=" * 60)
    print("   Contract Intelligence Platform - Supervisor Launcher")
    print("=" * 60)

    # DB init
    try:
        from database.db import init_db
        logger.info("Initialising database...")
        init_db()
        logger.info("Database ready.")
    except Exception as e:
        logger.warning("DB init skipped: %s", e)

    print("\n[ Starting Supervisor API ]\n")
    try:
        _process = _start(SERVER)
    except Exception as e:
        logger.error("Failed to start [%s]: %s", SERVER["name"], e)

    logger.info("Waiting for server to bind (3s)...")
    time.sleep(3)

    ok = _healthy(SERVER["port"])
    status = "UP" if ok else "STARTING"
    print("\n" + "-" * 60)
    print(f"  {'Server':<20} {'Port':<8} {'Status'}")
    print("-" * 60)
    print(f"  {SERVER['name']:<20} :{SERVER['port']}  {status}")
    print("-" * 60)

    print("\n  Supervisor API -> http://localhost:8000")
    print("  Logs           -> ./logs/")
    print()
    print("  To start MCP agent servers (separate terminal):")
    print("    python start_servers.py")
    print()
    print("  Press Ctrl+C to stop the supervisor.\n")

    threading.Thread(target=_monitor, daemon=True).start()

    try:
        while not _stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()
