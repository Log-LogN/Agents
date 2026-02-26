"""
start_servers.py
Launch all 8 servers for the HireSmart HR Hiring System.

Usage
    python start_servers.py
"""

import atexit
import os
import signal
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE, "logs")

SERVERS = [
    # Specialist servers - must start BEFORE the supervisor
    ("Job Management", "mcp_servers/job_server.py", 8001),
    ("Resume Screening", "mcp_servers/resume_server.py", 8002),
    ("Interview Scheduling", "mcp_servers/interview_server.py", 8003),
    ("Offer Management", "mcp_servers/offer_server.py", 8004),
    ("Onboarding", "mcp_servers/onboarding_server.py", 8005),
    ("Candidate Comms", "mcp_servers/comms_server.py", 8006),
    ("Analytics", "mcp_servers/analytics_server.py", 8007),
    # Supervisor starts LAST - connects to specialists above
    ("Supervisor Agent", "supervisor/supervisor_server.py", 9001),
]

_processes: list = []
_log_handles: list = []
_log_paths: list = []


def _slug(name: str) -> str:
    return name.lower().replace(" ", "_").replace("-", "_")


def _spawn(name: str, script: str, port: int):
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"{port}_{_slug(name)}.log")
    log_handle = open(log_path, "ab")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE, script)],
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    return proc, log_handle, log_path


def shutdown(sig=None, frame=None) -> None:
    print("\n  [STOPPING]  Stopping all servers...")
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

    for handle in _log_handles:
        try:
            handle.close()
        except Exception:
            pass

    print("  [OK]  All servers stopped.")
    if sig is not None:
        sys.exit(0)


def _watch_loop() -> None:
    while True:
        for i, (name, script, port) in enumerate(SERVERS):
            proc = _processes[i]
            if proc.poll() is None:
                continue

            print(f"\n  [ERROR]  {name} (port {port}) exited.")
            print(f"      log: {_log_paths[i]}")
            print(f"  [RESTART]  Restarting {name}...")

            try:
                _log_handles[i].close()
            except Exception:
                pass

            new_proc, new_handle, new_log = _spawn(name, script, port)
            _processes[i] = new_proc
            _log_handles[i] = new_handle
            _log_paths[i] = new_log
            print(f"  [OK]  {name} restarted (PID: {new_proc.pid})")

        time.sleep(5)


def main() -> None:
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    atexit.register(shutdown)

    print()
    print("  " + "=" * 62)
    print("     HireSmart HR Hiring System - Server Launcher")
    print("  " + "=" * 62)
    print()

    # Step 1: Start specialist servers
    print("  -- Specialist MCP Servers (ports 8001-8007) ------------")
    for name, script, port in SERVERS[:-1]:
        proc, handle, log_path = _spawn(name, script, port)
        _processes.append(proc)
        _log_handles.append(handle)
        _log_paths.append(log_path)
        print(f"  [OK]  {name:<24} -> http://127.0.0.1:{port}/mcp   PID {proc.pid}")
        print(f"        log: {log_path}")
        time.sleep(0.6)

    # Step 2: Wait for specialists to be ready
    print()
    print("  [WAITING]  Waiting 2 s for specialist servers to be ready...")
    time.sleep(2)

    # Step 3: Start supervisor
    print()
    print("  -- Supervisor MCP Server (port 9001) -------------------")
    sup_name, sup_script, sup_port = SERVERS[-1]
    sup_proc, sup_handle, sup_log = _spawn(sup_name, sup_script, sup_port)
    _processes.append(sup_proc)
    _log_handles.append(sup_handle)
    _log_paths.append(sup_log)
    print(f"  [OK]  {sup_name:<24} -> http://127.0.0.1:{sup_port}/mcp   PID {sup_proc.pid}")
    print(f"        log: {sup_log}")
    print()

    print("  " + "=" * 62)
    print(f"  [RUNNING]  All {len(SERVERS)} servers running!")
    print()
    print("  Open a NEW terminal and run:")
    print("      streamlit run app.py")
    print()
    print("  Ctrl+C to stop all servers.")
    print("  " + "=" * 62)
    print()

    _watch_loop()


if __name__ == "__main__":
    main()
