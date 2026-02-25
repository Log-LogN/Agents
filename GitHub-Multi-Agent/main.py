"""
main.py — Local Development Launcher
======================================
Starts all services in parallel using asyncio subprocesses.
Use this for local development instead of Docker.

Usage:
    python main.py

For production, use Docker Compose:
    docker-compose up --build
"""

import asyncio
import os
import signal
import sys


SERVICES = [
    {
        "name": "GitHub Agent (port 8001)",
        "cmd": [sys.executable, "-m", "uvicorn", "agents.github.api:app",
                "--host", "0.0.0.0", "--port", "8001", "--reload"],
    },
    {
        "name": "Supervisor (port 8000)",
        "cmd": [sys.executable, "-m", "uvicorn", "supervisor.api:app",
                "--host", "0.0.0.0", "--port", "8000", "--reload"],
    },
]


async def run_service(name: str, cmd: list[str]):
    """Start a single service subprocess and stream its logs."""
    print(f"[Launcher] Starting: {name}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ},
    )

    async for line in proc.stdout:
        print(f"[{name}] {line.decode().rstrip()}")

    await proc.wait()
    print(f"[Launcher] Stopped: {name} (exit code {proc.returncode})")


async def main():
    print("=" * 60)
    print("  Multi-Agent System — Local Dev Launcher")
    print("=" * 60)
    print()
    print("  Services starting:")
    for svc in SERVICES:
        print(f"    • {svc['name']}")
    print()
    print("  Supervisor API:    http://localhost:8000")
    print("  GitHub Agent API:  http://localhost:8001")
    print()
    print("  API Docs (Swagger):")
    print("    http://localhost:8000/docs   ← Supervisor")
    print("    http://localhost:8001/docs   ← GitHub Agent")
    print()
    print("  Press Ctrl+C to stop all services")
    print("=" * 60)
    print()

    # Give github agent a head start before supervisor starts
    tasks = [
        asyncio.create_task(run_service(svc["name"], svc["cmd"]))
        for svc in SERVICES
    ]

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        print("\n[Launcher] Shutting down all services...")
        for task in tasks:
            task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[Launcher] Goodbye!")
