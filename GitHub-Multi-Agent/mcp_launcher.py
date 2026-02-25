import asyncio
import sys
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

console = Console()

MCP_SERVICES = [
    {
        "name": "GitHub MCP",
        "port": "8001",
        "color": "cyan",
        "cmd": [sys.executable, "-m", "uvicorn", "agents.github.api:app", "--host", "0.0.0.0", "--port", "8001"],
    },
    # Add more MCP tool servers here in the future
]


async def run_mcp(svc, status_dict):
    name, color = svc["name"], svc["color"]
    status_dict[name] = "[yellow]Starting...[/yellow]"

    proc = await asyncio.create_subprocess_exec(
        *svc["cmd"], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    status_dict[name] = "[bold green]ONLINE[/bold green]"

    # Read stdout lines and append to the shared logs structure (do not print directly).
    async for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        # append to logs (safe-guard exists in outer scope)
        LOGS[name].append((color, line))
        # trim
        if len(LOGS[name]) > LOG_MAX_LINES:
            LOGS[name].pop(0)

    rc = await proc.wait()
    status_dict[name] = f"[red]EXIT {rc}[/red]"
    LOGS[name].append(("red", f"Process exited with code {rc}"))


def get_table(status_dict):
    table = Table(title="Model Context Protocol (MCP) Layers", box=None)
    table.add_column("Service", style="bold")
    table.add_column("Status")
    for k, v in status_dict.items(): table.add_row(k, v)
    return table


def get_layout(status_dict, logs):
    """Return a single Panel containing the status table.

    We intentionally don't render the recent-logs panel here to avoid an empty container
    while Live is active (logs are streamed after Live exits).
    """
    table = get_table(status_dict)
    return Panel(table, title="MCP Status")


async def main():
    # ASCII banner for the MCP launcher (keeps visual parity with supervisor_launcher)
    ascii_banner = r"""
___  ________ ______   _____ ___________ _   _ ___________ 
|  \/  /  __ \| ___ \ /  ___|  ___| ___ \ | | |  ___| ___ \
| .  . | /  \/| |_/ / \ `--.| |__ | |_/ / | | | |__ | |_/ /
| |\/| | |    |  __/   `--. \  __||    /| | | |  __||    / 
| |  | | \__/\| |     /\__/ / |___| |\ \\ \_/ / |___| |\ \ 
\_|  |_/\____/\_|     \____/\____/\_| \_|\___/\____/\_| \_|
"""
    console.print(f"[green]{ascii_banner}[/green]")

    # shared state
    status_dict = {s["name"]: "[grey]Pending[/grey]" for s in MCP_SERVICES}
    global LOGS, LOG_MAX_LINES
    LOG_MAX_LINES = 1000
    LOGS = {s["name"]: [] for s in MCP_SERVICES}

    with Live(get_layout(status_dict, LOGS), refresh_per_second=4) as live:
        tasks = [asyncio.create_task(run_mcp(s, status_dict)) for s in MCP_SERVICES]
        # Keep the Live UI until all services report ONLINE (or all tasks finished).
        while True:
            live.update(get_layout(status_dict, LOGS))
            # If all services ONLINE, break to start streaming logs in plain output
            if all(v == "[bold green]ONLINE[/bold green]" for v in status_dict.values()):
                break
            # If all tasks finished unexpectedly, break as well
            if all(t.done() for t in tasks):
                break
            await asyncio.sleep(0.25)

    # Now stream logs to the console like the supervisor launcher does.
    console.print("\n[dim]All services ONLINE — streaming logs below (press Ctrl+C to stop)[/dim]\n")

    # Keep track of what we've already printed per-service
    last_idx = {name: 0 for name in LOGS}

    try:
        # While services are running, print new log lines as they arrive
        while not all(t.done() for t in tasks):
            for svc_name, entries in LOGS.items():
                for color, text in entries[last_idx[svc_name]:]:
                    console.print(f"[{color}]{svc_name}[/{color}] > {text}")
                last_idx[svc_name] = len(entries)
            await asyncio.sleep(0.1)

        # Drain any remaining lines after processes exit
        for svc_name, entries in LOGS.items():
            for color, text in entries[last_idx[svc_name]:]:
                console.print(f"[{color}]{svc_name}[/{color}] > {text}")

    except KeyboardInterrupt:
        console.print("\n[red]MCP Layer Shutdown.")
        for t in tasks:
            t.cancel()
        return


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]MCP Layer Shutdown.")