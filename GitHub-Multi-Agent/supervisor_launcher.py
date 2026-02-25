import asyncio
import sys
from rich.console import Console

console = Console()

SUPERVISOR_CMD = [
    sys.executable, "-m", "uvicorn", "supervisor.api:app",
    "--host", "0.0.0.0", "--port", "8000"
]

async def main():
    # Print the ASCII banner provided by the user at startup
    ascii_banner = r"""
 _____ _   _______ ___________ _   _ _____ _____  ___________ 
/  ___| | | | ___ \  ___| ___ \ | | |_   _/  ___||  _  | ___ \
\ `--.| | | | |_/ / |__ | |_/ / | | | | | \ `--. | | | | |_/ /
 `--. \ | | |  __/|  __||    /| | | | | |  `--. \| | | |    / 
/\__/ / |_| | |   | |___| |\ \\ \_/ /_| |_/\__/ /\ \_/ / |\ \ 
\____/ \___/\_|   \____/\_| \_|\___/ \___/\____/  \___/\_| \_|
"""
    console.print(f"[green]{ascii_banner}[/green]")
    console.print("[dim]Note: Ensure GitHub Agent (8001) and GitHub MCP (8001) are running...[/dim]\n")

    proc = await asyncio.create_subprocess_exec(
        *SUPERVISOR_CMD,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT
    )

    async for line in proc.stdout:
        # Highlighting the supervisor logs in a distinct style
        console.print(f"[bold white]SUPERVISOR[/bold white] > {line.decode().rstrip()}")

    await proc.wait()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]Supervisor Halted.")