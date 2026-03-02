import asyncio
import os
import uuid
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.columns import Columns
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich import box, markup
from rich.table import Table
import httpx
import json
import re

API_URL = "http://localhost:9000/chat/stream"

console = Console()
session_id = str(uuid.uuid4())

# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
def display_banner():
    banner_text = """                           
█████▄  ▄▄▄   ▄▄▄  ▄▄   ▄▄ 
██▄▄██ ██▀██ ██▀██ ██▀▄▀██ 
██▄▄█▀ ▀███▀ ▀███▀ ██   ██ 
                            """
    banner_panel = Panel(
        Align.center(Text(banner_text, style="bold cyan")),
        box=box.DOUBLE,
        border_style="cyan",
        title="[bold cyan] DEPENDENCY SCANNER CLI [/bold cyan]",
        title_align="center",
        subtitle="[bold magenta] Multi-Ecosystem Vulnerability Check [/bold magenta]",
        subtitle_align="center",
    )
    info_lines = [
        "[bold magenta]🚀 System Status[/bold magenta]",
        f"├── 🕒 Time: [green]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/green]",
        f"├── 🆔 Session: [bold bright_white on_black]{session_id[:16]}...[/bold bright_white on_black]",
        f"└── 🎯 Mode: [bold cyan] CLI Streaming[/bold cyan]",
    ]
    cmd_lines = [
        "[bold magenta]🎮 Commands[/bold magenta]",
        "",
        "[green]• exit / quit[/green] - End session",
        "[green]• clear[/green]       - Clear screen",
        "[green]• help[/green]        - Show this info",
        "",
        "[dim]Type a path to scan, or a GitHub repo URL[/dim]",
        "[dim]Example: './myproject' or 'https://github.com/org/repo'[/dim]",
    ]
    info_panel  = Panel("\n".join(info_lines), box=box.ROUNDED, border_style="cyan",  title="[bold cyan]System[/bold cyan]",   width=55)
    cmd_panel   = Panel("\n".join(cmd_lines),  box=box.ROUNDED, border_style="green", title="[bold green]Commands[/bold green]", width=55)
    console.print()
    console.print(banner_panel)
    console.print()
    console.print(Columns([info_panel, cmd_panel], equal=True, expand=True))
    console.print()

async def stream_chat(message: str):
    global session_id
    with console.status("[bold green]Contacting supervisor...", spinner="dots"):
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "POST",
                    API_URL,
                    json={"message": message, "session_id": session_id},
                ) as response:
                    async for line in response.aiter_lines():
                        if line.startswith("data: "):
                            data = line[6:].strip()
                            try:
                                payload = json.loads(data) if data else {}
                                event_type = payload.get("type")
                                if event_type:
                                    render_event(event_type, payload)
                            except Exception:
                                console.print(Panel(f"[red]Malformed event: {line}[/red]", border_style="red", box=box.ROUNDED))
        except Exception as e:
            console.print(Panel(f"[red]Supervisor error: {markup.escape(str(e))}[/red]", border_style="red", box=box.ROUNDED))

def render_event(event: str, data: dict):
    global session_id
    if event == "start":
        session_id = data.get("session_id", session_id)
        console.print(f"[bold green]Session:[/bold green] [bold bright_white on_black]{session_id}[/bold bright_white on_black]")
    elif event == "tool_call":
        tool = data.get("data", {})
        name = tool.get("tool_name", "?")
        args = tool.get("tool_input", {})
        args_str = ", ".join(f"[bold cyan]{k}[/bold cyan]=[bold white]{v}[/bold white]" for k, v in (args.items() if isinstance(args, dict) else []))
        console.print(Panel(f"[bold magenta]🔧 Tool:[/bold magenta] [bold yellow]{name}[/bold yellow]\n[dim]{args_str}[/dim]", border_style="magenta", box=box.ROUNDED))
    elif event == "output":
        output = data.get("data", "")
        console.print(Panel(output, border_style="bright_green", box=box.ROUNDED))
    elif event == "final_output":
        agent = data.get("agent_used", "Supervisor")
        console.print(f"[bold green]Final output by:[/bold green] [bold cyan]{agent}[/bold cyan]")
    elif event == "end":
        console.print("[bold green]--- End of response ---[/bold green]")
    else:
        console.print(f"[dim]Unknown event: {event}[/dim]")

# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────

async def main():
    global session_id
    display_banner()
    while True:
        try:
            console.print()
            user_input = Prompt.ask(
                "[bold bright_green on_black]CLI > [/bold bright_green on_black]",
                console=console,
                show_default=False,
            ).strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit", "q"):
                if Confirm.ask("\n[yellow]End session?[/yellow]"):
                    break
            elif user_input.lower() == "clear":
                console.clear()
                display_banner()
            elif user_input.lower() == "help":
                display_banner()
            elif user_input.lower().startswith("set session"):
                # set session <id>
                parts = user_input.split()
                if len(parts) == 3:
                    session_id = parts[2]
                    console.print(f"[bold cyan]Session set to:[/bold cyan] [bold bright_white on_black]{session_id}[/bold bright_white on_black]")
                else:
                    console.print("[red]Usage: set session <session_id>[/red]")
            elif user_input.lower() == "new session":
                session_id = str(uuid.uuid4())
                console.print(f"[bold cyan]New session:[/bold cyan] [bold bright_white on_black]{session_id}[/bold bright_white on_black]")
            else:
                await stream_chat(user_input)
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️ Interrupted[/yellow]")
            if Confirm.ask("[yellow]Exit CLI?[/yellow]"):
                break
        except Exception as e:
            console.print(
                Panel(
                    f"[red]{markup.escape(str(e))}[/red]",
                    box=box.ROUNDED,
                    border_style="red",
                    title="[bold red]Session Error[/bold red]",
                )
            )
    console.print(
        Panel(
            "[bold cyan]👋 Thank you for using CLI![/bold cyan]\n"
            "[green]🛡️ Stay secure![/green]",
            box=box.ROUNDED,
            border_style="cyan",
            title="[bold cyan]Session Complete[/bold cyan]",
        )
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold cyan]👋 Goodbye![/bold cyan]")
    except Exception as e:
        try:
            console.print(f"[bold red]❌ Critical Error: {markup.escape(str(e))}[/bold red]")
        except Exception:
            print(f"Critical Error: {e}")
