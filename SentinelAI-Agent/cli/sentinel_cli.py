import asyncio
import httpx
import json
import uuid
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.markdown import Markdown
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich.prompt import Prompt, Confirm
from rich.status import Status
from rich import box, markup
from rich.console import Group

API_URL = "http://localhost:8000/chat/stream"

console = Console()
session_id = str(uuid.uuid4())


# ─────────────────────────────────────────────
# Agent color mapping (matches Decepticon style)
# ─────────────────────────────────────────────

AGENT_COLORS = {
    "planner":     "magenta",
    "executor":    "cyan",
    "analyst":     "blue",
    "reporter":    "green",
    "supervisor":  "yellow",
    "default":     "white",
}

def get_agent_color(agent_name: str) -> str:
    name = (agent_name or "").lower()
    for key, color in AGENT_COLORS.items():
        if key in name:
            return color
    return AGENT_COLORS["default"]


# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────

def display_banner():
    banner_text = """
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
    """

    banner_panel = Panel(
        Align.center(Text(banner_text, style="bold cyan")),
        box=box.DOUBLE,
        border_style="cyan",
        title="[bold cyan] SENTINELAI [/bold cyan]",
        title_align="center",
        subtitle="[bold magenta] Multi-Agent Security System [/bold magenta]",
        subtitle_align="center",
    )

    info_lines = [
        "[bold magenta]🚀 System Status[/bold magenta]",
        f"├── 🕒 Time: [green]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/green]",
        f"├── 🆔 Session: [yellow]{session_id[:16]}...[/yellow]",
        f"└── 🎯 Mode: [bold cyan]Interactive Streaming[/bold cyan]",
    ]

    cmd_lines = [
        "[bold magenta]🎮 Commands[/bold magenta]",
        "",
        "[green]• exit / quit[/green] - End session",
        "[green]• clear[/green]       - Clear screen",
        "[green]• help[/green]        - Show this info",
        "",
        "[dim]Just type your security requests![/dim]",
        "[dim]Example: 'Scan 192.168.1.1'[/dim]",
    ]

    info_panel  = Panel("\n".join(info_lines), box=box.ROUNDED, border_style="cyan",  title="[bold cyan]System[/bold cyan]",   width=55)
    cmd_panel   = Panel("\n".join(cmd_lines),  box=box.ROUNDED, border_style="green", title="[bold green]Commands[/bold green]", width=55)

    console.print()
    console.print(banner_panel)
    console.print()
    console.print(Columns([info_panel, cmd_panel], equal=True, expand=True))
    console.print()


# ─────────────────────────────────────────────
# Event renderers
# ─────────────────────────────────────────────

class StreamRenderer:
    """Stateful renderer that mirrors Decepticon's display style."""

    def __init__(self):
        self._llm_buffer   = []
        self._current_agent = "SentinelAI"
        self._tool_tree     = None
        self._progress      = None
        self._task_id       = None

    # ── progress helpers ──────────────────────

    def start_progress(self, description: str = "[bold green]🤖 Working..."):
        if self._progress is None:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=True,
            )
            self._progress.start()
            self._task_id = self._progress.add_task(description, total=None)

    def stop_progress(self):
        if self._progress:
            self._progress.stop()
            self._progress = None
            self._task_id  = None

    def update_progress(self, description: str):
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, description=description)

    # ── event handlers ────────────────────────

    def on_agent_started(self, data: dict):
        self.stop_progress()
        agent = data.get("agent_name", self._current_agent)
        self._current_agent = agent
        color = get_agent_color(agent)
        console.print(
            Panel(
                f"[{color}]Agent initialising…[/{color}]",
                box=box.ROUNDED,
                border_style=color,
                title=f"[bold {color}]🧠 {agent}[/bold {color}]",
            )
        )
        self.start_progress(f"[bold {color}]🤖 {agent} thinking...")

    def on_tool_call_started(self, data: dict):
        self.stop_progress()
        tool_name  = data.get("tool_name", "Unknown Tool")
        tool_input = data.get("tool_input", {})

        display_name = tool_name.replace("_", " ").title()
        color = get_agent_color(self._current_agent)

        # Build argument string
        if isinstance(tool_input, dict):
            args_str = ", ".join(f"{k}={v}" for k, v in tool_input.items())
        else:
            args_str = str(tool_input)
        if len(args_str) > 120:
            args_str = args_str[:120] + "..."

        content = (
            f"[bold cyan]🔧 {display_name}[/bold cyan]\n"
            f"  [dim]→ {args_str}[/dim]"
        ) if args_str else f"[bold cyan]🔧 {display_name}[/bold cyan]"

        console.print(
            Panel(
                content,
                box=box.ROUNDED,
                border_style="yellow",
                title="[bold yellow]Tool Call[/bold yellow]",
            )
        )
        self.start_progress("[bold yellow]⚙️  Tool running...")

    def on_tool_call_completed(self, data: dict):
        self.stop_progress()
        result = data.get("result") or data.get("output", "")
        if result:
            safe = markup.escape(str(result))
            console.print(
                Panel(
                    safe,
                    box=box.ROUNDED,
                    border_style="green",
                    title="[bold green]✓ Tool Result[/bold green]",
                )
            )
        else:
            console.print("[green]✓ Tool completed[/green]")
        self.start_progress("[bold green]🤖 Continuing...")

    def on_llm_partial(self, data: dict):
        # Buffer streaming text; flush inline
        text = data.get("text", "")
        if text:
            self.stop_progress()
            console.print(text, end="")
            self._llm_buffer.append(text)

    def on_llm_final(self, data: dict):
        self.stop_progress()
        output = data.get("output", "").strip()

        # If we were streaming partial text, add a newline gap first
        if self._llm_buffer:
            console.print()          # close the inline stream
            self._llm_buffer.clear()

        if not output:
            return

        color = get_agent_color(self._current_agent)
        try:
            md = Markdown(markup.escape(output))
            body = md
        except Exception:
            body = markup.escape(output)

        console.print(
            Panel(
                body,
                box=box.ROUNDED,
                border_style=color,
                title=f"[bold {color}]✅ {self._current_agent} — Final Answer[/bold {color}]",
            )
        )

    def on_error(self, data: dict):
        self.stop_progress()
        message = data.get("message", "Unknown error")
        console.print(
            Panel(
                f"[red]{markup.escape(message)}[/red]",
                box=box.ROUNDED,
                border_style="red",
                title="[bold red]❌ Error[/bold red]",
            )
        )

    def dispatch(self, event: str, data: dict):
        handlers = {
            "agent_started":      self.on_agent_started,
            "tool_call_started":  self.on_tool_call_started,
            "tool_call_completed": self.on_tool_call_completed,
            "llm_partial":        self.on_llm_partial,
            "llm_final":          self.on_llm_final,
            "error":              self.on_error,
        }
        handler = handlers.get(event)
        if handler:
            handler(data)
        # else: silently ignore unknown events


# ─────────────────────────────────────────────
# Streaming client
# ─────────────────────────────────────────────

async def stream_chat(message: str):
    renderer = StreamRenderer()
    renderer.start_progress("[bold green]🤖 Working...")

    try:
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream(
                "POST",
                API_URL,
                json={"message": message, "session_id": session_id},
            ) as response:

                event = None
                data  = ""

                async for line in response.aiter_lines():

                    if not line:
                        if event:
                            try:
                                payload = json.loads(data) if data else {}
                            except Exception:
                                payload = {"raw": data}

                            renderer.dispatch(event, payload)

                        event = None
                        data  = ""
                        continue

                    if line.startswith("event: "):
                        event = line[7:].strip()
                    elif line.startswith("data: "):
                        data = line[6:].strip()

    except httpx.ConnectError:
        renderer.stop_progress()
        console.print(
            Panel(
                f"[red]Cannot connect to API at {API_URL}[/red]\n"
                "[dim]Make sure the server is running.[/dim]",
                box=box.ROUNDED,
                border_style="red",
                title="[bold red]Connection Error[/bold red]",
            )
        )
        return

    renderer.stop_progress()

    # Completion summary
    console.print(
        Panel(
            f"[bold green]✅ Request completed[/bold green]\n\n"
            f"[cyan]🕒 Time:[/cyan] {datetime.now().strftime('%H:%M:%S')}\n"
            f"[cyan]🆔 Session:[/cyan] [dim]{session_id[:25]}...[/dim]",
            box=box.ROUNDED,
            border_style="green",
            title="[bold green]🎉 Done[/bold green]",
        )
    )


# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────

async def main():
    display_banner()

    while True:
        try:
            console.print()
            user_input = Prompt.ask(
                "[bold blue]SentinelAI > [/bold blue]",
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

            else:
                console.print("[dim]Processing…[/dim]\n")
                await stream_chat(user_input)

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️ Interrupted[/yellow]")
            if Confirm.ask("[yellow]Exit SentinelAI?[/yellow]"):
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
            "[bold cyan]👋 Thank you for using SentinelAI![/bold cyan]\n"
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