import asyncio
import uuid
import time
import random
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich.prompt import Confirm
from rich import box, markup
from rich.rule import Rule
from rich.table import Table
import httpx
import json
from agent.supervisor.mcp_client import get_all_mcp_tools

API_URL = "http://localhost:9000/chat/stream"

console = Console()
session_id = str(uuid.uuid4())

# ─────────────────────────────────────────────
# Color Palette ( Green / Cyberpunk)
# ─────────────────────────────────────────────
C_PRIMARY    = "bright_green"
C_ACCENT     = "green"
C_DIM        = "dark_green"        # rich uses color names
C_WARN       = "yellow"
C_DANGER     = "bright_red"
C_INFO       = "cyan"
C_MUTED      = "grey50"
C_HIGHLIGHT  = "bold bright_green"
C_PANEL_B    = "green"
C_TOOL_B     = "bright_magenta"

# ─────────────────────────────────────────────
# Glitch / Typewriter helpers
# ─────────────────────────────────────────────
GLITCH_CHARS = "!@#$%^&*<>?/\\|{}[]~`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def glitch_print(text: str, delay: float = 0.03, passes: int = 3):
    """Print text with a glitch-reveal animation."""
    chars = list(text)
    length = len(chars)
    for p in range(passes):
        corrupted = [
            random.choice(GLITCH_CHARS) if random.random() < (1 - p / passes) else c
            for c in chars
        ]
        console.print(
            f"\r[{C_ACCENT}]{''.join(corrupted)}[/{C_ACCENT}]",
            end="",
            highlight=False,
        )
        time.sleep(delay)
    console.print(f"\r[{C_HIGHLIGHT}]{text}[/{C_HIGHLIGHT}]", highlight=False)

def typewriter(text: str, style: str = C_PRIMARY, delay: float = 0.018):
    """Character-by-character typewriter effect."""
    for ch in text:
        console.print(f"[{style}]{markup.escape(ch)}[/{style}]", end="", highlight=False)
        time.sleep(delay)
    console.print()

def scanline_separator(label: str = ""):
    chars = "─" * console.width
    if label:
        half = (console.width - len(label) - 2) // 2
        line = "─" * half + f" {label} " + "─" * half
    else:
        line = chars
    console.print(f"[{C_DIM}]{line[:console.width]}[/{C_DIM}]")

def hex_dump_line():
    """Fake hex dump decorative line."""
    addr = f"{random.randint(0,0xFFFF):04X}"
    data = " ".join(f"{random.randint(0,255):02X}" for _ in range(16))
    ascii_rep = "".join(chr(random.randint(33, 126)) for _ in range(16))
    console.print(f"[{C_MUTED}]{addr}  {data}  |{ascii_rep}|[/{C_MUTED}]")

async def boot_sequence():
    """Simulate a dynamic  boot sequence with live tools."""
    import random
    console.clear()
    version = f"v{random.randint(3, 5)}.{random.randint(0, 9)}.{random.randint(0, 9)}"
    feeds = [
        ("CVE INDEXER", C_PRIMARY),
        ("GHSA FEED", C_PRIMARY),
        ("OSV DATABASE", C_PRIMARY),
        ("NVD MIRROR", C_PRIMARY),
        ("DEPENDENCY RESOLVER", C_ACCENT),
    ]
    status_choices = ["[ONLINE]", "[SYNCED]", "[READY]", "[FAILED]", "[RETRYING]"]
    random.shuffle(feeds)
    boot_lines = [
        (f"INITIALIZING SCAN ENGINE {version} ...", C_INFO),
        ("LOADING VULNERABILITY DATABASE ....", C_INFO),
        ("CONNECTING TO ADVISORY FEEDS .......", C_INFO),
    ]
    for name, style in feeds:
        status = random.choices(status_choices, weights=[6, 3, 2, 1, 1])[0]
        boot_lines.append((f"{name:22} {status}", style if status != "[FAILED]" else C_DANGER))
        if status == "[FAILED]" and random.random() < 0.7:
            boot_lines.append((f"{name:22} [RETRYING]", C_WARN))
    if random.random() < 0.3:
        boot_lines.insert(random.randint(2, len(boot_lines)-2), ("GLITCH DETECTED — RECOVERING ...", C_DANGER))
    # Fetch live tools
    try:
        tools = await get_all_mcp_tools()
        if tools:
            boot_lines.append(("ACTIVE TOOLS:", C_HIGHLIGHT))
            for t in tools[:10]:  # show up to 10 tools
                boot_lines.append((f"  • {t.name}", C_ACCENT))
            if len(tools) > 10:
                boot_lines.append((f"  ...and {len(tools)-10} more", C_DIM))
        else:
            boot_lines.append(("No active tools detected.", C_DANGER))
    except Exception as e:
        boot_lines.append((f"[TOOLS ERROR] {e}", C_DANGER))
    boot_lines += [
        ("STEALTH MODE         [ACTIVE]", C_WARN),
        ("ALL SYSTEMS NOMINAL — SCANNING GRID UNLOCKED", C_HIGHLIGHT),
    ]
    console.print()
    for line, style in boot_lines:
        prefix = f"[{C_MUTED}][{datetime.now().strftime('%H:%M:%S.%f')[:12]}][/{C_MUTED}] "
        console.print(prefix, end="", highlight=False)
        typewriter(line, style=style, delay=0.012)
        time.sleep(random.uniform(0.03, 0.09))
    time.sleep(0.3)
    console.clear()

# ─────────────────────────────────────────────
# ASCII Banner  (big block letters)
# ─────────────────────────────────────────────
BANNER = r"""
██████╗  ██████╗  ██████╗ ███╗   ███╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██║   ██║██╔████╔██║    ███████╗██║     ███████║██╔██╗ ██║
██╔══██╗██║   ██║██║   ██║██║╚██╔╝██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║╚██████╔╝╚██████╔╝██║ ╚═╝ ██║    ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""

TAGLINE = "[ MULTI-ECOSYSTEM VULNERABILITY INTELLIGENCE SYSTEM ]"

def display_banner():
    # Top rule
    console.print(Rule(style=C_DIM))

    # Glitchy ASCII art
    for line in BANNER.strip("\n").splitlines():
        console.print(Align.center(f"[{C_ACCENT}]{line}[/{C_ACCENT}]"), highlight=False)

    console.print()
    console.print(Align.center(f"[bold {C_WARN}]{TAGLINE}[/bold {C_WARN}]"), highlight=False)
    console.print(Rule(style=C_DIM))
    console.print()

    # ── Info + Commands side-by-side ──────────────────────────────────
    now = datetime.now()

    info_table = Table(box=None, show_header=False, padding=(0, 1))
    info_table.add_column(style=C_MUTED, no_wrap=True)
    info_table.add_column(style=C_PRIMARY)
    info_table.add_row("◈ TIMESTAMP",   now.strftime("%Y-%m-%d %H:%M:%S"))
    info_table.add_row("◈ SESSION ID",  f"[bold]{session_id[:20]}…[/bold]")
    info_table.add_row("◈ MODE",        "STREAM  /  ASYNC")
    info_table.add_row("◈ ENDPOINT",    API_URL)
    info_table.add_row("◈ STATUS",      f"[bold {C_PRIMARY}]● ONLINE[/bold {C_PRIMARY}]")

    info_panel = Panel(
        info_table,
        title=f"[bold {C_INFO}]⬡  SYSTEM INTEL[/bold {C_INFO}]",
        border_style=C_ACCENT,
        box=box.HEAVY,
        padding=(0, 1),
    )

    cmd_lines = (
        f"[{C_MUTED}]▸[/{C_MUTED}] [bold {C_PRIMARY}]exit[/bold {C_PRIMARY}] / [bold {C_PRIMARY}]quit[/bold {C_PRIMARY}]    Terminate session\n"
        f"[{C_MUTED}]▸[/{C_MUTED}] [bold {C_PRIMARY}]clear[/bold {C_PRIMARY}]           Wipe terminal\n"
        f"[{C_MUTED}]▸[/{C_MUTED}] [bold {C_PRIMARY}]new session[/bold {C_PRIMARY}]     Rotate session ID\n"
        f"[{C_MUTED}]▸[/{C_MUTED}] [bold {C_PRIMARY}]help[/bold {C_PRIMARY}]            Redraw banner\n"
        f"\n"
        f"[{C_MUTED}]Target examples:[/{C_MUTED}]\n"
        f"  [{C_WARN}]./myproject[/{C_WARN}]\n"
        f"  [{C_WARN}]https://github.com/org/repo[/{C_WARN}]\n"
        f"  [{C_WARN}]check vuln for npm lodash 4.17.19[/{C_WARN}]"
    )
    cmd_panel = Panel(
        cmd_lines,
        title=f"[bold {C_INFO}]⬡  COMMAND MATRIX[/bold {C_INFO}]",
        border_style=C_ACCENT,
        box=box.HEAVY,
        padding=(0, 1),
    )

    console.print(Columns([info_panel, cmd_panel], equal=True, expand=True))
    console.print()

# ─────────────────────────────────────────────
# Stream & Render
# ─────────────────────────────────────────────

async def stream_chat(message: str):
    global session_id
    scanline_separator("TRANSMITTING")
    with console.status(
        f"[bold {C_PRIMARY}]◈ ESTABLISHING SECURE CHANNEL …[/bold {C_PRIMARY}]",
        spinner="aesthetic",
        spinner_style=C_PRIMARY,
    ):
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
                                _error_panel(f"Malformed payload: {markup.escape(line)}")
        except Exception as e:
            _error_panel(str(e))


def render_event(event: str, data: dict):
    global session_id

    if event == "start":
        session_id = data.get("session_id", session_id)
        _log_line("SESSION", session_id, C_INFO)

    elif event == "tool_call":
        tool = data.get("data", {})
        name = tool.get("tool_name", "UNKNOWN")
        args = tool.get("tool_input", {})

        args_grid = Table(box=None, show_header=False, padding=(0, 1), expand=False)
        args_grid.add_column(style=C_MUTED, no_wrap=True)
        args_grid.add_column(style=C_WARN)
        if isinstance(args, dict):
            for k, v in args.items():
                args_grid.add_row(f"  {k}", str(v))

        header = Text(f"⚙  INVOKING TOOL → {name}", style=f"bold {C_TOOL_B}")
        console.print(
            Panel(
                Columns([header, args_grid], expand=True),
                border_style=C_TOOL_B,
                box=box.HEAVY_HEAD,
                padding=(0, 1),
            )
        )

    elif event == "output":
        output = data.get("data", "")
        console.print(
            Panel(
                output,
                title=f"[bold {C_PRIMARY}]◈ SCAN OUTPUT[/bold {C_PRIMARY}]",
                border_style=C_PRIMARY,
                box=box.DOUBLE_EDGE,
                padding=(1, 2),
            )
        )

    elif event == "final_output":
        agent = data.get("agent_used", "SUPERVISOR")
        _log_line("FINAL AGENT", agent.upper(), C_WARN)

    elif event == "end":
        scanline_separator("RESPONSE COMPLETE")
        console.print()

    else:
        console.print(f"[{C_MUTED}]  ↳ unknown event: {event}[/{C_MUTED}]")


# ─────────────────────────────────────────────
# Utility renderers
# ─────────────────────────────────────────────

def _log_line(label: str, value: str, color: str = C_PRIMARY):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(
        f"[{C_MUTED}][{ts}][/{C_MUTED}] "
        f"[bold {color}]{label}[/bold {color}]"
        f"[{C_MUTED}] → [/{C_MUTED}]"
        f"[{color}]{markup.escape(value)}[/{color}]",
        highlight=False,
    )

def _error_panel(msg: str):
    console.print(
        Panel(
            f"[bold {C_DANGER}]✖  {markup.escape(msg)}[/bold {C_DANGER}]",
            border_style=C_DANGER,
            box=box.HEAVY,
            title=f"[bold {C_DANGER}]ERROR[/bold {C_DANGER}]",
        )
    )

# ─────────────────────────────────────────────
# Prompt styling
# ─────────────────────────────────────────────

def styled_prompt() -> str:
    """Return a -flavored prompt string."""
    ts   = datetime.now().strftime("%H:%M:%S")
    sid  = session_id[:8]
    # rich Prompt.ask doesn't support full markup in the prompt text reliably,
    # so we print the decoration separately and use a minimal prompt string.
    console.print(
        f"\n[{C_MUTED}]┌──([/{C_MUTED}]"
        f"[bold {C_PRIMARY}]root@roomscan[/bold {C_PRIMARY}]"
        f"[{C_MUTED}])-[[/{C_MUTED}]"
        f"[{C_WARN}]{ts}[/{C_WARN}]"
        f"[{C_MUTED}]]-[[/{C_MUTED}]"
        f"[{C_INFO}]sid:{sid}[/{C_INFO}]"
        f"[{C_MUTED}]][/{C_MUTED}]",
        highlight=False,
    )
    console.print(
        f"[{C_MUTED}]└─▶[/{C_MUTED}] ",
        end="",
        highlight=False,
    )
    return input()  # raw input so we control the prompt exactly

# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────

async def main():
    global session_id

    await boot_sequence()
    display_banner()

    while True:
        try:
            user_input = styled_prompt().strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q"):
                console.print()
                if Confirm.ask(f"[{C_WARN}]  TERMINATE SESSION?[/{C_WARN}]"):
                    break

            elif user_input.lower() == "clear":
                console.clear()
                display_banner()

            elif user_input.lower() == "help":
                display_banner()

            elif user_input.lower().startswith("set session"):
                parts = user_input.split()
                if len(parts) == 3:
                    session_id = parts[2]
                    _log_line("SESSION OVERRIDE", session_id, C_WARN)
                else:
                    _error_panel("Usage: set session <session_id>")

            elif user_input.lower() == "new session":
                session_id = str(uuid.uuid4())
                _log_line("NEW SESSION", session_id, C_INFO)

            else:
                await stream_chat(user_input)

        except KeyboardInterrupt:
            console.print(f"\n[{C_WARN}]  ⚡ SIGNAL INTERRUPT[/{C_WARN}]")
            if Confirm.ask(f"[{C_WARN}]  ABORT?[/{C_WARN}]"):
                break

        except Exception as e:
            _error_panel(str(e))

    # ── Outro ─────────────────────────────────
    console.print()
    console.print(Rule(style=C_DIM))
    console.print(
        Align.center(
            Text("SESSION TERMINATED  //  STAY IN THE SHADOWS", style=f"bold {C_PRIMARY}")
        )
    )
    console.print(Rule(style=C_DIM))
    console.print()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print(f"\n[bold {C_PRIMARY}]  ◈ GOODBYE, OPERATOR.[/bold {C_PRIMARY}]\n")
    except Exception as e:
        try:
            console.print(f"[bold {C_DANGER}]CRITICAL FAULT: {markup.escape(str(e))}[/bold {C_DANGER}]")
        except Exception:
            print(f"Critical Error: {e}")