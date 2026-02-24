"""CLI entrypoint for Phase-2 MCP chat."""

from __future__ import annotations

import asyncio

from app.chat_cli import run_chat
from core.logging import setup_logging


def main() -> None:
    setup_logging()
    asyncio.run(run_chat())


if __name__ == "__main__":
    main()
