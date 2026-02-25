"""Run strict MCP server over uvicorn."""

from __future__ import annotations

import sys
from pathlib import Path

import uvicorn

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


if __name__ == "__main__":
    uvicorn.run(
        "app.mcp_server:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        app_dir=str(ROOT_DIR),
    )
