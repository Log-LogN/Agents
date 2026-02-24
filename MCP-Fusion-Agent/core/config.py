"""Environment-driven settings for the application."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

from .constants import DEFAULT_MCP_SERVER_URL, DEFAULT_MODEL


@dataclass(frozen=True)
class Settings:
    openai_api_key: str
    model: str = DEFAULT_MODEL
    mcp_server_url: str = DEFAULT_MCP_SERVER_URL


def load_settings(model: str | None = None, mcp_server_url: str | None = None) -> Settings:
    load_dotenv()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set in the environment.")

    resolved_model = model or os.getenv("OPENAI_MODEL", DEFAULT_MODEL)
    resolved_mcp_url = mcp_server_url or os.getenv("MCP_SERVER_URL", DEFAULT_MCP_SERVER_URL)

    return Settings(
        openai_api_key=api_key,
        model=resolved_model,
        mcp_server_url=resolved_mcp_url,
    )
