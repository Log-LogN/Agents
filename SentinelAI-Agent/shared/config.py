"""
Centralized configuration loaded from environment variables.
All services import from here — never import os.getenv directly.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    # ── OpenAI ──────────────────────────────────────────────
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o")

    # ── Supervisor Security ──────────────────────────────────
    MAX_MESSAGE_LENGTH: int = int(os.getenv("MAX_MESSAGE_LENGTH", "2000"))

    # ── Agent Service URLs (used by supervisor) ──────────────
    RECON_AGENT_URL = os.getenv("RECON_AGENT_URL", "http://localhost:8001")
    VULN_AGENT_URL = os.getenv("VULN_AGENT_URL", "http://localhost:8002")
    REPORT_AGENT_URL = os.getenv("REPORT_AGENT_URL", "http://localhost:8003")

    # ── Supervisor ───────────────────────────────────────────
    SUPERVISOR_PORT: int = int(os.getenv("SUPERVISOR_PORT", "8000"))

    # ── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")



settings = Settings()
