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

    # ── Supervisor ───────────────────────────────────────────
    SUPERVISOR_PORT: int = int(os.getenv("SUPERVISOR_PORT", "8000"))

    # ── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Redis ───────────────────────────────────────────────
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))

    # ── Threat Intel Integrations ───────────────────────────
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    CISA_KEV_CACHE_TTL_SECONDS: int = int(os.getenv("CISA_KEV_CACHE_TTL_SECONDS", str(6 * 60 * 60)))

settings = Settings()
