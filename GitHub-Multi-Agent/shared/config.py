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

    # ── GitHub ───────────────────────────────────────────────
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")

    # ── Supervisor Security ──────────────────────────────────
    # Clients must send this in X-API-Key header to use /chat
    # Generate: python -c "import secrets; print(secrets.token_hex(32))"
    # Leave empty string to disable (dev only)
    SUPERVISOR_API_KEY: str = os.getenv("SUPERVISOR_API_KEY", "")

    # Rate limiting: max requests per minute per client IP
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))

    # Max message character length (prevent abuse / prompt injection padding)
    MAX_MESSAGE_LENGTH: int = int(os.getenv("MAX_MESSAGE_LENGTH", "2000"))

    # ── Agent Service URLs (used by supervisor) ──────────────
    GITHUB_AGENT_URL: str = os.getenv("GITHUB_AGENT_URL", "http://localhost:8001")
    # JIRA_AGENT_URL: str = os.getenv("JIRA_AGENT_URL", "http://localhost:8002")
    # SLACK_AGENT_URL: str = os.getenv("SLACK_AGENT_URL", "http://localhost:8003")

    # ── Supervisor ───────────────────────────────────────────
    SUPERVISOR_PORT: int = int(os.getenv("SUPERVISOR_PORT", "8000"))
    GITHUB_AGENT_PORT: int = int(os.getenv("GITHUB_AGENT_PORT", "8001"))

    # ── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Cache ────────────────────────────────────────────────
    CACHE_BACKEND: str = os.getenv("CACHE_BACKEND", "memory")  # memory | redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CACHE_MAX_SIZE: int = int(os.getenv("CACHE_MAX_SIZE", "256"))
    CACHE_DEFAULT_TTL: int = int(os.getenv("CACHE_DEFAULT_TTL", "120"))
    TOOL_VERSION: str = os.getenv("TOOL_VERSION", "v1")

    # ── Approval tokens ──────────────────────────────────────
    APPROVAL_SECRET: str = os.getenv(
        "APPROVAL_SECRET",
        os.getenv("SUPERVISOR_API_KEY", "") or "dev-approval-secret",
    )
    APPROVAL_TOKEN_TTL_SEC: int = int(os.getenv("APPROVAL_TOKEN_TTL_SEC", "600"))


settings = Settings()
