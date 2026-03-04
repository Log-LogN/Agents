"""
Centralized configuration loaded from environment variables.
All services import from here — never import os.getenv directly.
"""

import os
from contextlib import contextmanager
from contextvars import ContextVar
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────────────────────
# Runtime Context Variables (DEFINE FIRST — VERY IMPORTANT)
# ─────────────────────────────────────────────────────────────

_runtime_openai_model: ContextVar[str | None] = ContextVar(
    "runtime_openai_model", default=None
)

_runtime_openai_api_key: ContextVar[str | None] = ContextVar(
    "runtime_openai_api_key", default=None
)

# ─────────────────────────────────────────────────────────────
# Getter Functions
# ─────────────────────────────────────────────────────────────

def get_openai_api_key() -> str:
    runtime_key = (_runtime_openai_api_key.get() or "").strip()
    return runtime_key or os.getenv("OPENAI_API_KEY", "").strip()


def get_openai_model() -> str:
    runtime_model = (_runtime_openai_model.get() or "").strip()
    return runtime_model or os.getenv("OPENAI_MODEL", "gpt-4o").strip()


# ─────────────────────────────────────────────────────────────
# Settings Object
# ─────────────────────────────────────────────────────────────

class Settings:

    # ── OpenAI ──────────────────────────────────────────────
    OPENAI_API_KEY: str = get_openai_api_key()
    OPENAI_MODEL: str = get_openai_model()

    # ── Supervisor Security ──────────────────────────────────
    MAX_MESSAGE_LENGTH: int = int(os.getenv("MAX_MESSAGE_LENGTH", "2000"))

    # ── Supervisor ───────────────────────────────────────────
    SUPERVISOR_PORT: int = int(os.getenv("SUPERVISOR_PORT", "8000"))

    # ── Logging ──────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # ── Redis ────────────────────────────────────────────────
    REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT: int = int(os.getenv("REDIS_PORT", "6379"))
    REDIS_DB: int = int(os.getenv("REDIS_DB", "0"))
    REDIS_SESSION_TTL_SECONDS: int = int(
        os.getenv("REDIS_SESSION_TTL_SECONDS", str(24 * 60 * 60))
    )

    # ── Threat Intel Integrations ───────────────────────────
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    CISA_KEV_CACHE_TTL_SECONDS: int = int(
        os.getenv("CISA_KEV_CACHE_TTL_SECONDS", str(6 * 60 * 60))
    )


settings = Settings()

# ─────────────────────────────────────────────────────────────
# Runtime Override Context Manager
# ─────────────────────────────────────────────────────────────

@contextmanager
def runtime_openai_config(model: str | None = None, api_key: str | None = None):
    model_token = _runtime_openai_model.set(
        (model or "").strip() if model is not None else None
    )
    key_token = _runtime_openai_api_key.set(
        (api_key or "").strip() if api_key is not None else None
    )
    try:
        yield
    finally:
        _runtime_openai_model.reset(model_token)
        _runtime_openai_api_key.reset(key_token)