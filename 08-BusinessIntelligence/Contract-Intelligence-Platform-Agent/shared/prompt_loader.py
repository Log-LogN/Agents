"""Shared prompt loader with caching."""
from pathlib import Path
from typing import Dict

_CACHE: Dict[str, str] = {}

def load_prompt(filename: str) -> str:
    if filename in _CACHE:
        return _CACHE[filename]
    path = Path(__file__).resolve().parent / "prompts" / filename
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        text = ""
    _CACHE[filename] = text
    return text
