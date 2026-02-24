"""Routing helpers for supervisor-to-agent dispatch."""

from __future__ import annotations

import re

from core.constants import DATABASE_ROUTE_KEYWORDS, MATH_ROUTE_KEYWORDS


WORD_PROBLEM_MATH_KEYWORDS = (
    "remaining",
    "remain",
    "left",
    "after",
    "gave",
    "give",
    "take",
    "took",
    "minus",
    "less",
    "more",
    "total",
)


def infer_route(user_input: str) -> str:
    text = user_input.lower()

    if any(keyword in text for keyword in DATABASE_ROUTE_KEYWORDS):
        return "database_agent"

    if any(keyword in text for keyword in MATH_ROUTE_KEYWORDS):
        return "math_agent"

    if re.search(r"\d", text) and re.search(r"[\+\-\*/\^]", text):
        return "math_agent"

    numbers = re.findall(r"\d+(?:\.\d+)?", text)
    if numbers and any(keyword in text for keyword in WORD_PROBLEM_MATH_KEYWORDS):
        return "math_agent"

    if len(numbers) >= 2:
        return "math_agent"

    return "database_agent"
