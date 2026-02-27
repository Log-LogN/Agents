"""
Direct-answer fallback agent used when supervisor routing is undecidable.
"""

import os
import sys

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from shared.config import settings


DIRECT_ANSWER_AGENT = "direct_answer"

DIRECT_ANSWER_SYSTEM_PROMPT = SystemMessage(content=(
    "You are the default fallback assistant. "
    "When the supervisor cannot confidently select a specialist agent, "
    "provide a direct, concise answer and clearly note any missing context."
))


async def run_direct_answer(message: str) -> str:
    llm = ChatOpenAI(
        model=settings.OPENAI_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0.2,
    )
    response = await llm.ainvoke([
        DIRECT_ANSWER_SYSTEM_PROMPT,
        HumanMessage(content=message),
    ])
    if isinstance(response.content, str):
        return response.content
    return str(response.content)
