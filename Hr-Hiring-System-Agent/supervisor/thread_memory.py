"""
Redis-backed thread memory for supervisor chat.

Stores per-thread request/response pairs and compacts old turns into a summary
when configured text limits are exceeded.
"""

import json
import os
import time
import logging
from typing import Callable

import redis

log = logging.getLogger(__name__)


def _safe_int(value: str, default: int) -> int:
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except Exception:
        return default


class RedisThreadMemory:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "").strip() or "redis://127.0.0.1:6379/0"
        self.enabled = os.getenv("REDIS_ENABLED", "true").lower() not in ("0", "false", "no")
        self.namespace = os.getenv("REDIS_THREAD_NAMESPACE", "hr:thread")
        self.ttl_sec = _safe_int(os.getenv("REDIS_THREAD_TTL_SEC", "604800"), 604800)  # 7 days
        self.text_limit = _safe_int(os.getenv("REDIS_THREAD_TEXT_LIMIT", "20000"), 20000)
        self.keep_messages = _safe_int(os.getenv("REDIS_THREAD_KEEP_MESSAGES", "8"), 8)
        self.summary_max_chars = _safe_int(os.getenv("REDIS_SUMMARY_MAX_CHARS", "8000"), 8000)

        self._client = None
        if self.enabled:
            try:
                self._client = redis.from_url(redis_url, decode_responses=True, socket_timeout=1.0)
                self._client.ping()
                log.info("Redis thread memory enabled at %s", redis_url)
            except Exception as e:
                self._client = None
                self.enabled = False
                log.warning("Redis not available; thread memory disabled: %s", e)

    def _key(self, thread_id: str) -> str:
        return f"{self.namespace}:{thread_id}"

    def load(self, thread_id: str) -> dict:
        if not self.enabled or not self._client or not thread_id:
            return {"summary": "", "messages": []}

        try:
            data = self._client.hgetall(self._key(thread_id))
            summary = data.get("summary", "")
            raw_messages = data.get("messages", "[]")
            messages = json.loads(raw_messages) if raw_messages else []
            if not isinstance(messages, list):
                messages = []
            return {"summary": str(summary or ""), "messages": messages}
        except Exception as e:
            log.warning("Redis load failed for thread %s: %s", thread_id, e)
            return {"summary": "", "messages": []}

    def append_turn(
        self,
        thread_id: str,
        request_text: str,
        response_text: str,
        summarizer: Callable[[str, list], str] | None = None,
    ) -> None:
        if not self.enabled or not self._client or not thread_id:
            return

        request_text = (request_text or "").strip()
        response_text = (response_text or "").strip()
        if not request_text and not response_text:
            return

        data = self.load(thread_id)
        summary = data["summary"]
        messages = data["messages"]

        now = int(time.time())
        if request_text:
            messages.append({"role": "human", "content": request_text, "ts": now})
        if response_text:
            messages.append({"role": "ai", "content": response_text, "ts": now})

        summary, messages = self._compact_if_needed(summary, messages, summarizer=summarizer)

        try:
            key = self._key(thread_id)
            self._client.hset(
                key,
                mapping={
                    "summary": summary,
                    "messages": json.dumps(messages, ensure_ascii=True),
                    "updated_at": str(now),
                },
            )
            self._client.expire(key, self.ttl_sec)
        except Exception as e:
            log.warning("Redis save failed for thread %s: %s", thread_id, e)

    def _compact_if_needed(
        self,
        summary: str,
        messages: list,
        summarizer: Callable[[str, list], str] | None = None,
    ) -> tuple[str, list]:
        total_chars = len(summary) + sum(len(str(m.get("content", ""))) for m in messages)
        if total_chars <= self.text_limit or len(messages) <= self.keep_messages:
            return summary, messages

        old_messages = messages[:-self.keep_messages]
        kept_messages = messages[-self.keep_messages:]

        if summarizer:
            try:
                new_summary = summarizer(summary, old_messages)
            except Exception as e:
                log.warning("Summary generation failed, falling back to local summary: %s", e)
                new_summary = self._local_summary(summary, old_messages)
        else:
            new_summary = self._local_summary(summary, old_messages)

        if len(new_summary) > self.summary_max_chars:
            new_summary = new_summary[-self.summary_max_chars :]

        return new_summary, kept_messages

    def _local_summary(self, existing_summary: str, old_messages: list) -> str:
        lines = []
        if existing_summary:
            lines.append(existing_summary.strip())

        lines.append("Compressed thread summary:")
        for item in old_messages:
            role = "User" if item.get("role") == "human" else "Assistant"
            content = str(item.get("content", "")).strip().replace("\n", " ")
            if len(content) > 180:
                content = content[:180] + "..."
            if content:
                lines.append(f"- {role}: {content}")

        return "\n".join(lines).strip()
