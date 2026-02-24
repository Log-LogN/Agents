"""MCP client that connects to a standalone MCP server over Streamable HTTP."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

logger = logging.getLogger("agent.mcp_client")


class MCPClient:
    def __init__(self, server_url: str = "http://127.0.0.1:8000/mcp") -> None:
        self.server_url = server_url
        self.session: Optional[ClientSession] = None
        self._session_cm = None
        self._http_cm = None
        self._connected = False

    async def connect(self) -> None:
        if self._connected:
            return

        self._http_cm = streamable_http_client(self.server_url)
        read_stream, write_stream, _ = await self._http_cm.__aenter__()

        self._session_cm = ClientSession(read_stream, write_stream)
        self.session = await self._session_cm.__aenter__()
        await self.session.initialize()

        self._connected = True
        logger.info("Connected to MCP server over HTTP: %s", self.server_url)

    async def ensure_connected(self) -> None:
        if not self._connected or self.session is None:
            await self.connect()

    async def reconnect(self) -> None:
        await self.close()
        await self.connect()

    async def close(self) -> None:
        if self._session_cm is not None:
            try:
                await self._session_cm.__aexit__(None, None, None)
            except BaseException:
                logger.debug("Ignoring session close error during cleanup", exc_info=True)
            finally:
                self._session_cm = None

        if self._http_cm is not None:
            try:
                await self._http_cm.__aexit__(None, None, None)
            except BaseException:
                logger.debug("Ignoring HTTP transport close error during cleanup", exc_info=True)
            finally:
                self._http_cm = None

        self.session = None
        self._connected = False

    async def list_tools(self) -> List[Any]:
        await self.ensure_connected()

        assert self.session is not None
        try:
            tools_response = await self.session.list_tools()
        except Exception:
            logger.warning("list_tools failed, reconnecting MCP session and retrying once", exc_info=True)
            await self.reconnect()
            assert self.session is not None
            tools_response = await self.session.list_tools()

        return list(getattr(tools_response, "tools", []))

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        await self.ensure_connected()
        assert self.session is not None
        try:
            result = await self.session.call_tool(name, arguments=arguments)
        except Exception:
            logger.warning("Session call_tool failed, reconnecting MCP session and retrying once", exc_info=True)
            await self.reconnect()
            assert self.session is not None
            result = await self.session.call_tool(name, arguments=arguments)

        # Different SDK versions expose content slightly differently.
        text_value = getattr(result, "text", None)
        if isinstance(text_value, str) and text_value:
            return text_value

        content = getattr(result, "content", None)
        if isinstance(content, list):
            texts: List[str] = []
            for item in content:
                item_text = getattr(item, "text", None)
                if isinstance(item_text, str) and item_text:
                    texts.append(item_text)
            if texts:
                return "\n".join(texts)

        structured = getattr(result, "structuredContent", None)
        if structured is None:
            structured = getattr(result, "structured_content", None)
        if structured is not None:
            return str(structured)

        return str(result)
