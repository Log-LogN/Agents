from __future__ import annotations

import ast
import json
import logging
from typing import Any

logger = logging.getLogger("agent-tool-runner")


def normalize_tool_result(result: Any) -> dict:
    """
    Normalize LangChain-MCP tool outputs into a dict.

    MCP adapters sometimes return:
    - dict (already structured)
    - list[{"text": "...json..."}]
    - string that is JSON or a Python-literal list containing {"text": "..."}
    """
    if isinstance(result, dict):
        return result

    if isinstance(result, list) and result:
        first = result[0]
        if isinstance(first, dict) and "text" in first:
            text = first.get("text")
            if isinstance(text, str):
                try:
                    return json.loads(text)
                except Exception:
                    return {"raw": text}

    if isinstance(result, str):
        s = result.strip()
        if not s:
            return {"raw": ""}
        try:
            return json.loads(s)
        except Exception:
            try:
                parsed = ast.literal_eval(s)
                if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict) and "text" in parsed[0]:
                    text = parsed[0].get("text")
                    if isinstance(text, str):
                        try:
                            return json.loads(text)
                        except Exception:
                            return {"raw": text}
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
        return {"raw": s}

    return {"raw": str(result)}


async def ainvoke_tool(tool_map: dict, name: str, args: dict) -> tuple[dict, dict]:
    tool = tool_map.get(name)
    if tool is None:
        out = {"status": "error", "data": None, "error": f"Missing tool: {name}"}
        return out, {"tool_name": name, "tool_input": args, "tool_output": json.dumps(out)}

    logger.info("tool_call name=%s args_keys=%s", name, sorted(list(args.keys())))
    res = await tool.ainvoke(args)
    out = normalize_tool_result(res)
    logger.info("tool_result name=%s status=%s", name, out.get("status"))
    return out, {"tool_name": name, "tool_input": args, "tool_output": json.dumps(out)}

