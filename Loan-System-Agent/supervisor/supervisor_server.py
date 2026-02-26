"""
supervisor/supervisor_server.py
-------------------------------
Exposes the Supervisor Agent as a FastAPI server on port 9001.
We use a standard JSON endpoint instead of purely MCP to avoid Streamlit
client loop complications, whilst still keeping the supervisor in a separate HTTP server.
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from supervisor.graph import ainvoke

app = FastAPI(title="Supervisor API")

class ChatRequest(BaseModel):
    messages: list

@app.post("/chat")
async def process_chat(request: ChatRequest):
    """
    Process a chat message through the Supervisor LangGraph.
    Provide the entire conversation history as a list of message dicts.
    Returns the final reply, trace, and updated messages.
    """
    from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
    
    parsed_msgs = []
    for m in request.messages:
        role = m.get("role", m.get("type", ""))
        content = m.get("content", "")
        
        if role in ("human", "user"):
            parsed_msgs.append(HumanMessage(content=content))
        elif role in ("ai", "assistant"):
            parsed_msgs.append(AIMessage(content=content, tool_calls=m.get("tool_calls", [])))
        elif role == "tool":
            parsed_msgs.append(ToolMessage(content=content, tool_call_id=m.get("tool_call_id", ""), name=m.get("name", "")))
        elif role == "system":
            parsed_msgs.append(SystemMessage(content=content))
        else:
            parsed_msgs.append(HumanMessage(content=content))

    try:
        # Run graph
        result = await ainvoke(parsed_msgs)
        
        # Serialize messages back to dicts so they can be parsed by Streamlit
        serialized_msgs = []
        for msg in result["messages"]:
            if getattr(msg, "tool_calls", None):
                serialized_msgs.append({
                    "role": msg.type,
                    "content": msg.content,
                    "tool_calls": msg.tool_calls
                })
            elif msg.type == "tool":
                serialized_msgs.append({
                    "role": msg.type,
                    "content": msg.content,
                    "tool_call_id": msg.tool_call_id,
                    "name": msg.name
                })
            else:
                serialized_msgs.append({
                    "role": msg.type,
                    "content": msg.content
                })
                
        return {
            "final_reply": result["final_reply"],
            "trace": result["trace"],
            "messages": serialized_msgs
        }
    except Exception as e:
        import traceback
        raise HTTPException(status_code=500, detail=f"Error: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    print("[START] Supervisor FastAPI Server on http://127.0.0.1:9001")
    uvicorn.run(app, host="127.0.0.1", port=9001)
