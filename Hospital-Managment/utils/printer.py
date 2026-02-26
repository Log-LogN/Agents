"""
utils/printer.py
----------------
Helper to cleanly print conversation messages in the terminal.
"""

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage


def print_message(message):
    """Print a single message with role label and formatting."""
    if isinstance(message, HumanMessage):
        print(f"\n{'─'*60}")
        print(f"👤 YOU:\n   {message.content}")

    elif isinstance(message, AIMessage):
        if message.content:
            print(f"\n🤖 AGENT:\n   {message.content}")
        if hasattr(message, "tool_calls") and message.tool_calls:
            for tc in message.tool_calls:
                print(f"\n🔧 CALLING TOOL: {tc['name']}")
                print(f"   Args: {tc['args']}")

    elif isinstance(message, ToolMessage):
        print(f"\n📋 TOOL RESULT [{message.name}]:\n   {message.content}")


def print_separator():
    print(f"\n{'═'*60}")
