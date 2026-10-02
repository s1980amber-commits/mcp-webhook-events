"""Smallest useful example: an MCP server ChatGPT can subscribe to.

    pip install mcp-webhook-events uvicorn
    python examples/watch_server.py          # serves http://127.0.0.1:8000/mcp

Put it behind HTTPS on a public domain, add it to ChatGPT as a plugin, press "Refresh tools",
then in a Work chat ask ChatGPT to watch a ticket. Publish an event with:

    python examples/watch_server.py publish T-1 "Customer replied"
"""
import sys

import uvicorn
from mcp.server import MCPServer

from mcp_webhook_events import EventDefinition, McpEvents

STORE = "example-events.sqlite3"

TICKET_UPDATED = EventDefinition(
    name="ticket.updated",
    description="A support ticket you are watching was updated.",
    input_schema={"type": "object", "properties": {"ticket_id": {"type": "string"}},
                  "required": ["ticket_id"], "additionalProperties": False},
    payload_schema={"type": "object",
                    "properties": {"ticket_id": {"type": "string"}, "summary": {"type": "string"}},
                    "required": ["ticket_id", "summary"], "additionalProperties": False},
)

mcp = MCPServer("Ticket watcher")


@mcp.tool(description="Returns the current summary of a support ticket.")
def get_ticket(ticket_id: str) -> str:
    return f"Ticket {ticket_id}: open"


events = McpEvents(mcp, store=STORE, definitions=[TICKET_UPDATED])
events.install()

if __name__ == "__main__":
    if sys.argv[1:2] == ["publish"]:
        print("queued:", events.publish("ticket.updated", {"ticket_id": sys.argv[2], "summary": sys.argv[3]}))
        print(events.deliver_pending())
    else:
        uvicorn.run(mcp.streamable_http_app(stateless_http=True, json_response=True), port=8000)
