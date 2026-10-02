# mcp-webhook-events

**MCP Events for Python MCP servers. Let ChatGPT watch something in your app and act when it changes.**

On 29 September 2026 OpenAI added [MCP Events](https://developers.openai.com/plugins/build/mcp-events) to ChatGPT. A user can ask ChatGPT to watch something in your app, ChatGPT subscribes through your MCP server, and your server sends a signed webhook when it changes. ChatGPT then does whatever the user asked.

The official Python MCP SDK (`mcp` 2.2.0) does not support this yet. Neither does the TypeScript SDK (1.32.0). This package adds it to a server built on the official Python SDK, without forking or patching the SDK.

```bash
pip install mcp-webhook-events
```

## Proven with the real ChatGPT

Tested on 2 October 2026 against a live server ([UK Business Check](https://check.shaunessey.com), which watches UK companies):

1. After "Refresh tools", ChatGPT listed the server's `company.status_changed` event next to its tools.
2. In a Work chat, "watch company 00445790" made ChatGPT call `events/subscribe`. The callback was verified with a signed single-use challenge, and ChatGPT echoed it correctly.
3. A test event was signed and posted. ChatGPT's receiver returned `200`, and seconds later ChatGPT posted in the chat by itself: *"TEST — TESCO PLC (00445790): the service owner sent a test event; nothing about the company actually changed."*

## Quick start

```python
from mcp.server import MCPServer
from mcp_webhook_events import EventDefinition, McpEvents

mcp = MCPServer("Ticket watcher")

events = McpEvents(mcp, store="events.sqlite3", definitions=[
    EventDefinition(
        name="ticket.updated",
        description="A support ticket you are watching was updated.",
        input_schema={"type": "object", "properties": {"ticket_id": {"type": "string"}},
                      "required": ["ticket_id"], "additionalProperties": False},
        payload_schema={"type": "object",
                        "properties": {"ticket_id": {"type": "string"}, "summary": {"type": "string"}},
                        "required": ["ticket_id", "summary"], "additionalProperties": False},
    ),
])
events.install()   # adds events/list, events/subscribe, events/unsubscribe and the `events` capability

app = mcp.streamable_http_app(stateless_http=True, json_response=True)
```

When something changes, from anywhere that can open the same store (a cron job, a webhook handler, a worker):

```python
events.publish("ticket.updated", {"ticket_id": "T-1", "summary": "Customer replied"})
events.deliver_pending()   # sends now. Call it again on a timer to retry failures
```

By default an event goes to every live subscription whose `arguments` match fields of the same name in the event data. Pass `matches=` to an `EventDefinition` for anything cleverer.

A full example is in [`examples/watch_server.py`](examples/watch_server.py).

## What it handles for you

Everything on OpenAI's MCP Events page that a server has to do:

| Requirement | How |
|---|---|
| Advertise `events` in `server/discover` | Middleware on the result (see below) |
| `events/list`, `events/subscribe`, `events/unsubscribe` | Registered on the SDK's own handler table |
| `whsec_` secrets of 24 to 64 bytes | Checked before anything else |
| Arguments validated against your `inputSchema` | jsonschema |
| Callback verification with a fresh, signed, single-use challenge, constant-time compare | Yes, cached per caller and URL for 24 hours |
| JSON-RPC `-32015` with `data.reason` when verification fails | Yes |
| Deterministic, idempotent subscription IDs, key order ignored | SHA-256 of caller, URL, event name and canonical arguments |
| Subscriptions survive restarts | SQLite (WAL) |
| Expiry, `refreshBefore`, `ttlMs` | Default 7 days, minimum 1 hour, never "forever" |
| Secret rotation | Signs with old and new keys during a 24 hour window |
| Standard Webhooks signing, `webhook-id` = `eventId`, `X-MCP-Subscription-Id` | Uses the official `standardwebhooks` package |
| Retries with backoff, same event ID, fresh signature | 30s, 2m, 10m, 30m, 1h, 2h, then gives up |
| No retry on `410` or `413`, and `410` drops the subscription | Yes |
| One event per request, 256 KiB maximum | Enforced |
| HTTPS only, public addresses only, checked at connect time, no redirects | Yes, with TLS still checked against the original hostname |
| Forget what isn't needed | Expired subscriptions, their URLs and secrets, and old delivery history are purged |

Not included, because ChatGPT does not support them either: polling, streaming, replay cursors and the draft's `gap` and `terminated` notifications.

## Three things that had to be worked out

These are the parts that are not obvious from the documentation, in case you are building this yourself.

1. **Custom methods are allowed.** The SDK's low-level server has `add_request_handler(method, params_type, handler)`, and it accepts `events/*` methods over the 2026-07-28 Streamable HTTP transport. No fork is needed.
2. **Clients must send `Mcp-Method`.** On the modern transport, a request without an `Mcp-Method` header matching the body's method gets rejected with `-32020`. ChatGPT sends it, but your own test client needs to as well.
3. **The SDK drops unknown capabilities.** `ServerCapabilities` ignores unknown keys, and spec results are cleaned against the schema, so `events: {}` never reaches the wire if you put it in the result. This package adds it in middleware, after the result is serialised.

## Testing

```bash
pip install -e ".[test]"
python -m unittest discover -s tests -v
python tests/mutation_check.py     # breaks the code 25 ways, and every one must be caught
```

The tests run a local receiver that plays ChatGPT. It checks every signature with the official Standard Webhooks verifier rather than this package's own code. `mutation_check.py` proves the tests catch real faults: unverified callbacks, wrong signatures, ignored filters, retrying a `410`, leaking to private addresses and so on.

## Status

Version 0.1.0. MCP Events is still a [draft extension](https://github.com/modelcontextprotocol/experimental-ext-triggers-events), so details may change, and the official SDKs will probably add support at some point. Until they do, this is a small, tested way to use it today.

Issues and pull requests are welcome.

## Licence

MIT. Made by Shaun Owen.
