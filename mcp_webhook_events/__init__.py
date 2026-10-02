"""MCP Events (webhook delivery) for servers built on the official Python MCP SDK.

ChatGPT launched MCP Events on 29 September 2026: an MCP server lists events, ChatGPT
subscribes with a callback URL and signing secret, and the server POSTs signed events
when something changes. The official SDK (mcp 2.2.0) has no support for it. This adds it
without forking the SDK:

    from mcp_webhook_events import EventDefinition, McpEvents

    events = McpEvents(server, store="events.sqlite3", definitions=[
        EventDefinition(
            name="company.status_changed",
            description="A watched UK company's status or verdict changed.",
            input_schema={...},     # what a subscriber filters on
            payload_schema={...},   # the `data` of each delivered event
        ),
    ])
    events.install()                # events/list, events/subscribe, events/unsubscribe + capability

    # Later, from anywhere that shares the same store (a cron job, a webhook handler):
    events.publish("company.status_changed", {"company_number": "00445790", ...})
    events.deliver_pending()

Covered: callback verification with a single-use challenge, Standard Webhooks signing,
deterministic idempotent subscription IDs, subscriptions that survive restarts (SQLite),
expiry and refresh, secret rotation, retries with backoff that keep the event ID,
no retry on 410/413, 256 KiB limit, HTTPS-only callbacks to public addresses with no
redirects. Not covered (ChatGPT doesn't support them either): polling, streaming, replay
cursors, `gap`/`terminated` control notifications.

Spec followed: https://developers.openai.com/plugins/build/mcp-events (read 2 Oct 2026).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import http.client
import ipaddress
import json
import secrets
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import jsonschema
from standardwebhooks.webhooks import Webhook

__all__ = ["EventDefinition", "McpEvents", "CallbackError", "CALLBACK_ENDPOINT_ERROR"]
__version__ = "0.1.0"

CALLBACK_ENDPOINT_ERROR = -32015   # JSON-RPC code ChatGPT expects when callback verification fails
INVALID_PARAMS = -32602
MAX_BODY = 256 * 1024
DEFAULT_TTL_MS = 7 * 24 * 3600 * 1000
MIN_TTL_MS = 3600 * 1000
VERIFY_CACHE_SECONDS = 24 * 3600
ROTATION_WINDOW_SECONDS = 24 * 3600
RETRY_DELAYS = (30, 120, 600, 1800, 3600, 7200)    # seconds between attempts; then give up


class CallbackError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class EventDefinition:
    name: str
    description: str
    input_schema: dict
    payload_schema: dict
    # Decides whether published `data` matches a subscription's `arguments`.
    # Default: every subscription argument equals the field of the same name in `data`.
    matches: Callable[[dict, dict], bool] | None = None

    def wire(self) -> dict:
        return {"name": self.name, "description": self.description, "delivery": ["webhook"],
                "inputSchema": self.input_schema, "payloadSchema": self.payload_schema}


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def valid_secret(secret: Any) -> bool:
    if not isinstance(secret, str) or not secret.startswith("whsec_"):
        return False
    try:
        raw = base64.b64decode(secret[len("whsec_"):], validate=True)
    except (binascii.Error, ValueError):
        return False
    return 24 <= len(raw) <= 64


# ---- safe outbound HTTP ---------------------------------------------------------------

class SafeHttp:
    """POSTs JSON to a callback: HTTPS only, public addresses only (checked at connect time,
    then connects to that exact address with the original hostname for TLS), no redirects."""

    def __init__(self, allow_insecure_for_tests: bool = False, timeout: float = 10.0):
        self.allow_insecure = allow_insecure_for_tests
        self.timeout = timeout

    def check_url(self, url: str) -> urllib.parse.SplitResult:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" and not (self.allow_insecure and u.scheme == "http"):
            raise CallbackError("insecure_url")
        if not u.hostname or u.username or u.password:
            raise CallbackError("invalid_url")
        return u

    def _public_address(self, host: str, port: int) -> str:
        try:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            raise CallbackError("dns_failure") from None
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if self.allow_insecure or ip.is_global:
                return str(ip)
        raise CallbackError("blocked_address")

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
        u = self.check_url(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        ip = self._public_address(u.hostname, port)
        path = urllib.parse.urlunsplit(("", "", u.path or "/", u.query, ""))
        try:
            if u.scheme == "https":
                conn = _PinnedHTTPSConnection(u.hostname, ip, port, timeout=self.timeout)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=self.timeout)
            conn.request("POST", path, body=body, headers={**headers, "Host": u.netloc.split("@")[-1]})
            resp = conn.getresponse()
            data = resp.read(64 * 1024)
            conn.close()
            return resp.status, data   # http.client never follows redirects
        except socket.timeout:
            raise CallbackError("timeout") from None
        except (OSError, http.client.HTTPException):
            raise CallbackError("connection_failed") from None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, ip: str, port: int, timeout: float):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


# ---- the extension --------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions (
  id TEXT PRIMARY KEY, principal TEXT NOT NULL, name TEXT NOT NULL, arguments TEXT NOT NULL,
  url TEXT NOT NULL, secret TEXT NOT NULL, old_secret TEXT, old_secret_until REAL,
  expires_at REAL, created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS verified_callbacks (
  principal TEXT NOT NULL, url TEXT NOT NULL, verified_at REAL NOT NULL, PRIMARY KEY (principal, url));
CREATE TABLE IF NOT EXISTS outbox (
  event_id TEXT NOT NULL, subscription_id TEXT NOT NULL, body TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  last_result TEXT, created_at REAL NOT NULL, PRIMARY KEY (event_id, subscription_id));
"""


class McpEvents:
    def __init__(self, server: Any, store: str, definitions: list[EventDefinition], *,
                 principal: Callable[[Any], str] | None = None,
                 http: SafeHttp | None = None,
                 default_ttl_ms: int = DEFAULT_TTL_MS,
                 clock: Callable[[], float] = time.time):
        self.server = server
        self.store = store
        self.definitions = {d.name: d for d in definitions}
        self.principal = principal or (lambda ctx: "anonymous")
        self.http = http or SafeHttp()
        self.default_ttl_ms = default_ttl_ms
        self.clock = clock
        self._lock = threading.Lock()
        with self._db() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def _db(self):
        """One short transaction: commits on success, rolls back on error, always closes."""
        db = sqlite3.connect(self.store, timeout=30)
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.row_factory = sqlite3.Row
            with db:
                yield db
        finally:
            db.close()

    # -- wiring into the official SDK --

    def install(self) -> None:
        from mcp_types import RequestParams
        from pydantic import ConfigDict

        class AnyParams(RequestParams):
            model_config = ConfigDict(extra="allow")

        low = getattr(self.server, "_lowlevel_server", None) or getattr(self.server, "_mcp_server", self.server)
        low.add_request_handler("events/list", AnyParams, self._rpc(self.list_events))
        low.add_request_handler("events/subscribe", AnyParams, self._rpc(self.subscribe))
        low.add_request_handler("events/unsubscribe", AnyParams, self._rpc(self.unsubscribe))
        low.middleware.append(_AdvertiseEvents())

    def _rpc(self, fn):
        import anyio
        from mcp.shared.exceptions import MCPError

        async def handler(ctx, params):
            raw = params.model_dump(by_alias=True, exclude_none=False) if params is not None else {}
            raw.pop("_meta", None)
            raw.pop("meta", None)
            try:
                return await anyio.to_thread.run_sync(fn, self.principal(ctx), raw)
            except CallbackError as e:
                raise MCPError(code=CALLBACK_ENDPOINT_ERROR, message="Callback endpoint error",
                               data={"reason": e.reason}) from None
            except _InvalidParams as e:
                raise MCPError(code=INVALID_PARAMS, message=str(e)) from None
        return handler

    # -- the three methods (plain functions, testable without the SDK) --

    def list_events(self, principal: str, params: dict) -> dict:
        return {"events": [d.wire() for d in self.definitions.values()]}

    def subscribe(self, principal: str, params: dict) -> dict:
        name, args, delivery = self._parse(params)
        secret = delivery.get("secret")
        if not valid_secret(secret):
            raise _InvalidParams("delivery.secret must be whsec_ followed by base64 of 24 to 64 bytes")
        url = delivery["url"]
        self.http.check_url(url)
        sub_id = self.subscription_id(principal, url, name, args)
        expires_at = self._grant(params.get("ttlMs", "omitted"))

        with self._lock, self._db() as db:
            existing = db.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
        if not self._recently_verified(principal, url):
            self._verify_callback(sub_id, url, secret)
        now = self.clock()
        with self._lock, self._db() as db:
            db.execute("INSERT OR REPLACE INTO verified_callbacks VALUES (?,?,?)", (principal, url, now))
            if existing:
                rotating = existing["secret"] != secret
                db.execute("UPDATE subscriptions SET secret=?, old_secret=?, old_secret_until=?, expires_at=?, "
                           "updated_at=? WHERE id=?",
                           (secret, existing["secret"] if rotating else existing["old_secret"],
                            now + ROTATION_WINDOW_SECONDS if rotating else existing["old_secret_until"],
                            expires_at, now, sub_id))
            else:
                db.execute("INSERT INTO subscriptions (id, principal, name, arguments, url, secret, expires_at, "
                           "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                           (sub_id, principal, name, canonical(args), url, secret, expires_at, now, now))
        return {"id": sub_id, "refreshBefore": iso(expires_at) if expires_at else None,
                "cursor": None, "truncated": False}

    def unsubscribe(self, principal: str, params: dict) -> dict:
        name, args, delivery = self._parse(params, need_secret=False)
        sub_id = self.subscription_id(principal, delivery["url"], name, args)
        with self._lock, self._db() as db:
            db.execute("DELETE FROM subscriptions WHERE id=? AND principal=?", (sub_id, principal))
            db.execute("UPDATE outbox SET status='cancelled' WHERE subscription_id=? AND status='pending'", (sub_id,))
        return {}

    # -- publishing and delivery --

    def publish(self, name: str, data: dict, *, event_id: str | None = None,
                occurred_at: float | None = None, only_subscription: str | None = None) -> int:
        """Queue `data` for every live subscription to `name` whose arguments match. Returns how many."""
        d = self.definitions[name]
        jsonschema.validate(data, d.payload_schema)
        match = d.matches or (lambda args, data: all(data.get(k) == v for k, v in args.items()))
        event_id = event_id or "evt_" + secrets.token_hex(12)
        now = self.clock()
        queued = 0
        with self._lock, self._db() as db:
            for s in db.execute("SELECT * FROM subscriptions WHERE name=?", (name,)).fetchall():
                if s["expires_at"] and s["expires_at"] <= now:
                    continue
                if only_subscription and s["id"] != only_subscription:
                    continue
                if not match(json.loads(s["arguments"]), data):
                    continue
                body = canonical({"eventId": event_id, "name": name,
                                  "timestamp": iso(occurred_at or now), "data": data, "cursor": None})
                if len(body.encode()) > MAX_BODY:
                    raise ValueError("event body exceeds 256 KiB; send a summary and a read tool instead")
                db.execute("INSERT OR IGNORE INTO outbox (event_id, subscription_id, body, next_attempt_at, "
                           "created_at) VALUES (?,?,?,?,?)", (event_id, s["id"], body, now, now))
                queued += 1
        return queued

    def deliver_pending(self) -> dict:
        """Try every due delivery once. Safe to call from a cron job or a loop."""
        now = self.clock()
        self.purge(now)
        stats = {"delivered": 0, "retrying": 0, "failed": 0}
        with self._lock, self._db() as db:
            due = db.execute("SELECT o.*, s.url, s.secret, s.old_secret, s.old_secret_until FROM outbox o "
                             "JOIN subscriptions s ON s.id=o.subscription_id "
                             "WHERE o.status='pending' AND o.next_attempt_at<=?", (now,)).fetchall()
        for row in due:
            status, outcome = self._send(row)
            attempts = row["attempts"] + 1
            with self._lock, self._db() as db:
                if 200 <= status < 300:
                    db.execute("UPDATE outbox SET status='delivered', attempts=?, last_result=? "
                               "WHERE event_id=? AND subscription_id=?",
                               (attempts, str(status), row["event_id"], row["subscription_id"]))
                    stats["delivered"] += 1
                    continue
                if status == 410:   # receiver says the subscription is gone
                    db.execute("DELETE FROM subscriptions WHERE id=?", (row["subscription_id"],))
                final = status in (410, 413) or attempts > len(RETRY_DELAYS)
                db.execute("UPDATE outbox SET status=?, attempts=?, next_attempt_at=?, last_result=? "
                           "WHERE event_id=? AND subscription_id=?",
                           ("failed" if final else "pending", attempts,
                            now + (0 if final else RETRY_DELAYS[attempts - 1]), outcome,
                            row["event_id"], row["subscription_id"]))
                stats["failed" if final else "retrying"] += 1
        return stats

    def purge(self, now: float | None = None) -> None:
        """Forget what's no longer needed: expired subscriptions (with their callback URL and
        secret), their queued events, old verification records and old delivery history."""
        now = self.clock() if now is None else now
        with self._lock, self._db() as db:
            expired = [r["id"] for r in db.execute(
                "SELECT id FROM subscriptions WHERE expires_at IS NOT NULL AND expires_at<=?", (now,))]
            for sub_id in expired:
                db.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
                db.execute("UPDATE outbox SET status='cancelled' WHERE subscription_id=? AND status='pending'",
                           (sub_id,))
            db.execute("DELETE FROM verified_callbacks WHERE verified_at<? AND url NOT IN "
                       "(SELECT url FROM subscriptions)", (now - VERIFY_CACHE_SECONDS,))
            db.execute("DELETE FROM outbox WHERE status!='pending' AND created_at<?", (now - 7 * 24 * 3600,))

    def _send(self, row) -> tuple[int, str]:
        signed_at = now_utc()
        body = row["body"]
        sig = Webhook(row["secret"]).sign(row["event_id"], signed_at, body)
        if row["old_secret"] and row["old_secret_until"] and row["old_secret_until"] > self.clock():
            sig += " " + Webhook(row["old_secret"]).sign(row["event_id"], signed_at, body)
        headers = {"Content-Type": "application/json", "webhook-id": row["event_id"],
                   "webhook-timestamp": str(int(signed_at.timestamp())), "webhook-signature": sig,
                   "X-MCP-Subscription-Id": row["subscription_id"]}
        try:
            status, _ = self.http.post(row["url"], body.encode(), headers)
            return status, str(status)
        except CallbackError as e:
            return 0, e.reason

    # -- helpers --

    @staticmethod
    def subscription_id(principal: str, url: str, name: str, args: dict) -> str:
        digest = hashlib.sha256(canonical([principal, url, name, args]).encode()).hexdigest()
        return "sub_" + digest[:32]

    def _parse(self, params: dict, need_secret: bool = True) -> tuple[str, dict, dict]:
        name = params.get("name")
        if name not in self.definitions:
            raise _InvalidParams("Unknown event name")
        args = params.get("arguments") or {}
        try:
            jsonschema.validate(args, self.definitions[name].input_schema)
        except jsonschema.ValidationError as e:
            raise _InvalidParams(f"Invalid arguments: {e.message}") from None
        delivery = params.get("delivery") or {}
        if delivery.get("mode") != "webhook" or not isinstance(delivery.get("url"), str):
            raise _InvalidParams("delivery.mode must be webhook with a url")
        return name, args, delivery

    def _grant(self, requested: Any) -> float | None:
        if requested is None:            # ttlMs: null asks for no expiry; we grant a finite one instead
            ttl = self.default_ttl_ms
        elif requested == "omitted":
            ttl = self.default_ttl_ms
        elif isinstance(requested, (int, float)) and requested > 0:
            ttl = max(MIN_TTL_MS, min(int(requested), self.default_ttl_ms))
        else:
            raise _InvalidParams("ttlMs must be a positive number of milliseconds or null")
        return self.clock() + ttl / 1000

    def _recently_verified(self, principal: str, url: str) -> bool:
        with self._db() as db:
            row = db.execute("SELECT verified_at FROM verified_callbacks WHERE principal=? AND url=?",
                             (principal, url)).fetchone()
        return bool(row) and self.clock() - row["verified_at"] < VERIFY_CACHE_SECONDS

    def _verify_callback(self, sub_id: str, url: str, secret: str) -> None:
        challenge = secrets.token_urlsafe(32)
        msg_id = "msg_verification_" + secrets.token_hex(8)
        body = canonical({"type": "verification", "challenge": challenge})
        signed_at = now_utc()
        headers = {"Content-Type": "application/json", "webhook-id": msg_id,
                   "webhook-timestamp": str(int(signed_at.timestamp())),
                   "webhook-signature": Webhook(secret).sign(msg_id, signed_at, body),
                   "X-MCP-Subscription-Id": sub_id}
        status, data = self.http.post(url, body.encode(), headers)
        if not 200 <= status < 300:
            raise CallbackError("challenge_failed")
        try:
            echoed = json.loads(data.decode() or "{}").get("challenge")
        except (ValueError, AttributeError):
            raise CallbackError("challenge_failed") from None
        if not isinstance(echoed, str) or not hmac.compare_digest(echoed, challenge):
            raise CallbackError("challenge_failed")

    def active_subscriptions(self, name: str | None = None) -> list[dict]:
        now = self.clock()
        with self._db() as db:
            rows = db.execute("SELECT id, name, arguments, url, expires_at FROM subscriptions"
                              + (" WHERE name=?" if name else ""), (name,) if name else ()).fetchall()
        return [{"id": r["id"], "name": r["name"], "arguments": json.loads(r["arguments"]),
                 "url": r["url"], "expires_at": r["expires_at"]}
                for r in rows if not r["expires_at"] or r["expires_at"] > now]


class _InvalidParams(Exception):
    pass


class _AdvertiseEvents:
    """Adds `events: {}` to server/discover capabilities. The SDK's result sieve drops unknown
    capability keys, so this runs as middleware on the already-serialized result."""

    async def __call__(self, ctx, call_next):
        result = await call_next(ctx)
        if ctx.method in ("server/discover", "initialize") and isinstance(result, dict):
            result.setdefault("capabilities", {})["events"] = {}
        return result
