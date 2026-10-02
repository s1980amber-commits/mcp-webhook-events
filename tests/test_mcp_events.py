"""Tests for mcp_webhook_events. A local receiver plays ChatGPT: it checks every signature with the
official Standard Webhooks verifier, echoes challenges, and can be told to fail.

Run: python -m unittest discover -s tests -v
"""
import base64
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from standardwebhooks.webhooks import Webhook, WebhookVerificationError  # noqa: E402

import mcp_webhook_events as me  # noqa: E402

SECRET = "whsec_" + base64.b64encode(b"k" * 32).decode()
SECRET2 = "whsec_" + base64.b64encode(b"z" * 32).decode()

DEF = me.EventDefinition(
    name="thing.changed",
    description="A watched thing changed.",
    input_schema={"type": "object", "properties": {"thing_id": {"type": "string"}},
                  "required": ["thing_id"], "additionalProperties": False},
    payload_schema={"type": "object", "properties": {"thing_id": {"type": "string"}, "text": {"type": "string"}},
                    "required": ["thing_id", "text"], "additionalProperties": False},
)


class Receiver:
    """Fake ChatGPT webhook endpoint."""

    def __init__(self):
        self.received = []          # (headers, body_dict, verified_with)
        self.script = []            # statuses to return for the next deliveries
        self.challenge_mode = "echo"
        self.secrets = [SECRET]
        rec = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                headers = {k.lower(): v for k, v in self.headers.items()}
                verified = []
                for s in rec.secrets:
                    try:
                        Webhook(s).verify(body, headers)
                        verified.append(s)
                    except WebhookVerificationError:
                        pass
                data = json.loads(body)
                rec.received.append((headers, data, verified))
                if not verified:
                    return self._reply(401, {})
                if data.get("type") == "verification":
                    if rec.challenge_mode == "echo":
                        return self._reply(200, {"challenge": data["challenge"]})
                    if rec.challenge_mode == "wrong":
                        return self._reply(200, {"challenge": "nope"})
                    return self._reply(500, {})
                status = rec.script.pop(0) if rec.script else 200
                return self._reply(status, {})

            def _reply(self, status, obj):
                out = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp-events/cb_1"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def events(self):
        return [r for r in self.received if r[1].get("type") != "verification"]

    def challenges(self):
        return [r for r in self.received if r[1].get("type") == "verification"]


class Clock:
    def __init__(self):
        self.t = 1_790_000_000.0

    def __call__(self):
        return self.t


def make(receiver=None, clock=None):
    d = tempfile.mkdtemp()
    ev = me.McpEvents(server=None, store=os.path.join(d, "ev.sqlite3"), definitions=[DEF],
                      http=me.SafeHttp(allow_insecure_for_tests=True), clock=clock or time.time)
    return ev


def sub_params(url, thing="a1", secret=SECRET, **extra):
    return {"name": "thing.changed", "arguments": {"thing_id": thing},
            "delivery": {"mode": "webhook", "url": url, "secret": secret}, "cursor": None, **extra}


class SubscribeTests(unittest.TestCase):
    def setUp(self):
        self.rx = Receiver()
        self.ev = make()

    def tearDown(self):
        self.rx.httpd.shutdown()
        self.rx.httpd.server_close()

    def test_list_events_wire_format(self):
        out = self.ev.list_events("p", {})
        self.assertEqual(out["events"][0]["name"], "thing.changed")
        self.assertEqual(out["events"][0]["delivery"], ["webhook"])
        self.assertIn("inputSchema", out["events"][0])
        self.assertIn("payloadSchema", out["events"][0])

    def test_subscribe_verifies_callback_with_signed_single_use_challenge(self):
        out = self.ev.subscribe("p", sub_params(self.rx.url))
        self.assertTrue(out["id"].startswith("sub_"))
        self.assertIsNotNone(out["refreshBefore"])
        self.assertIsNone(out["cursor"])
        self.assertFalse(out["truncated"])
        (headers, body, verified), = self.rx.challenges()
        self.assertEqual(verified, [SECRET])                       # official verifier accepted it
        self.assertTrue(headers["webhook-id"].startswith("msg_verification_"))
        self.assertEqual(headers["x-mcp-subscription-id"], out["id"])
        self.assertGreaterEqual(len(body["challenge"]), 32)
        self.assertEqual(len(self.ev.active_subscriptions()), 1)

    def test_subscribe_is_idempotent_and_key_order_proof(self):
        a = self.ev.subscribe("p", sub_params(self.rx.url))
        p2 = sub_params(self.rx.url)
        p2["arguments"] = dict(reversed(list(p2["arguments"].items())))
        b = self.ev.subscribe("p", p2)
        self.assertEqual(a["id"], b["id"])
        self.assertEqual(len(self.ev.active_subscriptions()), 1)
        self.assertEqual(len(self.rx.challenges()), 1)              # cached verification, no second challenge

    def test_different_principal_url_or_args_get_different_ids(self):
        ids = {self.ev.subscription_id("p", self.rx.url, "thing.changed", {"thing_id": "a"}),
               self.ev.subscription_id("q", self.rx.url, "thing.changed", {"thing_id": "a"}),
               self.ev.subscription_id("p", self.rx.url + "x", "thing.changed", {"thing_id": "a"}),
               self.ev.subscription_id("p", self.rx.url, "thing.changed", {"thing_id": "b"})}
        self.assertEqual(len(ids), 4)

    def test_failed_challenge_is_rejected_and_nothing_stored(self):
        for mode in ("wrong", "error"):
            with self.subTest(mode):
                self.rx.challenge_mode = mode
                ev = make()
                with self.assertRaises(me.CallbackError) as raised:
                    ev.subscribe("p", sub_params(self.rx.url))
                self.assertEqual(raised.exception.reason, "challenge_failed")
                self.assertEqual(ev.active_subscriptions(), [])

    def test_bad_inputs_rejected_before_any_callback(self):
        bad = [
            sub_params(self.rx.url, secret="not-a-secret"),
            sub_params(self.rx.url, secret="whsec_" + base64.b64encode(b"short").decode()),
            sub_params(self.rx.url, secret="whsec_" + base64.b64encode(b"x" * 65).decode()),
            {**sub_params(self.rx.url), "name": "nope"},
            {**sub_params(self.rx.url), "arguments": {"thing_id": 5}},
            {**sub_params(self.rx.url), "arguments": {"thing_id": "a", "extra": 1}},
            {**sub_params(self.rx.url), "delivery": {"mode": "poll", "url": self.rx.url, "secret": SECRET}},
        ]
        for p in bad:
            with self.subTest(p):
                with self.assertRaises(me._InvalidParams):
                    self.ev.subscribe("p", p)
        self.assertEqual(self.rx.received, [])

    def test_unsubscribe_is_idempotent(self):
        self.ev.subscribe("p", sub_params(self.rx.url))
        p = sub_params(self.rx.url)
        del p["delivery"]["secret"]
        self.assertEqual(self.ev.unsubscribe("p", p), {})
        self.assertEqual(self.ev.unsubscribe("p", p), {})
        self.assertEqual(self.ev.active_subscriptions(), [])

    def test_other_principal_cannot_unsubscribe(self):
        self.ev.subscribe("p", sub_params(self.rx.url))
        p = sub_params(self.rx.url)
        self.ev.unsubscribe("someone-else", p)
        self.assertEqual(len(self.ev.active_subscriptions()), 1)


class SafetyTests(unittest.TestCase):
    def test_https_only_and_public_addresses_only(self):
        http = me.SafeHttp()
        for url, reason in [("http://example.com/x", "insecure_url"), ("ftp://example.com", "insecure_url"),
                            ("https://user:pw@example.com/x", "invalid_url")]:
            with self.subTest(url):
                with self.assertRaises(me.CallbackError) as r:
                    http.check_url(url)
                self.assertEqual(r.exception.reason, reason)
        for host in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "localhost", "::1"):
            with self.subTest(host):
                with self.assertRaises(me.CallbackError) as r:
                    http._public_address(host, 443)
                self.assertEqual(r.exception.reason, "blocked_address")

    def test_redirects_are_not_followed(self):
        class R(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), R)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        status, _ = me.SafeHttp(allow_insecure_for_tests=True).post(
            f"http://127.0.0.1:{httpd.server_address[1]}/", b"{}", {})
        httpd.shutdown()
        httpd.server_close()
        self.assertEqual(status, 302)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.rx = Receiver()
        self.clock = Clock()
        self.ev = make(clock=self.clock)
        self.sub = self.ev.subscribe("p", sub_params(self.rx.url, thing="a1"))
        self.ev.subscribe("p", sub_params(self.rx.url + "/other", thing="b2"))

    def tearDown(self):
        self.rx.httpd.shutdown()
        self.rx.httpd.server_close()

    def test_publish_only_reaches_matching_subscriptions_signed(self):
        self.assertEqual(self.ev.publish("thing.changed", {"thing_id": "a1", "text": "hello"}), 1)
        self.assertEqual(self.ev.deliver_pending(), {"delivered": 1, "retrying": 0, "failed": 0})
        (headers, body, verified), = self.rx.events()
        self.assertEqual(verified, [SECRET])
        self.assertEqual(headers["webhook-id"], body["eventId"])
        self.assertEqual(headers["x-mcp-subscription-id"], self.sub["id"])
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(body["name"], "thing.changed")
        self.assertEqual(body["data"], {"thing_id": "a1", "text": "hello"})
        self.assertTrue(body["timestamp"].endswith("Z"))
        self.assertIsNone(body["cursor"])
        self.assertNotIn("type", body)
        self.assertEqual(self.ev.deliver_pending()["delivered"], 0)   # not sent twice

    def test_retries_keep_event_id_with_fresh_signature_and_back_off(self):
        self.rx.script = [500, 503]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"})
        self.assertEqual(self.ev.deliver_pending()["retrying"], 1)
        self.assertEqual(self.ev.deliver_pending()["retrying"], 0)    # not due yet: backing off
        self.clock.t += me.RETRY_DELAYS[0]
        self.assertEqual(self.ev.deliver_pending()["retrying"], 1)
        self.clock.t += me.RETRY_DELAYS[1]
        time.sleep(1.1)                                              # new real signing second
        self.assertEqual(self.ev.deliver_pending()["delivered"], 1)
        ids = {h["webhook-id"] for h, _, _ in self.rx.events()}
        sigs = {h["webhook-signature"] for h, _, _ in self.rx.events()}
        self.assertEqual(len(ids), 1)
        self.assertEqual(len(self.rx.events()), 3)
        self.assertGreater(len(sigs), 1)

    def test_gives_up_after_bounded_attempts(self):
        self.rx.script = [500] * 20
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"})
        results = []
        for _ in range(len(me.RETRY_DELAYS) + 2):
            results.append(self.ev.deliver_pending())
            self.clock.t += max(me.RETRY_DELAYS)
        self.assertEqual(sum(r["failed"] for r in results), 1)
        self.assertEqual(len(self.rx.events()), len(me.RETRY_DELAYS) + 1)

    def test_410_and_413_are_not_retried_and_410_drops_the_subscription(self):
        self.rx.script = [413]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"})
        self.assertEqual(self.ev.deliver_pending()["failed"], 1)
        self.rx.script = [410]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "y"})
        self.assertEqual(self.ev.deliver_pending()["failed"], 1)
        self.assertNotIn(self.sub["id"], [s["id"] for s in self.ev.active_subscriptions()])
        self.clock.t += max(me.RETRY_DELAYS)
        self.ev.deliver_pending()
        self.assertEqual(len(self.rx.events()), 2)

    def test_expired_subscriptions_get_nothing(self):
        self.clock.t += me.DEFAULT_TTL_MS / 1000 + 1
        self.assertEqual(self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"}), 0)

    def test_ttl_is_granted_within_bounds(self):
        out = self.ev.subscribe("p", sub_params(self.rx.url, thing="c3", ttlMs=1000))
        self.assertEqual(out["refreshBefore"], me.iso(self.clock.t + me.MIN_TTL_MS / 1000))
        out = self.ev.subscribe("p", sub_params(self.rx.url, thing="c3", ttlMs=None))
        self.assertIsNotNone(out["refreshBefore"])                  # never grant "forever"

    def test_secret_rotation_signs_with_both_keys(self):
        self.ev.subscribe("p", sub_params(self.rx.url, thing="a1", secret=SECRET2))
        self.rx.secrets = [SECRET, SECRET2]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"})
        self.ev.deliver_pending()
        headers, _, verified = self.rx.events()[-1]
        self.assertEqual(sorted(verified), sorted([SECRET, SECRET2]))
        self.assertEqual(len(headers["webhook-signature"].split(" ")), 2)
        self.clock.t += me.ROTATION_WINDOW_SECONDS + 1
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "later"})
        self.ev.deliver_pending()
        self.assertEqual(self.rx.events()[-1][2], [SECRET2])

    def test_payload_must_match_schema_and_size(self):
        with self.assertRaises(Exception):
            self.ev.publish("thing.changed", {"thing_id": "a1"})
        with self.assertRaises(ValueError):
            self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x" * (me.MAX_BODY + 1)})

    def test_unsubscribe_cancels_pending_deliveries(self):
        self.rx.script = [500]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "x"})
        self.ev.deliver_pending()
        p = sub_params(self.rx.url, thing="a1")
        self.ev.unsubscribe("p", p)
        self.clock.t += max(me.RETRY_DELAYS)
        self.ev.deliver_pending()
        self.assertEqual(len(self.rx.events()), 1)

    def test_resubscribing_does_not_resurrect_old_queued_events(self):
        self.rx.script = [500]
        self.ev.publish("thing.changed", {"thing_id": "a1", "text": "old news"})
        self.ev.deliver_pending()
        self.ev.unsubscribe("p", sub_params(self.rx.url, thing="a1"))
        self.ev.subscribe("p", sub_params(self.rx.url, thing="a1"))
        self.clock.t += max(me.RETRY_DELAYS)
        self.ev.deliver_pending()
        texts = [b["data"]["text"] for _, b, _ in self.rx.events()]
        self.assertEqual(texts, ["old news"])            # only the first, failed attempt; never re-sent

    def test_expired_subscriptions_are_deleted_with_their_address(self):
        import sqlite3
        self.clock.t += me.DEFAULT_TTL_MS / 1000 + me.VERIFY_CACHE_SECONDS + 1
        self.ev.deliver_pending()
        with sqlite3.connect(self.ev.store) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM subscriptions").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM verified_callbacks").fetchone()[0], 0)

    def test_survives_restart(self):
        again = me.McpEvents(server=None, store=self.ev.store, definitions=[DEF],
                             http=me.SafeHttp(allow_insecure_for_tests=True), clock=self.clock)
        self.assertEqual(len(again.active_subscriptions()), 2)
        again.publish("thing.changed", {"thing_id": "a1", "text": "after restart"})
        self.assertEqual(again.deliver_pending()["delivered"], 1)


class SdkWiringTests(unittest.TestCase):
    """The real official SDK over HTTP, the way ChatGPT talks to it."""

    @classmethod
    def setUpClass(cls):
        import uvicorn
        from mcp.server import MCPServer
        cls.rx = Receiver()
        mcp = MCPServer("wiring-test")

        @mcp.tool(description="noop")
        def noop() -> str:
            return "ok"

        cls.ev = me.McpEvents(mcp, store=os.path.join(tempfile.mkdtemp(), "e.sqlite3"), definitions=[DEF],
                              http=me.SafeHttp(allow_insecure_for_tests=True))
        cls.ev.install()
        app = mcp.streamable_http_app(stateless_http=True, json_response=True)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            cls.port = s.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_config=None))
        threading.Thread(target=cls.server.run, daemon=True).start()
        while not cls.server.started:
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.rx.httpd.shutdown()

    def rpc(self, method, params):
        meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "t", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {}}
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": {**params, "_meta": meta}}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/mcp", data=body, headers={
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    def test_discover_advertises_events_and_keeps_tools(self):
        caps = self.rpc("server/discover", {})["result"]["capabilities"]
        self.assertEqual(caps["events"], {})
        self.assertIn("tools", caps)

    def test_events_methods_over_http(self):
        listed = self.rpc("events/list", {})["result"]["events"]
        self.assertEqual(listed[0]["name"], "thing.changed")
        sub = self.rpc("events/subscribe", sub_params(self.rx.url))["result"]
        self.assertTrue(sub["id"].startswith("sub_"))
        self.assertEqual(self.rpc("events/unsubscribe", sub_params(self.rx.url))["result"].get("resultType"),
                         "complete")

    def test_callback_failure_is_json_rpc_32015_with_reason(self):
        self.rx.challenge_mode = "wrong"
        try:
            err = self.rpc("events/subscribe", sub_params(self.rx.url, thing="zz"))["error"]
        finally:
            self.rx.challenge_mode = "echo"
        self.assertEqual(err["code"], -32015)   # the number ChatGPT expects, not our own constant
        self.assertEqual(err["data"]["reason"], "challenge_failed")

    def test_invalid_params_over_http(self):
        err = self.rpc("events/subscribe", {**sub_params(self.rx.url), "name": "nope"})["error"]
        self.assertEqual(err["code"], -32602)


if __name__ == "__main__":
    unittest.main()
