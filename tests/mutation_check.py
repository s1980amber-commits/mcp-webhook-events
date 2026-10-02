"""Breaks mcp_webhook_events one way at a time and expects the test suite to FAIL each time.
Restores the file after every break. Exit 1 if any break slips through.

Run: python tests/mutation_check.py
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "mcp_webhook_events" / "__init__.py"

BREAKS = [
    ("callback never verified",
     "            self._verify_callback(sub_id, url, secret)\n", "            pass\n"),
    ("any challenge reply accepted",
     "if not isinstance(echoed, str) or not hmac.compare_digest(echoed, challenge):",
     "if False:"),
    ("subscription id ignores arguments",
     "canonical([principal, url, name, args])", "canonical([principal, url, name])"),
    ("subscription id ignores principal",
     "canonical([principal, url, name, args])", "canonical([url, name, args])"),
    ("signed body differs from sent body",
     'status, _ = self.http.post(row["url"], body.encode(), headers)',
     'status, _ = self.http.post(row["url"], (body + " ").encode(), headers)'),
    ("webhook-id differs from eventId",
     '"webhook-id": row["event_id"],', '"webhook-id": "msg_" + row["event_id"],'),
    ("no subscription id header",
     '"X-MCP-Subscription-Id": row["subscription_id"]}', '}'),
    ("410 and 413 retried",
     "final = status in (410, 413) or attempts > len(RETRY_DELAYS)",
     "final = attempts > len(RETRY_DELAYS)"),
    ("410 keeps the subscription",
     '                    db.execute("DELETE FROM subscriptions WHERE id=?", (row["subscription_id"],))\n',
     '                    pass\n'),
    ("no backoff",
     "now + (0 if final else RETRY_DELAYS[attempts - 1])", "now"),
    ("retries forever",
     "final = status in (410, 413) or attempts > len(RETRY_DELAYS)",
     "final = status in (410, 413)"),
    ("filters ignored",
     "                if not match(json.loads(s[\"arguments\"]), data):\n",
     "                if False:\n"),
    ("expiry ignored",
     "                if s[\"expires_at\"] and s[\"expires_at\"] <= now:\n",
     "                if False:\n"),
    ("no dual signing during rotation",
     'sig += " " + Webhook(row["old_secret"]).sign(row["event_id"], signed_at, body)', 'pass'),
    ("private addresses allowed",
     "if self.allow_insecure or ip.is_global:", "if True:"),
    ("plain http allowed",
     'if u.scheme != "https" and not (self.allow_insecure and u.scheme == "http"):',
     'if u.scheme not in ("https", "http"):'),
    ("events capability not advertised",
     'result.setdefault("capabilities", {})["events"] = {}', 'pass'),
    ("wrong error code for callback failure",
     "CALLBACK_ENDPOINT_ERROR = -32015", "CALLBACK_ENDPOINT_ERROR = -32000"),
    ("secret length not checked",
     "return 24 <= len(raw) <= 64", "return True"),
    ("verification never cached",
     "return bool(row) and self.clock() - row[\"verified_at\"] < VERIFY_CACHE_SECONDS", "return False"),
    ("unsubscribe leaves pending deliveries",
     "db.execute(\"UPDATE outbox SET status='cancelled' WHERE subscription_id=? AND status='pending'\", (sub_id,))",
     "pass"),
    ("expired subscriptions never purged",
     "        self.purge(now)\n", ""),
    ("no size limit",
     "if len(body.encode()) > MAX_BODY:", "if False:"),
    ("payload not validated",
     "        jsonschema.validate(data, d.payload_schema)\n", ""),
    ("forever subscriptions granted",
     "            ttl = self.default_ttl_ms\n        elif requested == \"omitted\":",
     "            return None\n        elif requested == \"omitted\":"),
]


def passes():
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT,
                       capture_output=True, text=True, timeout=600)
    return r.returncode == 0


def main():
    if not passes():
        sys.exit("The untouched code already fails its tests.")
    original = TARGET.read_text(encoding="utf-8")
    missed = []
    for label, old, new in BREAKS:
        if original.count(old) != 1:
            sys.exit(f"Can't apply '{label}': text not found exactly once.")
        try:
            TARGET.write_text(original.replace(old, new), encoding="utf-8")
            caught = not passes()
        finally:
            TARGET.write_text(original, encoding="utf-8")
        print(("CAUGHT  " if caught else "MISSED  ") + label, flush=True)
        if not caught:
            missed.append(label)
    if missed:
        sys.exit(f"{len(missed)} break(s) slipped through.")
    print(f"All {len(BREAKS)} deliberate breaks were caught.")


if __name__ == "__main__":
    main()
