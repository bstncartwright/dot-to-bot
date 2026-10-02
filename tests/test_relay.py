import base64
import hashlib
import hmac
import http.client
import json
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient
from relay.bend_policy import BendPolicy
from relay.core import CallbackTransport, MAX_ATTEMPTS, Policy, Relay, RelayError, canonical, signed_headers, signing_key
from relay.server import create_app

ROOT = Path(__file__).resolve().parents[1]
SECRET = "whsec_" + base64.b64encode(b"local-test-key-only-32-bytes!!!!!!").decode()


class Receiver:
    def __init__(self):
        self.requests, self.events, self.seen = [], [], set()
        self.status, self.bad_challenge, self.callback = 200, False, None
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                headers = dict(self.headers)
                event = json.loads(body)
                expected = signed_headers(headers["webhook-id"], body, owner.secret, headers["X-MCP-Subscription-Id"], now=int(headers["webhook-timestamp"]))["webhook-signature"]
                if expected.split()[0] not in headers["webhook-signature"].split():
                    self.send_error(401)
                    return
                owner.requests.append((event, headers, body))
                if event.get("type") == "verification":
                    data = {"challenge": "wrong" if owner.bad_challenge else event["challenge"]}
                    status = 200
                else:
                    status, data = owner.status, {}
                    if 200 <= status < 300 and event["eventId"] not in owner.seen:
                        owner.seen.add(event["eventId"])
                        owner.events.append(event)
                        if owner.callback:
                            owner.callback(event)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())
            def log_message(self, *_):
                pass
        self.secret = SECRET
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/callback?mock=yes"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config = Path(self.temp.name) / "config.json"
        self.agents = {a: {"token_sha256": hashlib.sha256((a + "-test-token").encode()).hexdigest(), "send_to": [b for b in ("fred", "bean") if b != a]} for a in ("fred", "bean", "outsider")}
        self.agents["outsider"]["send_to"] = []
        self.save_config()
        self.admission = BendPolicy(ROOT / "bend/policy")
        self.policy = Policy(self.config, self.admission)
        self.receivers = [Receiver(), Receiver()]
        self.now = 1800000000.0
        self.db_path = Path(self.temp.name) / "relay.sqlite"
        self.transport = CallbackTransport([r.url for r in self.receivers])
        self.relay = Relay(self.db_path, self.policy, self.transport, lambda: self.now)
        self.client = TestClient(create_app(self.relay, start_worker=False), base_url="http://127.0.0.1:8080")
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.relay.close()
        for r in self.receivers:
            r.close()
        self.temp.cleanup()

    def save_config(self):
        self.config.write_text(json.dumps({"agents": self.agents}))

    def rpc(self, agent, method, params=None, headers=None):
        payload = dict(params or {})
        payload["_meta"] = {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}, "io.modelcontextprotocol/clientInfo": {"name": "mock-" + agent, "version": "1"}}
        hs = {"Authorization": "Bearer " + agent + "-test-token", "Accept": "application/json", "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
        if method == "tools/call":
            hs["Mcp-Name"] = params["name"]
        hs.update(headers or {})
        envelope = {"jsonrpc": "2.0", "id": 1, "method": method, "params": payload}
        if hasattr(self, "live_port"):
            connection = http.client.HTTPConnection("127.0.0.1", self.live_port, timeout=5)
            try:
                connection.request("POST", "/mcp", json.dumps(envelope), {**hs, "Content-Type": "application/json"})
                return json.loads(connection.getresponse().read())
            finally:
                connection.close()
        response = self.client.post("/mcp", json=envelope, headers=hs)
        return response.json()

    def subscribe(self, agent="bean", receiver=0, **extra):
        args = {"name": "message.created", "arguments": {"recipient": agent}, "delivery": {"mode": "webhook", "url": self.receivers[receiver].url, "secret": self.receivers[receiver].secret}, **extra}
        return self.rpc(agent, "events/subscribe", args)

    def send(self, sender="fred", recipient="bean", key="one", reply=None):
        args = {"recipient": recipient, "body": "harmless mock hello", "idempotency_key": key}
        if reply:
            args["reply_to"] = reply
        return self.rpc(sender, "tools/call", {"name": "send_message", "arguments": args})

    def test_mcp2_mock_round_trip_signed_events(self):
        self.assertEqual(self.rpc("fred", "server/discover")["result"]["supportedVersions"], ["2026-07-28"])
        self.assertIn("events", self.rpc("fred", "server/discover")["result"]["capabilities"])
        event = self.rpc("bean", "events/list")["result"]["events"][0]
        self.assertEqual(event["delivery"], ["webhook"])
        self.assertEqual(event["inputSchema"]["properties"]["recipient"]["const"], "bean")
        self.assertEqual(len(self.rpc("fred", "tools/list")["result"]["tools"]), 2)
        bean_sub = self.subscribe()["result"]["id"]
        self.subscribe("fred", 1)["result"]
        first = self.send()["result"]["structuredContent"]
        self.assertTrue(self.relay.deliver_one())
        got = self.receivers[0].events[0]
        self.assertEqual(got["data"]["id"], first["id"])
        self.assertEqual(self.receivers[0].requests[-1][1]["X-MCP-Subscription-Id"], bean_sub)
        reply = self.send("bean", "fred", "reply", first["id"])["result"]["structuredContent"]
        self.assertEqual(reply["correlation_id"], first["correlation_id"])
        self.assertEqual(reply["hop"], 1)
        self.relay.deliver_one()
        self.assertEqual(self.receivers[1].events[0]["data"]["id"], reply["id"])
        read = self.rpc("fred", "tools/call", {"name": "read_messages", "arguments": {}})["result"]["structuredContent"]
        self.assertEqual([m["id"] for m in read["messages"]], [reply["id"]])

    def test_auth_isolation_and_injection(self):
        self.assertEqual(self.rpc("fred", "events/list", headers={"Authorization": "Bearer bad"}), {"error": "Unauthorized"})
        sent = self.send()["result"]["structuredContent"]
        denied = self.rpc("outsider", "tools/call", {"name": "read_messages", "arguments": {"message_id": sent["id"]}})
        self.assertEqual(denied["error"]["code"], -32012)
        self.assertIn("error", self.send("outsider", "bean"))
        self.assertIn("error", self.rpc("fred", "events/subscribe", {"name": "message.created", "arguments": {"recipient": "bean"}, "delivery": {"mode": "webhook", "url": self.receivers[0].url, "secret": SECRET}}))
        self.assertIn("error", self.rpc("fred", "tools/call", {"name": "send_message", "arguments": {"sender": "bean", "recipient": "bean", "body": "x", "idempotency_key": "forged"}}))
        self.assertEqual(self.rpc("fred", "server/discover", headers={"MCP-Protocol-Version": "2025-11-25"})["error"], "MCP-Protocol-Version: 2026-07-28 required")
        self.assertIn("error", self.rpc("fred", "tools/list", headers={"Mcp-Method": "events/list"}))

    def test_duplicate_retry_and_restart(self):
        self.subscribe()["result"]
        first = self.send()["result"]["structuredContent"]
        self.assertEqual(self.send()["result"]["structuredContent"], first)
        self.assertIn("error", self.rpc("fred", "tools/call", {"name": "send_message", "arguments": {"recipient": "bean", "body": "changed", "idempotency_key": "one"}}))
        self.receivers[0].status = 503
        self.relay.deliver_one()
        self.assertFalse(self.relay.deliver_one())
        self.relay.close()
        self.relay = Relay(self.db_path, self.policy, self.transport, lambda: self.now)
        self.now += 5
        self.receivers[0].status = 200
        self.relay.deliver_one()
        attempts = [r for r in self.receivers[0].requests if r[0].get("eventId")]
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0][2], attempts[1][2])
        self.assertEqual(attempts[0][1]["webhook-id"], attempts[1][1]["webhook-id"])
        self.assertNotEqual(attempts[0][1]["webhook-timestamp"], attempts[1][1]["webhook-timestamp"])
        self.assertEqual(self.relay.read("bean", {})["messages"][0]["id"], first["id"])
        self.assertEqual(self.relay.db.execute("SELECT state FROM deliveries").fetchone()[0], "delivered")

    def test_reply_loop_and_branch_limits(self):
        message = self.send()["result"]["structuredContent"]
        for hop in range(1, 7):
            message = self.send(message["recipient"], message["sender"], str(hop), message["id"])["result"]["structuredContent"]
            self.assertEqual(message["hop"], hop)
        self.assertIn("error", self.send(message["recipient"], message["sender"], "seven", message["id"]))
        root = self.send(key="second")["result"]["structuredContent"]
        self.send("bean", "fred", "r1", root["id"])["result"]
        self.assertIn("error", self.send("bean", "fred", "r2", root["id"]))
        self.assertIn("error", self.send("outsider", "fred", "spoof", root["id"]))

    def test_subscription_idempotence_rotation_and_unsubscribe(self):
        one = self.subscribe()["result"]
        self.assertEqual(self.subscribe()["result"]["id"], one["id"])
        self.assertEqual(len(self.receivers[0].requests), 1)
        old = self.receivers[0].secret
        self.receivers[0].secret = "whsec_" + base64.b64encode(b"replacement-local-test-secret!!!!").decode()
        self.subscribe()["result"]
        self.send()["result"]
        self.relay.deliver_one()
        headers, body = self.receivers[0].requests[-1][1:]
        old_sig = signed_headers(headers["webhook-id"], body, old, one["id"], now=int(headers["webhook-timestamp"]))["webhook-signature"]
        self.assertIn(old_sig, headers["webhook-signature"])
        self.send(key="pending")["result"]
        args = {"name": "message.created", "arguments": {"recipient": "bean"}, "delivery": {"mode": "webhook", "url": self.receivers[0].url}}
        self.rpc("bean", "events/unsubscribe", args)["result"]
        self.rpc("bean", "events/unsubscribe", args)["result"]
        self.assertFalse(self.relay.deliver_one())
        self.assertEqual(self.relay.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)

    def test_failed_challenge_secret_and_callback_protection(self):
        self.receivers[0].bad_challenge = True
        error = self.subscribe()["error"]
        self.assertEqual(error["code"], -32015)
        self.assertEqual(error["data"]["reason"], "challenge_failed")
        self.assertEqual(self.relay.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 0)
        for bad in ("abc", "whsec_bad", "whsec_" + base64.b64encode(b"short").decode()):
            with self.assertRaises(RelayError):
                signing_key(bad)
        transport = CallbackTransport()
        for url in ("http://example.com", "https://127.0.0.1/x", "https://[::1]/", "https://user:pass@example.com/", "https://169.254.169.254/", "https://10.0.0.1/"):
            with self.assertRaises(RelayError):
                transport.destination(url)
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with patch("socket.getaddrinfo", side_effect=[public, private]):
            transport.destination("https://callback.example")
            with self.assertRaises(RelayError):
                transport.destination("https://callback.example")

    def test_expiry_revocation_and_permanent_failures(self):
        self.subscribe(ttlMs=1000)["result"]
        self.send()["result"]
        self.now += 2
        self.relay.deliver_one()
        self.assertEqual(len(self.receivers[0].events), 0)
        self.subscribe()["result"]
        self.send(key="revoked")["result"]
        self.agents["fred"]["send_to"] = []
        self.save_config()
        self.relay.deliver_one()
        self.assertEqual(len(self.receivers[0].events), 0)
        self.agents["fred"]["send_to"] = ["bean"]
        self.save_config()
        for status in (410, 413, 302):
            self.subscribe()["result"]
            self.send(key=str(status))["result"]
            self.receivers[0].status = status
            self.relay.deliver_one()
            self.now += 1000
            self.assertFalse(self.relay.deliver_one())
            self.assertEqual(self.relay.db.execute("SELECT state FROM deliveries WHERE last_status=?", (status,)).fetchone()[0], "dead")

    def test_bounded_retries_crash_lease_and_concurrent_dedup(self):
        self.subscribe()["result"]
        args = {"recipient": "bean", "body": "mock", "idempotency_key": "race"}
        with ThreadPoolExecutor(max_workers=4) as pool:
            rows = list(pool.map(lambda _: self.relay.send("fred", args), range(8)))
        self.assertEqual(len({r["id"] for r in rows}), 1)
        self.receivers[0].status = 503
        for _ in range(MAX_ATTEMPTS):
            self.relay.deliver_one()
            self.now += 400
        self.assertFalse(self.relay.deliver_one())
        self.assertEqual(self.relay.db.execute("SELECT attempts,state FROM deliveries").fetchone()[:], (MAX_ATTEMPTS, "dead"))
        self.relay.send("fred", {**args, "idempotency_key": "crash"})
        with self.relay.db:
            self.relay.db.execute("UPDATE deliveries SET state='sending',attempts=1,lease_until=? WHERE state='pending'", (self.now + 30,))
        self.assertFalse(self.relay.deliver_one())
        self.now += 31
        self.receivers[0].status = 200
        self.relay.deliver_one()
        self.assertEqual(len(self.receivers[0].events), 1)

    def test_live_loopback_mcp_http(self):
        import uvicorn
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        self.live_port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(create_app(self.relay), host="127.0.0.1", port=self.live_port, log_level="critical", access_log=False))
        thread = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(server.started)
            self.assertIn("events", self.rpc("fred", "server/discover")["result"]["capabilities"])
            bean_ready, fred_ready = threading.Event(), threading.Event()
            self.receivers[0].callback = lambda _: bean_ready.set()
            self.receivers[1].callback = lambda _: fred_ready.set()
            self.subscribe()["result"]
            self.subscribe("fred", 1)["result"]
            request = self.send(key="live-request")["result"]["structuredContent"]
            self.assertTrue(bean_ready.wait(3))
            reply = self.send("bean", "fred", "live-reply", request["id"])["result"]["structuredContent"]
            self.assertTrue(fred_ready.wait(3))
            self.assertEqual(reply["correlation_id"], request["correlation_id"])
            messages = self.rpc("fred", "tools/call", {"name": "read_messages", "arguments": {}})["result"]["structuredContent"]["messages"]
            self.assertEqual(messages[0]["id"], reply["id"])
        finally:
            del self.live_port
            server.should_exit = True
            thread.join(5)
            listener.close()
            self.assertFalse(thread.is_alive())

    def test_worker_delivers_and_receiver_deduplicates(self):
        delivered = threading.Event()
        self.receivers[0].callback = lambda event: delivered.set()
        self.client.__exit__(None, None, None)
        self.client = TestClient(create_app(self.relay), base_url="http://127.0.0.1:8080")
        self.client.__enter__()
        self.subscribe()["result"]
        self.send()["result"]
        self.assertTrue(delivered.wait(3))
        event, headers, body = self.receivers[0].requests[-1]
        self.transport.post(self.receivers[0].url, body, signed_headers(event["eventId"], body, SECRET, headers["X-MCP-Subscription-Id"], now=self.now + 1))
        self.assertEqual(len(self.receivers[0].events), 1)

    def test_rate_bound_read_pagination_and_null_ttl(self):
        self.subscribe(ttlMs=None)["result"]
        self.assertIn("error", self.subscribe(cursor="unsupported-replay"))
        for i in range(60):
            self.relay.send("fred", {"recipient": "bean", "body": "mock", "idempotency_key": str(i)})
        with self.assertRaises(RelayError):
            self.relay.send("fred", {"recipient": "bean", "body": "mock", "idempotency_key": "61"})
        page = self.relay.read("bean", {"limit": 10})
        self.assertEqual(len(page["messages"]), 10)
        rest = self.relay.read("bean", {"after": page["next_after"], "limit": 100})
        self.assertEqual(len(rest["messages"]), 50)
        self.assertEqual(self.relay.read("outsider", {})["messages"], [])
        self.agents["bean"]["enabled"] = False
        self.save_config()
        self.assertEqual(self.rpc("bean", "events/list"), {"error": "Unauthorized"})

    def test_callback_pins_ip_preserves_tls_name_and_query(self):
        transport = CallbackTransport()
        public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        raw, conn, tls = MagicMock(), MagicMock(), MagicMock()
        conn.getresponse.return_value.status = 302
        conn.getresponse.return_value.read.return_value = b"redirect"
        with patch("socket.getaddrinfo", return_value=public) as dns, patch("socket.socket", return_value=raw), patch("http.client.HTTPConnection", return_value=conn), patch("ssl.create_default_context", return_value=tls):
            self.assertEqual(transport.post("https://callback.example/path?x=1", b"{}", {}), (302, b"redirect"))
            raw.connect.assert_called_once_with(("93.184.216.34", 443))
            tls.wrap_socket.assert_called_once_with(raw, server_hostname="callback.example")
            conn.request.assert_called_once_with("POST", "/path?x=1", b"{}", {})
            self.assertEqual(dns.call_count, 1)

    def test_bend_gate_and_signing_vector(self):
        for hop in range(10):
            self.assertEqual(self.admission.admit(True, hop), hop <= 6)
            self.assertFalse(self.admission.admit(False, hop))
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("bend", 2)):
            self.assertFalse(self.admission.admit(True, 0))
        # Independent Standard Webhooks known-material construction.
        body = b'{"hello":"mock"}'
        key = base64.b64decode(SECRET[6:])
        expected = "v1," + base64.b64encode(hmac.new(key, b"evt_test.123." + body, hashlib.sha256).digest()).decode()
        self.assertEqual(signed_headers("evt_test", body, SECRET, "sub_test", now=123)["webhook-signature"], expected)


if __name__ == "__main__":
    unittest.main()
