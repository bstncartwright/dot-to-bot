"""Persistent, scoped messaging and a transactional webhook outbox."""
import base64
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
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

MAX_MESSAGES = 8
MAX_ATTEMPTS = 5


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


class RelayError(Exception):
    def __init__(self, message, code=-32602, reason=None):
        super().__init__(message)
        self.code, self.reason = code, reason


def signing_key(secret):
    try:
        if not isinstance(secret, str) or not secret.startswith("whsec_"):
            raise ValueError()
        key = base64.b64decode(secret[6:], validate=True)
        if not 24 <= len(key) <= 64:
            raise ValueError()
        return key
    except (ValueError, TypeError):
        raise RelayError("Signing secret must be whsec_ plus 24–64 base64 bytes") from None


def signed_headers(event_id, body, secret, subscription_id, old_secret=None, now=None):
    timestamp = str(int(time.time() if now is None else now))
    material = event_id.encode() + b"." + timestamp.encode() + b"." + body
    signatures = ["v1," + base64.b64encode(hmac.digest(signing_key(key), material, "sha256")).decode()
                  for key in [secret, old_secret] if key]
    return {"Content-Type": "application/json", "webhook-id": event_id,
            "webhook-timestamp": timestamp, "webhook-signature": " ".join(signatures),
            "X-MCP-Subscription-Id": subscription_id}


class CallbackTransport:
    """Resolve on every request, reject nonpublic addresses, and pin the socket.

    The ONLY HTTP exception is an exact explicitly injected loopback URL in tests.
    TLS keeps the original hostname for SNI and certificate validation. No proxies,
    redirects, ambient credentials or second DNS lookup are used.
    """
    def __init__(self, mock_urls=()):
        self.mock_urls = frozenset(mock_urls)
        for url in self.mock_urls:
            p = urlsplit(url)
            if p.scheme != "http" or p.hostname not in ("127.0.0.1", "::1"):
                raise ValueError("Mock URLs must be numeric loopback HTTP URLs")

    def destination(self, url):
        try:
            p = urlsplit(url)
            if p.username or p.password or p.fragment or not p.hostname or len(url) > 2048:
                raise ValueError()
            mock = url in self.mock_urls
            if p.scheme != "https" and not mock:
                raise ValueError()
            port = p.port or (443 if p.scheme == "https" else 80)
            addresses = socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)
            if not addresses:
                raise ValueError()
            for _, _, _, _, address in addresses:
                ip = ipaddress.ip_address(address[0])
                if not mock and (not ip.is_global or ip.is_multicast or getattr(ip, "ipv4_mapped", None)):
                    raise ValueError()
            return p, addresses
        except (ValueError, OSError):
            raise RelayError("Callback destination rejected", -32015, "invalid_url") from None

    def post(self, url, body, headers):
        if len(body) > 262144:
            raise RelayError("Webhook too large")
        p, addresses = self.destination(url)
        family, socktype, proto, _, address = addresses[0]
        raw = socket.socket(family, socktype, proto)
        raw.settimeout(10)
        connection = http.client.HTTPConnection(p.hostname, p.port or (443 if p.scheme == "https" else 80), timeout=10)
        try:
            raw.connect(address)
            connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=p.hostname) if p.scheme == "https" else raw
            connection.request("POST", (p.path or "/") + ("?" + p.query if p.query else ""), body, headers)
            response = connection.getresponse()
            data = response.read(262145)
            if len(data) > 262144:
                raise RelayError("Callback response too large", -32015, "challenge_failed")
            return response.status, data
        finally:
            connection.close()
            raw.close()


class Policy:
    """Reload the operator-owned file for each auth/grant check; no self-grants."""
    def __init__(self, path, admission):
        self.path, self.admission = path, admission

    def agents(self):
        try:
            with open(self.path) as f:
                agents = json.load(f)["agents"]
            if not isinstance(agents, dict) or not agents:
                raise ValueError()
            hashes = set()
            for agent, record in agents.items():
                digest = record["token_sha256"]
                if not isinstance(agent, str) or not agent or len(agent) > 64 or len(digest) != 64 or digest in hashes:
                    raise ValueError()
                bytes.fromhex(digest)
                hashes.add(digest)
                if not isinstance(record.get("send_to", []), list):
                    raise ValueError()
            return agents
        except (OSError, ValueError, KeyError, TypeError):
            raise RelayError("Authorization unavailable", -32012) from None

    def authenticate(self, token):
        digest = hashlib.sha256(token.encode()).hexdigest()
        for agent, record in self.agents().items():
            if record.get("enabled", True) and hmac.compare_digest(record["token_sha256"], digest):
                return agent
        raise RelayError("Unauthorized", -32012)

    def active(self, agent):
        record = self.agents().get(agent)
        return bool(record and record.get("enabled", True))

    def authorize(self, sender, recipient):
        agents = self.agents()
        granted = self.active(sender) and self.active(recipient) and sender != recipient and recipient in agents[sender].get("send_to", [])
        if not self.admission.admit(granted, 0):
            raise RelayError("Recipient is outside this agent's grant", -32012)


class Relay:
    def __init__(self, db_path, policy, transport=None, clock=time.time):
        self.policy, self.transport, self.clock = policy, transport or CallbackTransport(), clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS messages(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, sender TEXT, recipient TEXT,
              body TEXT, correlation_id TEXT, reply_to TEXT, hop INTEGER, created REAL,
              request_key TEXT, fingerprint TEXT, UNIQUE(sender,request_key), UNIQUE(reply_to));
            CREATE INDEX IF NOT EXISTS inbox ON messages(recipient,seq);
            CREATE TABLE IF NOT EXISTS subscriptions(
              id TEXT PRIMARY KEY, owner TEXT, url TEXT, secret TEXT, old_secret TEXT,
              rotate_until REAL, expires REAL, active INTEGER, verified_until REAL);
            CREATE TABLE IF NOT EXISTS deliveries(
              subscription_id TEXT REFERENCES subscriptions(id), message_id TEXT REFERENCES messages(id),
              event_id TEXT UNIQUE, body TEXT, state TEXT, attempts INTEGER DEFAULT 0,
              due REAL, lease_until REAL DEFAULT 0, claim TEXT, last_status INTEGER,
              PRIMARY KEY(subscription_id,message_id));
        ''')
        self.db.commit()

    def close(self):
        self.db.close()

    def send(self, agent, args):
        allowed = {"recipient", "body", "idempotency_key", "reply_to"}
        if not isinstance(args, dict) or set(args) - allowed:
            raise RelayError("Unexpected send arguments")
        recipient, body, key = [args.get(x) for x in ("recipient", "body", "idempotency_key")]
        if not all(isinstance(x, str) for x in (recipient, body, key)) or not 1 <= len(key) <= 128 or not 1 <= len(body.encode()) <= 4096:
            raise RelayError("Body must be 1–4096 UTF-8 bytes; key 1–128 characters")
        reply = args.get("reply_to")
        if reply is not None and (not isinstance(reply, str) or len(reply) > 128):
            raise RelayError("Invalid reply_to")
        self.policy.authorize(agent, recipient)
        fingerprint = hashlib.sha256(canonical(args).encode()).hexdigest()
        now = self.clock()
        with self.lock, self.db:
            # IMMEDIATE serializes competing senders before checking chain limits.
            self.db.execute("BEGIN IMMEDIATE")
            existing = self.db.execute("SELECT * FROM messages WHERE sender=? AND request_key=?", (agent, key)).fetchone()
            if existing:
                if existing["fingerprint"] != fingerprint:
                    raise RelayError("Idempotency key reused with different arguments")
                return self.public(existing)
            recent = self.db.execute("SELECT count(*) FROM messages WHERE sender=? AND created>?", (agent, now - 3600)).fetchone()[0]
            if recent >= 60:
                raise RelayError("Agent hourly message limit reached")
            hop, correlation = 0, str(uuid.uuid4())
            if reply:
                parent = self.db.execute("SELECT * FROM messages WHERE id=? AND recipient=? AND sender=?", (reply, agent, recipient)).fetchone()
                if not parent:
                    raise RelayError("Reply target unavailable", -32012)
                hop, correlation = parent["hop"] + 1, parent["correlation_id"]
                count = self.db.execute("SELECT count(*) FROM messages WHERE correlation_id=?", (correlation,)).fetchone()[0]
                if not self.policy.admission.admit(True, hop) or count >= MAX_MESSAGES:
                    raise RelayError("Conversation loop limit reached")
                if self.db.execute("SELECT 1 FROM messages WHERE reply_to=?", (reply,)).fetchone():
                    raise RelayError("A reply already exists for this message")
            msg_id = "msg_" + uuid.uuid4().hex
            self.db.execute("INSERT INTO messages(id,sender,recipient,body,correlation_id,reply_to,hop,created,request_key,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (msg_id, agent, recipient, body, correlation, reply, hop, now, key, fingerprint))
            row = self.db.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
            event = {"eventId": "evt_" + msg_id[4:], "name": "message.created", "timestamp": iso(now), "data": self.public(row), "cursor": None}
            for sub in self.db.execute("SELECT * FROM subscriptions WHERE owner=? AND active=1 AND expires>?", (recipient, now)).fetchall():
                self.db.execute("INSERT INTO deliveries(subscription_id,message_id,event_id,body,state,due) VALUES(?,?,?,?,?,?)",
                                (sub["id"], msg_id, event["eventId"] + "_" + sub["id"][4:], canonical({**event, "eventId": event["eventId"] + "_" + sub["id"][4:]}), "pending", now))
            return self.public(row)

    @staticmethod
    def public(row):
        return {k: row[k] for k in ("seq", "id", "sender", "recipient", "body", "correlation_id", "reply_to", "hop")} | {"created_at": iso(row["created"])}

    def read(self, agent, args):
        if not self.policy.active(agent):
            raise RelayError("Unauthorized", -32012)
        if not isinstance(args, dict) or set(args) - {"message_id", "after", "limit"}:
            raise RelayError("Unexpected read arguments")
        with self.lock:
            if "message_id" in args:
                if set(args) != {"message_id"} or not isinstance(args["message_id"], str):
                    raise RelayError("Invalid read arguments")
                row = self.db.execute("SELECT * FROM messages WHERE id=? AND (recipient=? OR sender=?)", (args["message_id"], agent, agent)).fetchone()
                if not row:
                    raise RelayError("Message unavailable", -32012)
                return {"message": self.public(row)}
            after, limit = args.get("after", 0), args.get("limit", 50)
            if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 100:
                raise RelayError("Invalid read page")
            rows = self.db.execute("SELECT * FROM messages WHERE recipient=? AND seq>? ORDER BY seq LIMIT ?", (agent, after, limit)).fetchall()
            return {"messages": [self.public(r) for r in rows], "next_after": rows[-1]["seq"] if rows else after}

    def identity(self, agent, args):
        if args.get("name") != "message.created" or args.get("arguments") != {"recipient": agent}:
            raise RelayError("Event filter must match the authenticated agent", -32012)
        delivery = args.get("delivery", {})
        if not isinstance(delivery, dict) or delivery.get("mode") != "webhook" or not isinstance(delivery.get("url"), str):
            raise RelayError("Webhook delivery required")
        identity = canonical([agent, delivery["url"], args["name"], args["arguments"]])
        return "sub_" + hashlib.sha256(identity.encode()).hexdigest(), delivery

    def subscribe(self, agent, args):
        if set(args) - {"name", "arguments", "delivery", "cursor", "ttlMs"}:
            raise RelayError("Unexpected subscription arguments")
        if not self.policy.active(agent):
            raise RelayError("Unauthorized", -32012)
        sub_id, delivery = self.identity(agent, args)
        if set(delivery) != {"mode", "url", "secret"}:
            raise RelayError("Invalid delivery arguments")
        secret, url = delivery["secret"], delivery["url"]
        signing_key(secret)
        self.transport.destination(url)
        if args.get("cursor") is not None:
            raise RelayError("Protocol replay is unsupported; read_messages recovers missed messages")
        ttl = args.get("ttlMs", 86400000)
        if ttl is None:
            ttl = 86400000  # Decline infinite lifetimes explicitly with a finite grant.
        if type(ttl) is not int or ttl <= 0:
            raise RelayError("Invalid ttlMs")
        ttl = min(ttl, 86400000)
        now = self.clock()
        with self.lock:
            old = self.db.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            count = self.db.execute("SELECT count(*) FROM subscriptions WHERE owner=? AND active=1 AND expires>?", (agent, now)).fetchone()[0]
            if count >= 16 and not (old and old["active"] and old["expires"] > now):
                raise RelayError("Subscription limit reached")
            verified = bool(old and old["active"] and old["verified_until"] > now and old["secret"] == secret)
        if not verified:
            challenge = secrets.token_urlsafe(32)
            body = canonical({"type": "verification", "challenge": challenge}).encode()
            headers = signed_headers("verify_" + uuid.uuid4().hex, body, secret, sub_id, now=now)
            try:
                status, data = self.transport.post(url, body, headers)
                echo = json.loads(data).get("challenge", "")
                if not 200 <= status < 300 or not isinstance(echo, str) or not hmac.compare_digest(echo, challenge):
                    raise ValueError()
            except (TimeoutError, socket.timeout):
                raise RelayError("Callback verification timed out", -32015, "timeout") from None
            except (ValueError, AttributeError, OSError, http.client.HTTPException):
                raise RelayError("Callback verification failed", -32015, "challenge_failed") from None
        with self.lock, self.db:
            if not self.policy.active(agent):
                raise RelayError("Unauthorized", -32012)
            old = self.db.execute("SELECT * FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            count = self.db.execute("SELECT count(*) FROM subscriptions WHERE owner=? AND active=1 AND expires>?", (agent, now)).fetchone()[0]
            if count >= 16 and not (old and old["active"] and old["expires"] > now):
                raise RelayError("Subscription limit reached")
            previous = old["secret"] if old and old["secret"] != secret else (old["old_secret"] if old else None)
            rotation = now + 300 if old and old["secret"] != secret else (old["rotate_until"] if old else 0)
            self.db.execute("INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET secret=excluded.secret,old_secret=excluded.old_secret,rotate_until=excluded.rotate_until,expires=excluded.expires,active=1,verified_until=excluded.verified_until",
                            (sub_id, agent, url, secret, previous, rotation, now + ttl / 1000, 1, now + 300))
        return {"id": sub_id, "refreshBefore": iso(now + ttl / 1000), "cursor": None, "truncated": False}

    def unsubscribe(self, agent, args):
        if set(args) != {"name", "arguments", "delivery"} or set(args["delivery"]) != {"mode", "url"}:
            raise RelayError("Invalid unsubscribe arguments")
        sub_id, _ = self.identity(agent, args)
        with self.lock, self.db:
            self.db.execute("UPDATE subscriptions SET active=0 WHERE id=? AND owner=?", (sub_id, agent))
            self.db.execute("UPDATE deliveries SET state='cancelled' WHERE subscription_id=? AND state IN ('pending','sending')", (sub_id,))
        return {}

    def deliver_one(self):
        """At-least-once durable claim; crash retries after a 30 second lease."""
        now = self.clock()
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT d.*,s.owner,s.url,s.secret,s.old_secret,s.rotate_until,s.expires,s.active,m.sender,m.recipient FROM deliveries d JOIN subscriptions s ON s.id=d.subscription_id JOIN messages m ON m.id=d.message_id WHERE (d.state='pending' AND d.due<=?) OR (d.state='sending' AND d.lease_until<=?) ORDER BY d.due LIMIT 1", (now, now)).fetchone()
            if not row:
                return False
            try:
                self.policy.authorize(row["sender"], row["recipient"])
                allowed = row["active"] and row["expires"] > now
            except RelayError:
                allowed = False
            if not allowed or row["attempts"] >= MAX_ATTEMPTS:
                self.db.execute("UPDATE deliveries SET state=? WHERE subscription_id=? AND message_id=?", ("cancelled" if not allowed else "dead", row["subscription_id"], row["message_id"]))
                return True
            claim = uuid.uuid4().hex
            attempt = row["attempts"] + 1
            self.db.execute("UPDATE deliveries SET state='sending',attempts=?,lease_until=?,claim=? WHERE subscription_id=? AND message_id=?", (attempt, now + 30, claim, row["subscription_id"], row["message_id"]))
        body = row["body"].encode()
        headers = signed_headers(row["event_id"], body, row["secret"], row["subscription_id"], row["old_secret"] if row["rotate_until"] > now else None, now=now)
        try:
            status, _ = self.transport.post(row["url"], body, headers)
        except (OSError, RelayError, http.client.HTTPException):
            status = 0
        transient = status == 0 or status in (408, 425, 429) or 500 <= status < 600
        state = "delivered" if 200 <= status < 300 else ("pending" if transient and attempt < MAX_ATTEMPTS else "dead")
        with self.lock, self.db:
            self.db.execute("UPDATE deliveries SET state=?,last_status=?,due=?,lease_until=0 WHERE claim=? AND state='sending'", (state, status, self.clock() + min(300, 2 ** attempt), claim))
            if status == 410:
                self.db.execute("UPDATE subscriptions SET active=0 WHERE id=?", (row["subscription_id"],))
        return True
