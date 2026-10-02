# MCP and Events interoperability

Reference: [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events),
checked 2026-09-30. The relay registers `events/list`, `events/subscribe`, and
`events/unsubscribe` on the same authenticated `/mcp` endpoint as tools, advertises
`events` in `server/discover`, and supports protocol `2026-07-28` only.

The inspected PyPI `mcp==2.2.0` / `mcp-types==2.2.0` supports modern stateless
transport, per-request metadata, header matching, and `server/discover`. Its
built-in server methods and capability model do not include the draft Events API.
We use its public `Server.add_request_handler` hooks and an ASGI discovery
response adapter that adds the draft `events` capability after the SDK validates
the standard discovery result. Without that adapter its closed capability wire
model strips `events`. This is webhook delivery, not old MCP SSE notifications.
SDK behavior is exercised in the HTTP tests; actual ChatGPT registration remains
an integration test to perform after separately approved hosting/auth setup.

## MCP 2.0 request format

Every request uses `Authorization: Bearer <agent-token>`,
`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method` matching its JSON method,
`Accept: application/json`, and `Content-Type: application/json`. `tools/call`
also requires `Mcp-Name` matching the tool name. Each request carries metadata:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "events/subscribe",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientCapabilities": {},
      "io.modelcontextprotocol/clientInfo": {"name": "mock-bean", "version": "1"}
    },
    "name": "message.created",
    "arguments": {"recipient": "bean"},
    "delivery": {
      "mode": "webhook",
      "url": "https://receiver.example/callback",
      "secret": "whsec_<base64-of-24-to-64-random-bytes>"
    },
    "cursor": null,
    "ttlMs": 86400000
  }
}
```

Only the principal's inbox is discoverable/subscribable. Identity hashes the
principal, exact URL, event name and canonical arguments. Refresh updates the
same subscription. Default/max lifetime is 24 hours, positive shorter requests
are honored, and null requests receive a finite grant. At most 16 active
subscriptions per agent. Unsubscribe supplies the original name, arguments and
`delivery: {mode, url}` and is idempotent.

## Callback and delivery lifecycle

A signed fresh challenge must receive a 2xx response echoing the challenge before
activation. Successful checks cache for five minutes on the same subscription
identity and key. Key changes force verification and rotate signatures for five
minutes. Secrets must decode to 24–64 bytes. Signing uses Standard Webhooks
HMAC-SHA256 over `webhook-id.timestamp.exact-body`, with `v1,<base64>` signatures.
The mock independently checks signed verification and application bodies.

Callback requests resolve DNS on each connection, reject every nonpublic address,
connect to a validated socket address, and preserve the original TLS hostname.
No redirects or proxies. Private/loopback HTTP callbacks exist only through an
explicit programmatic test transport; the server CLI has no switch to allow them.
Verification and event requests have a ten second socket timeout and bounded bodies.

The durable outbox tracks pending → sending (30 second lease) → delivered or dead,
with attempts, due time, last HTTP status, and immutable event body/ID. A crash can
repeat a delivery after lease expiry. Receivers must deduplicate event IDs before
acting and make replies idempotent. Success acknowledges receipt, not completion
of the recipient's work. Transient errors retry with exponential delay for at
most five attempts; 410, 413 and other permanent responses are terminal. A 410
also disables the subscription. Refresh never resurrects dead/acknowledged jobs.
Revoked agent/recipient grants, expiration and unsubscribe cancel pending work.
A request already in flight can reach its recipient during revocation; no system
can retract an acknowledged network request.

Protocol replay is deliberately unsupported (`cursor: null`); a nonnull replay
cursor fails. Subscriptions wake for new arrivals only. SQLite preserves queued
retries across restart; missed inbox arrivals can always be fetched through
`read_messages` using its independent sequence pagination. No control/gap/poll/
stream delivery modes are advertised.

## Bean ordinary-webhook adapter

Bean is known to support webhooks/MCP; MCP Events compatibility is unconfirmed.
An adapter can expose the callback above, echo verification, validate Standard
Webhooks signature/time with its secret, persist a unique `(subscription,eventId)`
receipt before acting, fetch message data, and translate it into Bean's supported
local webhook ingress. Its replies call `send_message` using Bean's own token,
the received message ID as `reply_to`, and a stable derived idempotency key.
Do not allow payloads to choose identities, credentials or new grants. Adapter
invocation and actual Bean authorization are separate integration work; no real
Bean endpoint or account is configured here. Ordinary inbound webhook support
alone does not establish MCP Events compatibility.
