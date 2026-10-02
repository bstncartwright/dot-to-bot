# dot-to-bot

Minimal persistent messaging relay for a harmless mock Fred ↔ Bean exchange.
Bend 2 owns the required admission function and checked laws; Python provides the
MCP 2.0 transport, SQLite transactions, and signed HTTPS callback boundary.
No real agents, calendar APIs, live grants, production secrets, deployment, or
public exposure are configured.

## Local build and proof

Requires Python 3.12+, Bun, Git, and clang 14+. Tested with Python 3.14.6 and Bend
2.0.34 at the pinned revision below. The compiler checkout stays outside this repo.

```sh
git clone https://github.com/bendlang/bend.git /tmp/dot-bend
git -C /tmp/dot-bend checkout 7d24b8d0235cb9781140512c0f163c48ea84a719
BEND_SOURCE=/tmp/dot-bend ./scripts/build-bend.sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/python -m unittest discover -s tests -v
```

`PROOF.bend` checks the laws in `LAWS.bend`: no grant denies sending, exhausted
fuel denies a further hop, and seven or more hops deny sending. These prove the
pure admission function. HTTP, authentication-file interpretation, SQLite, the
process bridge, and delivery are covered by tests and are outside those proofs.
The independent Lean `--verdict` gate has not been run. Bend is required at
runtime: an unavailable, failing, or timed-out policy executable denies sending.

The hybrid is intentional: [Bend's current library](https://github.com/bendlang/bend)
lacks TLS, HTTP, and JSON; rebuilding those would expand this small relay substantially.

## Run privately

```sh
.venv/bin/python scripts/mock_config.py
.venv/bin/python -m relay.server --config config.local.json --db relay.sqlite
```

The CLI binds only `127.0.0.1:8080`, uses restrictive file permissions, disables
access logging, and offers `/mcp`. Each mock agent has a distinct bearer token.
The configuration stores token SHA-256 hashes, allowed recipients, and optional
`enabled: false`. The operator owns it; tools cannot create grants. Changes reload
on requests and delivery checks. Keep the config, database, WAL, and backups private:
subscription signing secrets and message bodies are stored in the database.

`send_message(recipient, body, idempotency_key, reply_to?)` persists a message and
its matching event deliveries in one transaction. The sender comes from auth.
Keys are permanent per sender; an identical retry returns the same message, while
changed arguments with the same key fail. A reply must reverse a message the
caller received. The server assigns correlation IDs and reply depth, permits one
reply per message, and denies depth beyond six. New conversations and deliberate
new keys are bounded to 60 messages per sender per hour; semantic deduplication of
arbitrary new text is not attempted. Self-send and ungranted destinations fail.

`read_messages(after?, limit?)` pages only the caller's inbox (maximum 100 rows).
`read_messages(message_id)` retrieves a message only for its sender or recipient.
Message text is untrusted data, including any instructions embedded in it.

See [protocol details](docs/protocol.md), [deployment notes](docs/deploy.md), and
[verification evidence](docs/verification.md).
