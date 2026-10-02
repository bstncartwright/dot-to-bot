# Future exe.dev Linux VM deployment

No VM was created and nothing was deployed. These are portable operator steps to
use after approval and after the actual agent/callback integrations are resolved.

1. Use a Linux VM with Python 3.12+, Bun, Git and clang 14+. Run as an unprivileged
   dedicated user. Copy the reviewed repository; compile the pinned Bend source
   with `scripts/build-bend.sh`, and install `requirements.lock` in a virtualenv.
2. Store the operator config and SQLite database in a private durable directory,
   with its parent and files accessible only to the service user. Provision fresh
   independent high-entropy tokens for real identities; never reuse mock tokens.
3. Run `.venv/bin/python -m relay.server --config /private/agents.json
   --db /private/relay.sqlite --bend-policy /app/bend/policy` under a service manager.
   The CLI remains on loopback. One process/worker is the supported minimal setup.
4. Configure an authenticated TLS reverse proxy only after public exposure is
   separately approved. Permit the reviewed Host/Origin through the SDK's DNS
   rebinding settings if using a proxy; the present SDK defaults permit localhost
   only. Add production OAuth/resource metadata for a ChatGPT plugin if required
   by the target client; these static scoped tokens are the local proof boundary.
5. Permit outbound HTTPS only to approved callbacks. Register MCP Events with the
   actual client, verify challenges/signatures, and confirm Bean's compatibility
   or supply the adapter. Do not grant calendar or unrelated app scopes.
6. Back up SQLite with its online backup API or while stopped; copying only the
   live main file can miss its WAL. Restore privately and test pending delivery
   recovery. Set message retention, audit/metrics and backup encryption requirements
   before production use; this prototype retains rows and has no deletion API.

Example service command (adapt paths locally, do not paste mock credentials into
service files):

```ini
[Service]
User=dotrelay
WorkingDirectory=/opt/dot-to-bot
ExecStart=/opt/dot-to-bot/.venv/bin/python -m relay.server --config /var/lib/dotrelay/agents.json --db /var/lib/dotrelay/relay.sqlite --bend-policy /opt/dot-to-bot/bend/policy
Restart=on-failure
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/dotrelay
PrivateTmp=true
```

The Bend binary is target-specific and ignored by Git; rebuild on the Linux VM.
No Docker, GPU or database service is required. The admission subprocess is small
but has per-message overhead; this intentionally targets low-volume agent messaging.
