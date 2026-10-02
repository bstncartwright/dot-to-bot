# Local verification — 2026-09-30

- Repository: `bstncartwright/dot-to-bot`, based on `develop`.
- Implementation branch: `local/messaging-relay`.
- Python: 3.14.6; MCP SDK and types: 2.2.0 (locked dependencies included).
- Bend: 2.0.34, source commit `7d24b8d0235cb9781140512c0f163c48ea84a719`.
- `BEND_SOURCE=/tmp/dot-bend scripts/build-bend.sh`: `ALL PROOFS CHECK`, native
  admission executable compiled and used by the tests. No Lean kernel verdict.
- `/tmp/dot-relay-venv/bin/python -m unittest discover -s tests -v`:
  **13 tests passed in 13.271 seconds**.

Coverage includes actual loopback Uvicorn MCP HTTP requests with two signed local
callback servers; Fred request → Bean inbox event → Bean reply → Fred inbox event
and read; SDK discovery/events/tools and envelope/header validation; distinct-agent
isolation and sender spoof rejection; concurrent idempotent sends; mismatched-key
rejection; restart persistence; immutable event ID/body with fresh retry signatures;
claimed-job crash recovery; bounded retries and 410/413/redirect handling; challenge
failure; malformed keys; private IP rejection/DNS rebinding; pinned connection/TLS
hostname/query preservation; refresh/secret rotation/unsubscribe; TTL and access
revocation; quota/pagination; background delivery; receiver duplicate suppression;
Bend gate behavior and fail-closed timeout; reply depth/branch rejection.

The workspace `.venv` suffered filesystem read timeouts; the successful test run
used the same dependencies in `/tmp/dot-relay-venv`. No external callbacks or actual
agents were contacted. Mock receiver endpoints were bound only to numeric loopback
and shut down at the end. No mock credentials are committed.

An SDK/Pydantic `TypedDictExtraConfigWarning` is emitted for request metadata: its
open `_meta` keys remain allowed while unexpected subscription fields are rejected.
This warning did not prevent the protocol tests from passing.

Remaining integration work: actual Bean event compatibility or webhook adapter;
actual ChatGPT registration and authentication requirements; approved private
exe.dev hosting/TLS/proxy configuration; fresh real credentials and explicit grants;
retention/backup/operational requirements. Validation involved no deployment, real
agent contact, or calendar access.

Publication verification repeated on 2026-10-02: Bend returned `ALL PROOFS CHECK`
and all 13 tests passed in 11.745 seconds using the original checkout and the
temporary dependency environment. Publication is authorized as a draft PR;
merging, deployment, production access and real-agent contact remain outside scope.
