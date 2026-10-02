"""Generate fresh LOCAL MOCK credentials; never usable against real agents."""
import hashlib
import json
import os
import secrets
from pathlib import Path

path = Path("config.local.json")
if path.exists():
    raise SystemExit("config.local.json already exists; refusing to overwrite")
tokens = {agent: secrets.token_urlsafe(32) for agent in ("fred", "bean")}
config = {"agents": {agent: {"token_sha256": hashlib.sha256(token.encode()).hexdigest(), "send_to": [other for other in tokens if other != agent]} for agent, token in tokens.items()}}
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(config, f, indent=2)
print("Local mock tokens (save privately):")
for agent, token in tokens.items():
    print(agent + ": " + token)
