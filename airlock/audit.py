from __future__ import annotations

import json
import time
from pathlib import Path
from .policy import redact_secrets


class AuditLog:
    def __init__(self, path: str = "airlock-audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, action: str, allowed: bool, reason: str, **details) -> None:
        record = {
            "ts": time.time(),
            "action": action,
            "allowed": allowed,
            "reason": redact_secrets(reason),
            "details": {k: redact_secrets(str(v)) for k, v in details.items()},
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
