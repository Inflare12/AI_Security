from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

from .policy import redact_secrets


class AuditLog:
    """Append-only JSONL audit log with a tamper-evident hash chain."""

    def __init__(self, path: str = "airlock-audit.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        try:
            with self.path.open("rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if not size:
                    return "0" * 64
                chunk = min(size, 8192)
                f.seek(-chunk, 2)
                lines = f.read().splitlines()
                if not lines:
                    return "0" * 64
                record = json.loads(lines[-1].decode("utf-8"))
                return str(record.get("event_hash", "0" * 64))
        except (OSError, ValueError, json.JSONDecodeError):
            return "0" * 64

    def event(self, action: str, allowed: bool, reason: str, **details) -> None:
        record = {
            "ts": time.time(),
            "action": redact_secrets(action),
            "allowed": bool(allowed),
            "reason": redact_secrets(reason),
            "details": {k: redact_secrets(str(v)) for k, v in details.items()},
        }
        with self._lock:
            record["previous_hash"] = self._last_hash()
            payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record["event_hash"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, separators=(",", ":")) + "\n")

    def verify(self) -> bool:
        previous = "0" * 64
        try:
            with self.path.open("r", encoding="utf-8") as f:
                for line in f:
                    record = json.loads(line)
                    actual = record.pop("event_hash", None)
                    if record.get("previous_hash") != previous or not actual:
                        return False
                    payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
                    expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    if actual != expected:
                        return False
                    previous = actual
        except (OSError, ValueError, json.JSONDecodeError):
            return False
        return True
