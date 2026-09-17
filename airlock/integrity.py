from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_json(data: Any) -> str:
    return hashlib.sha256(canonical_json(data)).hexdigest()


def verify_file(path: str | Path, expected_sha256: str) -> bool:
    expected = expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ValueError("expected_sha256 must be a 64-character hexadecimal SHA-256 digest")
    return sha256_file(path) == expected


def verify_policy_file(path: str | Path, expected_sha256: str | None) -> None:
    if expected_sha256 is None or not expected_sha256.strip():
        return
    if not verify_file(path, expected_sha256):
        raise PermissionError("policy integrity verification failed")
