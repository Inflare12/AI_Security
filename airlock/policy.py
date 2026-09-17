from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
import os
import re


@dataclass
class Limits:
    max_tool_calls_per_minute: int = 30
    max_output_bytes: int = 1_000_000


@dataclass
class Policy:
    network_enabled: bool = False
    allowed_hosts: set[str] = field(default_factory=set)
    read_paths: list[Path] = field(default_factory=list)
    write_paths: list[Path] = field(default_factory=list)
    allowed_commands: set[str] = field(default_factory=set)
    limits: Limits = field(default_factory=Limits)

    @staticmethod
    def from_dict(data: dict) -> "Policy":
        net = data.get("network", {})
        fs = data.get("filesystem", {})
        cmds = data.get("commands", {})
        lim = data.get("limits", {})
        return Policy(
            network_enabled=bool(net.get("enabled", False)),
            allowed_hosts={h.lower().strip().rstrip(".") for h in net.get("allowed_hosts", [])},
            read_paths=[Path(p).resolve() for p in fs.get("read", [])],
            write_paths=[Path(p).resolve() for p in fs.get("write", [])],
            allowed_commands={os.path.basename(c).lower() for c in cmds.get("allowed", [])},
            limits=Limits(
                max_tool_calls_per_minute=int(lim.get("max_tool_calls_per_minute", 30)),
                max_output_bytes=int(lim.get("max_output_bytes", 1_000_000)),
            ),
        )

    def check_url(self, url: str) -> tuple[bool, str]:
        if not self.network_enabled:
            return False, "network disabled by policy"
        parsed = urlparse(url)
        if parsed.scheme not in {"https"}:
            return False, "only HTTPS is permitted"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host not in self.allowed_hosts:
            return False, "host not in allowlist"
        return True, "allowed"

    @staticmethod
    def _inside(path: Path, roots: Iterable[Path]) -> bool:
        try:
            path = path.resolve(strict=False)
            return any(path == root or root in path.parents for root in roots)
        except (OSError, RuntimeError):
            return False

    def check_file(self, path: str, write: bool = False) -> tuple[bool, str]:
        p = Path(path)
        roots = self.write_paths if write else self.read_paths
        if not self._inside(p, roots):
            return False, "path outside policy allowlist"
        return True, "allowed"

    def check_command(self, command: str) -> tuple[bool, str]:
        # Only compare the executable basename. Shell strings are deliberately rejected.
        if any(x in command for x in ["&&", "||", ";", "|", ">", "<", "`", "$", "\n", "\r"]):
            return False, "shell metacharacters are not permitted"
        parts = command.split()
        if not parts:
            return False, "empty command"
        exe = os.path.basename(parts[0]).lower()
        if exe not in self.allowed_commands:
            return False, "executable not in allowlist"
        return True, "allowed"


SECRET_PATTERNS = [
    re.compile(r"(?i)\b(sk-[A-Za-z0-9_-]{16,})\b"),
    re.compile(r"(?i)\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"(?i)\b(AIza[0-9A-Za-z_-]{20,})\b"),
    re.compile(r"(?i)\b(eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
]


def redact_secrets(text: str) -> str:
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[REDACTED_SECRET]", result)
    return result
