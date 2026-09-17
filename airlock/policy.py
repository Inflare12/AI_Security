from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Limits:
    max_tool_calls_per_minute: int = 30
    max_output_bytes: int = 1_000_000
    max_command_seconds: int = 10
    max_network_seconds: int = 10
    max_file_bytes: int = 1_000_000


@dataclass
class Policy:
    network_enabled: bool = False
    allowed_hosts: set[str] = field(default_factory=set)
    read_paths: list[Path] = field(default_factory=list)
    write_paths: list[Path] = field(default_factory=list)
    allowed_commands: set[str] = field(default_factory=set)
    limits: Limits = field(default_factory=Limits)
    deny_private_ips: bool = True

    @staticmethod
    def from_dict(data: dict) -> Policy:
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
                max_tool_calls_per_minute=max(1, int(lim.get("max_tool_calls_per_minute", 30))),
                max_output_bytes=max(1, int(lim.get("max_output_bytes", 1_000_000))),
                max_command_seconds=max(1, int(lim.get("max_command_seconds", 10))),
                max_network_seconds=max(1, int(lim.get("max_network_seconds", 10))),
                max_file_bytes=max(1, int(lim.get("max_file_bytes", 1_000_000))),
            ),
            deny_private_ips=bool(net.get("deny_private_ips", True)),
        )

    def check_url(self, url: str) -> tuple[bool, str]:
        if not self.network_enabled:
            return False, "network disabled by policy"
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            return False, "only credential-free HTTPS URLs are permitted"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host or host not in self.allowed_hosts:
            return False, "host not in allowlist"
        try:
            addr = ipaddress.ip_address(host)
            if self.deny_private_ips and (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_unspecified):
                return False, "private/reserved IP destinations are blocked"
        except ValueError:
            pass
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
        if p.exists() and p.is_file():
            try:
                if p.stat().st_size > self.limits.max_file_bytes:
                    return False, "file exceeds policy size limit"
            except OSError:
                return False, "file metadata could not be read"
        return True, "allowed"

    def check_command(self, command: str) -> tuple[bool, str]:
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
    re.compile(r"(?i)\b(aws_secret_access_key\s*[=:]\s*[^\s]+)\b"),
]


def redact_secrets(text: str) -> str:
    result = text
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[REDACTED_SECRET]", result)
    return result
