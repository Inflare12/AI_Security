from __future__ import annotations

import ipaddress
import shlex
import socket
import subprocess
import time
from collections import deque
from urllib.parse import HTTPRedirectHandler, ProxyHandler, Request, build_opener, urlparse

from .audit import AuditLog
from .kill_switch import KillSwitch
from .monitor import RuntimeMonitor
from .policy import Policy, redact_secrets


class SecurityViolation(PermissionError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Airlock:
    def __init__(self, policy: Policy, audit: AuditLog | None = None,
                 kill_switch: KillSwitch | None = None, monitor: RuntimeMonitor | None = None):
        self.policy = policy
        self.audit = audit or AuditLog()
        self.kill_switch = kill_switch or KillSwitch()
        self.monitor = monitor
        self._tool_calls: deque[float] = deque()

    def _deny(self, action: str, reason: str, **details):
        self.audit.event(action, False, reason, **details)
        if self.monitor:
            self.monitor.violation(f"{action}: {reason}")
        raise SecurityViolation(reason)

    def _check_alive(self) -> None:
        if self.kill_switch.engaged:
            self._deny("kill_switch", "AI Security emergency stop is engaged")

    def _consume_tool_call(self, action: str) -> None:
        now = time.monotonic()
        window = 60.0
        while self._tool_calls and now - self._tool_calls[0] > window:
            self._tool_calls.popleft()
        if len(self._tool_calls) >= self.policy.limits.max_tool_calls_per_minute:
            self._deny(action, "tool-call rate limit exceeded")
        self._tool_calls.append(now)

    def _resolve_public_host(self, host: str) -> None:
        if not self.policy.deny_private_ips:
            return
        try:
            addresses = {info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        except OSError as exc:
            self._deny("network", "hostname resolution failed", host=host, error=type(exc).__name__)
        for raw in addresses:
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_unspecified:
                self._deny("network", "hostname resolves to a private/reserved address", host=host)

    def request_url(self, url: str, timeout: float = 10) -> bytes:
        self._check_alive()
        self._consume_tool_call("network")
        ok, reason = self.policy.check_url(url)
        if not ok:
            return self._deny("network", reason, url=url)
        parsed = urlparse(url)
        if parsed.port not in (None, 443):
            return self._deny("network", "only HTTPS port 443 is permitted", url=url)
        self._resolve_public_host(parsed.hostname or "")
        self.audit.event("network", True, reason, url=url)
        req = Request(url, headers={"User-Agent": "AI-Security-Airlock/1.1"})
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(req, timeout=min(float(timeout), self.policy.limits.max_network_seconds)) as response:
                data = response.read(self.policy.limits.max_output_bytes + 1)
        except Exception as exc:
            self.audit.event("network_error", False, type(exc).__name__, url=url)
            raise
        if len(data) > self.policy.limits.max_output_bytes:
            return self._deny("network", "response exceeds output limit", url=url)
        return data

    def read_file(self, path: str) -> str:
        self._check_alive()
        self._consume_tool_call("file_read")
        ok, reason = self.policy.check_file(path, write=False)
        if not ok:
            return self._deny("file_read", reason, path=path)
        self.audit.event("file_read", True, reason, path=path)
        with open(path, "r", encoding="utf-8") as f:
            return f.read(self.policy.limits.max_output_bytes)

    def write_file(self, path: str, content: str) -> None:
        self._check_alive()
        self._consume_tool_call("file_write")
        ok, reason = self.policy.check_file(path, write=True)
        if not ok:
            return self._deny("file_write", reason, path=path)
        if len(content.encode("utf-8")) > self.policy.limits.max_file_bytes:
            return self._deny("file_write", "content exceeds file size limit", path=path)
        self.audit.event("file_write", True, reason, path=path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(redact_secrets(content))

    def run_command(self, command: str) -> str:
        self._check_alive()
        self._consume_tool_call("command")
        ok, reason = self.policy.check_command(command)
        if not ok:
            return self._deny("command", reason, command=command)
        try:
            parts = shlex.split(command, posix=(__import__("os").name != "nt"))
        except ValueError:
            return self._deny("command", "invalid command quoting", command=command)
        if len(parts) != 1:
            return self._deny("command", "free-form command arguments are disabled; use a typed tool", command=command)
        self.audit.event("command", True, reason, command=command)
        result = subprocess.run(
            parts, capture_output=True, text=True,
            timeout=self.policy.limits.max_command_seconds, shell=False,
        )
        output = (result.stdout + result.stderr)[: self.policy.limits.max_output_bytes]
        return redact_secrets(output)
