from __future__ import annotations

import subprocess
from urllib.request import Request, urlopen

from .audit import AuditLog
from .kill_switch import KillSwitch
from .monitor import RuntimeMonitor
from .policy import Policy, redact_secrets


class SecurityViolation(PermissionError):
    pass


class Airlock:
    def __init__(self, policy: Policy, audit: AuditLog | None = None,
                 kill_switch: KillSwitch | None = None, monitor: RuntimeMonitor | None = None):
        self.policy = policy
        self.audit = audit or AuditLog()
        self.kill_switch = kill_switch or KillSwitch()
        self.monitor = monitor

    def _deny(self, action: str, reason: str, **details):
        self.audit.event(action, False, reason, **details)
        if self.monitor:
            self.monitor.violation(f"{action}: {reason}")
        raise SecurityViolation(reason)

    def _check_alive(self) -> None:
        if self.kill_switch.engaged:
            self._deny("kill_switch", "AI Security emergency stop is engaged")

    def request_url(self, url: str, timeout: float = 10) -> bytes:
        self._check_alive()
        ok, reason = self.policy.check_url(url)
        if not ok:
            return self._deny("network", reason, url=url)
        self.audit.event("network", True, reason, url=url)
        req = Request(url, headers={"User-Agent": "AI-Security-Airlock/1.0"})
        try:
            with urlopen(req, timeout=min(float(timeout), self.policy.limits.max_network_seconds)) as response:
                data = response.read(self.policy.limits.max_output_bytes + 1)
        except Exception as exc:
            self.audit.event("network_error", False, type(exc).__name__, url=url)
            raise
        if len(data) > self.policy.limits.max_output_bytes:
            return self._deny("network", "response exceeds output limit", url=url)
        return data

    def read_file(self, path: str) -> str:
        self._check_alive()
        ok, reason = self.policy.check_file(path, write=False)
        if not ok:
            return self._deny("file_read", reason, path=path)
        self.audit.event("file_read", True, reason, path=path)
        with open(path, "r", encoding="utf-8") as f:
            return f.read(self.policy.limits.max_output_bytes)

    def write_file(self, path: str, content: str) -> None:
        self._check_alive()
        ok, reason = self.policy.check_file(path, write=True)
        if not ok:
            return self._deny("file_write", reason, path=path)
        if len(content.encode("utf-8")) > self.policy.limits.max_output_bytes:
            return self._deny("file_write", "content exceeds output limit", path=path)
        self.audit.event("file_write", True, reason, path=path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(redact_secrets(content))

    def run_command(self, command: str) -> str:
        self._check_alive()
        ok, reason = self.policy.check_command(command)
        if not ok:
            return self._deny("command", reason, command=command)
        self.audit.event("command", True, reason, command=command)
        result = subprocess.run(
            command.split(), capture_output=True, text=True,
            timeout=self.policy.limits.max_command_seconds, shell=False,
        )
        output = (result.stdout + result.stderr)[: self.policy.limits.max_output_bytes]
        return redact_secrets(output)
