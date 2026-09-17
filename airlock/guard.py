from __future__ import annotations

import subprocess
from urllib.request import Request, urlopen
from .audit import AuditLog
from .kill_switch import KillSwitch
from .policy import Policy, redact_secrets


class SecurityViolation(PermissionError):
    pass


class Airlock:
    def __init__(self, policy: Policy, audit: AuditLog | None = None, kill_switch: KillSwitch | None = None):
        self.policy = policy
        self.audit = audit or AuditLog()
        self.kill_switch = kill_switch or KillSwitch()

    def _check_alive(self) -> None:
        if self.kill_switch.engaged:
            self.audit.event("kill_switch", False, "emergency kill switch engaged")
            raise SecurityViolation("AI Security emergency stop is engaged")

    def request_url(self, url: str, timeout: float = 10) -> bytes:
        self._check_alive()
        ok, reason = self.policy.check_url(url)
        self.audit.event("network", ok, reason, url=url)
        if not ok:
            raise SecurityViolation(reason)
        req = Request(url, headers={"User-Agent": "AI-Security-Airlock/0.1"})
        with urlopen(req, timeout=timeout) as response:
            data = response.read(self.policy.limits.max_output_bytes + 1)
        if len(data) > self.policy.limits.max_output_bytes:
            raise SecurityViolation("response exceeds output limit")
        return data

    def read_file(self, path: str) -> str:
        self._check_alive()
        ok, reason = self.policy.check_file(path, write=False)
        self.audit.event("file_read", ok, reason, path=path)
        if not ok:
            raise SecurityViolation(reason)
        with open(path, "r", encoding="utf-8") as f:
            return f.read(self.policy.limits.max_output_bytes)

    def write_file(self, path: str, content: str) -> None:
        self._check_alive()
        ok, reason = self.policy.check_file(path, write=True)
        self.audit.event("file_write", ok, reason, path=path)
        if not ok:
            raise SecurityViolation(reason)
        if len(content.encode("utf-8")) > self.policy.limits.max_output_bytes:
            raise SecurityViolation("content exceeds output limit")
        with open(path, "w", encoding="utf-8") as f:
            f.write(redact_secrets(content))

    def run_command(self, command: str) -> str:
        self._check_alive()
        ok, reason = self.policy.check_command(command)
        self.audit.event("command", ok, reason, command=command)
        if not ok:
            raise SecurityViolation(reason)
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=10, shell=False)
        output = (result.stdout + result.stderr)[: self.policy.limits.max_output_bytes]
        return redact_secrets(output)
