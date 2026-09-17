from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from dataclasses import dataclass

from .audit import AuditLog
from .kill_switch import KillSwitch


@dataclass(frozen=True)
class RegisteredProcess:
    pid: int
    name: str | None = None


class ContainmentController:
    """Operator/security-monitor emergency containment for AI processes.

    The model must never receive this object as a normal tool. The kill switch
    path should be outside every model-writable directory.
    """

    def __init__(self, kill_switch: KillSwitch | None = None,
                 audit: AuditLog | None = None, allow_host_shutdown: bool = False) -> None:
        self.kill_switch = kill_switch or KillSwitch()
        self.audit = audit or AuditLog()
        self.allow_host_shutdown = allow_host_shutdown
        self._processes: dict[int, RegisteredProcess] = {}
        self._lock = threading.Lock()

    def register_pid(self, pid: int, name: str | None = None) -> None:
        pid = int(pid)
        if pid <= 0:
            raise ValueError("pid must be positive")
        with self._lock:
            self._processes[pid] = RegisteredProcess(pid, name)
        self.audit.event("register_process", True, "process registered", pid=pid, name=name or "")

    def unregister_pid(self, pid: int) -> None:
        with self._lock:
            self._processes.pop(int(pid), None)

    def registered_pids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(self._processes)

    def engage(self, reason: str = "manual emergency stop") -> None:
        """Fail closed, then terminate every registered AI process."""
        self.kill_switch.engage(reason)
        with self._lock:
            processes = tuple(self._processes.values())
        results = {p.pid: self.terminate_pid(p.pid) for p in processes}
        self.audit.event("containment", True, reason, terminated_pids=list(results), results=results)

    def terminate_pid(self, pid: int) -> bool:
        pid = int(pid)
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                ok = result.returncode == 0
            else:
                pgid = os.getpgid(pid)
                if pgid == pid:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
                ok = True
        except (ProcessLookupError, PermissionError, OSError):
            ok = False
        self.audit.event("terminate_process", ok, "process termination", pid=pid)
        return ok

    def shutdown_host(self, reason: str = "AI security emergency") -> None:
        """Last-resort OS shutdown; explicitly disabled by default."""
        if not self.allow_host_shutdown:
            raise PermissionError("host shutdown is disabled; enable it explicitly")
        self.audit.event("host_shutdown", True, reason)
        if os.name == "nt":
            subprocess.Popen(["shutdown", "/s", "/t", "0"], close_fds=True)
        elif sys.platform == "darwin":
            subprocess.Popen(["shutdown", "-h", "now"], close_fds=True)
        else:
            subprocess.Popen(["shutdown", "-h", "now"], close_fds=True)
