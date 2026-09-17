from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from .audit import AuditLog
from .kill_switch import KillSwitch


class ContainmentController:
    """Emergency containment for model/agent processes.

    The controller is operator/security-monitor driven. A model cannot call this
    object unless the host application explicitly exposes it as a privileged tool.
    Host shutdown is disabled by default and requires explicit opt-in.
    """

    def __init__(
        self,
        kill_switch: KillSwitch | None = None,
        audit: AuditLog | None = None,
        allow_host_shutdown: bool = False,
    ) -> None:
        self.kill_switch = kill_switch or KillSwitch()
        self.audit = audit or AuditLog()
        self.allow_host_shutdown = allow_host_shutdown
        self._pids: set[int] = set()
        self._lock = threading.Lock()

    def register_pid(self, pid: int) -> None:
        with self._lock:
            self._pids.add(int(pid))
        self.audit.event("register_process", True, "process registered", pid=pid)

    def unregister_pid(self, pid: int) -> None:
        with self._lock:
            self._pids.discard(int(pid))

    def engage(self, reason: str = "manual emergency stop") -> None:
        """Engage the kill switch and terminate all registered AI processes."""
        self.kill_switch.engage(reason)
        with self._lock:
            pids = list(self._pids)
        for pid in pids:
            self.terminate_pid(pid)
        self.audit.event("containment", True, reason, terminated_pids=pids)

    def terminate_pid(self, pid: int) -> bool:
        pid = int(pid)
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                ok = result.returncode == 0
            else:
                os.killpg(pid, signal.SIGKILL)
                ok = True
        except (ProcessLookupError, PermissionError, OSError):
            try:
                os.kill(pid, signal.SIGKILL)
                ok = True
            except (ProcessLookupError, PermissionError, OSError):
                ok = False
        self.audit.event("terminate_process", ok, "process termination", pid=pid)
        return ok

    def shutdown_host(self, reason: str = "AI security emergency") -> None:
        """Optionally request an OS shutdown. Disabled unless explicitly configured."""
        if not self.allow_host_shutdown:
            raise PermissionError("host shutdown is disabled; enable it explicitly")
        self.audit.event("host_shutdown", True, reason)
        if os.name == "nt":
            subprocess.Popen(["shutdown", "/s", "/t", "0"], close_fds=True)
        elif sys.platform == "darwin":
            subprocess.Popen(["shutdown", "-h", "now"], close_fds=True)
        else:
            subprocess.Popen(["shutdown", "-h", "now"], close_fds=True)
