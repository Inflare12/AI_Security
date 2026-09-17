from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

from .audit import AuditLog
from .containment import ContainmentController
from .kill_switch import KillSwitch


class AISupervisor:
    """Operator-owned launcher that registers and contains one AI process tree."""

    def __init__(self, containment: ContainmentController, audit: AuditLog | None = None) -> None:
        self.containment = containment
        self.audit = audit or containment.audit
        self.process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _safe_env(extra: dict[str, str] | None = None) -> dict[str, str]:
        allowed = {
            "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR",
            "LANG", "LC_ALL", "PYTHONPATH", "PYTHONHOME",
        }
        env = {k: v for k, v in os.environ.items() if k in allowed}
        if extra:
            env.update(extra)
        return env

    def start(self, argv: list[str], cwd: str | Path | None = None,
              env: dict[str, str] | None = None) -> int:
        if not argv or any(not isinstance(x, str) or not x for x in argv):
            raise ValueError("argv must be a non-empty list of strings")
        with self._lock:
            if self.process and self.process.poll() is None:
                raise RuntimeError("an AI process is already running")
            kwargs: dict[str, object] = {
                "args": argv,
                "cwd": str(cwd) if cwd else None,
                "env": self._safe_env(env),
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.STDOUT,
                "text": True,
                "shell": False,
            }
            if os.name != "nt":
                kwargs["start_new_session"] = True
            self.process = subprocess.Popen(**kwargs)  # type: ignore[arg-type]
            self.containment.register_pid(self.process.pid, argv[0])
            self.audit.event("ai_start", True, "AI process started", pid=self.process.pid, executable=argv[0])
            return self.process.pid

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            process = self.process
        if process is None:
            raise RuntimeError("no AI process is running")
        return process.wait(timeout=timeout)

    def output(self, max_bytes: int = 1_000_000) -> str:
        with self._lock:
            process = self.process
        if process is None or process.stdout is None:
            return ""
        data = process.stdout.read(max_bytes)
        return data

    def stop(self, reason: str = "operator stop") -> None:
        with self._lock:
            process = self.process
        if process is None or process.poll() is not None:
            return
        self.containment.engage(reason)

    def reap(self) -> int | None:
        with self._lock:
            process = self.process
        if process is None:
            return None
        code = process.poll()
        if code is not None:
            self.containment.unregister_pid(process.pid)
            self.audit.event("ai_exit", True, "AI process exited", pid=process.pid, returncode=code)
        return code

    def run(self, argv: list[str], cwd: str | Path | None = None,
            env: dict[str, str] | None = None) -> int:
        self.start(argv, cwd=cwd, env=env)
        return self.wait()
