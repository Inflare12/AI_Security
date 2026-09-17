from __future__ import annotations

import os
import subprocess
import threading
from pathlib import Path

from .audit import AuditLog
from .containment import ContainmentController
from .windows_job import WindowsJob


class AISupervisor:
    """Operator-owned launcher that registers and contains one AI process tree."""

    def __init__(self, containment: ContainmentController, audit: AuditLog | None = None) -> None:
        self.containment = containment
        self.audit = audit or containment.audit
        self.process: subprocess.Popen[str] | None = None
        self._job: WindowsJob | None = None
        self._lock = threading.Lock()

    @staticmethod
    def _safe_env(extra: dict[str, str] | None = None) -> dict[str, str]:
        allowed = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
        env = {k: v for k, v in os.environ.items() if k in allowed}
        if extra:
            for key, value in extra.items():
                if not key or "=" in key or "\x00" in key or "\x00" in value:
                    raise ValueError("invalid environment variable")
                env[key] = value
        return env

    def start(self, argv: list[str], cwd: str | Path | None = None,
              env: dict[str, str] | None = None) -> int:
        if not argv or any(not isinstance(x, str) or not x or "\x00" in x for x in argv):
            raise ValueError("argv must be a non-empty list of safe strings")
        executable = Path(argv[0])
        if not executable.is_absolute():
            raise ValueError("the supervised executable must be an absolute path")
        if not executable.is_file():
            raise FileNotFoundError(str(executable))
        with self._lock:
            if self.process and self.process.poll() is None:
                raise RuntimeError("an AI process is already running")
            job = WindowsJob() if os.name == "nt" else None
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
            try:
                self.process = subprocess.Popen(**kwargs)  # type: ignore[arg-type]
                if job is not None:
                    job.assign(int(self.process._handle))
                self._job = job
            except Exception:
                if job is not None:
                    job.close()
                if self.process is not None and self.process.poll() is None:
                    self.process.kill()
                    self.process.wait()
                self.process = None
                raise
            self.containment.register_pid(self.process.pid, executable.name)
            self.audit.event("ai_start", True, "AI process started", pid=self.process.pid, executable=str(executable))
            return self.process.pid

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            process = self.process
        if process is None:
            raise RuntimeError("no AI process is running")
        return process.wait(timeout=timeout)

    def output(self, max_bytes: int = 1_000_000) -> str:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        with self._lock:
            process = self.process
        if process is None or process.stdout is None:
            return ""
        return process.stdout.read(max_bytes)

    def stop(self, reason: str = "operator stop") -> None:
        with self._lock:
            process = self.process
            job = self._job
        if process is None or process.poll() is not None:
            return
        if job is not None:
            job.terminate(1)
        else:
            self.containment.engage(reason)
        self.audit.event("ai_stop", True, reason, pid=process.pid)

    def reap(self) -> int | None:
        with self._lock:
            process = self.process
            job = self._job
        if process is None:
            return None
        code = process.poll()
        if code is not None:
            self.containment.unregister_pid(process.pid)
            if job is not None:
                job.close()
                with self._lock:
                    self._job = None
            self.audit.event("ai_exit", True, "AI process exited", pid=process.pid, returncode=code)
        return code

    def run(self, argv: list[str], cwd: str | Path | None = None,
            env: dict[str, str] | None = None) -> int:
        self.start(argv, cwd=cwd, env=env)
        return self.wait()
