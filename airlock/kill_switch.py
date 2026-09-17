from __future__ import annotations

import os
from pathlib import Path


class KillSwitch:
    """Filesystem-backed fail-safe emergency stop.

    Keep this path outside every directory writable by the model. Creating the
    marker is the fail-safe action; removing it is an explicit operator action.
    """

    def __init__(self, path: str = "AI_SECURITY_KILL"):
        self.path = Path(path).resolve()

    @property
    def engaged(self) -> bool:
        return self.path.exists()

    def engage(self, reason: str = "manual emergency stop") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.path.open("x", encoding="utf-8") as handle:
                handle.write(reason[:4096] + "\n")
        except FileExistsError:
            return
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def release(self) -> None:
        if self.path.is_symlink():
            raise PermissionError("refusing to release a symlink kill switch")
        self.path.unlink(missing_ok=True)
