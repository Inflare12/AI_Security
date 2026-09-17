from __future__ import annotations

from pathlib import Path


class KillSwitch:
    """Filesystem-backed emergency stop.

    Keep this path outside every directory writable by the model. Creating the
    file is the fail-safe action; removing it is an explicit operator action.
    """

    def __init__(self, path: str = "AI_SECURITY_KILL"):
        self.path = Path(path).resolve()

    @property
    def engaged(self) -> bool:
        return self.path.exists()

    def engage(self, reason: str = "manual emergency stop") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(reason + "\n", encoding="utf-8")

    def release(self) -> None:
        self.path.unlink(missing_ok=True)
