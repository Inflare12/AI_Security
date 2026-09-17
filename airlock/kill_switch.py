from __future__ import annotations

from pathlib import Path


class KillSwitch:
    """Filesystem-backed emergency stop for the broker.

    Create the configured file to block all brokered actions. Put this file outside
    any directory writable by the model process.
    """

    def __init__(self, path: str = "AI_SECURITY_KILL"):
        self.path = Path(path)

    @property
    def engaged(self) -> bool:
        return self.path.exists()
