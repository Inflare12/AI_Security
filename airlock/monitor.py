from __future__ import annotations

import time
from collections import deque

from .audit import AuditLog
from .containment import ContainmentController


class RuntimeMonitor:
    """Small circuit breaker for runaway or repeatedly denied AI behavior."""

    def __init__(self, containment: ContainmentController, audit: AuditLog | None = None,
                 window_seconds: int = 60, violation_threshold: int = 8) -> None:
        self.containment = containment
        self.audit = audit or containment.audit
        self.window_seconds = window_seconds
        self.violation_threshold = violation_threshold
        self._violations: deque[float] = deque()
        self._tripped = False

    @property
    def tripped(self) -> bool:
        return self._tripped

    def violation(self, reason: str) -> bool:
        now = time.monotonic()
        self._violations.append(now)
        while self._violations and now - self._violations[0] > self.window_seconds:
            self._violations.popleft()
        count = len(self._violations)
        self.audit.event("runtime_violation", False, reason, count=count)
        if count >= self.violation_threshold and not self._tripped:
            self._tripped = True
            self.containment.engage(f"automatic circuit breaker: {count} violations/{self.window_seconds}s")
        return self._tripped

    def reset(self) -> None:
        self._violations.clear()
        self._tripped = False
        self.audit.event("monitor_reset", True, "operator reset")
