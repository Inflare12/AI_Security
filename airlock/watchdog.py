from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

from .audit import AuditLog
from .containment import ContainmentController
from .kill_switch import KillSwitch


def heartbeat_is_fresh(path: Path, timeout: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime <= timeout
    except FileNotFoundError:
        return False


def process_exists(pid: int) -> bool:
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return result.returncode == 0 and str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def watch(pid: int, heartbeat: str, kill_path: str, timeout: float = 15.0,
          interval: float = 2.0, audit_path: str = "airlock-audit.jsonl") -> int:
    if pid <= 0 or timeout <= 0 or interval <= 0:
        raise ValueError("pid, timeout and interval must be positive")
    kill_switch = KillSwitch(kill_path)
    audit = AuditLog(audit_path)
    containment = ContainmentController(kill_switch, audit)
    containment.register_pid(pid, "watched-ai")
    hb = Path(heartbeat)
    audit.event("watchdog_start", True, "watchdog started", pid=pid)
    while not kill_switch.engaged:
        if not process_exists(pid):
            return 0
        if not heartbeat_is_fresh(hb, timeout):
            containment.engage("watchdog heartbeat expired")
            return 2
        time.sleep(interval)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent AI heartbeat watchdog")
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--heartbeat", required=True)
    parser.add_argument("--kill-switch", default="AI_SECURITY_KILL")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--audit", default="airlock-audit.jsonl")
    args = parser.parse_args()
    return watch(args.pid, args.heartbeat, args.kill_switch, args.timeout, args.interval, args.audit)


if __name__ == "__main__":
    raise SystemExit(main())
