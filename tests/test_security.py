from pathlib import Path

import pytest

from airlock import Airlock, AuditLog, ContainmentController, KillSwitch, Policy, RuntimeMonitor, SecurityViolation


def policy(tmp_path: Path) -> Policy:
    return Policy.from_dict({
        "filesystem": {"read": [str(tmp_path)], "write": [str(tmp_path / "out")]},
        "commands": {"allowed": ["python"]},
        "limits": {"max_output_bytes": 1000},
    })


def test_network_denied_by_default(tmp_path):
    airlock = Airlock(policy(tmp_path), AuditLog(str(tmp_path / "audit.jsonl")))
    with pytest.raises(SecurityViolation):
        airlock.request_url("https://example.com")


def test_path_escape_denied(tmp_path):
    airlock = Airlock(policy(tmp_path), AuditLog(str(tmp_path / "audit.jsonl")))
    with pytest.raises(SecurityViolation):
        airlock.read_file(str(tmp_path.parent / "secret.txt"))


def test_shell_chaining_denied(tmp_path):
    airlock = Airlock(policy(tmp_path), AuditLog(str(tmp_path / "audit.jsonl")))
    with pytest.raises(SecurityViolation):
        airlock.run_command("python -c x ; whoami")


def test_secret_redaction(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    airlock = Airlock(policy(tmp_path), AuditLog(str(tmp_path / "audit.jsonl")))
    airlock.write_file(str(out / "x.txt"), "token=sk-1234567890abcdefXYZ")
    assert "sk-123" not in (out / "x.txt").read_text()
    assert "REDACTED_SECRET" in (out / "x.txt").read_text()


def test_kill_switch_blocks_actions(tmp_path):
    ks = KillSwitch(str(tmp_path / "KILL"))
    ks.engage("test")
    airlock = Airlock(policy(tmp_path), AuditLog(str(tmp_path / "audit.jsonl")), ks)
    with pytest.raises(SecurityViolation):
        airlock.read_file(str(tmp_path / "x.txt"))


def test_circuit_breaker_trips(tmp_path):
    ks = KillSwitch(str(tmp_path / "KILL"))
    containment = ContainmentController(ks, AuditLog(str(tmp_path / "audit.jsonl")))
    monitor = RuntimeMonitor(containment, violation_threshold=2)
    assert not monitor.violation("one")
    assert monitor.violation("two")
    assert ks.engaged
