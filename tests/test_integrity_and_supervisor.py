from pathlib import Path
import sys

from airlock import AuditLog
from airlock.integrity import sha256_file, verify_file, verify_policy_file
from airlock.supervisor import AISupervisor
from airlock.containment import ContainmentController
from airlock.kill_switch import KillSwitch


def test_file_integrity(tmp_path: Path):
    target = tmp_path / "policy.json"
    target.write_text('{"safe":true}', encoding="utf-8")
    digest = sha256_file(target)
    assert verify_file(target, digest)
    target.write_text('{"safe":false}', encoding="utf-8")
    assert not verify_file(target, digest)
    verify_policy_file(target, None)


def test_audit_hash_chain(tmp_path: Path):
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    audit.event("one", True, "ok")
    audit.event("two", False, "blocked")
    assert audit.verify()
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    lines[0] = lines[0].replace("\"one\"", "\"tampered\"")
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not audit.verify()


def test_supervisor_strips_unapproved_environment(tmp_path: Path):
    ks = KillSwitch(str(tmp_path / "KILL"))
    audit = AuditLog(str(tmp_path / "audit.jsonl"))
    containment = ContainmentController(ks, audit)
    supervisor = AISupervisor(containment, audit)
    pid = supervisor.start([sys.executable, "-c", "print('ok')"], cwd=tmp_path,
                           env={"AI_TEST_VALUE": "not-inherited"})
    code = supervisor.wait(timeout=10)
    assert code == 0
    supervisor.reap()
    assert pid > 0
