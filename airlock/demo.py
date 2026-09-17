from pathlib import Path
from .audit import AuditLog
from .guard import Airlock, SecurityViolation
from .policy import Policy


def main() -> None:
    workspace = Path("workspace").resolve()
    output = (workspace / "output").resolve()
    output.mkdir(parents=True, exist_ok=True)

    policy = Policy.from_dict({
        "network": {"enabled": False, "allowed_hosts": []},
        "filesystem": {"read": [str(workspace)], "write": [str(output)]},
        "commands": {"allowed": ["python"]},
    })
    airlock = Airlock(policy, AuditLog("airlock-audit.jsonl"))

    print("AI Security Airlock demo")
    for label, action in [
        ("internet", lambda: airlock.request_url("https://example.com")),
        ("protected file", lambda: airlock.read_file(str(Path.home() / ".env"))),
        ("shell chain", lambda: airlock.run_command("python --version && whoami")),
    ]:
        try:
            action()
            print(f"[UNEXPECTED ALLOW] {label}")
        except (SecurityViolation, OSError, ValueError) as exc:
            print(f"[BLOCKED] {label}: {exc}")

    allowed = output / "hello.txt"
    airlock.write_file(str(allowed), "Airlock approved this write.\n")
    print(f"[ALLOWED] wrote {allowed}")


if __name__ == "__main__":
    main()
