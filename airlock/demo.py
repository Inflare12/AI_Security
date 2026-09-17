from pathlib import Path

from .audit import AuditLog
from .guard import Airlock, SecurityViolation
from .policy import Policy


def main():
    workspace = Path("workspace")
    output = workspace / "output"
    output.mkdir(parents=True, exist_ok=True)
    policy = Policy.from_dict({
        "network": {"enabled": False},
        "filesystem": {"read": [str(workspace)], "write": [str(output)]},
        "commands": {"allowed": ["python"]},
    })
    airlock = Airlock(policy, AuditLog())
    try:
        airlock.request_url("https://example.com")
    except SecurityViolation as exc:
        print("blocked network:", exc)
    try:
        airlock.read_file(str(Path.home() / ".env"))
    except SecurityViolation as exc:
        print("blocked secret file:", exc)
    try:
        airlock.run_command("python ; whoami")
    except SecurityViolation as exc:
        print("blocked shell chaining:", exc)
    airlock.write_file(str(output / "hello.txt"), "hello from Airlock\n")
    print("allowed write completed")


if __name__ == "__main__":
    main()
