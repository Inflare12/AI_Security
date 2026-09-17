# AI Security — Airlock + Shield

A defensive, local-first security layer for people running their own AI models and agents.

**Core principle:** never rely on an AI model to keep itself safe. Put a security boundary around the runtime: deny capabilities by default, isolate the process, monitor violations, preserve evidence, and keep an operator-controlled emergency containment path outside the model.

> **Security note:** this project is a defense-in-depth control layer, not a guarantee of perfect security. For untrusted models, use a hardened container or VM, remove host secrets, keep policy and emergency controls outside the model-writable filesystem, and validate the exact deployment environment.

## Components

### Airlock

- network disabled by default
- exact HTTPS host allowlist
- private/reserved/loopback destination checks
- no ambient HTTP proxy and no redirects
- filesystem read/write allowlists with resolved-path containment
- shell metacharacter rejection
- free-form command arguments disabled by default
- tool-call and resource limits
- secret redaction
- fail-closed kill switch
- audit events for allowed and denied operations

### Runtime Monitor

A policy-violation circuit breaker. A configurable number of violations inside a rolling time window engages containment without asking the model for permission.

### Containment Controller

- operator/security-monitor emergency stop
- registered AI process tracking
- process-tree termination on Windows
- process-group termination on Unix-like systems
- optional host shutdown, disabled by default
- audit records for containment actions

The model is not given the containment controller as a normal capability.

### AI Supervisor

`AISupervisor` launches an operator-selected AI executable with:

- `shell=False`
- absolute executable path requirement
- minimal inherited environment
- stdin disabled
- stdout/stderr capture
- process registration with the containment controller
- Unix process-group isolation
- Windows Job Object process-tree isolation

Windows Job Objects allow a group of processes to be managed as a unit, including terminating the associated process tree. The supervisor uses a private unnamed Job Object for each Windows AI process. 

This is the preferred launch path when the AI must be supervised by Airlock.

### Watchdog

`airlock.watchdog` is a separate monitoring process that watches an AI PID and an operator-controlled heartbeat file. If the heartbeat expires, it engages containment. The watchdog never receives model output as an authorization signal.

### Policy Integrity

`airlock.integrity` provides SHA-256 file verification so deployments can pin a policy file to an expected digest before startup.

### Audit Log

The JSONL audit log is append-only from the application's perspective and uses a hash chain. `AuditLog.verify()` detects modification or deletion/reordering of existing events.

For important deployments, copy audit events to protected remote storage as well.

### Shield

An API defense gateway with:

- optional constant-time API-key authentication
- per-client rate limiting based on the actual connection address
- request and response size limits
- suspicious-request indicators
- fixed operator-configured HTTPS upstream
- no client-controlled destination
- no redirects or ambient proxy
- response secret redaction

Shield is **not** a universal internet firewall. Its suspicious-request detector is heuristic and should be treated as an abuse signal, not as semantic AI security.

### Docker sandbox

The included example uses:

- `network_mode: none`
- dropped Linux capabilities
- `no-new-privileges`
- read-only root filesystem
- CPU, memory and PID limits
- only required mounts

For higher-risk workloads, add a hardened container runtime or VM and host-level policy controls.

## Architecture

```text
                    UNTRUSTED AI / AGENT
                              |
                              v
                 +--------------------------+
                 |         AIRLOCK          |
                 | policy + capability     |
                 | limits + secret filter  |
                 +------------+-------------+
                              |
                    approved capability
                              v
                 +--------------------------+
                 | SANDBOX / TOOL BROKER    |
                 | restricted FS/network    |
                 +------------+-------------+
                              |
                              v
                         safe resource

        +-------------------+-------------------+
        |                   |                   |
        v                   v                   v
   Audit Log          Runtime Monitor      AI Supervisor
   hash chain         circuit breaker      process control
        |                   |                   |
        +-------------------+-------------------+
                              |
                              v
                    +--------------------------+
                    |       CONTAINMENT        |
                    | kill switch + stop tree |
                    +--------------------------+
                              ^
                              |
                         independent
                          watchdog

PUBLIC API:
Client --> Shield --> one fixed operator-configured upstream
```

## Quick start

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install everything needed for local development and tests:

```bash
python -m pip install -e ".[shield,test]"
```

Run the demo:

```bash
python -m airlock.demo
```

Run the test suite:

```bash
pytest -q
```

Security checks used by CI:

```bash
python -m pip check
ruff check airlock shield tests
pip-audit --skip-editable
```

## Policy

Start from `policy.example.json`. Keep the real policy outside every model-writable directory.

A minimal policy can disable every optional capability:

```python
from airlock import Airlock, AuditLog, Policy

policy = Policy.from_dict({
    "network": {"enabled": False, "allowed_hosts": [], "deny_private_ips": True},
    "filesystem": {"read": ["./workspace"], "write": ["./workspace/output"]},
    "commands": {"allowed": []},
})

airlock = Airlock(policy, AuditLog("audit.jsonl"))
```

### Policy integrity

After creating a policy, record its SHA-256 digest in the deployment configuration and verify it before starting the model:

```python
from airlock.integrity import verify_policy_file

verify_policy_file("/secure/policy.json", EXPECTED_POLICY_SHA256)
```

If the expected digest is supplied and does not match, startup should be aborted by the deployment supervisor.

## Emergency stop

The kill-switch file must live outside all model-writable paths:

```python
from airlock import KillSwitch

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
kill.engage("operator emergency stop")
```

While engaged, Airlock refuses brokered actions. Releasing the switch is an operator action:

```python
kill.release()
```

### Automatic containment

```python
from airlock import AuditLog, ContainmentController, KillSwitch, RuntimeMonitor

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
containment = ContainmentController(kill, AuditLog("audit.jsonl"))
monitor = RuntimeMonitor(containment, violation_threshold=8, window_seconds=60)

containment.register_pid(model_pid, name="my-model")
monitor.violation("attempted access outside policy")
```

When the threshold is reached, containment engages without model approval.

## Supervised AI launch

The supervisor requires an absolute executable path and strips most inherited environment variables:

```python
from airlock import AuditLog, AISupervisor, ContainmentController, KillSwitch

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
containment = ContainmentController(kill, AuditLog("audit.jsonl"))
supervisor = AISupervisor(containment)

pid = supervisor.start(["/absolute/path/to/your/model-runner"])
```

On Windows, the supervisor also places the process into a private Job Object so the process tree can be terminated as a unit. On Unix-like systems it starts a new process group and containment can terminate the group.

For high-risk deployment, put the supervised process inside Docker/VM isolation as well. The supervisor is process control, not a replacement for a kernel boundary.

## Watchdog

Start the watchdog outside the AI process and outside its writable directory:

```bash
python -m airlock.watchdog \
  --pid 12345 \
  --heartbeat /secure/operator/ai.heartbeat \
  --kill-switch /secure/operator/AI_SECURITY_KILL
```

The AI host application should update the heartbeat periodically. If it stops doing so, the watchdog engages containment.

## Host shutdown

Host shutdown is disabled by default and should only be used as a tested last-resort operator procedure:

```python
containment = ContainmentController(
    kill_switch=kill,
    audit=AuditLog("audit.jsonl"),
    allow_host_shutdown=True,
)
containment.shutdown_host("critical AI runtime incident")
```

This is never a normal model capability. Data is not intentionally deleted by the containment operation.

## Shield gateway

Start locally:

```bash
uvicorn shield.gateway:app --host 127.0.0.1 --port 8787
```

Health endpoint:

```text
GET http://127.0.0.1:8787/health
```

Request inspection:

```bash
curl -X POST http://127.0.0.1:8787/inspect \
  -H "Content-Type: application/json" \
  -d '{"prompt":"hello"}'
```

For proxy mode, configure one fixed HTTPS upstream:

```text
AI_SHIELD_UPSTREAM_URL=https://your-ai-api.example/v1/chat/completions
AI_SHIELD_API_KEY=use-a-long-random-secret
AI_SHIELD_REQUESTS_PER_MINUTE=60
AI_SHIELD_MAX_REQUEST_BYTES=2000000
AI_SHIELD_MAX_RESPONSE_BYTES=4000000
```

Do not expose a development instance with `AI_SHIELD_API_KEY` unset to the public internet.

## Production deployment checklist

1. Sandbox the model in a hardened container or VM.
2. Keep model networking disabled unless a narrowly scoped egress broker is required.
3. Never mount cloud credentials, SSH keys, `.env` files, Docker sockets or an unrestricted home directory.
4. Keep policy, kill switch, watchdog state and operator controls outside model-writable storage.
5. Prefer typed capabilities over free-form shell access.
6. Bound CPU, memory, disk, PIDs, request size, concurrency, retries and tool-call rate.
7. Keep audit logs outside model-writable storage and ship important events to protected storage.
8. Verify the policy digest before startup.
9. Require independent approval for high-impact actions.
10. Test the actual deployment, not only the Python library.
11. On Windows, validate the Job Object behavior under the exact account and parent-process environment used in production.
12. Have a documented incident process for containment, credential revocation, network isolation, evidence preservation and recovery.

## Testing and CI

CI tests the Linux build on Python 3.10–3.13 and runs a Windows Python 3.12 smoke suite. The Linux jobs perform:

- package installation
- dependency consistency checks
- Python compilation
- Ruff static checks
- dependency vulnerability auditing with `pip-audit --skip-editable`
- unit/security tests
- coverage reporting

The Windows smoke job performs package installation, dependency checks, compilation and the complete pytest suite, including supervised-process termination.

GitHub Actions is configured with read-only repository contents permissions. For stronger supply-chain controls, repository administrators should also require full-SHA pinning for third-party Actions and review workflow changes.

## Threat model

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for threats, controls, residual risks and incident response.

See [`SECURITY.md`](SECURITY.md) for vulnerability reporting and deployment security requirements.

## Status

**Version 1.1.1 development.** The repository contains the Airlock capability layer, runtime monitor, containment controller, supervised launcher, Windows Job Object isolation, watchdog, policy integrity checks, tamper-evident audit log, Shield gateway, Docker sandbox and automated Linux/Windows CI security checks.

Security is defense-in-depth. A passing CI suite means the tested code paths currently pass the automated gates; it does not mathematically prove the absence of every possible bug or deployment-specific vulnerability.

## License

Apache-2.0 — see `LICENSE`.
