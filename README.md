# AI Security — Airlock + Shield

A defensive, local-first security layer for people running their own AI models and agents.

**Core idea:** never rely on the model to keep itself safe. Put a security boundary around it: deny capabilities by default, isolate the runtime, monitor behavior, and keep an independent emergency containment path.

> **Important:** this is a security control layer, not a guarantee of perfect safety. For production, run untrusted AI inside a hardened container/VM and keep security policy, credentials and the kill switch outside anything the model can write.

## What is included

### Airlock — capability firewall

- network disabled by default
- exact HTTPS host allowlist
- private/reserved IP checks and DNS destination checks
- no ambient HTTP proxy use and no redirects in brokered requests
- filesystem read/write allowlists with path containment
- executable allowlist with shell-metacharacter rejection
- tool-call, command, network and file limits
- secret redaction in logs and brokered writes
- structured JSONL audit trail
- fail-closed kill switch

### Runtime Monitor — circuit breaker

Repeated policy violations can automatically trip the security boundary. The default example is **8 violations in 60 seconds**. When tripped, the monitor engages the kill switch and the containment controller terminates registered AI processes.

### Containment Controller — emergency stop

- engage kill switch
- terminate registered model/agent process trees
- preserve an audit trail
- optional full host OS shutdown

**Host shutdown is disabled by default** and must be explicitly enabled by an operator. It is a last-resort incident response action, never a normal AI capability.

### Shield — API defense gateway

- optional API-key authentication
- per-client IP rate limiting without trusting spoofable client identity headers
- request and response-size limits
- suspicious-request indicators
- fixed operator-configured HTTPS upstream
- no client-controlled destination
- no redirects or ambient HTTP proxy use
- response secret redaction
- health endpoint

Shield is an API boundary, not a universal firewall for the internet.

### Sandbox

The included Docker configuration demonstrates a strong default runtime boundary:

- `network_mode: none`
- dropped Linux capabilities
- `no-new-privileges`
- read-only root filesystem
- limited memory/CPU/process count
- only required directories mounted

For high-sensitivity deployments, use a hardened container runtime or VM in addition to Airlock.

## Architecture

```text
                         UNTRUSTED AI / AGENT
                                  |
                                  | tool request
                                  v
                    +---------------------------+
                    |         AIRLOCK            |
                    | deny-by-default policy     |
                    | files / network / command  |
                    | limits + secret redaction |
                    +-------------+-------------+
                                  |
                         approved capability
                                  v
                    +---------------------------+
                    |   SANDBOX / TOOL BROKER    |
                    | no host secrets            |
                    | restricted filesystem      |
                    | restricted network        |
                    +-------------+-------------+
                                  |
                                  v
                        allowed resource/tool

                    +---------------------------+
                    |      RUNTIME MONITOR       |
                    | violations / rate spikes  |
                    | circuit breaker            |
                    +-------------+-------------+
                                  |
                            threshold hit
                                  v
                    +---------------------------+
                    |      CONTAINMENT           |
                    | kill switch + process stop |
                    | optional host shutdown     |
                    +---------------------------+

PUBLIC API PATH

Client --> Shield --> one fixed AI upstream
            |
            +--> auth / rate / size / abuse checks
```

## Quick start

### Install

```bash
python -m venv .venv
# Windows PowerShell
.\\.venv\\Scripts\\Activate.ps1
# Linux/macOS
# source .venv/bin/activate

pip install -e ".[shield,test]"
```

### Run the demo

```bash
python -m airlock.demo
```

### Run tests

```bash
pytest -q
```

The GitHub Actions workflow tests Python 3.10–3.13, installs the package itself, compiles the security modules and produces coverage artifacts.

## Using Airlock

```python
from airlock import Airlock, AuditLog, Policy

policy = Policy.from_dict({
    "network": {
        "enabled": False,
        "allowed_hosts": [],
        "deny_private_ips": True,
    },
    "filesystem": {
        "read": ["./workspace"],
        "write": ["./workspace/output"],
    },
    "commands": {"allowed": []},
})

airlock = Airlock(policy, AuditLog("audit.jsonl"))
text = airlock.read_file("./workspace/input.txt")
```

Use `policy.example.json` as the starting point. Keep the policy outside model-writable directories.

## Emergency stop

The kill switch is a file that must be outside all model-writable directories.

```python
from airlock import KillSwitch

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
kill.engage("operator emergency stop")
```

After investigation, an operator can explicitly release it:

```python
kill.release()
```

While engaged, Airlock refuses brokered actions.

### Automatic containment

```python
from airlock import AuditLog, ContainmentController, KillSwitch, RuntimeMonitor

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
containment = ContainmentController(kill, AuditLog("audit.jsonl"))
monitor = RuntimeMonitor(containment, violation_threshold=8, window_seconds=60)

containment.register_pid(model_process.pid, name="my-model")
monitor.violation("attempted access outside policy")
```

When the threshold is reached, containment engages automatically.

## Optional host shutdown

Do **not** enable this unless your deployment has a tested emergency procedure.

```python
containment = ContainmentController(
    kill_switch=kill,
    audit=AuditLog("audit.jsonl"),
    allow_host_shutdown=True,
)

# Operator/security monitor only:
containment.shutdown_host("critical AI runtime incident")
```

The shutdown method is intentionally not part of `Airlock` and should never be exposed as a normal model tool.

## Shield gateway

Start locally:

```bash
uvicorn shield.gateway:app --host 127.0.0.1 --port 8787
```

Health:

```text
GET http://127.0.0.1:8787/health
```

Inspect a request:

```bash
curl -X POST http://127.0.0.1:8787/inspect \
  -H "Content-Type: application/json" \
  -d '{"prompt":"hello"}'
```

For a protected upstream, configure a **single fixed HTTPS destination**:

```text
AI_SHIELD_UPSTREAM_URL=https://your-ai-api.example/v1/chat/completions
AI_SHIELD_API_KEY=use-a-long-random-secret
AI_SHIELD_REQUESTS_PER_MINUTE=60
AI_SHIELD_MAX_REQUEST_BYTES=2000000
AI_SHIELD_MAX_RESPONSE_BYTES=4000000
```

Then clients use `/v1/proxy`. They cannot provide an arbitrary destination URL, so this endpoint is not an open proxy.

If `AI_SHIELD_API_KEY` is unset, authentication is intentionally disabled for local development. Do not expose that configuration publicly.

## Sandbox deployment

Start from the included `sandbox/docker-compose.yml` and replace the placeholder model command with your runner. The model should not receive the Docker socket, host credentials, unrestricted filesystem mounts or a network interface.

If the model genuinely needs internet access, prefer a separate egress broker that performs domain/IP policy checks instead of enabling unrestricted networking inside the model container.

## Production deployment rules

1. **Sandbox the model.** A Python wrapper is not a kernel security boundary.
2. **Default to no network.** Broker required web access through a narrow egress layer.
3. **Do not mount secrets.** Never give the model SSH keys, cloud credentials, `.env` files, Docker socket or an unrestricted home directory.
4. **Keep policy and kill switch outside the model sandbox.** Make policy read-only to the model.
5. **Use least privilege.** Prefer typed tools with fixed schemas over arbitrary shell commands.
6. **Limit resources.** CPU, RAM, disk, PIDs, request size, concurrency, retries and tool-chain depth should all be bounded.
7. **Protect audit logs.** Keep them outside model-writable storage and ship them to protected storage for important deployments.
8. **Test adversarially.** Add regression tests whenever a new tool, model, memory system or prompt pathway is introduced.
9. **Separate approval from execution.** High-impact actions should require an independent policy/approval layer.
10. **Have an incident procedure.** Know how to stop the model, revoke credentials, isolate networking, preserve evidence and recover.

## Threat model

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for threats, controls, residual risks and incident response.

For security vulnerabilities, see [`SECURITY.md`](SECURITY.md).

## Current status

**Release line: 1.1.x development.** The repository contains the core Airlock, containment, monitor, Shield and Docker-sandbox components. Treat the project as security-sensitive software: review the threat model and validate the exact deployment environment before using it to protect valuable systems.

## Roadmap

- signed/versioned policy bundles
- policy integrity verification
- typed capability manifests
- Linux seccomp/AppArmor adapters
- Windows Job Objects/AppContainer adapter
- dedicated DNS-pinned egress broker
- tamper-evident remote audit storage
- desktop tray dashboard + operator Kill AI button
- multi-agent identity and capability delegation
- approval tokens bound to exact high-impact actions
- fleet-wide policy management

## License

Apache-2.0 — see `LICENSE`.
