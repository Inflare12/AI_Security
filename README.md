# AI Security — Airlock + Shield

A defensive, local-first security layer for people running their own AI models and agents.

**Core idea:** never rely on the model to keep itself safe. Put a security boundary around it: deny capabilities by default, isolate the runtime, monitor behavior, and have an emergency containment path that can stop the model before it can keep acting.

> **Important:** this is a security control layer, not a guarantee of perfect safety. For production, run untrusted AI inside a hardened container/VM and keep security policy and the kill switch outside anything the model can write.

## What is included

### 1. Airlock — capability firewall

Airlock is an in-process policy/tool broker:

- network disabled by default
- exact HTTPS host allowlist when network is enabled
- private/reserved IP blocking for basic SSRF defense
- read/write filesystem allowlists with path containment
- executable allowlist with shell metacharacter rejection
- command, network and file size/time limits
- secret redaction in logs and brokered writes
- structured JSONL audit trail
- fail-closed kill switch

### 2. Runtime Monitor — circuit breaker

Repeated policy violations can automatically trip the security boundary. The default example is **8 violations in 60 seconds**. When tripped, the monitor engages the kill switch and the containment controller terminates registered AI processes.

This is deliberately independent of the model's own reasoning.

### 3. Containment Controller — emergency stop

The controller can:

- engage the kill switch
- terminate registered model/agent process trees
- preserve an audit trail
- optionally request a full host OS shutdown

**Host shutdown is disabled by default** and requires explicit operator configuration. It is a last-resort response, not something an AI model should be given as a tool.

### 4. Shield — API defense gateway

Shield provides an application-facing boundary with:

- API-key authentication option
- per-client rate limiting
- request-size limits
- suspicious-request indicators
- a fixed-upstream proxy (the client cannot choose the destination)
- response secret redaction
- health endpoint

Shield is designed to sit in front of an AI API. It is not an open proxy and is not a universal firewall for the internet.

### 5. Sandbox

The included Docker configuration demonstrates the intended production boundary:

- `network_mode: none`
- dropped Linux capabilities
- `no-new-privileges`
- read-only root filesystem
- limited memory/CPU/process count
- only required directories mounted

For high-sensitivity deployments, use a stronger isolation boundary such as a hardened container runtime or VM.

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
                    | restricted filesystem     |
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

Client --> Shield --> fixed AI upstream
            |
            +--> auth / rate / size / abuse checks / audit
```

## Quick start

### Install

```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
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

CI runs the same regression suite on pushes and pull requests.

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

# The model should request capabilities through your application/tool adapter.
text = airlock.read_file("./workspace/input.txt")
```

Use `policy.example.json` as the starting point for your own policy.

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

Once engaged, Airlock refuses brokered actions.

### Automatic containment

```python
from airlock import AuditLog, ContainmentController, KillSwitch, RuntimeMonitor

kill = KillSwitch("/secure/operator/AI_SECURITY_KILL")
containment = ContainmentController(kill, AuditLog("audit.jsonl"))
monitor = RuntimeMonitor(containment, violation_threshold=8, window_seconds=60)

# Register the model process after you launch it.
containment.register_pid(model_process.pid)

# Feed security violations into the monitor.
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

Start it locally:

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
AI_SHIELD_API_KEY=replace-with-a-long-random-key
AI_SHIELD_REQUESTS_PER_MINUTE=60
AI_SHIELD_MAX_REQUEST_BYTES=2000000
```

Then clients use `/v1/proxy`. They cannot provide an arbitrary destination URL, which prevents this endpoint from becoming an open proxy.

## Production deployment rules

1. **Sandbox the model.** A Python wrapper is not a kernel security boundary.
2. **Default to no network.** If web access is needed, broker it through an allowlisted egress service.
3. **Do not mount secrets.** Never give the model your home directory, SSH keys, cloud credentials, `.env` files, Docker socket, or unrestricted device access.
4. **Keep policy and kill switch outside the model sandbox.** Make policy read-only to the model.
5. **Use least privilege.** Expose typed tools instead of arbitrary shell commands whenever possible.
6. **Limit resources.** CPU, RAM, disk, PIDs, request size, concurrency, retries and tool-chain depth should all be bounded.
7. **Log security events.** Keep audit logs outside model-writable storage and protect them from tampering.
8. **Test adversarially.** Add regression tests whenever a new tool, model, prompt, memory system or policy is introduced.
9. **Separate approval from execution.** High-impact actions should require an independent policy/approval layer.
10. **Have an incident procedure.** Know how to stop the model, revoke credentials, isolate networking, preserve evidence and recover.

## Threat model

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for threats, controls, residual risks and incident response.

## Why this architecture?

Modern agent security guidance emphasizes least privilege, sandboxing, restricted network egress, resource limits, monitoring, circuit breakers and independent approval for high-impact actions. AI Security is designed around those principles rather than relying on a prompt saying "don't do anything dangerous."

## Roadmap

- signed/versioned policy bundles
- policy integrity verification
- typed capability manifests
- Linux seccomp/AppArmor adapters
- Windows Job Objects/AppContainer adapter
- stronger DNS rebinding/SSRF controls through an external egress broker
- tamper-evident remote audit storage
- desktop tray dashboard + operator Kill AI button
- multi-agent identity and capability delegation
- approval tokens bound to exact high-impact actions
- fleet-wide policy management

## License

Apache-2.0 — see `LICENSE`.
