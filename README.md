# AI Security — Airlock + Shield

A local-first security layer for people running or building their own AI models.

**Goal:** make an AI runtime *capability-limited by default*: no arbitrary internet access, no arbitrary shell/process execution, no unrestricted filesystem access, and no direct access to secrets. Separately, the Shield gateway helps applications defend their AI-facing APIs against abusive or automated traffic.

> This project is a defensive control layer. It does not claim that model behavior can be made perfectly safe by prompt filtering alone. The primary boundary is the operating system/runtime and an explicit tool broker.

## Architecture

```text
                 LOCAL MACHINE
+-----------------------------------------------------------+
|  Your App / Agent                                         |
|       |                                                   |
|       v                                                   |
|  AI Security SDK                                          |
|       |  requests tools / network / files                |
|       v                                                   |
|  AIRLOCK POLICY ENGINE                                    |
|   - deny-by-default capabilities                          |
|   - domain allowlist                                      |
|   - path allowlist                                        |
|   - command allowlist                                     |
|   - rate + resource limits                                |
|   - secret redaction                                      |
|   - audit log                                             |
|       |                                                   |
|       +------> approved Tool Broker                       |
|       +------> approved Network Proxy                     |
|       +------> approved Files                             |
+-----------------------------------------------------------+

             OPTIONAL PUBLIC/API DEPLOYMENT

Client --> SHIELD GATEWAY --> your AI API
             |    |
             |    +--> rate limits / request size
             +-------> abuse/anomaly rules + audit
```

## What this MVP provides

- **Airlock policy engine** with deny-by-default decisions.
- **Network guard** that only permits explicitly approved HTTPS hosts.
- **Filesystem guard** with path containment checks.
- **Command guard** with an explicit executable allowlist.
- **Secret redaction** for common API-key/token formats before logs or model-visible tool output.
- **Audit logger** using JSON Lines.
- **Shield HTTP gateway** with request-size and rate-limit protection and a simple suspicious-request detector.
- No model is given a raw socket, arbitrary shell, or unrestricted file API through this layer.

## Important limitation

A Python wrapper cannot stop a model process that already has unrestricted OS privileges from bypassing the wrapper. For a strong boundary, run the model in a container/VM/sandbox with networking disabled and mount only the directories it needs. Airlock should sit *inside* that sandbox as the tool broker.

## Quick start

```bash
python -m airlock.demo
```

Run the Shield gateway:

```bash
pip install -r requirements.txt
uvicorn shield.gateway:app --host 127.0.0.1 --port 8787
```

Then configure your application to call your AI provider/model through the gateway rather than exposing the model directly.

## Example policy

```yaml
network:
  enabled: false
  allowed_hosts: []
filesystem:
  read:
    - ./workspace
  write:
    - ./workspace/output
commands:
  allowed:
    - python
limits:
  max_tool_calls_per_minute: 30
```

When internet access is genuinely required, use a narrow allowlist such as `api.example.com`, never unrestricted outbound access.

## Roadmap

1. OS-level sandbox adapters (Docker/Podman, Windows Job Objects/AppContainer, Linux namespaces/seccomp).
2. Signed policy files and policy-lock mode.
3. Model/tool capability manifests.
4. Human approval for high-risk actions.
5. Network DNS/IP pinning and SSRF protection.
6. Persistent tamper-evident audit storage.
7. A small desktop tray app showing active capabilities and a one-click **Kill AI** control.
8. Optional enterprise Shield service for fleet-wide telemetry and policy distribution.

## License

Apache-2.0 — see `LICENSE`.
