# Threat model

AI Security assumes the model/agent may be mistaken, manipulated, compromised, or intentionally goal-seeking. The security boundary must therefore not depend on the model obeying instructions.

## Threats covered

- Prompt injection causing unauthorized tool use
- Arbitrary filesystem reads/writes outside approved paths
- Shell/command injection
- Network exfiltration and unauthorized outbound requests
- SSRF attempts against private/reserved destinations
- Secret leakage into tool output or logs
- Runaway tool loops and request floods
- Resource exhaustion through oversized outputs/files
- Persistence attempts through writable policy/security directories
- Compromised model process attempting to bypass the Python SDK

## Controls

1. Deny-by-default capabilities.
2. Explicit filesystem and executable allowlists.
3. HTTPS host allowlisting and private/reserved IP blocking.
4. Request/response, timeout, and rate limits.
5. Secret redaction in audit and file outputs.
6. Immutable-from-the-model kill-switch placement.
7. Runtime circuit breaker that can engage containment after repeated violations.
8. Process-tree termination for registered model processes.
9. Optional operator-enabled host shutdown for emergency response.
10. Container-level isolation: no network, dropped capabilities, read-only root filesystem, limited CPU/RAM/PIDs.

## What this does NOT guarantee

The Python package is not a kernel boundary. A model process with unrestricted host privileges can bypass an in-process guard. Production deployments must run untrusted models in a hardened sandbox/container/VM and should keep the kill switch and policy outside model-writable paths.

The Shield gateway is not a universal internet firewall. It protects applications that route their traffic through it. It cannot stop an unrelated malicious AI running somewhere else.

## Incident response

When the circuit breaker trips:

1. Stop model/agent processes.
2. Preserve the audit log and relevant evidence.
3. Revoke/rotate credentials that the model could access.
4. Block network egress at the sandbox/network layer.
5. Inspect the model, tools, prompts, memory and policy changes.
6. Only release the kill switch after human review.

## Production principle

Treat policy as code. Review changes to capabilities like code changes, test them in CI, and never allow the model itself to edit or approve its own security policy.
