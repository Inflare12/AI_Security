# Security Policy

## Scope

AI Security is a defensive control layer for AI runtimes, agents and AI-facing APIs. It is not a guarantee that an AI system can never be compromised or that every attack can be detected.

## Reporting a vulnerability

Please do not publish an unpatched vulnerability as a public issue.

For security reports, use GitHub's private vulnerability reporting feature for this repository when available. Include:

- affected version/commit
- deployment environment
- exact reproduction steps
- expected vs actual security boundary
- logs or minimal proof-of-concept where safe
- suggested mitigation, if known

Do not include API keys, passwords, private user data, or other secrets in a report.

## Security design requirements

Production deployments should:

1. run untrusted models in a hardened container or VM;
2. disable model networking unless explicitly brokered;
3. keep policy files, credentials and the kill switch outside model-writable paths;
4. avoid exposing the Docker socket, host filesystem, SSH keys or cloud credentials;
5. use typed tools instead of arbitrary shell commands where possible;
6. keep audit logs outside model-writable storage;
7. configure resource limits and an independent emergency stop;
8. test every new tool and model with adversarial regression cases.

## Emergency containment

The emergency controller can terminate registered AI processes. Full host shutdown is intentionally disabled by default and should only be enabled as part of a tested operator incident procedure.

Never expose host shutdown or containment credentials as ordinary model tools.
