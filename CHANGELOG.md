# Changelog

## 1.1.1

- Added operator-owned AI supervisor with absolute executable paths, minimal environment inheritance and process registration.
- Added independent heartbeat watchdog with cross-platform process detection.
- Added SHA-256 policy/file integrity verification helpers.
- Upgraded the audit log to a tamper-evident hash chain with verification support.
- Disabled free-form command arguments in Airlock to reduce arbitrary-code execution risk.
- Hardened Shield request-size handling and removed client identity from inspection responses.
- Added Shield, integrity, supervisor and regression security tests.
- Added `pip check`, Ruff and `pip-audit` gates to CI.
- Added Dependabot configuration and CODEOWNERS for security-sensitive paths.
- Updated documentation and version metadata.

## 1.1.0

- Hardened Shield authentication and client rate limiting.
- Disabled ambient proxy use and redirects for brokered HTTPS requests.
- Added fixed-upstream validation and response-size limits.
- Added Airlock tool-call rate limiting.
- Added public/private DNS destination checks as defense-in-depth.
- Hardened kill-switch marker creation and permissions.
- Hardened process containment registration and termination behavior.
- Added Python package discovery configuration so CI installs `airlock` and `shield` correctly.
- Added multi-version Python CI and coverage artifacts.
- Added security disclosure policy.

## 1.0.0

- Airlock capability policy engine.
- Network, filesystem and command guards.
- Secret redaction and JSONL audit trail.
- Runtime circuit breaker.
- Emergency containment and optional host shutdown.
- Docker sandbox example.
- Shield API gateway.
