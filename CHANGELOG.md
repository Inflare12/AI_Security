# Changelog

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
