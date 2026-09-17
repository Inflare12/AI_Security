from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="AI Security Shield", version="0.1.0")

WINDOW = 60.0
MAX_REQUEST_BYTES = int(os.getenv("AI_SHIELD_MAX_REQUEST_BYTES", "2000000"))
RATE = int(os.getenv("AI_SHIELD_REQUESTS_PER_MINUTE", "60"))
_seen: dict[str, deque[float]] = defaultdict(deque)

# These are deliberately broad indicators, not a claim that text alone proves malicious intent.
SUSPICIOUS_MARKERS = (
    "ignore previous instructions",
    "disable security",
    "bypass the sandbox",
    "steal credentials",
    "exfiltrate",
)


def client_id(request: Request) -> str:
    # Prefer a deployment's authenticated identity in production. IP is only a fallback.
    return request.headers.get("x-client-id") or (request.client.host if request.client else "unknown")


def rate_allowed(identity: str) -> bool:
    now = time.monotonic()
    q = _seen[identity]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE:
        return False
    q.append(now)
    return True


@app.get("/health")
def health():
    return {"ok": True, "service": "shield"}


@app.post("/inspect")
async def inspect(request: Request):
    identity = client_id(request)
    if not rate_allowed(identity):
        return JSONResponse({"allowed": False, "reason": "rate limit exceeded"}, status_code=429)

    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        return JSONResponse({"allowed": False, "reason": "request too large"}, status_code=413)

    text = body.decode("utf-8", errors="replace").lower()
    markers = [m for m in SUSPICIOUS_MARKERS if m in text]
    # Shield reports signals; the protected application decides whether to block or require review.
    return {
        "allowed": not bool(markers),
        "signals": markers,
        "bytes": len(body),
        "identity": identity,
    }
