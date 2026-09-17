from __future__ import annotations

import json
import os
import time
import uuid
from collections import defaultdict, deque
from urllib.parse import urlparse
from urllib.request import Request as URLRequest, urlopen

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from airlock.policy import redact_secrets

app = FastAPI(title="AI Security Shield", version="1.0.0")
WINDOW = 60.0
MAX_REQUEST_BYTES = int(os.getenv("AI_SHIELD_MAX_REQUEST_BYTES", "2000000"))
RATE = int(os.getenv("AI_SHIELD_REQUESTS_PER_MINUTE", "60"))
API_KEY = os.getenv("AI_SHIELD_API_KEY", "")
UPSTREAM = os.getenv("AI_SHIELD_UPSTREAM_URL", "")
_seen: dict[str, deque[float]] = defaultdict(deque)

SUSPICIOUS_MARKERS = (
    "ignore previous instructions", "disable security", "bypass the sandbox",
    "steal credentials", "exfiltrate", "dump environment variables",
)


def client_id(request: Request) -> str:
    return request.headers.get("x-client-id") or (request.client.host if request.client else "unknown")


def authenticated(request: Request) -> bool:
    if not API_KEY:
        return True  # Local deployments may intentionally run without an API key.
    return request.headers.get("authorization") == f"Bearer {API_KEY}"


def rate_allowed(identity: str) -> bool:
    now = time.monotonic()
    q = _seen[identity]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE:
        return False
    q.append(now)
    return True


def inspect_bytes(body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="replace").lower()
    return [marker for marker in SUSPICIOUS_MARKERS if marker in text]


def common_checks(request: Request, body: bytes) -> tuple[str, JSONResponse | None]:
    identity = client_id(request)
    if not authenticated(request):
        return identity, JSONResponse({"allowed": False, "error": "unauthorized"}, status_code=401)
    if not rate_allowed(identity):
        return identity, JSONResponse({"allowed": False, "error": "rate limit exceeded"}, status_code=429)
    if len(body) > MAX_REQUEST_BYTES:
        return identity, JSONResponse({"allowed": False, "error": "request too large"}, status_code=413)
    return identity, None


@app.get("/health")
def health():
    return {"ok": True, "service": "shield", "upstream_configured": bool(UPSTREAM)}


@app.post("/inspect")
async def inspect(request: Request):
    body = await request.body()
    identity, error = common_checks(request, body)
    if error:
        return error
    signals = inspect_bytes(body)
    return {
        "allowed": not bool(signals),
        "signals": signals,
        "bytes": len(body),
        "request_id": str(uuid.uuid4()),
        "identity": identity,
    }


@app.post("/v1/proxy")
async def proxy(request: Request):
    """Proxy to one fixed upstream URL configured by the operator.

    The client cannot choose the destination, preventing this endpoint from becoming
    an open proxy/SSRF primitive. The upstream must be HTTPS and contain no credentials.
    """
    body = await request.body()
    identity, error = common_checks(request, body)
    if error:
        return error
    if not UPSTREAM:
        return JSONResponse({"error": "AI_SHIELD_UPSTREAM_URL is not configured"}, status_code=503)
    parsed = urlparse(UPSTREAM)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return JSONResponse({"error": "invalid upstream configuration"}, status_code=500)
    signals = inspect_bytes(body)
    if signals:
        return JSONResponse({"error": "request blocked by Shield", "signals": signals}, status_code=403)

    headers = {"Content-Type": request.headers.get("content-type", "application/json"), "User-Agent": "AI-Security-Shield/1.0"}
    req = URLRequest(UPSTREAM, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=30) as upstream_response:
            response_body = upstream_response.read(MAX_REQUEST_BYTES)
            status = upstream_response.status
            content_type = upstream_response.headers.get("content-type", "application/json")
    except Exception as exc:
        return JSONResponse({"error": "upstream request failed", "type": type(exc).__name__}, status_code=502)

    return Response(content=redact_secrets(response_body.decode("utf-8", errors="replace")), status_code=status, media_type=content_type.split(";", 1)[0])
