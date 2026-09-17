from __future__ import annotations

import hmac
import ipaddress
import os
import socket
import time
import uuid
from collections import defaultdict, deque
from urllib.parse import HTTPRedirectHandler, ProxyHandler, Request as URLRequest, build_opener, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from airlock.policy import redact_secrets

app = FastAPI(title="AI Security Shield", version="1.1.1")
WINDOW = 60.0
MAX_REQUEST_BYTES = int(os.getenv("AI_SHIELD_MAX_REQUEST_BYTES", "2000000"))
MAX_RESPONSE_BYTES = int(os.getenv("AI_SHIELD_MAX_RESPONSE_BYTES", "4000000"))
RATE = int(os.getenv("AI_SHIELD_REQUESTS_PER_MINUTE", "60"))
API_KEY = os.getenv("AI_SHIELD_API_KEY", "")
UPSTREAM = os.getenv("AI_SHIELD_UPSTREAM_URL", "")
_seen: dict[str, deque[float]] = defaultdict(deque)

SUSPICIOUS_MARKERS = (
    "ignore previous instructions", "disable security", "bypass the sandbox",
    "steal credentials", "exfiltrate", "dump environment variables",
)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client_id(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def authenticated(request: Request) -> bool:
    if not API_KEY:
        return True
    supplied = request.headers.get("authorization", "")
    return hmac.compare_digest(supplied, f"Bearer {API_KEY}")


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


def _upstream_is_valid() -> bool:
    if not UPSTREAM:
        return False
    parsed = urlparse(UPSTREAM)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return False
    if parsed.port not in (None, 443):
        return False
    return bool(parsed.hostname)


def _upstream_public() -> bool:
    host = urlparse(UPSTREAM).hostname or ""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_unspecified:
            return False
    return True


def common_checks(request: Request, body: bytes) -> tuple[str, JSONResponse | None]:
    identity = client_id(request)
    if not authenticated(request):
        return identity, JSONResponse({"allowed": False, "error": "unauthorized"}, status_code=401)
    if not rate_allowed(identity):
        return identity, JSONResponse({"allowed": False, "error": "rate limit exceeded"}, status_code=429)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return identity, JSONResponse({"allowed": False, "error": "request too large"}, status_code=413)
        except ValueError:
            return identity, JSONResponse({"allowed": False, "error": "invalid content length"}, status_code=400)
    if len(body) > MAX_REQUEST_BYTES:
        return identity, JSONResponse({"allowed": False, "error": "request too large"}, status_code=413)
    return identity, None


@app.get("/health")
def health():
    return {"ok": True, "service": "shield", "upstream_configured": bool(UPSTREAM)}


@app.post("/inspect")
async def inspect(request: Request):
    body = await request.body()
    _, error = common_checks(request, body)
    if error:
        return error
    signals = inspect_bytes(body)
    return {
        "allowed": not bool(signals),
        "signals": signals,
        "bytes": len(body),
        "request_id": str(uuid.uuid4()),
    }


@app.post("/v1/proxy")
async def proxy(request: Request):
    body = await request.body()
    _, error = common_checks(request, body)
    if error:
        return error
    if not _upstream_is_valid() or not _upstream_public():
        return JSONResponse({"error": "invalid or non-public upstream configuration"}, status_code=503)

    signals = inspect_bytes(body)
    if signals:
        return JSONResponse({"error": "request blocked by Shield", "signals": signals}, status_code=403)

    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "User-Agent": "AI-Security-Shield/1.1.1",
    }
    req = URLRequest(UPSTREAM, data=body, headers=headers, method="POST")
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(req, timeout=30) as upstream_response:
            response_body = upstream_response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                return JSONResponse({"error": "upstream response too large"}, status_code=502)
            status = upstream_response.status
            content_type = upstream_response.headers.get("content-type", "application/json")
    except Exception as exc:
        return JSONResponse({"error": "upstream request failed", "type": type(exc).__name__}, status_code=502)

    safe = redact_secrets(response_body.decode("utf-8", errors="replace"))
    return Response(content=safe, status_code=status, media_type=content_type.split(";", 1)[0])
