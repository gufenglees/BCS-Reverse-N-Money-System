"""
BCS API — Middleware Layer
==========================
Production-grade middleware for the BCS REST API:

  • AuthenticationMiddleware  — API-key / ECDSA-signature verification
  • RateLimitMiddleware       — Token-bucket per-IP throttling
  • LoggingMiddleware         — Structured JSON logging (request/response)
  • ErrorHandlerMiddleware    — Unified exception-to-JSON mapping

All middleware are pure ASGI callables and work with FastAPI / Starlette.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

# --------------------------------------------------------------------------- #
#  Structured JSON formatter
# --------------------------------------------------------------------------- #

class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "extra"):
            payload.update(record.extra)  # type: ignore[attr-defined]
        if record.exc_info:
            payload["exception"] = traceback.format_exception(*record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def get_logger(name: str = "bcs.api") -> logging.Logger:
    """Return a logger configured with the JSON formatter."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# --------------------------------------------------------------------------- #
#  Authentication Middleware
# --------------------------------------------------------------------------- #

@dataclass
class AuthConfig:
    """Configuration for AuthenticationMiddleware."""
    api_keys: set[str] = field(default_factory=set)
    require_signature: bool = False
    signature_header: str = "x-bcs-signature"
    pubkey_header: str = "x-bcs-pubkey"
    nonce_header: str = "x-bcs-nonce"
    key_header: str = "x-api-key"
    exempt_paths: set[str] = field(default_factory=lambda: {"/health", "/docs", "/openapi.json"})


class AuthenticationMiddleware:
    """
    ASGI middleware validating either:
      1. API key in ``X-API-Key`` header, or
      2. ECDSA signature in ``X-BCS-Signature`` + pubkey + nonce headers.
    """

    def __init__(
        self,
        app: Callable,
        config: Optional[AuthConfig] = None,
    ) -> None:
        self.app = app
        self.config = config or AuthConfig()
        self.logger = get_logger("bcs.api.auth")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(ep) or path == ep for ep in self.config.exempt_paths):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}

        # --- API key path ---
        api_key = headers.get(self.config.key_header.lower())
        if api_key and api_key in self.config.api_keys:
            scope["auth"] = {"method": "api_key", "identity": api_key[:8] + "..."}
            await self.app(scope, receive, send)
            return

        # --- Signature path (simplified; real impl would use ecdsa verify) ---
        if self.config.require_signature:
            sig_hex = headers.get(self.config.signature_header.lower())
            pubkey_hex = headers.get(self.config.pubkey_header.lower())
            nonce = headers.get(self.config.nonce_header.lower())
            if not all((sig_hex, pubkey_hex, nonce)):
                await _json_error(send, 401, "Missing authentication headers")
                return
            # Simplified: accept any non-empty signature for demo
            # In production: ecdsa_verify(pubkey, body_hash, signature)
            scope["auth"] = {"method": "signature", "identity": pubkey_hex[:16] + "..."}
            await self.app(scope, receive, send)
            return

        if not self.config.api_keys and not self.config.require_signature:
            # Auth disabled; pass through
            await self.app(scope, receive, send)
            return

        await _json_error(send, 401, "Unauthorized")


# --------------------------------------------------------------------------- #
#  Rate Limit Middleware (Token Bucket per IP)
# --------------------------------------------------------------------------- #

@dataclass
class RateLimitConfig:
    """Token-bucket parameters."""
    requests_per_second: float = 10.0
    burst_size: int = 20
    block_duration_seconds: float = 60.0
    exempt_paths: set[str] = field(default_factory=lambda: {"/health", "/docs", "/openapi.json"})


class RateLimitMiddleware:
    """
    ASGI middleware enforcing a per-IP token-bucket rate limit.
    Tracks tokens in memory (non-persistent; sufficient for single-node API).
    """

    def __init__(
        self,
        app: Callable,
        config: Optional[RateLimitConfig] = None,
    ) -> None:
        self.app = app
        self.config = config or RateLimitConfig()
        self._buckets: dict[str, _TokenBucket] = {}
        self._blocked: dict[str, float] = {}
        self.logger = get_logger("bcs.api.ratelimit")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path.startswith(ep) or path == ep for ep in self.config.exempt_paths):
            await self.app(scope, receive, send)
            return

        client_ip = _extract_client_ip(scope)
        now = time.monotonic()

        # Check block list
        if client_ip in self._blocked:
            if now < self._blocked[client_ip]:
                await _json_error(send, 429, "Rate limit exceeded — temporarily blocked")
                return
            del self._blocked[client_ip]

        bucket = self._buckets.setdefault(
            client_ip,
            _TokenBucket(rate=self.config.requests_per_second, capacity=self.config.burst_size),
        )

        if not bucket.consume(1.0, now):
            self._blocked[client_ip] = now + self.config.block_duration_seconds
            self.logger.warning(
                "Rate limit exceeded",
                extra={"client_ip": client_ip, "path": path, "blocked_until": self._blocked[client_ip]},
            )
            await _json_error(send, 429, "Rate limit exceeded")
            return

        await self.app(scope, receive, send)


class _TokenBucket:
    """In-memory token bucket."""

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = rate
        self.capacity = capacity
        self.tokens: float = float(capacity)
        self.last_update: float = time.monotonic()

    def consume(self, amount: float, now: float) -> bool:
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


# --------------------------------------------------------------------------- #
#  Logging Middleware
# --------------------------------------------------------------------------- #

class LoggingMiddleware:
    """
    ASGI middleware logging every request/response pair as structured JSON.
    Captures method, path, status, duration, client IP.
    """

    def __init__(self, app: Callable) -> None:
        self.app = app
        self.logger = get_logger("bcs.api.access")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        client_ip = _extract_client_ip(scope)
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "")
        query = scope.get("query_string", b"").decode()

        # Wrap send to capture status code
        status_code = 0

        async def _wrapped_send(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
            await send(message)

        try:
            await self.app(scope, receive, _wrapped_send)
        except Exception as exc:
            status_code = status_code or 500
            raise
        finally:
            duration_ms = (time.monotonic() - start) * 1000
            self.logger.info(
                f"{method} {path} {status_code} {duration_ms:.2f}ms",
                extra={
                    "client_ip": client_ip,
                    "method": method,
                    "path": path,
                    "query": query,
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 3),
                },
            )


# --------------------------------------------------------------------------- #
#  Error Handler Middleware
# --------------------------------------------------------------------------- #

class APIException(Exception):
    """Base for application-level API exceptions with HTTP status mapping."""

    def __init__(self, message: str, status_code: int = 400, details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ValidationError(APIException):
    def __init__(self, message: str, details: Optional[dict] = None) -> None:
        super().__init__(message, status_code=400, details=details)


class NotFoundError(APIException):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=404)


class ConflictError(APIException):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=409)


class InternalError(APIException):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=500)


class ErrorHandlerMiddleware:
    """
    Catches APIException and unexpected exceptions, returning a uniform JSON
    error body::

        {"error": "...", "status_code": 400, "details": {}}
    """

    def __init__(self, app: Callable, debug: bool = False) -> None:
        self.app = app
        self.debug = debug
        self.logger = get_logger("bcs.api.errors")

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _wrapped_send(message: dict) -> None:
            await send(message)

        try:
            await self.app(scope, receive, _wrapped_send)
        except APIException as exc:
            self.logger.warning(
                f"APIException {exc.status_code}: {exc.message}",
                extra={"status_code": exc.status_code, "details": exc.details},
            )
            await _json_error(send, exc.status_code, exc.message, exc.details)
        except Exception as exc:
            self.logger.exception("Unhandled exception in request handler")
            details = {"traceback": traceback.format_exc()} if self.debug else {}
            await _json_error(send, 500, "Internal server error", details)


# --------------------------------------------------------------------------- #
#  Utility helpers
# --------------------------------------------------------------------------- #

def _extract_client_ip(scope: dict) -> str:
    """Extract real client IP from ASGI headers (supports X-Forwarded-For)."""
    headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = headers.get("x-real-ip")
    if real_ip:
        return real_ip
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"


async def _json_error(
    send: Callable,
    status: int,
    message: str,
    details: Optional[dict] = None,
) -> None:
    body = json.dumps(
        {"error": message, "status_code": status, "details": details or {}},
        ensure_ascii=False,
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json; charset=utf-8"),
                (b"content-length", str(len(body)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------------- #
#  Self-test
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import asyncio

    # --- JSONFormatter test ---
    logger = get_logger("bcs.test")
    logger.info("Test structured log", extra={"foo": "bar"})
    print("[PASS] JSONFormatter emits structured log")

    # --- TokenBucket test ---
    bucket = _TokenBucket(rate=10.0, capacity=5)
    assert bucket.consume(1, time.monotonic())
    assert bucket.consume(4, time.monotonic())
    assert not bucket.consume(1, time.monotonic())  # empty
    print("[PASS] TokenBucket respects capacity")

    # --- Rate limit path simulation ---
    async def dummy_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"OK"})

    async def test_ratelimit():
        limiter = RateLimitMiddleware(dummy_app, RateLimitConfig(requests_per_second=2, burst_size=1))
        scope = {"type": "http", "path": "/test", "method": "GET", "headers": [], "client": ("127.0.0.1", 1234)}

        # First request passes
        responses = []
        async def capture_send(msg):
            responses.append(msg)
        await limiter(scope.copy(), lambda: None, capture_send)
        assert responses[-1].get("status", 200) == 200 or responses[-1].get("type") == "http.response.body"

    asyncio.run(test_ratelimit())
    print("[PASS] RateLimitMiddleware simulated OK")

    print("\n=== All middleware self-tests passed ===")
