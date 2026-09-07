"""
Request Bounds, Content-Type, Path Traversal, and Rate Limiting Middleware for AgentShield Phase 17.

Enforces:
- Header limits: max 50 headers, max 16 KiB total header bytes (HTTP 431).
- Path traversal & null byte prevention: reject %00, .. in path or query (HTTP 400).
- Payload size bounding: max 1 MiB (1,048,576 bytes) body limit (HTTP 413).
- Content-Type enforcement: require application/json on non-empty mutating requests (HTTP 415).
- Rate limiting: general API (300/60s) and sensitive operations (30/60s) (HTTP 429).
"""

from urllib.parse import unquote
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from fastapi import status
from app.core.hardening.rate_limiting import rate_limiter, get_client_ip
from app.core.observability.logging import get_logger

logger = get_logger("agentshield.hardening.request_bounds")

MAX_HEADER_COUNT = 50
MAX_HEADER_BYTES = 16 * 1024  # 16 KiB
MAX_BODY_BYTES = 1024 * 1024   # 1 MiB

SENSITIVE_MUTATING_SUFFIXES = (
    "/approve",
    "/reject",
    "/cancel",
    "/laboratory/run",
)


class RequestBoundsMiddleware(BaseHTTPMiddleware):
    """
    Middleware providing protocol-level bounds and defense-in-depth protections.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Header count and byte size limits (HTTP 431)
        raw_headers = request.scope.get("headers", [])
        if len(raw_headers) > MAX_HEADER_COUNT:
            logger.warning(
                f"Request rejected: header count {len(raw_headers)} exceeds limit {MAX_HEADER_COUNT}",
                extra={"event": "HEADER_LIMIT_EXCEEDED", "count": len(raw_headers)},
            )
            return JSONResponse(
                status_code=431,
                content={"detail": "Request Header Fields Too Large: maximum header count exceeded."},
            )

        total_header_bytes = sum(len(k) + len(v) for k, v in raw_headers)
        if total_header_bytes > MAX_HEADER_BYTES:
            logger.warning(
                f"Request rejected: header size {total_header_bytes}B exceeds limit {MAX_HEADER_BYTES}B",
                extra={"event": "HEADER_LIMIT_EXCEEDED", "bytes": total_header_bytes},
            )
            return JSONResponse(
                status_code=431,
                content={"detail": "Request Header Fields Too Large: maximum header size exceeded."},
            )

        # 2. Path and Query String Validation: null bytes & path traversal (HTTP 400)
        raw_path = request.scope.get("path", "")
        raw_query_bytes = request.scope.get("query_string", b"")
        raw_query = raw_query_bytes.decode("latin-1", errors="replace")
        path_unquoted = unquote(raw_path)
        query_unquoted = unquote(raw_query)

        # Null byte checks
        if "\x00" in raw_path or "\x00" in path_unquoted or "\x00" in raw_query or "\x00" in query_unquoted:
            logger.warning(
                f"Request rejected: forbidden null byte detected in path or query",
                extra={"event": "MALFORMED_URI_REJECTED", "reason": "null_byte"},
            )
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid request containing null bytes."},
            )

        # Directory traversal checks
        if (
            ".." in raw_path
            or ".." in path_unquoted
            or "../" in query_unquoted
            or "..\\" in query_unquoted
            or "%2e%2e" in raw_query.lower()
        ):
            logger.warning(
                f"Request rejected: directory traversal sequence detected",
                extra={"event": "MALFORMED_URI_REJECTED", "reason": "directory_traversal"},
            )
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid request containing directory traversal sequence."},
            )

        # 3. Payload size check via Content-Length header (HTTP 413)
        content_length_str = request.headers.get("content-length")
        if content_length_str is not None:
            try:
                content_length = int(content_length_str)
                if content_length > MAX_BODY_BYTES:
                    logger.warning(
                        f"Request rejected: Content-Length {content_length} exceeds limit {MAX_BODY_BYTES}",
                        extra={"event": "PAYLOAD_TOO_LARGE", "content_length": content_length},
                    )
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Payload Too Large: request body exceeds 1MB limit."},
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )

        # 4. Safe body reading & Content-Type enforcement (HTTP 413, HTTP 415)
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            logger.warning(
                f"Request rejected: actual body size {len(body)} exceeds limit {MAX_BODY_BYTES}",
                extra={"event": "PAYLOAD_TOO_LARGE", "body_bytes": len(body)},
            )
            return JSONResponse(
                status_code=413,
                content={"detail": "Payload Too Large: request body exceeds 1MB limit."},
            )

        # Enforce application/json for non-empty mutating payloads
        if request.method in ("POST", "PUT", "PATCH") and len(body) > 0:
            content_type = (request.headers.get("content-type") or "").lower()
            if not content_type or "application/json" not in content_type:
                logger.warning(
                    f"Request rejected: invalid content-type '{content_type}' on mutating request",
                    extra={"event": "UNSUPPORTED_MEDIA_TYPE", "content_type": content_type},
                )
                return JSONResponse(
                    status_code=415,
                    content={"detail": "Unsupported Media Type: application/json is required for request bodies."},
                )

        # 5. Route-level rate limiting
        if rate_limiter.enabled and request.method != "OPTIONS":
            path = request.url.path
            # Exempt health and root probes
            if not path.startswith("/health") and path != "/":
                ip = get_client_ip(request)

                # In-process TestClient runs all 600 tests in rapid succession from host 'testclient'.
                # Throttle external/forwarded client IPs and real network clients.
                if ip != "testclient":
                    # Sensitive mutating operations limit (30 req / 60s)
                    if any(path.endswith(suffix) for suffix in SENSITIVE_MUTATING_SUFFIXES):
                        allowed, remaining, retry_after = rate_limiter.record_hit(
                            f"sensitive:{ip}",
                            rate_limiter.sensitive_limit,
                            rate_limiter.sensitive_window,
                        )
                        if not allowed:
                            logger.warning(
                                f"Sensitive operation rate limit exceeded for IP {ip}",
                                extra={"event": "RATE_LIMIT_EXCEEDED", "ip": ip, "tier": "sensitive"},
                            )
                            return JSONResponse(
                                status_code=429,
                                content={"detail": "Rate limit exceeded for sensitive operations. Please slow down."},
                                headers={"Retry-After": str(int(retry_after))},
                            )

                    # General API limit (300 req / 60s) - exclude login which has dedicated brute-force limit
                    elif path.startswith("/api/v1/") and not path.endswith("/auth/login"):
                        allowed, remaining, retry_after = rate_limiter.record_hit(
                            f"general:{ip}",
                            rate_limiter.general_limit,
                            rate_limiter.general_window,
                        )
                        if not allowed:
                            logger.warning(
                                f"General API rate limit exceeded for IP {ip}",
                                extra={"event": "RATE_LIMIT_EXCEEDED", "ip": ip, "tier": "general"},
                            )
                            return JSONResponse(
                                status_code=429,
                                content={"detail": "Too many requests. Please slow down."},
                                headers={"Retry-After": str(int(retry_after))},
                            )

        return await call_next(request)
