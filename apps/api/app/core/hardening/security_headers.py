"""
Security Headers and Cache-Control Enforcement Middleware for AgentShield Phase 17.

Enforces:
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Referrer-Policy: strict-origin-when-cross-origin
- Strict no-store Cache-Control headers on sensitive authentication, authorization,
  security operations, approval, and dev endpoints.
"""

from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

SENSITIVE_PATH_PREFIXES = (
    "/api/v1/auth",
    "/api/v1/security",
    "/api/v1/dev",
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    HTTP middleware attaching authoritative HTTP security headers and cache control policies.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response: Response = await call_next(request)

        # 1. Authoritative security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 2. Strict Cache-Control for sensitive paths
        path = request.url.path
        if any(path.startswith(prefix) for prefix in SENSITIVE_PATH_PREFIXES):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        elif "Cache-Control" not in response.headers:
            response.headers["Cache-Control"] = "no-cache"

        return response
