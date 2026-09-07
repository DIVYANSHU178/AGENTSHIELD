"""
AgentShield Phase 17: Centralized API and Service Hardening Subsystem.

Exports:
- SecurityHeadersMiddleware: Nosniff, DENY, referrer policy, strict cache control.
- RequestBoundsMiddleware: Payload size limits, header bounds, Content-Type enforcement,
  path traversal prevention, and rate limiting.
- SlidingWindowRateLimiter, rate_limiter, check_login_rate_limit, record_login_failure,
  record_login_success: Login brute force and tier-based rate limiting.
- validation_exception_handler: Standardized, sanitized 422 validation error handler.
"""

from app.core.hardening.security_headers import SecurityHeadersMiddleware
from app.core.hardening.request_bounds import RequestBoundsMiddleware
from app.core.hardening.rate_limiting import (
    SlidingWindowRateLimiter,
    rate_limiter,
    get_client_ip,
    check_login_rate_limit,
    record_login_failure,
    record_login_success,
)
from app.core.hardening.errors import validation_exception_handler

__all__ = [
    "SecurityHeadersMiddleware",
    "RequestBoundsMiddleware",
    "SlidingWindowRateLimiter",
    "rate_limiter",
    "get_client_ip",
    "check_login_rate_limit",
    "record_login_failure",
    "record_login_success",
    "validation_exception_handler",
]
