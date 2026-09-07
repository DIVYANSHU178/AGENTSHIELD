"""
Thread-safe, high-performance sliding window rate limiter for AgentShield Phase 17.

Provides:
- In-memory thread-safe rate tracking using threading.RLock.
- Login failure tracking (10 failed attempts / 60s per IP and per normalized username).
- Sensitive operation rate limiting (30 req / 60s).
- General API rate limiting (300 req / 60s).
- Header inspection for X-Forwarded-For with fallback to client.host.
- Automatic eviction of expired records to prevent unbounded memory growth.
"""

import time
import threading
from typing import Dict, List, Optional, Tuple
from starlette.requests import Request
from fastapi import HTTPException, status
from app.core.observability.logging import get_logger

logger = get_logger("agentshield.hardening.rate_limiting")


class SlidingWindowRateLimiter:
    """Thread-safe in-memory rate limiter using sliding timestamp windows."""

    def __init__(self):
        self._lock = threading.RLock()
        self._records: Dict[str, List[float]] = {}
        self._last_cleanup = time.monotonic()
        self.enabled = True

        # Default limits
        self.login_failure_limit = 10
        self.login_failure_window = 60.0
        self.sensitive_limit = 30
        self.sensitive_window = 60.0
        self.general_limit = 300
        self.general_window = 60.0

    def _cleanup_expired(self, now: float, max_window: float = 60.0) -> None:
        """Periodically purge entries older than max_window."""
        if now - self._last_cleanup > 30.0 or len(self._records) > 2000:
            self._last_cleanup = now
            keys_to_delete = []
            for k, timestamps in list(self._records.items()):
                valid = [t for t in timestamps if now - t <= max_window]
                if valid:
                    self._records[k] = valid
                else:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                self._records.pop(k, None)

    def is_blocked(self, key: str, limit: int, window_seconds: float) -> Tuple[bool, float]:
        """
        Check if the key has met or exceeded the limit without recording a new hit.
        Returns (is_blocked, retry_after_seconds).
        """
        if not self.enabled:
            return False, 0.0

        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now, window_seconds)
            timestamps = self._records.get(key, [])
            valid = [t for t in timestamps if now - t < window_seconds]
            if len(valid) >= limit:
                oldest = valid[0]
                retry_after = max(1.0, window_seconds - (now - oldest))
                return True, retry_after
            return False, 0.0

    def record_hit(self, key: str, limit: int, window_seconds: float) -> Tuple[bool, int, float]:
        """
        Record a hit against a rate limit window.
        Returns (allowed: bool, remaining_tokens: int, retry_after_seconds: float).
        """
        if not self.enabled:
            return True, limit, 0.0

        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now, window_seconds)
            timestamps = self._records.setdefault(key, [])
            valid = [t for t in timestamps if now - t < window_seconds]

            if len(valid) >= limit:
                oldest = valid[0]
                retry_after = max(1.0, window_seconds - (now - oldest))
                self._records[key] = valid
                return False, 0, retry_after

            valid.append(now)
            self._records[key] = valid
            remaining = max(0, limit - len(valid))
            return True, remaining, 0.0

    def record_failure(self, key: str, window_seconds: float = 60.0) -> None:
        """Record a failure timestamp for rate tracking."""
        if not self.enabled:
            return

        now = time.monotonic()
        with self._lock:
            self._cleanup_expired(now, window_seconds)
            timestamps = self._records.setdefault(key, [])
            valid = [t for t in timestamps if now - t < window_seconds]
            valid.append(now)
            self._records[key] = valid

    def clear(self, key: str) -> None:
        """Clear records for a specific key (e.g. on successful login)."""
        with self._lock:
            self._records.pop(key, None)

    def reset_for_testing(self) -> None:
        """Reset all rate limiter state for clean test isolation."""
        with self._lock:
            self._records.clear()
            self._last_cleanup = time.monotonic()


# Global rate limiter singleton
rate_limiter = SlidingWindowRateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract authoritative client IP address from request."""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host.strip()
    return "127.0.0.1"


def normalize_username(username: str) -> str:
    """Normalize username for consistent bucket tracking."""
    return username.strip().lower() if username else ""


def check_login_rate_limit(request: Request, username: str) -> None:
    """
    Check if IP or username has exceeded failed login attempts limit.
    Raises HTTP 429 Too Many Requests if throttled.
    """
    if not rate_limiter.enabled:
        return

    ip = get_client_ip(request)
    norm_user = normalize_username(username)

    ip_blocked, ip_retry = rate_limiter.is_blocked(
        f"login_fail:ip:{ip}",
        rate_limiter.login_failure_limit,
        rate_limiter.login_failure_window,
    )
    if ip_blocked:
        logger.warning(
            f"Rate limit exceeded: IP '{ip}' blocked from login attempts for {int(ip_retry)}s",
            extra={"event": "RATE_LIMIT_EXCEEDED", "ip": ip, "retry_after": int(ip_retry)},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
            headers={"Retry-After": str(int(ip_retry))},
        )

    if norm_user:
        user_blocked, user_retry = rate_limiter.is_blocked(
            f"login_fail:user:{norm_user}",
            rate_limiter.login_failure_limit,
            rate_limiter.login_failure_window,
        )
        if user_blocked:
            logger.warning(
                f"Rate limit exceeded: user '{norm_user}' blocked from login attempts for {int(user_retry)}s",
                extra={"event": "RATE_LIMIT_EXCEEDED", "username": norm_user, "retry_after": int(user_retry)},
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
                headers={"Retry-After": str(int(user_retry))},
            )


def record_login_failure(request: Request, username: str) -> None:
    """Record a failed login attempt against both IP and username buckets."""
    if not rate_limiter.enabled:
        return

    ip = get_client_ip(request)
    norm_user = normalize_username(username)

    rate_limiter.record_failure(f"login_fail:ip:{ip}", rate_limiter.login_failure_window)
    if norm_user:
        rate_limiter.record_failure(f"login_fail:user:{norm_user}", rate_limiter.login_failure_window)


def record_login_success(request: Request, username: str) -> None:
    """Clear failed login records for the authenticated username."""
    norm_user = normalize_username(username)
    if norm_user:
        rate_limiter.clear(f"login_fail:user:{norm_user}")
