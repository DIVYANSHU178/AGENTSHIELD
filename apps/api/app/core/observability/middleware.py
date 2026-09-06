"""
Centralized Observability and Correlation Middleware for AgentShield.

Enforces correlation ID propagation, request latency tracking, structured access logging,
and operational metrics collection across all inbound ASGI HTTP requests.
"""

import time
import logging
from typing import Callable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.observability.correlation import (
    CORRELATION_HEADER_NAMES,
    validate_and_sanitize_correlation_id,
    set_correlation_id,
    reset_correlation_id,
)
from app.core.observability.metrics import metrics_registry
from app.core.observability.logging import get_logger

logger = get_logger("agentshield.access")


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    HTTP Middleware that:
    1. Extracts and validates inbound X-Correlation-ID / X-Request-ID (or generates a new one).
    2. Stores the correlation ID in contextvars for the duration of the request lifecycle.
    3. Records request start time and duration.
    4. Records HTTP metrics in the MetricsRegistry.
    5. Injects X-Correlation-ID header into the outbound HTTP response.
    6. Emits structured access log lines.
    7. Strictly resets contextvars in a finally block.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Extract correlation ID from headers
        inbound_corr_id = None
        for header_name in CORRELATION_HEADER_NAMES:
            val = request.headers.get(header_name)
            if val:
                inbound_corr_id = val
                break

        # 2. Validate / generate
        correlation_id = validate_and_sanitize_correlation_id(inbound_corr_id)

        # 3. Bind to contextvars
        token = set_correlation_id(correlation_id)

        # Store on request.state for convenient access in endpoints
        request.state.correlation_id = correlation_id

        start_time = time.perf_counter()
        status_code = 500
        response = None

        try:
            response = await call_next(request)
            status_code = response.status_code
            # Attach correlation ID header to response
            response.headers["X-Correlation-ID"] = correlation_id
            return response

        except Exception as exc:
            # Let the application's global exception handler process it,
            # but record the duration and metric here if it bubbles up
            status_code = 500
            logger.error(
                f"Unhandled request exception on {request.method} {request.url.path}: {str(exc)}",
                exc_info=True,
                extra={
                    "correlation_id": correlation_id,
                    "event": "UNHANDLED_EXCEPTION",
                    "outcome": "ERROR",
                    "path": request.url.path,
                    "method": request.method,
                },
            )
            raise exc

        finally:
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Update metrics
            metrics_registry.record_http_request(
                method=request.method,
                path=request.url.path,
                status_code=status_code,
                duration_ms=duration_ms,
            )

            # Emit structured access log
            log_level = logging.INFO
            if status_code >= 500:
                log_level = logging.ERROR
            elif status_code >= 400:
                log_level = logging.WARNING

            # Avoid spamming access logs for routine rapid health probes in tests/production
            is_health = request.url.path in ("/health", "/health/live", "/health/ready", "/api/v1/health")
            if not is_health or status_code >= 400:
                logger.log(
                    log_level,
                    f"HTTP {request.method} {request.url.path} -> {status_code} ({duration_ms:.2f}ms)",
                    extra={
                        "correlation_id": correlation_id,
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": status_code,
                        "duration_ms": duration_ms,
                        "event": "HTTP_REQUEST",
                        "outcome": "SUCCESS" if status_code < 400 else "FAILURE",
                    },
                )

            # Strictly reset contextvar
            reset_correlation_id(token)
