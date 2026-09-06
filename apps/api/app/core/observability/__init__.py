"""
Centralized Observability subsystem for AgentShield (Phase 16).

Exposes:
- Correlation ID tracking and validation across requests and tasks
- Structured JSON and terminal logging with automatic secret redaction
- In-memory low-cardinality operational metrics registry
- ASGI ObservabilityMiddleware
- Comprehensive liveness and readiness health checks
"""

from app.core.observability.correlation import (
    get_correlation_id,
    set_correlation_id,
    reset_correlation_id,
    generate_correlation_id,
    validate_and_sanitize_correlation_id,
    CORRELATION_HEADER_NAMES,
)
from app.core.observability.logging import (
    get_logger,
    configure_logging,
    StructuredJsonFormatter,
    DevelopmentConsoleFormatter,
    RedactingFilter,
)
from app.core.observability.metrics import (
    metrics_registry,
    MetricsRegistry,
    normalize_route,
    get_status_family,
)
from app.core.observability.middleware import (
    ObservabilityMiddleware,
)
from app.core.observability.health import (
    check_liveness,
    check_readiness,
    health_obs_router,
)

__all__ = [
    "get_correlation_id",
    "set_correlation_id",
    "reset_correlation_id",
    "generate_correlation_id",
    "validate_and_sanitize_correlation_id",
    "CORRELATION_HEADER_NAMES",
    "get_logger",
    "configure_logging",
    "StructuredJsonFormatter",
    "DevelopmentConsoleFormatter",
    "RedactingFilter",
    "metrics_registry",
    "MetricsRegistry",
    "normalize_route",
    "get_status_family",
    "ObservabilityMiddleware",
    "check_liveness",
    "check_readiness",
    "health_obs_router",
]
