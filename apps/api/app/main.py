from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database import init_db
from app.api import api_router
from app.schemas.health import HealthResponse
from app.core.observability import (
    ObservabilityMiddleware,
    configure_logging,
    get_correlation_id,
    generate_correlation_id,
    get_logger,
    health_obs_router,
)
from app.core.hardening import (
    SecurityHeadersMiddleware,
    RequestBoundsMiddleware,
    validation_exception_handler,
)

logger = get_logger("agentshield.main")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for database initialization, logging, and startup security validation."""
    configure_logging(settings.ENVIRONMENT)
    if settings.is_production():
        settings.validate_production_secrets()
    init_db()
    logger.info(
        f"AgentShield API online: environment={settings.ENVIRONMENT}",
        extra={"event": "STARTUP", "outcome": "SUCCESS", "environment": settings.ENVIRONMENT},
    )
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description="AgentShield Security Layer API",
    version="0.1.0",
    lifespan=lifespan
)

# API Hardening Middlewares (Request Bounds, Content-Type, Traversal Defense, Rate Limiting, Security Headers)
app.add_middleware(RequestBoundsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

# Centralized Observability Middleware (correlation IDs, request timing, metrics, access logs)
app.add_middleware(ObservabilityMiddleware)

# Dynamic CORS Configuration supporting localhost and configurable LAN origins
cors_kwargs = {
    "allow_origins": settings.get_cors_origins(),
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
}
origin_regex = settings.get_cors_origin_regex()
if origin_regex:
    cors_kwargs["allow_origin_regex"] = origin_regex

app.add_middleware(CORSMiddleware, **cors_kwargs)

# Standardized and sanitized validation error handling
app.add_exception_handler(RequestValidationError, validation_exception_handler)


# Direct health endpoint at root /health (preserves backward compatibility)
@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Root health check endpoint."""
    return HealthResponse(status="ok", service="agentshield", environment=settings.ENVIRONMENT)

# Root liveness and readiness health endpoints (/health/live, /health/ready)
app.include_router(health_obs_router)

# Include API v1 router
app.include_router(api_router, prefix="/api/v1")

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors with strict secret sanitization and correlation attribution."""
    from app.security.audit.redaction import sanitize_string_value
    corr_id = None
    if hasattr(request, "state") and hasattr(request.state, "correlation_id"):
        raw_cid = request.state.correlation_id
        if isinstance(raw_cid, str) and raw_cid:
            corr_id = raw_cid
    if not corr_id:
        cid = get_correlation_id()
        corr_id = cid if (isinstance(cid, str) and cid) else generate_correlation_id()

    try:
        path = str(request.url.path)
        method = str(request.method)
    except Exception:
        path = "unknown"
        method = "unknown"

    logger.error(
        f"Unhandled server exception on {method} {path}: {type(exc).__name__}: {str(exc)}",
        exc_info=True,
        extra={
            "correlation_id": corr_id,
            "event": "UNHANDLED_EXCEPTION",
            "outcome": "ERROR",
            "path": path,
            "method": method,
        },
    )

    headers = {
        "X-Correlation-ID": corr_id,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    if settings.is_dev_mode():
        sanitized_error = sanitize_string_value(str(exc))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": sanitized_error, "correlation_id": corr_id},
            headers=headers,
        )

    # In production and QA, prevent internal information disclosure
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": "An unexpected error occurred.", "correlation_id": corr_id},
        headers=headers,
    )
