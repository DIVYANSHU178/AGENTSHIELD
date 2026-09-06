from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.database import init_db
from app.api import api_router
from app.schemas.health import HealthResponse

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for database initialization and startup security validation."""
    if settings.is_production():
        settings.validate_production_secrets()
    init_db()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description="AgentShield Security Layer API",
    version="0.1.0",
    lifespan=lifespan
)

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


# Direct health endpoint at root /health
@app.get("/health", response_model=HealthResponse, tags=["health"])
def health_check() -> HealthResponse:
    """Root health check endpoint."""
    return HealthResponse(status="ok", service="agentshield", environment=settings.ENVIRONMENT)

# Include API v1 router
app.include_router(api_router, prefix="/api/v1")

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Global exception handler for unhandled errors with strict secret sanitization."""
    from app.security.audit.redaction import sanitize_string_value

    if settings.is_dev_mode():
        sanitized_error = sanitize_string_value(str(exc))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "error": sanitized_error},
        )

    # In production and QA, prevent internal information disclosure
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": "An unexpected error occurred."},
    )
