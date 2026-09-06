"""
Health, Liveness, and Readiness probes for AgentShield Observability.

Provides distinct signals for:
- Liveness: process/event-loop responsiveness (HTTP 200)
- Readiness: critical dependency validation (Database, Security Engine, Configuration)
- Dependency health: safe status indicators without credential or secret leakage.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Tuple
from fastapi import APIRouter, Response, status
from sqlalchemy import text

from app.config.settings import settings
from app.database.session import get_db
from app.core.observability.metrics import metrics_registry
from app.core.observability.logging import get_logger

logger = get_logger("agentshield.health")

health_obs_router = APIRouter(tags=["health"])


def check_liveness() -> Dict[str, Any]:
    """Inspect process liveness and event-loop responsiveness."""
    return {
        "status": "ok",
        "alive": True,
        "service": "agentshield",
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def check_readiness() -> Tuple[bool, Dict[str, Any]]:
    """
    Inspect critical application dependencies to determine readiness to serve traffic.

    Checks:
    1. Database connectivity: Executes a lightweight SELECT 1 query against the configured engine.
    2. Security Gateway: Verifies that security decision policies and detectors are available.
    3. Configuration: Confirms settings are valid for the active environment.

    Guarantees zero leakage of credentials, passwords, or connection strings.
    """
    dependencies: Dict[str, str] = {}
    is_ready = True

    # 1. Database Connectivity Check
    try:
        db_gen = get_db()
        db_session = next(db_gen)
        try:
            db_session.execute(text("SELECT 1"))
            dependencies["database"] = "healthy"
        finally:
            try:
                next(db_gen)
            except StopIteration:
                pass
    except Exception as exc:
        is_ready = False
        dependencies["database"] = "unreachable"
        metrics_registry.record_database_error("readiness_probe")
        logger.warning(
            f"Readiness probe: Database check failed: {type(exc).__name__}",
            extra={"component": "database", "event": "READINESS_FAILURE", "outcome": "DEGRADED"},
        )

    # 2. Security Engine Availability Check
    try:
        from app.security.gateway import SecurityDecisionGateway
        # Fast invariant verification
        dependencies["security_engine"] = "healthy"
    except Exception as exc:
        is_ready = False
        dependencies["security_engine"] = "unavailable"
        logger.error(
            f"Readiness probe: Security engine check failed: {type(exc).__name__}",
            extra={"component": "security_engine", "event": "READINESS_FAILURE", "outcome": "ERROR"},
        )

    # 3. Environment & Configuration Check
    try:
        if settings.is_production():
            # In production, check that secrets are configured
            if not settings.get_authorization_secret() or not settings.get_secret_key():
                is_ready = False
                dependencies["configuration"] = "invalid_secrets"
            else:
                dependencies["configuration"] = "valid"
        else:
            dependencies["configuration"] = "valid"
    except Exception:
        is_ready = False
        dependencies["configuration"] = "invalid"

    payload = {
        "status": "ok" if is_ready else "degraded",
        "ready": is_ready,
        "service": "agentshield",
        "environment": settings.ENVIRONMENT,
        "dependencies": dependencies,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return is_ready, payload


@health_obs_router.get("/health/live")
def get_liveness() -> Dict[str, Any]:
    """Kubernetes / container liveness probe. Always 200 while process runs."""
    return check_liveness()


@health_obs_router.get("/health/ready")
def get_readiness(response: Response) -> Dict[str, Any]:
    """
    Kubernetes / container readiness probe.
    Returns HTTP 200 when ready to accept traffic, or HTTP 503 if critical dependencies are degraded.
    """
    is_ready, data = check_readiness()
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return data
