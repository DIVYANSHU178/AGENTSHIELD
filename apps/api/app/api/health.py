from typing import Any, Dict
from fastapi import APIRouter, Response, status
from app.schemas.health import HealthResponse
from app.config.settings import settings
from app.core.observability.health import check_liveness, check_readiness

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Health check endpoint for application status."""
    return HealthResponse(status="ok", service="agentshield", environment=settings.ENVIRONMENT)

@router.get("/health/live")
def get_health_live() -> Dict[str, Any]:
    """Process liveness probe."""
    return check_liveness()

@router.get("/health/ready")
def get_health_ready(response: Response) -> Dict[str, Any]:
    """Dependency readiness probe."""
    is_ready, data = check_readiness()
    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return data
