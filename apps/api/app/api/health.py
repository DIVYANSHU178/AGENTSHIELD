from fastapi import APIRouter
from app.schemas.health import HealthResponse
from app.config.settings import settings

router = APIRouter()

@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Health check endpoint for application status."""
    return HealthResponse(status="ok", service="agentshield", environment=settings.ENVIRONMENT)
