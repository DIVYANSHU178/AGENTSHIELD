from typing import List, Optional
from fastapi import APIRouter, HTTPException, status, Depends
from app.config import settings
from app.security.laboratory.contracts import (
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioRunRequest,
    ScenarioResult,
)
from app.security.laboratory.registry import (
    ScenarioRegistry,
    get_scenario_registry,
)
from app.security.laboratory.runner import ScenarioRunner
from app.security.laboratory.errors import (
    UnknownScenarioError,
    ScenarioExecutionError,
)
from app.security.operations.service import get_operations_service
from app.security.approval.service import get_approval_service

from app.security.identity.models import UserIdentity, Permission
from app.security.identity.dependencies import get_current_user_optional

laboratory_router = APIRouter(prefix="/dev/laboratory", tags=["scenario-laboratory"])

def verify_laboratory_development_mode() -> None:
    """Ensure the Scenario Laboratory endpoint is strictly disabled outside development/test environments."""
    env = (settings.ENVIRONMENT or "").strip().lower()
    if env not in ("development", "test", "testing", "dev", "local"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Scenario Laboratory is disabled in non-development environments.",
        )

def get_scenario_runner(
    registry: ScenarioRegistry = Depends(get_scenario_registry),
) -> ScenarioRunner:
    """Dependency provider for ScenarioRunner using shared operation and approval services."""
    operations_service = get_operations_service()
    approval_service = get_approval_service()
    if approval_service.audit_trail is None and operations_service.audit_trail is not None:
        approval_service._audit_trail = operations_service.audit_trail
    return ScenarioRunner(
        operations_service=operations_service,
        approval_service=approval_service,
        registry=registry,
    )

@laboratory_router.get(
    "/scenarios",
    response_model=List[ScenarioDefinition],
    dependencies=[Depends(verify_laboratory_development_mode)],
)
def list_laboratory_scenarios(
    category: Optional[ScenarioCategory] = None,
    registry: ScenarioRegistry = Depends(get_scenario_registry),
    current_user: Optional[UserIdentity] = Depends(get_current_user_optional),
) -> List[ScenarioDefinition]:
    """Retrieve catalog of authoritative laboratory scenario definitions without secrets."""
    if current_user is not None and not current_user.has_permission(Permission.VIEW_OPERATIONS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity '{current_user.username}' lacks permission to view scenarios.",
        )
    return registry.list_scenarios(category=category)

@laboratory_router.post(
    "/run",
    response_model=ScenarioResult,
    dependencies=[Depends(verify_laboratory_development_mode)],
)
def run_laboratory_scenario(
    body: ScenarioRunRequest,
    runner: ScenarioRunner = Depends(get_scenario_runner),
    current_user: Optional[UserIdentity] = Depends(get_current_user_optional),
) -> ScenarioResult:
    """Execute a laboratory scenario by ID through the real AgentShield security pipeline."""
    if current_user is not None and not current_user.has_permission(Permission.RUN_SCENARIO_LAB):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Identity '{current_user.username}' is not authorized to execute laboratory scenarios.",
        )
    try:
        return runner.run(scenario_id=body.scenario_id, request_id=body.request_id)
    except UnknownScenarioError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Laboratory execution failed: {str(exc)}",
        )
