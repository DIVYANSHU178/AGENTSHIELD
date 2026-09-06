from typing import List, Optional, Any, Dict
from fastapi import APIRouter, Depends, Query, HTTPException, status
from app.security.models import Severity, ThreatType, SecurityDecisionType, SecurityEvent
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.operations.contracts import (
    OverallSystemHealth,
    SecurityMetrics,
    ThreatActivityItem,
    SecurityDecisionItem,
    ExecutionActivityItem,
    OperationsOverview,
    OperationsControlRequest,
    OperationsControlResponse,
)
from app.security.operations.service import SecurityOperationsService, get_operations_service
from app.security.identity.models import Permission
from app.security.identity.dependencies import require_permission

router = APIRouter(prefix="/security/operations", tags=["security-operations"])

@router.get("/overview", response_model=OperationsOverview, dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])
def get_operations_overview(
    service: SecurityOperationsService = Depends(get_operations_service),
) -> OperationsOverview:
    """Retrieve unified operational overview snapshot for the Security Operations Console."""
    return service.get_overview()

@router.get("/health", response_model=OverallSystemHealth, dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])
def get_operations_health(
    service: SecurityOperationsService = Depends(get_operations_service),
) -> OverallSystemHealth:
    """Retrieve current operational health status across all AgentShield components."""
    return service.get_health()

@router.get("/metrics", response_model=SecurityMetrics, dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])
def get_operations_metrics(
    service: SecurityOperationsService = Depends(get_operations_service),
) -> SecurityMetrics:
    """Retrieve operational security metrics derived from live runtime and audit state."""
    return service.get_metrics()

@router.get("/telemetry", dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])
def get_operations_telemetry() -> Any:
    """Retrieve real-time operational telemetry metrics registry snapshot (Phase 16)."""
    from app.core.observability import metrics_registry
    return metrics_registry.get_telemetry_snapshot()

@router.get("/threats", response_model=List[ThreatActivityItem], dependencies=[Depends(require_permission(Permission.VIEW_THREATS))])
def get_operations_threats(
    limit: int = Query(default=50, ge=1, le=200),
    severity: Optional[Severity] = Query(default=None),
    threat_type: Optional[ThreatType] = Query(default=None),
    service: SecurityOperationsService = Depends(get_operations_service),
) -> List[ThreatActivityItem]:
    """Retrieve safely redacted recent threat activity items."""
    return service.get_threats(limit=limit, severity=severity, threat_type=threat_type)

@router.get("/decisions", response_model=List[SecurityDecisionItem], dependencies=[Depends(require_permission(Permission.VIEW_DECISIONS))])
def get_operations_decisions(
    limit: int = Query(default=50, ge=1, le=200),
    decision: Optional[SecurityDecisionType] = Query(default=None),
    service: SecurityOperationsService = Depends(get_operations_service),
) -> List[SecurityDecisionItem]:
    """Retrieve recent security decisions rendered by the policy engine."""
    return service.get_decisions(limit=limit, decision=decision)

@router.get("/executions", response_model=List[ExecutionActivityItem], dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])
def get_operations_executions(
    limit: int = Query(default=50, ge=1, le=200),
    status_filter: Optional[RuntimeExecutionStatus] = Query(default=None, alias="status"),
    service: SecurityOperationsService = Depends(get_operations_service),
) -> List[ExecutionActivityItem]:
    """Retrieve recent sandbox execution outcomes."""
    return service.get_executions(limit=limit, status=status_filter)

@router.get("/audit", response_model=List[SecurityEvent], dependencies=[Depends(require_permission(Permission.VIEW_AUDIT))])
def get_operations_audit(
    limit: int = Query(default=100, ge=1, le=500),
    request_id: Optional[str] = Query(default=None),
    service: SecurityOperationsService = Depends(get_operations_service),
) -> List[SecurityEvent]:
    """Retrieve safely redacted security audit trail events."""
    return service.get_audit_events(limit=limit, request_id=request_id)

@router.post("/control", response_model=OperationsControlResponse, dependencies=[Depends(require_permission(Permission.VIEW_OPERATIONS))])

def post_operations_control(
    request: OperationsControlRequest,
    service: SecurityOperationsService = Depends(get_operations_service),
) -> OperationsControlResponse:
    """
    Execute permitted read-only operational control queries.
    Rejects all mutating, execution, approval, or override actions.
    """
    try:
        return service.execute_control(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(exc),
        )
