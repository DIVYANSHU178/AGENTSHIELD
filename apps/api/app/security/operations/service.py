import copy
from typing import List, Optional, Dict, Any
from app.security.models import (
    ToolCategory,
    ActionType,
    ThreatType,
    Severity,
    SecurityDecisionType,
    SecurityEvent,
)
from app.security.runtime.contracts import (
    RuntimeExecutionResult,
    RuntimeExecutionStatus,
)
from app.security.gateway import SecurityEvaluationResult
from app.security.audit import SecurityAuditTrail
from app.security.audit.redaction import sanitize_audit_payload
from app.security.operations.contracts import (
    ComponentStatus,
    ComponentHealth,
    OverallSystemHealth,
    SecurityMetrics,
    ThreatActivityItem,
    SecurityDecisionItem,
    ExecutionActivityItem,
    OperationsOverview,
    OperationsControlAction,
    OperationsControlRequest,
    OperationsControlResponse,
)
from app.security.operations.health import SecurityHealthChecker
from app.security.models.utils import utc_now, generate_uuid
from app.security.persistence.audit_repository import AuditRepository
from app.security.persistence.decision_repository import DecisionRepository
from app.security.persistence.threat_repository import ThreatRepository
from app.security.persistence.execution_repository import ExecutionRepository


FORBIDDEN_CONTROL_ACTIONS = {
    "APPROVE_REQUEST",
    "REJECT_REQUEST",
    "EXECUTE_TOOL",
    "BYPASS_SECURITY",
    "OVERRIDE_POLICY",
    "ISSUE_AUTHORIZATION",
    "MODIFY_SIGNATURE",
    "DELETE_AUDIT",
    "DISABLE_ENFORCEMENT",
    "DISABLE_SANDBOX",
    "RESUME_EXECUTION",
}

class SecurityOperationsService:
    """
    Authoritative service backing the Security Operations Console (Phase 10/13).
    
    CORE ROLES:
    - Observer and operational inspection interface for AgentShield pipeline state.
    - Collects and serves defensive snapshots of metrics, health, threats, decisions, executions, and audit records.
    - Enforces complete redaction of sensitive credentials, keys, and tokens.
    - Strictly read-only: Rejects all execution, approval, override, and bypass operational attempts.
    - Supports durable persistence repositories for decisions, threats, executions, and audit trail.
    """

    def __init__(
        self,
        audit_trail: Optional[SecurityAuditTrail] = None,
        health_checker: Optional[SecurityHealthChecker] = None,
        decision_repo: Optional[Any] = None,
        threat_repo: Optional[Any] = None,
        execution_repo: Optional[Any] = None,
    ) -> None:
        self._decision_repo = decision_repo
        self._threat_repo = threat_repo
        self._execution_repo = execution_repo
        self._audit_trail = audit_trail if audit_trail is not None else SecurityAuditTrail()
        self._health_checker = health_checker or SecurityHealthChecker(audit_trail=self._audit_trail)
        self._threats: List[ThreatActivityItem] = []
        self._decisions: List[SecurityDecisionItem] = []
        self._executions: List[ExecutionActivityItem] = []
        self._runtime_count: int = 0
        self._runtime_failure_count: int = 0

    @property
    def audit_trail(self) -> SecurityAuditTrail:
        return self._audit_trail

    @property
    def health_checker(self) -> SecurityHealthChecker:
        return self._health_checker

    @property
    def decision_repo(self) -> Optional[Any]:
        return self._decision_repo

    @property
    def threat_repo(self) -> Optional[Any]:
        return self._threat_repo

    @property
    def execution_repo(self) -> Optional[Any]:
        return self._execution_repo

    def record_evaluation(self, evaluation: SecurityEvaluationResult) -> None:
        """
        Record a SecurityEvaluationResult from Phase 5 Gateway into operational logs.
        Extracts threat signals and policy decision records with full redaction.
        """
        if evaluation is None:
            return

        req = evaluation.request
        req_id = req.request_id

        # 1. Record Threat Signals
        for sig in evaluation.threat_report.signals:
            sanitized_evidence = sanitize_audit_payload(dict(sig.evidence)) if sig.evidence else {}
            sanitized_meta = sanitize_audit_payload(dict(sig.metadata)) if sig.metadata else {}
            item = ThreatActivityItem(
                threat_id=sig.signal_id or generate_uuid(),
                threat_type=sig.threat_type,
                severity=sig.severity,
                detector=sig.source or "unknown_detector",
                request_id=req_id,
                title=sig.title,
                description=sig.description,
                confidence=sig.confidence,
                timestamp=evaluation.evaluated_at,
                metadata={**sanitized_meta, "evidence": sanitized_evidence},
            )
            if self._threat_repo is not None:
                self._threat_repo.save(item)
            else:
                self._threats.append(item)

        # 2. Record Security Decision
        dec = evaluation.decision
        sanitized_dec_meta = sanitize_audit_payload(dict(dec.metadata)) if dec.metadata else {}
        dec_item = SecurityDecisionItem(
            decision_id=dec.decision_id or generate_uuid(),
            request_id=req_id,
            decision=dec.decision,
            risk_score=evaluation.risk_assessment.risk_score,
            severity=evaluation.risk_assessment.severity,
            policy_id=dec.policy_id,
            reason=dec.reason,
            threat_count=len(evaluation.threat_report.signals),
            timestamp=evaluation.evaluated_at,
            metadata=sanitized_dec_meta,
        )
        if self._decision_repo is not None:
            self._decision_repo.save(dec_item)
        else:
            self._decisions.append(dec_item)

    def record_runtime_execution(self, result: RuntimeExecutionResult) -> None:
        """
        Record a RuntimeExecutionResult from Phase 9 AgentRuntimeOrchestrator into operational logs.
        """
        if result is None:
            return

        self._runtime_count += 1
        if result.status == RuntimeExecutionStatus.FAILED:
            self._runtime_failure_count += 1

        # Record evaluation if present
        if result.evaluation is not None:
            self.record_evaluation(result.evaluation)

        # Record execution activity item
        req_id = result.request_id
        tool_name = "unknown"
        tool_cat = ToolCategory.OTHER
        action = ActionType.OTHER

        if result.evaluation and result.evaluation.request:
            tool_name = result.evaluation.request.tool_name
            tool_cat = result.evaluation.request.tool_category
            action = result.evaluation.request.action

        exec_item = ExecutionActivityItem(
            execution_id=generate_uuid(),
            request_id=req_id,
            tool_name=tool_name,
            tool_category=tool_cat,
            action=action,
            status=result.status,
            success=result.success,
            duration_ms=result.duration_ms,
            error=result.error,
            timestamp=result.completed_at,
            metadata={
                "decision": result.decision.value if result.decision else None,
                "authorized": result.authorized,
                "executed": result.executed,
            },
        )
        if self._execution_repo is not None:
            self._execution_repo.save(exec_item)
        else:
            self._executions.append(exec_item)

    def get_health(self) -> OverallSystemHealth:
        """Retrieve overall system health snapshot."""
        return self._health_checker.check_all()

    def get_metrics(self) -> SecurityMetrics:
        """Derive deterministic operational metrics from recorded state and audit trail."""
        if self._decision_repo is not None and self._threat_repo is not None and self._execution_repo is not None:
            total_requests = self._decision_repo.count()
            allowed = self._decision_repo.count(decision=SecurityDecisionType.ALLOW)
            require_approval = self._decision_repo.count(decision=SecurityDecisionType.REQUIRE_APPROVAL)
            blocked = self._decision_repo.count(decision=SecurityDecisionType.BLOCK)

            successful_exec = self._execution_repo.count(status=RuntimeExecutionStatus.COMPLETED, success=True)
            failed_exec = self._execution_repo.count(status=RuntimeExecutionStatus.FAILED)
            timed_out_exec = self._execution_repo.count(status=RuntimeExecutionStatus.TIMED_OUT)
            denied_exec = self._execution_repo.count(status=RuntimeExecutionStatus.DENIED)

            detected_threats_count = self._threat_repo.count()
            critical_risk = self._decision_repo.count(severity=Severity.CRITICAL)
            high_risk = self._decision_repo.count(severity=Severity.HIGH)
            medium_risk = self._decision_repo.count(severity=Severity.MEDIUM)

            audit_events_count = len(self._audit_trail)
            runtime_requests = self._execution_repo.count()
            runtime_failures = failed_exec
            authorized_count = successful_exec + failed_exec + timed_out_exec

            return SecurityMetrics(
                total_requests=total_requests,
                allowed=allowed,
                require_approval=require_approval,
                blocked=blocked,
                authorized=authorized_count,
                denied_execution=denied_exec,
                successful_execution=successful_exec,
                failed_execution=failed_exec,
                timed_out_execution=timed_out_exec,
                detected_threats=detected_threats_count,
                critical_risk_requests=critical_risk,
                high_risk_requests=high_risk,
                medium_risk_requests=medium_risk,
                audit_events=audit_events_count,
                runtime_requests=runtime_requests,
                runtime_failures=runtime_failures,
                calculated_at=utc_now(),
            )

        total_requests = len(self._decisions)
        allowed = sum(1 for d in self._decisions if d.decision == SecurityDecisionType.ALLOW)
        require_approval = sum(1 for d in self._decisions if d.decision == SecurityDecisionType.REQUIRE_APPROVAL)
        blocked = sum(1 for d in self._decisions if d.decision == SecurityDecisionType.BLOCK)

        successful_exec = sum(1 for e in self._executions if e.status == RuntimeExecutionStatus.COMPLETED and e.success)
        failed_exec = sum(1 for e in self._executions if e.status == RuntimeExecutionStatus.FAILED)
        timed_out_exec = sum(1 for e in self._executions if e.status == RuntimeExecutionStatus.TIMED_OUT)
        denied_exec = sum(1 for e in self._executions if e.status == RuntimeExecutionStatus.DENIED)

        authorized_count = sum(1 for e in self._executions if e.metadata.get("authorized") is True)
        detected_threats_count = len(self._threats)

        critical_risk = sum(1 for d in self._decisions if d.severity == Severity.CRITICAL)
        high_risk = sum(1 for d in self._decisions if d.severity == Severity.HIGH)
        medium_risk = sum(1 for d in self._decisions if d.severity == Severity.MEDIUM)

        audit_events_count = len(self._audit_trail)

        return SecurityMetrics(
            total_requests=total_requests,
            allowed=allowed,
            require_approval=require_approval,
            blocked=blocked,
            authorized=authorized_count,
            denied_execution=denied_exec,
            successful_execution=successful_exec,
            failed_execution=failed_exec,
            timed_out_execution=timed_out_exec,
            detected_threats=detected_threats_count,
            critical_risk_requests=critical_risk,
            high_risk_requests=high_risk,
            medium_risk_requests=medium_risk,
            audit_events=audit_events_count,
            runtime_requests=self._runtime_count,
            runtime_failures=self._runtime_failure_count,
            calculated_at=utc_now(),
        )

    def get_threats(
        self,
        limit: int = 50,
        severity: Optional[Severity] = None,
        threat_type: Optional[ThreatType] = None,
    ) -> List[ThreatActivityItem]:
        """Retrieve recent threats, optionally filtered by severity or threat type."""
        if self._threat_repo is not None:
            return self._threat_repo.list_threats(severity=severity, threat_type=threat_type, limit=limit)

        threats = list(reversed(self._threats))
        if severity:
            threats = [t for t in threats if t.severity == severity]
        if threat_type:
            threats = [t for t in threats if t.threat_type == threat_type]
        return [copy.deepcopy(t) for t in threats[:limit]]

    def get_decisions(
        self,
        limit: int = 50,
        decision: Optional[SecurityDecisionType] = None,
    ) -> List[SecurityDecisionItem]:
        """Retrieve recent security decisions."""
        if self._decision_repo is not None:
            return self._decision_repo.list_decisions(decision=decision, limit=limit)

        decisions = list(reversed(self._decisions))
        if decision:
            decisions = [d for d in decisions if d.decision == decision]
        return [copy.deepcopy(d) for d in decisions[:limit]]

    def get_executions(
        self,
        limit: int = 50,
        status: Optional[RuntimeExecutionStatus] = None,
    ) -> List[ExecutionActivityItem]:
        """Retrieve recent execution outcomes."""
        if self._execution_repo is not None:
            return self._execution_repo.list_executions(status=status, limit=limit)

        executions = list(reversed(self._executions))
        if status:
            executions = [e for e in executions if e.status == status]
        return [copy.deepcopy(e) for e in executions[:limit]]

    def get_audit_events(
        self,
        limit: int = 100,
        request_id: Optional[str] = None,
    ) -> List[SecurityEvent]:
        """Retrieve sanitized audit trail events."""
        events = self._audit_trail.get_events(request_id=request_id)
        # Redact any sensitive details defensively before returning
        sanitized_events: List[SecurityEvent] = []
        for ev in reversed(events):
            from app.security.models.utils import deep_freeze, FrozenDict
            sanitized_details = deep_freeze(sanitize_audit_payload(dict(ev.details))) if ev.details else FrozenDict()
            sanitized_meta = deep_freeze(sanitize_audit_payload(dict(ev.metadata))) if ev.metadata else FrozenDict()
            sanitized_ev = ev.model_copy(
                update={"details": sanitized_details, "metadata": sanitized_meta}
            )
            sanitized_events.append(sanitized_ev)
        return sanitized_events[:limit]

    def get_overview(self) -> OperationsOverview:
        """Retrieve unified dashboard overview snapshot."""
        return OperationsOverview(
            overall_health=self.get_health(),
            metrics=self.get_metrics(),
            recent_threats=self.get_threats(limit=10),
            recent_decisions=self.get_decisions(limit=10),
            recent_executions=self.get_executions(limit=10),
            generated_at=utc_now(),
        )

    def execute_control(self, request: OperationsControlRequest) -> OperationsControlResponse:
        """
        Safely execute permitted read-only operational control actions.
        Rejects all mutating, executing, approval, or override actions.
        """
        if request is None:
            raise ValueError("Operational control request cannot be None.")

        action = request.action
        if action == OperationsControlAction.READ_STATUS:
            return OperationsControlResponse(
                action=action,
                success=True,
                data=self.get_health().model_dump(),
                executed_at=utc_now(),
                message="Overall status retrieved.",
            )
        elif action == OperationsControlAction.READ_HEALTH:
            return OperationsControlResponse(
                action=action,
                success=True,
                data=self.get_health().model_dump(),
                executed_at=utc_now(),
                message="Component health retrieved.",
            )
        elif action == OperationsControlAction.READ_METRICS:
            return OperationsControlResponse(
                action=action,
                success=True,
                data=self.get_metrics().model_dump(),
                executed_at=utc_now(),
                message="Security metrics retrieved.",
            )
        elif action == OperationsControlAction.READ_THREATS:
            threats = [t.model_dump() for t in self.get_threats(limit=request.limit or 50)]
            return OperationsControlResponse(
                action=action,
                success=True,
                data=threats,
                executed_at=utc_now(),
                message="Threat activity retrieved.",
            )
        elif action == OperationsControlAction.READ_DECISIONS:
            decisions = [d.model_dump() for d in self.get_decisions(limit=request.limit or 50)]
            return OperationsControlResponse(
                action=action,
                success=True,
                data=decisions,
                executed_at=utc_now(),
                message="Decision activity retrieved.",
            )
        elif action == OperationsControlAction.READ_EXECUTIONS:
            executions = [e.model_dump() for e in self.get_executions(limit=request.limit or 50)]
            return OperationsControlResponse(
                action=action,
                success=True,
                data=executions,
                executed_at=utc_now(),
                message="Execution activity retrieved.",
            )
        elif action == OperationsControlAction.READ_AUDIT:
            events = [e.model_dump() for e in self.get_audit_events(limit=request.limit or 100, request_id=request.target)]
            return OperationsControlResponse(
                action=action,
                success=True,
                data=events,
                executed_at=utc_now(),
                message="Audit events retrieved.",
            )
        else:
            raise ValueError(f"Unsupported operational action '{action}'.")

    def clear(self) -> None:
        """Reset internal operational buffers and persistent stores."""
        if self._decision_repo is not None:
            self._decision_repo.clear()
        if self._threat_repo is not None:
            self._threat_repo.clear()
        if self._execution_repo is not None:
            self._execution_repo.clear()
        self._threats.clear()
        self._decisions.clear()
        self._executions.clear()
        self._runtime_count = 0
        self._runtime_failure_count = 0
        self._audit_trail.clear()

# Global default operations service instance for FastAPI dependency injection
_global_operations_service: Optional[SecurityOperationsService] = None

def get_operations_service() -> SecurityOperationsService:
    """Retrieve or initialize the global persistent SecurityOperationsService instance."""
    global _global_operations_service
    if _global_operations_service is None:
        from app.database import init_db
        init_db()
        audit_repo = AuditRepository()
        audit_trail = SecurityAuditTrail(repository=audit_repo)
        _global_operations_service = SecurityOperationsService(
            audit_trail=audit_trail,
            decision_repo=DecisionRepository(),
            threat_repo=ThreatRepository(),
            execution_repo=ExecutionRepository(),
        )
    return _global_operations_service

def set_operations_service(service: Optional[SecurityOperationsService]) -> None:
    """Explicitly set or reset the global SecurityOperationsService instance."""
    global _global_operations_service
    _global_operations_service = service
