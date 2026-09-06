import copy
from datetime import datetime
from typing import Dict, Any, Optional, List
from app.security.models import (
    ToolRequest,
    SecurityDecisionType,
    SecurityEvent,
    EventType,
)
from app.security.models.utils import generate_uuid, utc_now, ensure_utc, deep_freeze, FrozenDict
from app.security.enforcement.authorization import calculate_request_fingerprint
from app.security.gateway import SecurityEvaluationResult
from app.security.approval.contracts import (
    ApprovalStatus,
    ApprovalDecision,
    ReviewerIdentity,
    ApprovalResolution,
    ApprovalRequest,
)
from app.security.approval.policy import ApprovalPolicy, ApprovalPolicyEngine
from app.security.approval.workflow import validate_state_transition
from app.security.approval.errors import (
    ApprovalError,
    ApprovalNotFoundError,
    ApprovalExpiredError,
    ApprovalCancelledError,
    ApprovalRejectedError,
    ApprovalTamperingError,
    InvalidApprovalStateTransitionError,
)
from app.security.audit.trail import SecurityAuditTrail
from app.security.audit.redaction import sanitize_audit_payload, sanitize_string_value
from app.security.identity.models import UserIdentity, Permission
from app.security.identity.errors import AuthorizationDeniedError



class ApprovalService:
    """
    Authoritative, deterministic Approval Workflow service for AgentShield (Roadmap Phase 11/13).
    
    PRIMARY ARCHITECTURAL PRINCIPLE:
    Authoritative state machine and lifecycle manager for Phase 11 Approval Requests.
    Enforces Phase 14 RBAC authorization checks, time-bounded expiration, immutable audit recording,
    and persistent storage via Phase 13 ApprovalRepository.
    """

    def __init__(
        self,
        policy: Optional[ApprovalPolicy] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
        repository: Optional[Any] = None,
        authorization_service: Optional[Any] = None,
    ) -> None:
        self._policy_engine = ApprovalPolicyEngine(policy=policy)
        self._audit_trail = audit_trail
        self._repository = repository
        self._authorization_service = authorization_service
        self._approvals: Dict[str, ApprovalRequest] = {}
        self._request_to_approval: Dict[str, str] = {}

    @property
    def authorization_service(self) -> Optional[Any]:
        return self._authorization_service

    @property
    def policy_engine(self) -> ApprovalPolicyEngine:
        return self._policy_engine

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    @property
    def repository(self) -> Optional[Any]:
        return self._repository

    def create_approval(
        self,
        eval_result: SecurityEvaluationResult,
        ttl_seconds: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Create a new PENDING approval request bound to an evaluated ToolRequest.
        Fails safely if decision is not REQUIRE_APPROVAL.
        """
        # 1. Policy validation (rejects ALLOW or BLOCK)
        self._policy_engine.validate_can_create_approval(eval_result)

        req = eval_result.request
        created_at = utc_now()
        expires_at = self._policy_engine.calculate_expiration(created_at, ttl_seconds)

        # 2. Compute canonical request fingerprint (Phase 6 binding)
        fingerprint = calculate_request_fingerprint(req)

        approval = ApprovalRequest(
            approval_id=generate_uuid(),
            request_id=req.request_id,
            agent=req.agent,
            tool_name=req.tool_name,
            tool_category=req.tool_category,
            action=req.action,
            target=req.target,
            parameters=copy.deepcopy(req.parameters or {}),
            destination=req.destination,
            request_fingerprint=fingerprint,
            risk_score=eval_result.risk_assessment.risk_score,
            severity=eval_result.risk_assessment.severity,
            decision=SecurityDecisionType.REQUIRE_APPROVAL,
            created_at=created_at,
            expires_at=expires_at,
            status=ApprovalStatus.PENDING,
            resolution=None,
            metadata=copy.deepcopy(metadata or {}),
        )

        if self._repository is not None:
            existing = self._repository.get_by_request_id(req.request_id)
            if existing is not None:
                return copy.deepcopy(existing)
            self._repository.save(approval)
        else:
            if req.request_id in self._request_to_approval:
                return copy.deepcopy(self._approvals[self._request_to_approval[req.request_id]])
            self._approvals[approval.approval_id] = approval
            self._request_to_approval[approval.request_id] = approval.approval_id

        return copy.deepcopy(approval)

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Retrieve an approval request by ID, evaluating expiration dynamically."""
        if not approval_id or not isinstance(approval_id, str) or not approval_id.strip():
            raise ApprovalNotFoundError(f"Approval request with ID '{approval_id}' not found.")

        app_id_clean = approval_id.strip()

        if self._repository is not None:
            approval = self._repository.get_by_id(app_id_clean)
            if approval is None:
                raise ApprovalNotFoundError(f"Approval request with ID '{approval_id}' not found.")

            if approval.status == ApprovalStatus.PENDING and approval.is_expired():
                expired_approval = self._repository.update_status(app_id_clean, ApprovalStatus.EXPIRED)
                self._record_audit_event(
                    event_type=EventType.APPROVAL_EXPIRED,
                    request_id=approval.request_id,
                    details={
                        "approval_id": approval.approval_id,
                        "reason": "Approval request TTL expired prior to review",
                        "expires_at": approval.expires_at.isoformat(),
                    },
                )
                return copy.deepcopy(expired_approval)

            return copy.deepcopy(approval)

        if app_id_clean not in self._approvals:
            raise ApprovalNotFoundError(f"Approval request with ID '{approval_id}' not found.")

        approval = self._approvals[app_id_clean]

        # Dynamic expiration check for PENDING items
        if approval.status == ApprovalStatus.PENDING and approval.is_expired():
            expired_approval = approval.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self._approvals[app_id_clean] = expired_approval
            self._record_audit_event(
                event_type=EventType.APPROVAL_EXPIRED,
                request_id=approval.request_id,
                details={
                    "approval_id": approval.approval_id,
                    "reason": "Approval request TTL expired prior to review",
                    "expires_at": approval.expires_at.isoformat(),
                },
            )
            return copy.deepcopy(expired_approval)

        return copy.deepcopy(approval)

    def get_approval_by_request_id(self, request_id: str) -> Optional[ApprovalRequest]:
        """Look up approval request bound to a specific request ID."""
        if not request_id or not request_id.strip():
            return None

        req_id_clean = request_id.strip()

        if self._repository is not None:
            app = self._repository.get_by_request_id(req_id_clean)
            if app is None:
                return None
            return self.get_approval(app.approval_id)

        if req_id_clean not in self._request_to_approval:
            return None
        return self.get_approval(self._request_to_approval[req_id_clean])

    def list_approvals(
        self,
        status: Optional[ApprovalStatus] = None,
        limit: int = 50,
    ) -> List[ApprovalRequest]:
        """List recent approval requests, applying auto-expiration to pending items."""
        if self._repository is not None:
            raw_list = self._repository.list_approvals(status=None, limit=limit)
            result: List[ApprovalRequest] = []
            for app in raw_list:
                # Trigger dynamic expiration check
                fresh = self.get_approval(app.approval_id)
                if status is None or fresh.status == status:
                    result.append(fresh)
            return result[:limit]

        result: List[ApprovalRequest] = []
        for app_id in list(self._approvals.keys()):
            app = self.get_approval(app_id)
            if status is None or app.status == status:
                result.append(app)

        # Newest first
        result.sort(key=lambda a: a.created_at, reverse=True)
        return result[:limit]

    def approve(
        self,
        approval_id: str,
        reviewer: ReviewerIdentity,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Record reviewer approval resolution.
        Does NOT execute tools or manufacture authorization.
        """
        if not reason or not reason.strip():
            raise ValueError("Reviewer justification reason is required to approve.")

        # RBAC Check: VIEWER role cannot approve requests
        if reviewer.role and reviewer.role.strip().upper() == "VIEWER":
            self._record_audit_event(
                event_type=EventType.APPROVAL_AUTHORIZATION_DENIED,
                request_id=approval_id,
                details={
                    "approval_id": approval_id,
                    "reviewer_id": reviewer.reviewer_id,
                    "role": reviewer.role,
                    "reason": "Reviewer with role 'VIEWER' is not authorized to resolve approvals.",
                },
            )
            raise AuthorizationDeniedError("Reviewer with role 'VIEWER' is not authorized to resolve approvals.")

        approval = self.get_approval(approval_id)

        if approval.is_expired():
            raise ApprovalExpiredError(f"Cannot approve request '{approval_id}'; approval has expired.")

        validate_state_transition(approval.status, ApprovalStatus.APPROVED)

        resolution = ApprovalResolution(
            resolution_id=generate_uuid(),

            approval_id=approval.approval_id,
            request_id=approval.request_id,
            reviewer=reviewer,
            decision=ApprovalDecision.APPROVE,
            reason=sanitize_string_value(reason.strip()),
            resolved_at=utc_now(),
            metadata=copy.deepcopy(metadata or {}),
        )

        if self._repository is not None:
            resolved_approval = self._repository.update_status(
                approval.approval_id, ApprovalStatus.APPROVED, resolution=resolution
            )
        else:
            resolved_approval = approval.model_copy(
                update={
                    "status": ApprovalStatus.APPROVED,
                    "resolution": resolution,
                }
            )
            self._approvals[approval.approval_id] = resolved_approval

        self._record_audit_event(
            event_type=EventType.APPROVAL_APPROVED,
            request_id=approval.request_id,
            details={
                "approval_id": approval.approval_id,
                "reviewer_id": reviewer.reviewer_id,
                "reviewer_name": reviewer.reviewer_name,
                "role": reviewer.role,
                "reason": resolution.reason,
                "resolved_at": resolution.resolved_at.isoformat(),
            },
        )

        return copy.deepcopy(resolved_approval)

    def reject(
        self,
        approval_id: str,
        reviewer: ReviewerIdentity,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Record reviewer rejection resolution.
        """
        if not reason or not reason.strip():
            raise ValueError("Reviewer justification reason is required to reject.")

        # RBAC Check: VIEWER role cannot reject requests
        if reviewer.role and reviewer.role.strip().upper() == "VIEWER":
            self._record_audit_event(
                event_type=EventType.APPROVAL_AUTHORIZATION_DENIED,
                request_id=approval_id,
                details={
                    "approval_id": approval_id,
                    "reviewer_id": reviewer.reviewer_id,
                    "role": reviewer.role,
                    "reason": "Reviewer with role 'VIEWER' is not authorized to resolve approvals.",
                },
            )
            raise AuthorizationDeniedError("Reviewer with role 'VIEWER' is not authorized to resolve approvals.")

        approval = self.get_approval(approval_id)

        if approval.is_expired():
            raise ApprovalExpiredError(f"Cannot reject request '{approval_id}'; approval has expired.")

        validate_state_transition(approval.status, ApprovalStatus.REJECTED)

        resolution = ApprovalResolution(
            resolution_id=generate_uuid(),
            approval_id=approval.approval_id,
            request_id=approval.request_id,
            reviewer=reviewer,
            decision=ApprovalDecision.REJECT,
            reason=sanitize_string_value(reason.strip()),
            resolved_at=utc_now(),
            metadata=copy.deepcopy(metadata or {}),
        )

        if self._repository is not None:
            resolved_approval = self._repository.update_status(
                approval.approval_id, ApprovalStatus.REJECTED, resolution=resolution
            )
        else:
            resolved_approval = approval.model_copy(
                update={
                    "status": ApprovalStatus.REJECTED,
                    "resolution": resolution,
                }
            )
            self._approvals[approval.approval_id] = resolved_approval

        self._record_audit_event(
            event_type=EventType.APPROVAL_REJECTED,
            request_id=approval.request_id,
            details={
                "approval_id": approval.approval_id,
                "reviewer_id": reviewer.reviewer_id,
                "reviewer_name": reviewer.reviewer_name,
                "role": reviewer.role,
                "reason": resolution.reason,
                "resolved_at": resolution.resolved_at.isoformat(),
            },
        )

        return copy.deepcopy(resolved_approval)

    def cancel(self, approval_id: str, reason: str = "Cancelled by requester") -> ApprovalRequest:
        """Cancel a pending approval request."""
        approval = self.get_approval(approval_id)
        validate_state_transition(approval.status, ApprovalStatus.CANCELLED)

        if self._repository is not None:
            cancelled_approval = self._repository.update_status(approval.approval_id, ApprovalStatus.CANCELLED)
        else:
            cancelled_approval = approval.model_copy(update={"status": ApprovalStatus.CANCELLED})
            self._approvals[approval.approval_id] = cancelled_approval

        self._record_audit_event(
            event_type=EventType.APPROVAL_CANCELLED,
            request_id=approval.request_id,
            details={
                "approval_id": approval.approval_id,
                "reason": sanitize_string_value(reason),
            },
        )

        return copy.deepcopy(cancelled_approval)

    def approve_with_identity(
        self,
        approval_id: str,
        identity: UserIdentity,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Approve request with authenticated UserIdentity context enforcing RESOLVE_APPROVALS permission.
        """
        if not identity.has_permission(Permission.RESOLVE_APPROVALS):
            self._record_audit_event(
                event_type=EventType.APPROVAL_AUTHORIZATION_DENIED,
                request_id=approval_id,
                details={
                    "approval_id": approval_id,
                    "user_id": identity.user_id,
                    "username": identity.username,
                    "roles": [r.value for r in identity.roles],
                    "reason": f"Identity '{identity.username}' lacks RESOLVE_APPROVALS permission.",
                },
            )
            raise AuthorizationDeniedError(f"Identity '{identity.username}' is not authorized to resolve approvals.")

        self._record_audit_event(
            event_type=EventType.APPROVAL_AUTHORIZED,
            request_id=approval_id,
            details={
                "approval_id": approval_id,
                "user_id": identity.user_id,
                "username": identity.username,
                "roles": [r.value for r in identity.roles],
                "action": "APPROVE",
            },
        )

        reviewer = ReviewerIdentity(
            reviewer_id=identity.user_id,
            reviewer_name=identity.display_name,
            role=identity.roles[0].value if identity.roles else "SECURITY_REVIEWER",
            metadata={"username": identity.username},
        )
        return self.approve(approval_id=approval_id, reviewer=reviewer, reason=reason, metadata=metadata)

    def reject_with_identity(
        self,
        approval_id: str,
        identity: UserIdentity,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ApprovalRequest:
        """
        Reject request with authenticated UserIdentity context enforcing RESOLVE_APPROVALS permission.
        """
        if not identity.has_permission(Permission.RESOLVE_APPROVALS):
            self._record_audit_event(
                event_type=EventType.APPROVAL_AUTHORIZATION_DENIED,
                request_id=approval_id,
                details={
                    "approval_id": approval_id,
                    "user_id": identity.user_id,
                    "username": identity.username,
                    "roles": [r.value for r in identity.roles],
                    "reason": f"Identity '{identity.username}' lacks RESOLVE_APPROVALS permission.",
                },
            )
            raise AuthorizationDeniedError(f"Identity '{identity.username}' is not authorized to resolve approvals.")

        self._record_audit_event(
            event_type=EventType.APPROVAL_AUTHORIZED,
            request_id=approval_id,
            details={
                "approval_id": approval_id,
                "user_id": identity.user_id,
                "username": identity.username,
                "roles": [r.value for r in identity.roles],
                "action": "REJECT",
            },
        )

        reviewer = ReviewerIdentity(
            reviewer_id=identity.user_id,
            reviewer_name=identity.display_name,
            role=identity.roles[0].value if identity.roles else "SECURITY_REVIEWER",
            metadata={"username": identity.username},
        )
        return self.reject(approval_id=approval_id, reviewer=reviewer, reason=reason, metadata=metadata)


    def cancel_with_identity(
        self,
        approval_id: str,
        identity: UserIdentity,
        reason: str = "Cancelled by user",
    ) -> ApprovalRequest:
        """
        Cancel request with authenticated UserIdentity context enforcing CANCEL_APPROVAL permission.
        """
        if not identity.has_permission(Permission.CANCEL_APPROVAL):
            self._record_audit_event(
                event_type=EventType.APPROVAL_AUTHORIZATION_DENIED,
                request_id=approval_id,
                details={
                    "approval_id": approval_id,
                    "user_id": identity.user_id,
                    "username": identity.username,
                    "roles": [r.value for r in identity.roles],
                    "reason": f"Identity '{identity.username}' lacks CANCEL_APPROVAL permission.",
                },
            )
            raise AuthorizationDeniedError(f"Identity '{identity.username}' is not authorized to cancel approvals.")

        return self.cancel(approval_id=approval_id, reason=reason)


    def expire(self, approval_id: str) -> ApprovalRequest:
        """Manually or deterministically expire a pending approval request."""
        approval = self.get_approval(approval_id)
        validate_state_transition(approval.status, ApprovalStatus.EXPIRED)

        if self._repository is not None:
            expired_approval = self._repository.update_status(approval.approval_id, ApprovalStatus.EXPIRED)
        else:
            expired_approval = approval.model_copy(update={"status": ApprovalStatus.EXPIRED})
            self._approvals[approval.approval_id] = expired_approval

        self._record_audit_event(
            event_type=EventType.APPROVAL_EXPIRED,
            request_id=approval.request_id,
            details={
                "approval_id": approval.approval_id,
                "reason": "Approval request explicitly expired",
            },
        )

        return copy.deepcopy(expired_approval)

    def is_valid(self, approval_id: Any) -> bool:
        """
        Check if an approval request exists, has status APPROVED, and is not expired.
        
        FAIL-CLOSED SEMANTICS:
        - None, empty, whitespace-only, or non-string input -> False
        - Unknown approval ID -> False
        - PENDING, REJECTED, EXPIRED, CANCELLED -> False
        - APPROVED and expired -> False
        - APPROVED and unexpired -> True
        """
        if not isinstance(approval_id, str):
            return False
        stripped = approval_id.strip()
        if not stripped:
            return False
        try:
            approval = self.get_approval(stripped)
            return approval.status == ApprovalStatus.APPROVED and not approval.is_expired()
        except ApprovalError:
            return False

    def validate_against_request(self, approval: ApprovalRequest, request: ToolRequest) -> bool:
        """
        Strictly validate an approval request against a candidate ToolRequest.
        
        VALIDATION CHECKS:
        1. approval is not None and request is not None
        2. approval status is APPROVED
        3. approval is not expired
        4. request.request_id == approval.request_id
        5. request.agent.agent_id == approval.agent.agent_id
        6. request.tool_name == approval.tool_name
        7. request.tool_category == approval.tool_category
        8. request.action == approval.action
        9. request.target == approval.target
        10. request.destination == approval.destination
        11. calculate_request_fingerprint(request) == approval.request_fingerprint
        """
        if approval is None or request is None:
            return False

        if approval.status != ApprovalStatus.APPROVED:
            return False

        if approval.is_expired():
            return False

        if request.request_id != approval.request_id:
            return False

        if request.agent.agent_id != approval.agent.agent_id:
            return False

        if request.tool_name != approval.tool_name:
            return False

        if request.tool_category != approval.tool_category:
            return False

        if request.action != approval.action:
            return False

        if request.target != approval.target:
            return False

        if (request.destination or "") != (approval.destination or ""):
            return False

        expected_fingerprint = calculate_request_fingerprint(request)
        if approval.request_fingerprint != expected_fingerprint:
            return False

        return True

    def clear(self) -> None:
        """Clear stored approval records (for test isolation only)."""
        if self._repository is not None:
            self._repository.clear()
        self._approvals.clear()
        self._request_to_approval.clear()

    def _record_audit_event(
        self,
        event_type: EventType,
        request_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Record an approval lifecycle audit event if audit trail is configured."""
        if self._audit_trail is not None:
            try:
                ev = SecurityEvent(
                    event_id=generate_uuid(),
                    request_id=request_id,
                    event_type=event_type,
                    timestamp=utc_now(),
                    actor="approval_workflow",
                    details=sanitize_audit_payload(details),
                    metadata={"stage": "approval_workflow"},
                )
                self._audit_trail.record(ev)
            except Exception:
                # Defensive isolation: audit recording failures do not break approval workflow
                pass

# Singleton accessor for runtime/API integration
_GLOBAL_APPROVAL_SERVICE: Optional[ApprovalService] = None

def get_approval_service() -> ApprovalService:
    global _GLOBAL_APPROVAL_SERVICE
    if _GLOBAL_APPROVAL_SERVICE is None:
        from app.security.persistence.approval_repository import ApprovalRepository
        from app.security.operations.service import get_operations_service
        ops = get_operations_service()
        _GLOBAL_APPROVAL_SERVICE = ApprovalService(
            repository=ApprovalRepository(),
            audit_trail=ops.audit_trail,
        )
    return _GLOBAL_APPROVAL_SERVICE

def set_approval_service(service: Optional[ApprovalService]) -> None:
    global _GLOBAL_APPROVAL_SERVICE
    _GLOBAL_APPROVAL_SERVICE = service
