"""
Approval Repository for AgentShield Phase 13 Persistence Layer.

Provides durable storage, transactional state transitions, and querying for ApprovalRequest records.
"""

from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from app.models.models import ApprovalRequestModel
from app.security.models import (
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecisionType,
    Severity,
)
from app.security.models.utils import ensure_utc
from app.security.approval.contracts import (
    ApprovalRequest,
    ApprovalResolution,
    ApprovalStatus,
    ApprovalDecision,
    ReviewerIdentity,
)
from app.security.approval.workflow import validate_state_transition
from app.security.approval.errors import ApprovalNotFoundError
from app.security.audit.redaction import sanitize_audit_payload
from app.database.session import SessionLocal


class ApprovalRepository:
    """
    Durable repository managing ApprovalRequest and ApprovalResolution state in SQLite/SQLAlchemy.

    INVARIANTS:
    - Enforces Phase 11 state machine on all updates (terminal states cannot transition).
    - Preserves exact request_fingerprint and tool parameter bindings.
    - Transactional: Commits state transitions safely.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory or SessionLocal

    def _get_session(self) -> Session:
        return self._session_factory()

    def save(self, approval: ApprovalRequest) -> None:
        """Persist a new ApprovalRequest into storage."""
        if approval is None:
            return

        sanitized_params = sanitize_audit_payload(dict(approval.parameters)) if approval.parameters else {}
        sanitized_meta = sanitize_audit_payload(dict(approval.metadata)) if approval.metadata else {}

        session = self._get_session()
        try:
            existing = session.scalar(
                select(ApprovalRequestModel).where(
                    (ApprovalRequestModel.approval_id == approval.approval_id) |
                    (ApprovalRequestModel.request_id == approval.request_id)
                )
            )
            if existing is not None:
                return

            record = ApprovalRequestModel(
                approval_id=approval.approval_id,
                request_id=approval.request_id,
                agent_id=approval.agent.agent_id,
                agent_name=approval.agent.name,
                agent_role=approval.agent.metadata.get("role") if hasattr(approval.agent, "metadata") and approval.agent.metadata else None,
                tool_name=approval.tool_name,
                tool_category=approval.tool_category.value,
                action=approval.action.value,
                target=approval.target,
                parameters=sanitized_params,
                destination=approval.destination,
                request_fingerprint=approval.request_fingerprint,
                risk_score=approval.risk_score,
                severity=approval.severity.value,
                decision=approval.decision.value,
                created_at=approval.created_at,
                expires_at=approval.expires_at,
                status=approval.status.value,
                metadata_payload=sanitized_meta,
            )

            if approval.resolution is not None:
                res = approval.resolution
                record.resolution_id = res.resolution_id
                record.reviewer_id = res.reviewer.reviewer_id
                record.reviewer_name = res.reviewer.reviewer_name
                record.reviewer_role = res.reviewer.role
                record.resolution_decision = res.decision.value
                record.resolution_reason = res.reason
                record.resolved_at = res.resolved_at

            session.add(record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_by_id(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Fetch an approval request by its unique approval_id."""
        if not approval_id or not approval_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(ApprovalRequestModel).where(ApprovalRequestModel.approval_id == approval_id.strip())
            )
            if record is None:
                return None
            return self._record_to_approval(record)
        finally:
            session.close()

    def get_by_request_id(self, request_id: str) -> Optional[ApprovalRequest]:
        """Fetch an approval request by its bound request_id."""
        if not request_id or not request_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(ApprovalRequestModel).where(ApprovalRequestModel.request_id == request_id.strip())
            )
            if record is None:
                return None
            return self._record_to_approval(record)
        finally:
            session.close()

    def list_approvals(
        self,
        status: Optional[ApprovalStatus] = None,
        limit: int = 50,
    ) -> List[ApprovalRequest]:
        """
        List recent approval requests (newest first).
        """
        session = self._get_session()
        try:
            stmt = select(ApprovalRequestModel).order_by(ApprovalRequestModel.id.desc())
            if status is not None:
                stmt = stmt.where(ApprovalRequestModel.status == status.value)
            if limit > 0:
                stmt = stmt.limit(limit)

            records = session.scalars(stmt).all()
            return [self._record_to_approval(r) for r in records]
        finally:
            session.close()

    def update_status(
        self,
        approval_id: str,
        new_status: ApprovalStatus,
        resolution: Optional[ApprovalResolution] = None,
    ) -> ApprovalRequest:
        """
        Transactionally update the status and optional resolution of an approval.
        Enforces state transition rules strictly.
        """
        if not approval_id or not approval_id.strip():
            raise ApprovalNotFoundError("Approval ID cannot be empty.")

        session = self._get_session()
        try:
            record = session.scalar(
                select(ApprovalRequestModel).where(ApprovalRequestModel.approval_id == approval_id.strip())
            )
            if record is None:
                raise ApprovalNotFoundError(f"Approval request with ID '{approval_id}' not found.")

            current_status = ApprovalStatus(record.status)
            validate_state_transition(current_status, new_status)

            record.status = new_status.value

            if resolution is not None:
                record.resolution_id = resolution.resolution_id
                record.reviewer_id = resolution.reviewer.reviewer_id
                record.reviewer_name = resolution.reviewer.reviewer_name
                record.reviewer_role = resolution.reviewer.role
                record.resolution_decision = resolution.decision.value
                record.resolution_reason = resolution.reason
                record.resolved_at = resolution.resolved_at

            session.commit()
            return self._record_to_approval(record)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def count(self, status: Optional[ApprovalStatus] = None) -> int:
        """Count total approval records, optionally filtered by status."""
        session = self._get_session()
        try:
            stmt = select(func.count(ApprovalRequestModel.id))
            if status is not None:
                stmt = stmt.where(ApprovalRequestModel.status == status.value)
            return session.scalar(stmt) or 0
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all stored approval records (for test isolation only)."""
        session = self._get_session()
        try:
            session.query(ApprovalRequestModel).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _record_to_approval(record: ApprovalRequestModel) -> ApprovalRequest:
        resolution = None
        if record.resolution_id:
            resolution = ApprovalResolution(
                resolution_id=record.resolution_id,
                approval_id=record.approval_id,
                request_id=record.request_id,
                reviewer=ReviewerIdentity(
                    reviewer_id=record.reviewer_id or "unknown",
                    reviewer_name=record.reviewer_name or "Unknown Reviewer",
                    role=record.reviewer_role,
                ),
                decision=ApprovalDecision(record.resolution_decision or "REJECT"),
                reason=record.resolution_reason or "",
                resolved_at=ensure_utc(record.resolved_at),
            )

        agent = AgentIdentity(
            agent_id=record.agent_id,
            name=record.agent_name,
            metadata={"role": record.agent_role} if record.agent_role else {},
        )

        return ApprovalRequest(
            approval_id=record.approval_id,
            request_id=record.request_id,
            agent=agent,
            tool_name=record.tool_name,
            tool_category=ToolCategory(record.tool_category),
            action=ActionType(record.action),
            target=record.target,
            parameters=record.parameters or {},
            destination=record.destination,
            request_fingerprint=record.request_fingerprint,
            risk_score=record.risk_score,
            severity=Severity(record.severity),
            decision=SecurityDecisionType(record.decision),
            created_at=ensure_utc(record.created_at),
            expires_at=ensure_utc(record.expires_at),
            status=ApprovalStatus(record.status),
            resolution=resolution,
            metadata=record.metadata_payload or {},
        )
