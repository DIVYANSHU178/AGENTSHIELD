"""
Decision Repository for AgentShield Phase 13 Persistence Layer.

Provides durable storage and operational querying for SecurityDecisionItem records.
"""

from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from app.models.models import SecurityDecisionModel
from app.security.models import SecurityDecisionType, Severity
from app.security.models.utils import ensure_utc
from app.security.operations.contracts import SecurityDecisionItem
from app.security.audit.redaction import sanitize_audit_payload
from app.database.session import SessionLocal


class DecisionRepository:
    """
    Durable repository managing SecurityDecisionItem records in SQLite/SQLAlchemy.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory or SessionLocal

    def _get_session(self) -> Session:
        return self._session_factory()

    def save(self, item: SecurityDecisionItem) -> None:
        """Persist a SecurityDecisionItem into storage."""
        if item is None:
            return

        sanitized_meta = sanitize_audit_payload(dict(item.metadata)) if item.metadata else {}
        session = self._get_session()
        try:
            # Check for existing decision_id
            existing = session.scalar(
                select(SecurityDecisionModel).where(SecurityDecisionModel.decision_id == item.decision_id)
            )
            if existing is not None:
                return

            record = SecurityDecisionModel(
                decision_id=item.decision_id,
                request_id=item.request_id,
                decision=item.decision.value,
                risk_score=item.risk_score,
                severity=item.severity.value,
                policy_id=item.policy_id,
                reason=item.reason,
                threat_count=item.threat_count,
                timestamp=item.timestamp,
                metadata_payload=sanitized_meta,
            )
            session.add(record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_by_id(self, decision_id: str) -> Optional[SecurityDecisionItem]:
        """Fetch a decision by its unique decision_id."""
        if not decision_id or not decision_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(SecurityDecisionModel).where(SecurityDecisionModel.decision_id == decision_id.strip())
            )
            if record is None:
                return None
            return self._record_to_item(record)
        finally:
            session.close()

    def list_decisions(
        self,
        decision: Optional[SecurityDecisionType] = None,
        limit: int = 50,
    ) -> List[SecurityDecisionItem]:
        """
        List recent security decisions (newest first).
        """
        session = self._get_session()
        try:
            stmt = select(SecurityDecisionModel).order_by(SecurityDecisionModel.id.desc())
            if decision is not None:
                stmt = stmt.where(SecurityDecisionModel.decision == decision.value)
            if limit > 0:
                stmt = stmt.limit(limit)

            records = session.scalars(stmt).all()
            return [self._record_to_item(r) for r in records]
        finally:
            session.close()

    def count(self, decision: Optional[SecurityDecisionType] = None, severity: Optional[Severity] = None) -> int:
        """Count total decisions recorded, optionally filtered by decision or severity."""
        session = self._get_session()
        try:
            stmt = select(func.count(SecurityDecisionModel.id))
            if decision is not None:
                stmt = stmt.where(SecurityDecisionModel.decision == decision.value)
            if severity is not None:
                stmt = stmt.where(SecurityDecisionModel.severity == severity.value)
            return session.scalar(stmt) or 0
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all stored decision records (for test isolation only)."""
        session = self._get_session()
        try:
            session.query(SecurityDecisionModel).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _record_to_item(record: SecurityDecisionModel) -> SecurityDecisionItem:
        return SecurityDecisionItem(
            decision_id=record.decision_id,
            request_id=record.request_id,
            decision=SecurityDecisionType(record.decision),
            risk_score=record.risk_score,
            severity=Severity(record.severity),
            policy_id=record.policy_id,
            reason=record.reason,
            threat_count=record.threat_count,
            timestamp=ensure_utc(record.timestamp),
            metadata=record.metadata_payload or {},
        )
