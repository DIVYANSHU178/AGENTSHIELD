"""
Audit Repository for AgentShield Phase 13 Persistence Layer.

Provides durable, immutable storage and chronological querying for SecurityAuditTrail events.
"""

from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from app.models.models import AuditRecordModel
from app.security.models import SecurityEvent, EventType
from app.security.models.utils import ensure_utc, deep_freeze, FrozenDict
from app.security.audit.redaction import sanitize_audit_payload
from app.security.audit.errors import InvalidSecurityEventError
from app.database.session import SessionLocal


class AuditRepository:
    """
    Durable repository managing SecurityAuditTrail records in SQLite/SQLAlchemy.

    INVARIANTS:
    - Immutable: Stored audit records cannot be modified.
    - Chronological: Queries return events in strict insertion order.
    - Sanitized: Secret tokens and sensitive keys are redacted before writing.
    - Idempotent: Re-saving an identical event_id is safely ignored.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory or SessionLocal

    def _get_session(self) -> Session:
        return self._session_factory()

    def save(self, event: SecurityEvent) -> None:
        """
        Persist a SecurityEvent into the database.
        Raises InvalidSecurityEventError if event is malformed.
        """
        if event is None or not isinstance(event, SecurityEvent):
            raise InvalidSecurityEventError(
                f"Cannot persist invalid audit event: expected SecurityEvent instance, got {type(event).__name__}."
            )

        if not event.event_id or not event.event_id.strip():
            raise InvalidSecurityEventError("Cannot persist SecurityEvent with empty event_id.")

        if not event.request_id or not event.request_id.strip():
            raise InvalidSecurityEventError("Cannot persist SecurityEvent with empty request_id.")

        if not event.actor or not event.actor.strip():
            raise InvalidSecurityEventError("Cannot persist SecurityEvent with empty actor.")

        sanitized_details = sanitize_audit_payload(dict(event.details)) if event.details else {}
        sanitized_meta = sanitize_audit_payload(dict(event.metadata)) if event.metadata else {}

        session = self._get_session()
        try:
            # Check for existing event_id (idempotency check)
            existing = session.scalar(
                select(AuditRecordModel).where(AuditRecordModel.event_id == event.event_id)
            )
            if existing is not None:
                # Already stored; preserve immutability and return
                return

            record = AuditRecordModel(
                event_id=event.event_id,
                request_id=event.request_id,
                event_type=event.event_type.value,
                timestamp=event.timestamp,
                actor=event.actor,
                details=sanitized_details,
                metadata_payload=sanitized_meta,
            )
            session.add(record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_by_event_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Fetch a single audit event by its event_id."""
        if not event_id or not event_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(AuditRecordModel).where(AuditRecordModel.event_id == event_id.strip())
            )
            if record is None:
                return None
            return self._record_to_event(record)
        finally:
            session.close()

    def get_events(
        self,
        request_id: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[SecurityEvent]:
        """
        Retrieve audit events in chronological order (oldest first).
        """
        session = self._get_session()
        try:
            stmt = select(AuditRecordModel).order_by(AuditRecordModel.id.asc())
            if request_id is not None and request_id.strip():
                stmt = stmt.where(AuditRecordModel.request_id == request_id.strip())
            if limit is not None and limit > 0:
                stmt = stmt.limit(limit)

            records = session.scalars(stmt).all()
            return [self._record_to_event(r) for r in records]
        finally:
            session.close()

    def count(self, request_id: Optional[str] = None) -> int:
        """Count total audit events recorded."""
        session = self._get_session()
        try:
            stmt = select(func.count(AuditRecordModel.id))
            if request_id is not None and request_id.strip():
                stmt = stmt.where(AuditRecordModel.request_id == request_id.strip())
            return session.scalar(stmt) or 0
        finally:
            session.close()

    def clear(self) -> None:
        """Delete all audit events (for test isolation only)."""
        session = self._get_session()
        try:
            session.query(AuditRecordModel).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _record_to_event(record: AuditRecordModel) -> SecurityEvent:
        """Convert an AuditRecordModel to an immutable SecurityEvent."""
        return SecurityEvent(
            event_id=record.event_id,
            request_id=record.request_id,
            event_type=EventType(record.event_type),
            timestamp=ensure_utc(record.timestamp),
            actor=record.actor,
            details=deep_freeze(record.details or {}),
            metadata=deep_freeze(record.metadata_payload or {}),
        )
