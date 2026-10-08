"""
Threat Repository for AgentShield Phase 13 Persistence Layer.

Provides durable storage and operational querying for ThreatActivityItem records.
"""

from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from app.models.models import ThreatActivityModel
from app.security.models import ThreatType, Severity
from app.security.models.utils import ensure_utc
from app.security.operations.contracts import ThreatActivityItem
from app.security.audit.redaction import sanitize_audit_payload
from app.database.session import SessionLocal


class ThreatRepository:
    """
    Durable repository managing ThreatActivityItem records in SQLite/SQLAlchemy.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory or SessionLocal

    def _get_session(self) -> Session:
        return self._session_factory()

    def save(self, item: ThreatActivityItem) -> None:
        """Persist a ThreatActivityItem into storage."""
        if item is None:
            return

        sanitized_meta = sanitize_audit_payload(dict(item.metadata)) if item.metadata else {}
        session = self._get_session()
        try:
            # Phase 2.0 / F7 — atomic insert, no check-then-insert race.
            # The unique constraint on threat_id is authoritative:
            # ``ON CONFLICT DO NOTHING`` collapses concurrent writers of the
            # same threat_id into exactly one durable row.
            values = dict(
                threat_id=item.threat_id,
                threat_type=item.threat_type.value,
                severity=item.severity.value,
                detector=item.detector,
                request_id=item.request_id,
                title=item.title,
                description=item.description,
                confidence=item.confidence,
                timestamp=item.timestamp,
                metadata_payload=sanitized_meta,
            )
            stmt = sqlite_insert(ThreatActivityModel).values(**values).on_conflict_do_nothing(
                index_elements=["threat_id"]
            )
            session.execute(stmt)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_by_id(self, threat_id: str) -> Optional[ThreatActivityItem]:
        """Fetch a threat by its unique threat_id."""
        if not threat_id or not threat_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(ThreatActivityModel).where(ThreatActivityModel.threat_id == threat_id.strip())
            )
            if record is None:
                return None
            return self._record_to_item(record)
        finally:
            session.close()

    def list_threats(
        self,
        severity: Optional[Severity] = None,
        threat_type: Optional[ThreatType] = None,
        limit: int = 50,
    ) -> List[ThreatActivityItem]:
        """
        List recent threats (newest first).
        """
        session = self._get_session()
        try:
            stmt = select(ThreatActivityModel).order_by(ThreatActivityModel.id.desc())
            if severity is not None:
                stmt = stmt.where(ThreatActivityModel.severity == severity.value)
            if threat_type is not None:
                stmt = stmt.where(ThreatActivityModel.threat_type == threat_type.value)
            if limit > 0:
                stmt = stmt.limit(limit)

            records = session.scalars(stmt).all()
            return [self._record_to_item(r) for r in records]
        finally:
            session.close()

    def count(self, severity: Optional[Severity] = None) -> int:
        """Count total threats recorded, optionally filtered by severity."""
        session = self._get_session()
        try:
            stmt = select(func.count(ThreatActivityModel.id))
            if severity is not None:
                stmt = stmt.where(ThreatActivityModel.severity == severity.value)
            return session.scalar(stmt) or 0
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all stored threat records (for test isolation only)."""
        session = self._get_session()
        try:
            session.query(ThreatActivityModel).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _record_to_item(record: ThreatActivityModel) -> ThreatActivityItem:
        return ThreatActivityItem(
            threat_id=record.threat_id,
            threat_type=ThreatType(record.threat_type),
            severity=Severity(record.severity),
            detector=record.detector,
            request_id=record.request_id,
            title=record.title,
            description=record.description,
            confidence=record.confidence,
            timestamp=ensure_utc(record.timestamp),
            metadata=record.metadata_payload or {},
        )
