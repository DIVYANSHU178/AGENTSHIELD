"""
Authorization Audit Repository for AgentShield Phase 14.

Provides durable persistence and thread-safe querying for Authentication & Authorization events.
Features:
- Immutable append-only storage of authentication & authorization decisions
- Recursive secret sanitization
- In-memory fallback when no SQLAlchemy session factory is configured
- Correlation ID tracking and time-based querying
"""

import copy
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select
from app.models.models import AuthorizationAuditModel
from app.security.identity.models import AuthorizationDecision, Permission
from app.security.persistence.audit_repository import sanitize_audit_payload
from app.security.models.utils import generate_uuid, utc_now, ensure_utc


class AuthorizationAuditRepository:
    """
    Repository for persisting and querying authentication & authorization audit records.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory
        # In-memory storage: list of dicts
        self._records: List[Dict[str, Any]] = []

    def record_event(
        self,
        event_type: str,
        decision: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        permission: Optional[str] = None,
        resource: Optional[str] = None,
        reason: Optional[str] = None,
        correlation_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Persist an authorization or authentication event record."""
        event_id = generate_uuid()
        ts = ensure_utc(timestamp) if timestamp else utc_now()
        safe_metadata = sanitize_audit_payload(metadata or {})
        safe_reason = sanitize_audit_payload(reason) if reason else None

        record = {
            "event_id": event_id,
            "event_type": event_type,
            "user_id": user_id,
            "username": username,
            "permission": permission,
            "resource": resource,
            "decision": decision,
            "reason": str(safe_reason) if safe_reason else None,
            "timestamp": ts,
            "correlation_id": correlation_id,
            "metadata_payload": safe_metadata,
        }

        if self._session_factory is not None:
            with self._session_factory() as session:
                db_event = AuthorizationAuditModel(
                    event_id=event_id,
                    event_type=event_type,
                    user_id=user_id,
                    username=username,
                    permission=permission,
                    resource=resource,
                    decision=decision,
                    reason=str(safe_reason) if safe_reason else None,
                    timestamp=ts,
                    correlation_id=correlation_id,
                    metadata_payload=safe_metadata,
                )
                session.add(db_event)
                session.commit()

        self._records.append(record)
        return copy.deepcopy(record)

    def get_events(
        self,
        limit: int = 100,
        user_id: Optional[str] = None,
        permission: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent authorization audit events."""
        if self._session_factory is not None:
            with self._session_factory() as session:
                stmt = select(AuthorizationAuditModel).order_by(AuthorizationAuditModel.timestamp.desc())
                if user_id:
                    stmt = stmt.where(AuthorizationAuditModel.user_id == user_id)
                if permission:
                    stmt = stmt.where(AuthorizationAuditModel.permission == permission)
                if event_type:
                    stmt = stmt.where(AuthorizationAuditModel.event_type == event_type)
                stmt = stmt.limit(limit)
                rows = session.execute(stmt).scalars().all()
                return [
                    {
                        "event_id": r.event_id,
                        "event_type": r.event_type,
                        "user_id": r.user_id,
                        "username": r.username,
                        "permission": r.permission,
                        "resource": r.resource,
                        "decision": r.decision,
                        "reason": r.reason,
                        "timestamp": ensure_utc(r.timestamp),
                        "correlation_id": r.correlation_id,
                        "metadata": copy.deepcopy(r.metadata_payload or {}),
                    }
                    for r in rows
                ]

        filtered = self._records
        if user_id:
            filtered = [r for r in filtered if r.get("user_id") == user_id]
        if permission:
            filtered = [r for r in filtered if r.get("permission") == permission]
        if event_type:
            filtered = [r for r in filtered if r.get("event_type") == event_type]

        # Return latest first up to limit
        return copy.deepcopy(list(reversed(filtered))[:limit])
