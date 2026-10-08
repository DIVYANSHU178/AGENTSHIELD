"""
Execution Repository for AgentShield Phase 13 Persistence Layer.

Provides durable storage and operational querying for ExecutionActivityItem records.
"""

from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from sqlalchemy import select, func
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from app.models.models import ExecutionActivityModel
from app.security.models import ToolCategory, ActionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.models.utils import ensure_utc
from app.security.operations.contracts import ExecutionActivityItem
from app.security.audit.redaction import sanitize_audit_payload
from app.database.session import SessionLocal


class ExecutionRepository:
    """
    Durable repository managing ExecutionActivityItem records in SQLite/SQLAlchemy.
    """

    def __init__(self, session_factory: Optional[Callable[[], Session]] = None) -> None:
        self._session_factory = session_factory or SessionLocal

    def _get_session(self) -> Session:
        return self._session_factory()

    def save(self, item: ExecutionActivityItem) -> None:
        """Persist an ExecutionActivityItem into storage."""
        if item is None:
            return

        sanitized_meta = sanitize_audit_payload(dict(item.metadata)) if item.metadata else {}
        session = self._get_session()
        try:
            # Phase 2.0 / F7 — atomic insert, no check-then-insert race.
            # The unique constraint on execution_id is authoritative:
            # ``ON CONFLICT DO NOTHING`` collapses concurrent writers of the
            # same execution_id into exactly one durable row instead of one
            # writer failing with IntegrityError.
            values = dict(
                execution_id=item.execution_id,
                request_id=item.request_id,
                tool_name=item.tool_name,
                tool_category=item.tool_category.value,
                action=item.action.value,
                status=item.status.value,
                success=item.success,
                duration_ms=item.duration_ms,
                error=item.error,
                timestamp=item.timestamp,
                metadata_payload=sanitized_meta,
            )
            stmt = sqlite_insert(ExecutionActivityModel).values(**values).on_conflict_do_nothing(
                index_elements=["execution_id"]
            )
            session.execute(stmt)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def get_by_id(self, execution_id: str) -> Optional[ExecutionActivityItem]:
        """Fetch an execution by its unique execution_id."""
        if not execution_id or not execution_id.strip():
            return None

        session = self._get_session()
        try:
            record = session.scalar(
                select(ExecutionActivityModel).where(ExecutionActivityModel.execution_id == execution_id.strip())
            )
            if record is None:
                return None
            return self._record_to_item(record)
        finally:
            session.close()

    def list_executions(
        self,
        status: Optional[RuntimeExecutionStatus] = None,
        limit: int = 50,
    ) -> List[ExecutionActivityItem]:
        """
        List recent executions (newest first).
        """
        session = self._get_session()
        try:
            stmt = select(ExecutionActivityModel).order_by(ExecutionActivityModel.id.desc())
            if status is not None:
                stmt = stmt.where(ExecutionActivityModel.status == status.value)
            if limit > 0:
                stmt = stmt.limit(limit)

            records = session.scalars(stmt).all()
            return [self._record_to_item(r) for r in records]
        finally:
            session.close()

    def count(self, status: Optional[RuntimeExecutionStatus] = None, success: Optional[bool] = None) -> int:
        """Count total executions recorded, optionally filtered by status or success."""
        session = self._get_session()
        try:
            stmt = select(func.count(ExecutionActivityModel.id))
            if status is not None:
                stmt = stmt.where(ExecutionActivityModel.status == status.value)
            if success is not None:
                stmt = stmt.where(ExecutionActivityModel.success == success)
            return session.scalar(stmt) or 0
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all stored execution records (for test isolation only)."""
        session = self._get_session()
        try:
            session.query(ExecutionActivityModel).delete()
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    @staticmethod
    def _record_to_item(record: ExecutionActivityModel) -> ExecutionActivityItem:
        return ExecutionActivityItem(
            execution_id=record.execution_id,
            request_id=record.request_id,
            tool_name=record.tool_name,
            tool_category=ToolCategory(record.tool_category),
            action=ActionType(record.action),
            status=RuntimeExecutionStatus(record.status),
            success=record.success,
            duration_ms=record.duration_ms,
            error=record.error,
            timestamp=ensure_utc(record.timestamp),
            metadata=record.metadata_payload or {},
        )
