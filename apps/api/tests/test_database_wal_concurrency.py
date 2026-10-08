"""
Phase 2.0 / F7 — SQLite robustness hardening.

Proves, against a REAL file-backed SQLite database:

  A. Every sqlite engine built by the application enables WAL journal mode,
     a 5s busy timeout, and foreign keys.
  B. ``configure_database()`` applies the same hardening to its engine.
  C. Concurrent writers inserting the SAME execution_id collapse to exactly
     one durable row (the previous check-then-insert pattern could race and
     let a second writer hit IntegrityError).
  D. Concurrent writers inserting the SAME threat_id behave identically.
  E. Idempotent duplicate insert still works (no exception, single row).
"""

import threading

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.database.session import (
    _build_engine,
    _sqlite_connect_args,
    configure_database,
    init_db,
)
from app.security.models import ActionType, ToolCategory
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.models.utils import utc_now
from app.security.operations.contracts import ExecutionActivityItem, ThreatActivityItem
from app.security.models import ThreatType, Severity
from app.security.persistence import ExecutionRepository, ThreatRepository


@pytest.fixture
def db_engine(tmp_path):
    db_file = tmp_path / "f7_wal.db"
    engine = _build_engine(f"sqlite:///{db_file}")
    init_db(target_engine=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session_factory(db_engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=db_engine)


def _pragma(db_engine, name: str) -> str:
    with db_engine.connect() as conn:
        return conn.execute(text(f"PRAGMA {name};")).scalar()


def test_wal_journal_mode_enabled(db_engine):
    assert _pragma(db_engine, "journal_mode").lower() == "wal"


def test_busy_timeout_configured(db_engine):
    assert _pragma(db_engine, "busy_timeout") == 5000


def test_foreign_keys_enabled(db_engine):
    assert _pragma(db_engine, "foreign_keys") == 1


def test_sqlite_connect_args_include_busy_timeout():
    args = _sqlite_connect_args("sqlite:///./x.db")
    assert args.get("timeout") == 5.0
    assert args.get("check_same_thread") is False
    # Non-sqlite URLs must not receive sqlite-only connect args.
    assert _sqlite_connect_args("postgresql://localhost/db") == {}


def test_configure_database_engine_uses_wal(tmp_path):
    db_file = tmp_path / "f7_reconfigured.db"
    engine = configure_database(f"sqlite:///{db_file}")
    try:
        with engine.connect() as conn:
            mode = conn.execute(text("PRAGMA journal_mode;")).scalar()
            busy = conn.execute(text("PRAGMA busy_timeout;")).scalar()
        assert str(mode).lower() == "wal"
        assert busy == 5000
    finally:
        engine.dispose()


def _spawn_savers(repo, items):
    errors = []

    def worker(item):
        try:
            repo.save(item)
        except Exception as exc:  # pragma: no cover - defect path
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(it,)) for it in items]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return errors


def test_concurrent_same_execution_id_produces_exactly_one_row(db_session_factory):
    repo = ExecutionRepository(session_factory=db_session_factory)
    items = [
        ExecutionActivityItem(
            execution_id="exec-race",
            request_id=f"req-{i}",
            tool_name=f"tool.{i}",
            tool_category=ToolCategory.SYSTEM,
            action=ActionType.EXECUTE,
            status=RuntimeExecutionStatus.COMPLETED,
            success=True,
            duration_ms=1.0,
            timestamp=utc_now(),
            metadata={"worker": i},
        )
        for i in range(16)
    ]
    errors = _spawn_savers(repo, items)
    assert not errors, f"concurrent execution save errors: {errors}"
    # Fresh DB + 16 racers on the same execution_id -> exactly one durable row.
    assert repo.count() == 1


def test_concurrent_same_threat_id_produces_exactly_one_row(db_session_factory):
    repo = ThreatRepository(session_factory=db_session_factory)
    items = [
        ThreatActivityItem(
            threat_id="thr-race",
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=Severity.HIGH,
            detector=f"det-{i}",
            request_id=f"req-{i}",
            title="Racing threat",
            description="same id",
            confidence=0.5,
            timestamp=utc_now(),
            metadata={"worker": i},
        )
        for i in range(16)
    ]
    errors = _spawn_savers(repo, items)
    assert not errors, f"concurrent threat save errors: {errors}"
    # Fresh DB + 16 racers on the same threat_id -> exactly one durable row.
    assert repo.count() == 1


def test_sequential_duplicate_insert_stays_single_row(db_session_factory):
    """Idempotent replay: saving the same execution_id twice must not error."""
    repo = ExecutionRepository(session_factory=db_session_factory)
    item = ExecutionActivityItem(
        execution_id="exec-idem",
        request_id="req-idem",
        tool_name="tool.idem",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        status=RuntimeExecutionStatus.COMPLETED,
        success=True,
        duration_ms=1.0,
        timestamp=utc_now(),
        metadata={},
    )
    repo.save(item)
    repo.save(item)
    assert repo.count() == 1