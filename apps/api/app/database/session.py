import sqlite3
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator, Optional, Any
from app.config import settings
from app.database.base import Base

# Phase 2.0 / F7 — SQLite robustness hardening.
#   * ``timeout=5.0`` -> sqlite3 BUSY TIMEOUT: writers wait up to 5s for a
#     contended database instead of immediately raising "database is locked".
#   * WAL journal mode -> readers never block writers; concurrent readers are
#     allowed during a write.
#   * foreign_keys=ON -> referential integrity at the engine level.
SQLITE_BUSY_TIMEOUT_SECONDS = 5.0
SQLITE_JOURNAL_MODE = "WAL"


def _sqlite_connect_args(url: Any) -> dict:
    """Connect arguments for sqlite engines (busy timeout + thread safety)."""
    if str(url).startswith("sqlite"):
        return {"check_same_thread": False, "timeout": SQLITE_BUSY_TIMEOUT_SECONDS}
    return {}


def _apply_sqlite_pragmas(dbapi_connection, connection_record) -> None:
    """Enable WAL / busy_timeout / foreign_keys on every new sqlite connection."""
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA journal_mode={SQLITE_JOURNAL_MODE};")
        cursor.execute(f"PRAGMA busy_timeout={int(SQLITE_BUSY_TIMEOUT_SECONDS * 1000)};")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
    except Exception:
        pass


def _build_engine(url: Any):
    """Create an engine with the sqlite WAL/busy-timeout hardening applied."""
    conn_args = _sqlite_connect_args(url)
    eng = create_engine(url, connect_args=conn_args, echo=False)
    if str(url).startswith("sqlite"):
        event.listen(eng, "connect", _apply_sqlite_pragmas)
    return eng


engine = _build_engine(settings.DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db(target_engine: Optional[Any] = None) -> None:
    """Initialize database tables safely and idempotently."""
    import app.models  # noqa: F401 - Register models with Base.metadata
    use_engine = target_engine or engine
    try:
        Base.metadata.create_all(bind=use_engine)
        # Ensure schema migrations for existing database files
        try:
            from sqlalchemy import text
            with use_engine.connect() as conn:
                cols = [r[1] for r in conn.execute(text("PRAGMA table_info(approval_requests);")).fetchall()]
                if cols and "execution_result" not in cols:
                    conn.execute(text("ALTER TABLE approval_requests ADD COLUMN execution_result JSON;"))
                    conn.commit()
        except Exception:
            pass
        try:
            from app.core.observability import get_logger
            masked_url = settings.mask_connection_url(str(use_engine.url))
            get_logger("agentshield.database").info(
                f"Database tables verified/initialized: {masked_url}",
                extra={"component": "database", "event": "DB_INIT", "outcome": "SUCCESS"},
            )
        except Exception:
            pass
    except Exception as exc:
        try:
            from app.core.observability import metrics_registry, get_logger
            metrics_registry.record_database_error("init_db")
            get_logger("agentshield.database").error(
                f"Database initialization error: {type(exc).__name__}",
                extra={"component": "database", "event": "DB_INIT", "outcome": "ERROR"},
            )
        except Exception:
            pass
        raise

def get_db() -> Generator[Session, None, None]:
    """Dependency for providing a database session to endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def configure_database(target_url: Optional[str] = None) -> Any:
    """
    Dynamically reconfigure the database engine and SessionLocal to point to a specified URL
    (or to settings.DATABASE_URL if target_url is not specified).
    Also invalidates and resets in-memory singleton services to ensure all repositories
    rebind to the new session factory.
    """
    global engine, SessionLocal
    url = target_url or settings.DATABASE_URL
    engine = _build_engine(url)
    SessionLocal.configure(bind=engine)

    # Invalidate singleton services so subsequent calls re-initialize with the new database
    try:
        from app.security.operations.service import set_operations_service
        set_operations_service(None)
    except Exception:
        pass

    try:
        from app.security.approval.service import set_approval_service
        set_approval_service(None)
    except Exception:
        pass

    try:
        from app.security.identity.authentication import set_auth_service
        set_auth_service(None)
    except Exception:
        pass

    try:
        from app.security.identity.authorization import set_authorization_service
        set_authorization_service(None)
    except Exception:
        pass

    return engine
