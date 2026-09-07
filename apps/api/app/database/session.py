from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from typing import Generator, Optional, Any
from app.config import settings
from app.database.base import Base

connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False
)

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
    conn_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=conn_args, echo=False)
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
