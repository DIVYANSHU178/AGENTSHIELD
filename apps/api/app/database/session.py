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
    Base.metadata.create_all(bind=use_engine)

def get_db() -> Generator[Session, None, None]:
    """Dependency for providing a database session to endpoints."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
