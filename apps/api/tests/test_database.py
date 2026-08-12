from sqlalchemy import create_engine, inspect
from app.database.base import Base
from app.database.session import get_db

def test_database_initialization(tmp_path):
    """Verify database engine creation and table creation mechanism."""
    db_file = tmp_path / "test.db"
    db_url = f"sqlite:///{db_file}"
    
    test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    
    inspector = inspect(test_engine)
    assert inspector is not None

def test_get_db_session():
    """Verify database session dependency yields a valid session."""
    db_gen = get_db()
    db_session = next(db_gen)
    assert db_session is not None
    try:
        next(db_gen)
    except StopIteration:
        pass
