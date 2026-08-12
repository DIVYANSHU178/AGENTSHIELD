def test_app_imports():
    """Verify that all core application modules import cleanly without errors."""
    from app.main import app
    from app.config import settings
    from app.database import engine, Base, init_db, get_db
    
    assert app.title == "AgentShield"
    assert settings.APP_NAME == "AgentShield"
    assert engine is not None
    assert Base is not None
