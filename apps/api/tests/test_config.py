from app.config import Settings

def test_configuration_loading():
    """Verify central configuration loading and default parameters."""
    config = Settings()
    assert config.APP_NAME == "AgentShield"
    assert config.ENVIRONMENT in ["development", "testing", "production"]
    assert config.API_HOST == "127.0.0.1"
    assert config.API_PORT == 8001
    assert config.OLLAMA_BASE_URL == "http://localhost:11434"
    assert config.OLLAMA_MODEL_NAME == "llama3"
