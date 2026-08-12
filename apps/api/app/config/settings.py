from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "AgentShield"
    ENVIRONMENT: str = "development"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./agentshield.db"
    
    # Future AI provider placeholders (DO NOT CONNECT IN PHASE 0)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL_NAME: str = "llama3"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
