from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_NAME: str = "AgentShield"
    ENVIRONMENT: str = "development"
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./agentshield.db"

    # Security Authorization Secret Configuration
    # Set AGENTSHIELD_AUTHORIZATION_SECRET in production environments.
    AGENTSHIELD_AUTHORIZATION_SECRET: Optional[str] = None
    SECRET_KEY: str = "agentshield-local-security-secret-key-change-in-prod"

    # Future AI provider placeholders (DO NOT CONNECT IN PHASE 0)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL_NAME: str = "llama3"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    def get_authorization_secret(self) -> str:
        """
        Resolve secret key used for HMAC-SHA256 security authorization credential signing.
        In non-development environments (ENVIRONMENT != 'development'), AGENTSHIELD_AUTHORIZATION_SECRET is mandatory.
        In development mode, falls back to a documented local development secret if not set.
        """
        if self.AGENTSHIELD_AUTHORIZATION_SECRET and self.AGENTSHIELD_AUTHORIZATION_SECRET.strip():
            return self.AGENTSHIELD_AUTHORIZATION_SECRET

        if self.ENVIRONMENT != "development":
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: AGENTSHIELD_AUTHORIZATION_SECRET environment variable "
                "must be explicitly set in non-development environments."
            )

        # Documented local development fallback secret key
        return "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"

settings = Settings()
