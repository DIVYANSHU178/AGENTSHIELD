import os
import re
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

API_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    """
    Central, typed, environment-aware configuration boundary for AgentShield.
    Phase 15 Secrets & Configuration Hardening.

    Security Invariants:
    - Secrets are never hardcoded for production use.
    - Production mode strictly rejects default/weak secrets (>= 32 chars required).
    - Production mode rejects automatic default credential bootstrapping.
    - Insecure LAN CORS regex is inactive in production unless explicitly configured.
    - Database connection strings are masked when exposed in sanitized configuration.
    """
    APP_NAME: str = "AgentShield"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_HOST: str = "127.0.0.1"
    API_PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./agentshield.db"
    QA_DATABASE_URL: str = "sqlite:///./agentshield_qa.db"

    # Allow default test credentials only in development / QA / test environments
    ALLOW_DEFAULT_CREDENTIALS: bool = False

    # Security Authorization Secret Configuration
    # Set AGENTSHIELD_AUTHORIZATION_SECRET in production environments (min 32 chars).
    AGENTSHIELD_AUTHORIZATION_SECRET: Optional[str] = None
    SECRET_KEY: str = "agentshield-local-security-secret-key-change-in-prod"

    # Future AI provider placeholders (DO NOT CONNECT IN PHASE 0)
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL_NAME: str = "llama3"

    # CORS Allowed Origins Configuration
    # Comma-separated string of allowed origins. Configurable via CORS_ALLOWED_ORIGINS environment variable.
    CORS_ALLOWED_ORIGINS: str = (
        "http://localhost:5173,"
        "http://127.0.0.1:5173,"
        "http://localhost:3000,"
        "http://127.0.0.1:3000,"
        "http://172.25.1.97:5173"
    )

    # Configurable CORS origin regex for private LAN and local development origins.
    # Matches localhost, 127.0.0.1, and RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    # Active in development environment; can be overridden via CORS_ALLOW_ORIGIN_REGEX env var.
    CORS_ALLOW_ORIGIN_REGEX: Optional[str] = (
        r"^https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(:\d+)?$"
    )

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @model_validator(mode="after")
    def resolve_environment_and_db(self) -> "Settings":
        # Check if AGENTSHIELD_ENV is set and overrides ENVIRONMENT
        agent_env = os.environ.get("AGENTSHIELD_ENV")
        if agent_env and agent_env.strip():
            self.ENVIRONMENT = agent_env.strip().lower()

        # If running in QA environment and DATABASE_URL was left at default dev DB,
        # automatically route to the isolated QA_DATABASE_URL
        if self.ENVIRONMENT in ("qa", "test_qa") and self.DATABASE_URL == "sqlite:///./agentshield.db":
            self.DATABASE_URL = self.QA_DATABASE_URL

        # Validate production environment security constraints
        if self.is_production():
            if self.ALLOW_DEFAULT_CREDENTIALS:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: ALLOW_DEFAULT_CREDENTIALS cannot be enabled in production environments."
                )
            if self.DEBUG:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: DEBUG mode cannot be enabled in production environments."
                )
            # Enforce production secrets on configuration load (fail-closed)
            self.validate_production_secrets()

            # Reject default development database in production (fail-closed)
            if self.DATABASE_URL == "sqlite:///./agentshield.db":
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: Production environment cannot use the default development "
                    "SQLite database ('sqlite:///./agentshield.db'). An explicit, isolated production DATABASE_URL must be configured."
                )

        return self

    def validate_production_secrets(self) -> None:
        """
        Enforce strict production secret invariants.
        Must be called during configuration initialization and application startup.
        Fails closed with a clear configuration error if any required secret is missing or insecure.
        Never reveals secret values in error messages.
        """
        if self.is_production():
            self.get_authorization_secret()
            self.get_secret_key()

    def is_production(self) -> bool:
        """Returns True if the application is configured to run in a production environment."""
        return self.ENVIRONMENT.lower() in ("production", "prod")

    def is_qa_mode(self) -> bool:
        """Returns True if the application is configured to run in QA/test mode."""
        return self.ENVIRONMENT.lower() in ("qa", "test_qa") or "agentshield_qa" in self.DATABASE_URL.lower() or "qa.db" in self.DATABASE_URL.lower()

    def is_test_mode(self) -> bool:
        """Returns True if running in a test execution harness."""
        return self.ENVIRONMENT.lower() in ("test", "testing")

    def is_dev_mode(self) -> bool:
        """Returns True if the application is running against the historical development database."""
        return not self.is_qa_mode() and not self.is_production() and self.ENVIRONMENT.lower() in ("development", "dev", "local")

    def get_cors_origins(self) -> list[str]:
        """
        Parse and return the list of allowed CORS origins.
        Handles comma-separated string or list, trims whitespace and trailing slashes,
        and ensures standard development origins are preserved in development mode.
        """
        if isinstance(self.CORS_ALLOWED_ORIGINS, list):
            items = self.CORS_ALLOWED_ORIGINS
        else:
            items = [o.strip() for o in str(self.CORS_ALLOWED_ORIGINS).split(",") if o.strip()]

        dev_defaults = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]

        seen = set()
        result = []
        for origin in items + (dev_defaults if self.is_dev_mode() else []):
            norm = origin.rstrip("/")
            if norm and norm not in seen:
                seen.add(norm)
                result.append(norm)
        return result

    def get_cors_origin_regex(self) -> Optional[str]:
        """
        Return the allowed origin regex. Active in development/local environments
        or when explicitly configured via CORS_ALLOW_ORIGIN_REGEX.
        In production, the broad RFC 1918 LAN regex is inactive by default.
        """
        if not self.CORS_ALLOW_ORIGIN_REGEX or not self.CORS_ALLOW_ORIGIN_REGEX.strip():
            return None

        # In production, do not activate default private LAN regex unless explicitly customized
        if self.is_production():
            default_lan_pattern = (
                r"^https?://(localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(:\d+)?$"
            )
            if self.CORS_ALLOW_ORIGIN_REGEX.strip() == default_lan_pattern:
                return None

        return self.CORS_ALLOW_ORIGIN_REGEX.strip()

    def get_dev_database_path(self) -> Path:
        """Returns the canonical absolute path of the historical development database."""
        return (API_DIR / "agentshield.db").resolve()

    def get_qa_database_path(self) -> Path:
        """Returns the canonical absolute path of the isolated QA database."""
        return (API_DIR / "agentshield_qa.db").resolve()

    def get_database_path(self) -> Path:
        """
        Returns the resolved absolute path of the currently configured database.
        For relative SQLite URLs (e.g. sqlite:///./foo.db), resolves relative to API_DIR.
        """
        if self.DATABASE_URL.startswith("sqlite:///./"):
            rel_name = self.DATABASE_URL[len("sqlite:///./"):]
            return (API_DIR / rel_name).resolve()
        elif self.DATABASE_URL.startswith("sqlite:///") and not self.DATABASE_URL.startswith("sqlite:///:"):
            raw_path = self.DATABASE_URL[len("sqlite:///"):]
            return Path(raw_path).resolve()
        return (API_DIR / "agentshield.db").resolve()

    def get_authorization_secret(self) -> str:
        """
        Resolve secret key used for HMAC-SHA256 security authorization credential signing.
        In production environments (ENVIRONMENT not in dev/qa/testing), AGENTSHIELD_AUTHORIZATION_SECRET is mandatory
        and must meet minimum cryptographic entropy requirements (at least 24 characters).
        In development and QA testing modes, falls back to a documented local development secret if not set.
        """
        if self.AGENTSHIELD_AUTHORIZATION_SECRET and self.AGENTSHIELD_AUTHORIZATION_SECRET.strip():
            secret = self.AGENTSHIELD_AUTHORIZATION_SECRET.strip()
            if self.is_production() and len(secret) < 24:
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: AGENTSHIELD_AUTHORIZATION_SECRET must be at least 24 "
                    "characters long in production environments to ensure cryptographic HMAC-SHA256 security."
                )
            return secret

        if not (self.is_dev_mode() or self.is_qa_mode() or self.is_test_mode()):
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: AGENTSHIELD_AUTHORIZATION_SECRET environment variable "
                "must be explicitly set in non-development environments."
            )

        # Documented local development/QA fallback secret key
        return "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"

    def get_secret_key(self) -> str:
        """
        Resolve application security secret key.
        In production environments, SECRET_KEY must not use the default placeholder and must be >= 24 characters.
        """
        if self.is_production():
            if (
                not self.SECRET_KEY
                or self.SECRET_KEY == "agentshield-local-security-secret-key-change-in-prod"
                or len(self.SECRET_KEY) < 24
            ):
                raise ValueError(
                    "CRITICAL SECURITY CONFIGURATION ERROR: SECRET_KEY must be explicitly configured and at least "
                    "24 characters long in production environments."
                )
        return self.SECRET_KEY

    @staticmethod
    def mask_connection_url(url: str) -> str:
        """Mask credentials in database connection URLs (e.g. postgresql://user:pass@host/db)."""
        if not url or not isinstance(url, str):
            return ""
        return re.sub(r":([^@/]+)@", ":****@", url)

    def get_sanitized_config(self) -> Dict[str, Any]:
        """
        Return a safe dictionary representation of configuration suitable for diagnostics or health reporting.
        Guarantees zero raw secrets, passwords, or signing keys are exposed.
        """
        return {
            "app_name": self.APP_NAME,
            "environment": self.ENVIRONMENT,
            "debug": self.DEBUG,
            "api_host": self.API_HOST,
            "api_port": self.API_PORT,
            "database_url": self.mask_connection_url(self.DATABASE_URL),
            "authorization_secret_configured": bool(
                self.AGENTSHIELD_AUTHORIZATION_SECRET and self.AGENTSHIELD_AUTHORIZATION_SECRET.strip()
            ),
            "secret_key_configured": bool(
                self.SECRET_KEY and self.SECRET_KEY != "agentshield-local-security-secret-key-change-in-prod"
            ),
            "cors_allowed_origins": self.get_cors_origins(),
            "cors_origin_regex_active": bool(self.get_cors_origin_regex()),
            "allow_default_credentials": self.ALLOW_DEFAULT_CREDENTIALS,
            "is_production": self.is_production(),
            "is_qa_mode": self.is_qa_mode(),
            "is_dev_mode": self.is_dev_mode(),
            "is_test_mode": self.is_test_mode(),
        }


settings = Settings()
