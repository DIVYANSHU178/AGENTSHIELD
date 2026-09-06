import json
import pytest
from app.config.settings import Settings
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityEnforcementBoundary,
)

def test_key_management_development_fallback():
    dev_settings = Settings(ENVIRONMENT="development", AGENTSHIELD_AUTHORIZATION_SECRET=None)
    secret = dev_settings.get_authorization_secret()
    assert secret == "agentshield-dev-local-hmac-secret-key-do-not-use-in-production"

def test_key_management_non_development_secret_present():
    prod_settings = Settings(
        ENVIRONMENT="production",
        AGENTSHIELD_AUTHORIZATION_SECRET="prod-super-secret-key-999",
        SECRET_KEY="a" * 32,
        DATABASE_URL="sqlite:///./agentshield_prod.db",
    )
    secret = prod_settings.get_authorization_secret()
    assert secret == "prod-super-secret-key-999"

def test_key_management_non_development_secret_missing_raises():
    with pytest.raises(ValueError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        Settings(ENVIRONMENT="production", AGENTSHIELD_AUTHORIZATION_SECRET=None, SECRET_KEY="a" * 32)

def test_key_management_empty_secret_rejection():
    with pytest.raises(ValueError, match="CRITICAL SECURITY CONFIGURATION ERROR"):
        Settings(ENVIRONMENT="production", AGENTSHIELD_AUTHORIZATION_SECRET="   ", SECRET_KEY="a" * 32)

def test_secret_never_leaks_in_serialized_authorization_or_metadata():
    secret_key = "sensitive-secret-token-to-never-leak"
    boundary = SecurityEnforcementBoundary(secret_key=secret_key)
    agent = AgentIdentity(name="LeakCheckAgent")
    req = ToolRequest(
        request_id="req-leak-check",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    res = boundary.enforce(req)
    assert res.authorized is True
    assert res.authorization is not None

    # Check serialized JSON string
    auth_json = res.authorization.model_dump_json()
    assert secret_key not in auth_json

    # Check dict representation
    auth_dict = res.authorization.model_dump()
    assert secret_key not in str(auth_dict)

    # Check result metadata
    assert secret_key not in str(res.metadata)
    assert secret_key not in str(res.authorization.metadata)
    assert secret_key not in res.reason
