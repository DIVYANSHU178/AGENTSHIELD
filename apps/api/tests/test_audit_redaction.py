from app.config.settings import settings
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.audit.redaction import (
    sanitize_audit_payload,
    sanitize_string_value,
    mask_string,
)
from app.security.audit.factory import SecurityEventFactory

def test_mask_string():
    assert mask_string("secretpassword") == "**********word"
    assert mask_string("123") == "****"
    assert mask_string("") == ""

def test_sanitize_string_with_secret_patterns():
    text_with_api_key = "Using key sk-proj-1234567890abcdef1234567890 to authenticate"
    sanitized = sanitize_string_value(text_with_api_key)
    assert "sk-proj-" not in sanitized
    assert "[REDACTED_TOKEN]" in sanitized

    text_with_bearer = "Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    sanitized_bearer = sanitize_string_value(text_with_bearer)
    assert "eyJhbGci" not in sanitized_bearer
    assert "[REDACTED_TOKEN]" in sanitized_bearer

def test_sanitize_configuration_secret():
    secret_key = settings.get_authorization_secret()
    text = f"Internal config secret is {secret_key} used for signatures"
    sanitized = sanitize_string_value(text)
    assert secret_key not in sanitized
    assert "[REDACTED_SECRET_KEY]" in sanitized

def test_sanitize_audit_payload_nested_dict():
    raw_payload = {
        "user": "admin",
        "password": "SuperSecretPassword123!",
        "api_key": "sk-1234567890123456789012345",
        "nested": {
            "auth_token": "secret_token_value_999",
            "safe_counter": 42,
            "items": ["safe_item", "sk-proj-abcdef1234567890abcdef"],
        },
    }

    sanitized = sanitize_audit_payload(raw_payload)

    # Password must be masked
    assert sanitized["password"] != "SuperSecretPassword123!"
    assert "SuperSecretPassword" not in str(sanitized)

    # API key must be masked/redacted
    assert "sk-123456" not in str(sanitized)

    # Nested auth_token must be masked/redacted
    assert "secret_token_value_999" not in str(sanitized)

    # Safe data preserved
    assert sanitized["user"] == "admin"
    assert sanitized["nested"]["safe_counter"] == 42
    assert sanitized["nested"]["items"][0] == "safe_item"

def test_event_factory_redacts_secrets_in_request_target_and_destination():
    secret_val = settings.get_authorization_secret()
    req = ToolRequest(
        request_id="req-leak-test",
        agent=AgentIdentity(name="SecretAgent"),
        tool_name="network.upload",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.UPLOAD,
        target=f"sensitive_files/{secret_val}.key",
        destination=f"http://example.com/api?token={secret_val}",
    )

    event = SecurityEventFactory.create_requested_event(req)
    event_json = event.model_dump_json()

    # The actual secret string must never be in the event JSON!
    assert secret_val not in event_json
