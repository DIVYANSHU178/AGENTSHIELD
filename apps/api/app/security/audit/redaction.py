import re
from typing import Any, Dict, List, Union
from app.config.settings import settings

SENSITIVE_KEY_PATTERNS = [
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "auth_token",
    "bearer",
    "credential",
]

SAFE_OPERATIONAL_KEYS = {
    "authorized",
    "authorization_id",
    "has_authorization",
    "parameter_keys",
}

SECRET_REGEX_PATTERNS = [
    re.compile(r"sk-proj-[a-zA-Z0-9_-]{15,}", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9]{20,}", re.IGNORECASE),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    re.compile(r"Bearer\s+[a-zA-Z0-9._~+/-]+=*", re.IGNORECASE),
]

def mask_string(val: str) -> str:
    """Mask a sensitive string leaving at most 4 trailing characters visible."""
    if not val:
        return ""
    clean = val.strip()
    if len(clean) <= 4:
        return "****"
    return "*" * (len(clean) - 4) + clean[-4:]

def sanitize_string_value(val: str) -> str:
    """Sanitize string values by replacing known secret patterns."""
    if not isinstance(val, str) or not val:
        return val

    # Check for known configuration secrets
    try:
        auth_secret = settings.get_authorization_secret()
        if auth_secret and auth_secret in val:
            val = val.replace(auth_secret, "[REDACTED_SECRET_KEY]")
    except Exception:
        pass

    if settings.SECRET_KEY and settings.SECRET_KEY in val:
        val = val.replace(settings.SECRET_KEY, "[REDACTED_SECRET_KEY]")

    # Check for regex secret patterns
    for pattern in SECRET_REGEX_PATTERNS:
        val = pattern.sub("[REDACTED_TOKEN]", val)

    return val

def sanitize_audit_payload(data: Any) -> Any:
    """
    Recursively sanitize dictionary, list, or primitive values for safe audit storage.
    Ensures no passwords, API keys, HMAC secrets, or tokens leak into audit events.
    """
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for k, v in data.items():
            key_str = str(k).lower()
            is_sensitive = (
                any(s in key_str for s in SENSITIVE_KEY_PATTERNS)
                and key_str not in SAFE_OPERATIONAL_KEYS
            )
            if is_sensitive:
                if isinstance(v, str):
                    sanitized[str(k)] = mask_string(v)
                else:
                    sanitized[str(k)] = "[REDACTED]"
            else:
                sanitized[str(k)] = sanitize_audit_payload(v)
        return sanitized

    elif isinstance(data, (list, tuple, set)):
        return [sanitize_audit_payload(item) for item in data]

    elif isinstance(data, str):
        return sanitize_string_value(data)

    elif isinstance(data, (int, float, bool)) or data is None:
        return data

    else:
        # For arbitrary objects, convert to string safely
        return sanitize_string_value(str(data))
