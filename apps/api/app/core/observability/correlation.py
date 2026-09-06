"""
Correlation ID context management and validation for AgentShield Observability.

Manages request-scoped correlation identifiers across asynchronous tasks and thread pools
using Python standard contextvars.
"""

import re
import uuid
from contextvars import ContextVar, Token
from typing import Optional

CORRELATION_HEADER_NAMES = ("x-correlation-id", "x-request-id")
CORRELATION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")
DEFAULT_CORRELATION_PREFIX = "req-"

# Thread-safe, async-safe context variable holding the current correlation ID
_correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id", default="req-system-init")


def generate_correlation_id() -> str:
    """Generate a high-entropy, cryptographically safe correlation ID in req-<uuid4> format."""
    return f"{DEFAULT_CORRELATION_PREFIX}{uuid.uuid4()}"


def validate_and_sanitize_correlation_id(raw_id: Optional[str]) -> str:
    """
    Validate an untrusted correlation ID against strict security rules.

    Rules:
    - 8 to 64 characters
    - Must match ^[a-zA-Z0-9_-]{8,64}$
    - Strictly rejects whitespace, control characters, newlines, quotes, or JSON payloads
    - If invalid, empty, or None, returns a newly generated high-entropy correlation ID.
    """
    if not raw_id or not isinstance(raw_id, str):
        return generate_correlation_id()

    # Reject leading/trailing whitespace or whitespace inside
    if raw_id != raw_id.strip() or any(c.isspace() for c in raw_id):
        return generate_correlation_id()

    # Reject control characters, newlines, quotes
    if any(ord(c) < 32 or ord(c) > 126 or c in ('"', "'", "\\", "`") for c in raw_id):
        return generate_correlation_id()

    # Check strict regex pattern
    if not CORRELATION_ID_PATTERN.match(raw_id):
        return generate_correlation_id()

    return raw_id


def get_correlation_id() -> str:
    """Retrieve the current request correlation ID from contextvars."""
    return _correlation_id_ctx.get()


def set_correlation_id(corr_id: str) -> Token:
    """
    Set the current correlation ID in contextvars.
    Returns a Token that can be used to reset the context later.
    """
    return _correlation_id_ctx.set(corr_id)


def reset_correlation_id(token: Token) -> None:
    """Reset the correlation ID context to its prior value."""
    _correlation_id_ctx.reset(token)
