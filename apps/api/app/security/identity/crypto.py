"""
Cryptographic Utilities for AgentShield Phase 14 Identity & Authentication.

Provides:
- PBKDF2-HMAC-SHA256 password hashing with per-user salt and 100,000 iterations
- Constant-time password verification to resist timing attacks
- Cryptographically secure session token generation
"""

import hashlib
import hmac
import os
import secrets
from typing import Tuple, Optional


PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16


def generate_salt() -> str:
    """Generate a random 16-byte hex-encoded cryptographic salt."""
    return secrets.token_hex(SALT_BYTES)


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a plaintext password using PBKDF2-HMAC-SHA256.
    Returns (hex_password_hash, hex_salt).
    """
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")

    use_salt = salt or generate_salt()
    salt_bytes = bytes.fromhex(use_salt)
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS,
    )
    return hash_bytes.hex(), use_salt


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    """
    Verify a candidate plaintext password against a stored hash and salt
    using constant-time comparison.
    """
    if not password or not password_hash or not password_salt:
        return False
    try:
        candidate_hash, _ = hash_password(password, salt=password_salt)
        return hmac.compare_digest(candidate_hash, password_hash)
    except Exception:
        return False


def generate_secure_token() -> str:
    """Generate a high-entropy 32-byte URL-safe cryptographic session token."""
    return secrets.token_urlsafe(32)
