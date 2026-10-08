"""
AgentShield — Security Signing Key Infrastructure (Phase 1.2).

Ed25519 signing/verification keys are the cryptographic root of the v2
ExecutionAuthorizationToken protocol between AgentShield (mints) and EOS
(verifies). AgentShield is the ONLY party that ever holds the private signing
key; EOS holds public keys exclusively.

Key material precedence (highest first):
  1. AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64  (base64 of a PKCS8 PEM private key)
  2. AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE     (path to a PEM private key file)
  3. Dev auto-generation under ``<repo>/apps/api/.keys/`` — ONLY in
     non-production environments (missing keys fail closed in production: no
     mint, no published public key).

Key rotation: a token carries ``key_id`` (default "v1"). EOS fetches the map of
public keys and batches issuances under the active key id. Old public keys can
be published alongside the active one via ``AGENTSHIELD_SIGNING_PUBLIC_KEYS``
(JSON map ``{key_id: base64}``) to keep already-issued tokens verifiable during
rotation.
"""

from .service import (
    SigningKeyManager,
    get_signing_key_manager,
    SIGNING_ALGORITHM_ED25519,
    key_manager,
)

__all__ = [
    "SigningKeyManager",
    "get_signing_key_manager",
    "SIGNING_ALGORITHM_ED25519",
    "key_manager",
]