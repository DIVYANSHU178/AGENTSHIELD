"""
AgentShield — Public Signing Key Router (Phase 1.2).

Publishes the Ed25519 public keys that EOS uses to verify v2
ExecutionAuthorizationTokens. These endpoints are intentionally public
(no agent credential required): a public key is not a secret.

Endpoints:
  GET /api/v1/security/signing/public-key   -> active key identity (protocol §3.2)
  GET /api/v1/security/signing/public-keys  -> full {key_id: base64} map + issuer

Fail-closed: when no signing key is loaded (production without configured key
material), these return 503 so EOS treats the signing plane as unavailable.
"""

from typing import Dict

from fastapi import APIRouter, HTTPException, status

from app.security.keys import get_signing_key_manager

signing_router = APIRouter(prefix="/security/signing", tags=["signing-keys"])


@signing_router.get("/public-key")
def get_public_key() -> Dict:
    manager = get_signing_key_manager()
    if not manager.has_signing_key():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=manager.signing_unavailable_reason() or "Signing key unavailable.",
        )
    return manager.public_key_info()


@signing_router.get("/public-keys")
def get_public_keys() -> Dict:
    manager = get_signing_key_manager()
    if not manager.has_signing_key():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=manager.signing_unavailable_reason() or "Signing key unavailable.",
        )
    return {
        "issuer": manager.issuer,
        "active_key_id": manager.active_key_id,
        "algorithm": manager.algorithm,
        "public_keys": manager.public_key_map(),
    }