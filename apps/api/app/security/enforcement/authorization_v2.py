"""
AgentShield — ExecutionAuthorizationToken v2 (Ed25519) minting (Phase 1.2).

Normative contract: `EOS/PHASE_1_2_AUTHORIZATION_PROTOCOL.md` §2–§5.

AgentShield is the SOLE signer of v2 tokens. The canonical payload layout
(§4.2) is law: both repos must serialize byte-identically. EOS verifies with
public keys only; this module never hands out the private key.

Mint sites (protocol §5):
  1. ``agent/service.handle_action`` — policy ALLOW decision.
  2. ``agent/service.handle_action`` — approval-satisfied resume.
(``ApprovalService.approve`` records approval execution_state for eos-style
requests but never mints an EOS-facing v2 token; the approval-satisfied resume
is the single mint moment — Phase 1.2 plan §8.6, mandate §14.)
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from app.security.keys import SigningKeyManager, get_signing_key_manager, SIGNING_ALGORITHM_ED25519
from app.security.keys.service import SigningKeyError
from app.security.models.utils import generate_uuid, utc_now, ensure_utc
from app.config.settings import settings


def _b64url_decode(value: str) -> bytes:
    import base64
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def ensure_utc_dt(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return ensure_utc(value)


def compute_arguments_hash(parameters: Optional[Dict[str, Any]]) -> str:
    """
    Deterministic SHA-256 over the canonical JSON of the exact server-received
    ``parameters`` dict (protocol §4.4). EOS recomputes the identical value over
    ``{**arguments, "operation": ..., "target": ...}`` and requires equality.
    """
    canonical = json.dumps(parameters or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_canonical_payload_v2(
    *,
    issuer: str,
    key_id: str,
    authorization_id: str,
    action_id: str,
    correlation_id: str,
    decision: str,
    principal: str,
    tool: str,
    target: str,
    request_fingerprint: str,
    arguments_hash: str,
    policy_id: str,
    risk_score: float,
    issued_at: datetime,
    expires_at: Optional[datetime],
    approval_id: Optional[str],
    nonce: str,
) -> str:
    """
    Canonical payload signed by Ed25519 (protocol §4.2). Line order MUST NOT
    change; this is byte-exact shared law with the EOS repository.
    """
    issued_iso = ensure_utc(issued_at).isoformat()
    expires_iso = ensure_utc(expires_at).isoformat() if expires_at else ""
    lines = [
        "authz.v2",
        f"issuer:{issuer}",
        f"kid:{key_id}",
        f"authz_id:{authorization_id}",
        f"action_id:{action_id}",
        f"correlation_id:{correlation_id}",
        "decision:ALLOW",
        f"principal:{principal}",
        f"tool:{tool}",
        f"target:{target}",
        f"fingerprint:{request_fingerprint}",
        f"args_hash:{arguments_hash}",
        f"policy_id:{policy_id}",
        f"risk_score:{risk_score:.2f}",
        f"issued_at:{issued_iso}",
        f"expires_at:{expires_iso}",
        f"approval_id:{approval_id or ''}",
        f"nonce:{nonce}",
    ]
    return "\n".join(lines)


def mint_execution_authorization_v2(
    *,
    action_id: str,
    correlation_id: str,
    request_fingerprint: str,
    principal: str,
    tool: str,
    target: str,
    parameters: Optional[Dict[str, Any]],
    policy_id: str,
    risk_score: float,
    approval_id: Optional[str] = None,
    manager: Optional[SigningKeyManager] = None,
    ttl_seconds: Optional[int] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Mint a v2 ExecutionAuthorizationToken field-dict (protocol §3.1) signed with
    the active Ed25519 key. Fails CLOSED (raises SigningKeyError) when no
    signing key is available.
    """
    mgr = manager or get_signing_key_manager()
    if not mgr.has_signing_key():
        raise SigningKeyError(
            mgr.signing_unavailable_reason() or "AgentShield signing key unavailable."
        )

    ttl = ttl_seconds or int(getattr(settings, "AGENTSHIELD_AUTH_TOKEN_TTL_SECONDS", 120) or 120)
    issued = utc_now()
    expires = issued + timedelta(seconds=max(int(ttl), 1))
    authorization_id = generate_uuid()
    nonce = generate_uuid()
    arguments_hash = compute_arguments_hash(parameters)
    issuer = mgr.issuer
    key_id = mgr.active_key_id

    payload = build_canonical_payload_v2(
        issuer=issuer,
        key_id=key_id,
        authorization_id=authorization_id,
        action_id=action_id,
        correlation_id=correlation_id,
        decision="ALLOW",
        principal=principal,
        tool=tool,
        target=target or "",
        request_fingerprint=request_fingerprint,
        arguments_hash=arguments_hash,
        policy_id=policy_id,
        risk_score=float(risk_score),
        issued_at=issued,
        expires_at=expires,
        approval_id=approval_id,
        nonce=nonce,
    )
    signature = mgr.sign(payload.encode("utf-8"))

    metadata: Dict[str, Any] = dict(extra_metadata or {})
    metadata["protocol"] = "authorization.v2"
    metadata["signed_payload_algo"] = SIGNING_ALGORITHM_ED25519

    return {
        "authorization_id": authorization_id,
        "action_id": action_id,
        "correlation_id": correlation_id,
        "decision": "ALLOW",
        "request_fingerprint": request_fingerprint,
        "policy_id": policy_id,
        "risk_score": float(risk_score),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "issuer": issuer,
        "key_id": key_id,
        "signature_algorithm": SIGNING_ALGORITHM_ED25519,
        "principal": principal,
        "tool": tool,
        "target": target or "",
        "arguments_hash": arguments_hash,
        "approval_id": approval_id,
        "nonce": nonce,
        "signature": signature,
        "metadata": metadata,
    }


def verify_v2_signature(
    token_fields: Dict[str, Any],
    expected_issuer: str,
    expected_principal: str,
    manager: Optional[SigningKeyManager] = None,
) -> str:
    """
    Self-test verification of a v2 token field-dict. Returns "" on success or a
    rejection code mirroring the EOS choke-point vocabulary.
    """
    mgr = manager or get_signing_key_manager()
    if token_fields.get("signature_algorithm") != SIGNING_ALGORITHM_ED25519:
        return "token_signature_legacy"
    if token_fields.get("issuer") != expected_issuer:
        return "token_issuer_mismatch"
    if token_fields.get("decision", "").upper() != "ALLOW":
        return "token_decision_invalid"
    if token_fields.get("principal") != expected_principal:
        return "principal_mismatch"
    key_id = token_fields.get("key_id")
    if not key_id:
        return "key_id_untrusted"
    try:
        payload = build_canonical_payload_v2(
            issuer=token_fields.get("issuer", ""),
            key_id=key_id,
            authorization_id=token_fields.get("authorization_id", ""),
            action_id=token_fields.get("action_id", ""),
            correlation_id=token_fields.get("correlation_id", ""),
            decision="ALLOW",
            principal=token_fields.get("principal", ""),
            tool=token_fields.get("tool", ""),
            target=token_fields.get("target", "") or "",
            request_fingerprint=token_fields.get("request_fingerprint", ""),
            arguments_hash=token_fields.get("arguments_hash", ""),
            policy_id=token_fields.get("policy_id", ""),
            risk_score=float(token_fields.get("risk_score", 0.0)),
            issued_at=ensure_utc_dt(token_fields.get("issued_at")),
            expires_at=ensure_utc_dt(token_fields.get("expires_at")) if token_fields.get("expires_at") else None,
            approval_id=token_fields.get("approval_id"),
            nonce=token_fields.get("nonce", ""),
        )
        if not mgr.verify(payload.encode("utf-8"), token_fields.get("signature", ""), key_id=key_id):
            return "token_signature_invalid"
    except Exception:
        return "token_signature_invalid"
    return ""