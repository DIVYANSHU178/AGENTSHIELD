"""
Phase 1.2 v2 Authorization Protocol Tests (AgentShield mint side).

The canonical payload byte layout (protocol §4.2) is pinned here with an exact
expected string so the EOS repo's verifier can be asserted byte-identical.
These tests also cover:
- compute_arguments_hash determinism (JSON canonical form)
- mint shape: all protocol §3.1 fields, TTL bound, base64url Ed25519 signature
- mint fail-closed when the signing plane is unavailable
- verify_v2_signature accept/tamper/legacy-marker rejection codes
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.config.settings import Settings
from app.security.enforcement.authorization_v2 import (
    build_canonical_payload_v2,
    compute_arguments_hash,
    mint_execution_authorization_v2,
    verify_v2_signature,
)
from app.security.keys import SigningKeyManager, SIGNING_ALGORITHM_ED25519
from app.security.keys.service import SigningKeyError


def _dev_manager(tmp_path) -> SigningKeyManager:
    return SigningKeyManager(
        configured_settings=Settings(ENVIRONMENT="development", _env_file=None),
        keys_dir=str(tmp_path),
    )


def _prod_manager(tmp_path) -> SigningKeyManager:
    return SigningKeyManager(
        configured_settings=SimpleNamespace(
            ENVIRONMENT="production",
            AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64=None,
            AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE=None,
            AGENTSHIELD_SIGNING_PUBLIC_KEYS=None,
            AGENTSHIELD_SIGNING_KEY_ID="v1",
            AGENTSHIELD_SIGNING_ISSUER="eos.agentshield",
            AGENTSHIELD_SIGNING_DEV_AUTOGEN=False,
        ),
        keys_dir=str(tmp_path),
    )


# ---------------------------------------------------------------------------
# Canonical payload byte-layout (protocol §4.2) — LOCKED
# ---------------------------------------------------------------------------

def test_canonical_payload_layout_is_locked():
    issued = datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc)
    expires = datetime(2026, 9, 23, 10, 2, 0, tzinfo=timezone.utc)
    payload = build_canonical_payload_v2(
        issuer="eos.agentshield",
        key_id="v1",
        authorization_id="authz_test_0001",
        action_id="act_test_0001",
        correlation_id="corr_test_0001",
        decision="ALLOW",
        principal="eos_core",
        tool="system_time",
        target="any",
        request_fingerprint="a" * 64,
        arguments_hash="b" * 64,
        policy_id="policy.risk.low.allow",
        risk_score=10.0,
        issued_at=issued,
        expires_at=expires,
        approval_id=None,
        nonce="nonce_test_0001",
    )
    expected = "\n".join(
        [
            "authz.v2",
            "issuer:eos.agentshield",
            "kid:v1",
            "authz_id:authz_test_0001",
            "action_id:act_test_0001",
            "correlation_id:corr_test_0001",
            "decision:ALLOW",
            "principal:eos_core",
            "tool:system_time",
            "target:any",
            f"fingerprint:{'a' * 64}",
            f"args_hash:{'b' * 64}",
            "policy_id:policy.risk.low.allow",
            "risk_score:10.00",
            "issued_at:2026-09-23T10:00:00+00:00",
            "expires_at:2026-09-23T10:02:00+00:00",
            "approval_id:",
            "nonce:nonce_test_0001",
        ]
    )
    assert payload == expected


def test_canonical_payload_emits_approval_id_when_present():
    issued = datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc)
    payload = build_canonical_payload_v2(
        issuer="iss", key_id="k1", authorization_id="z", action_id="a",
        correlation_id="c", decision="ALLOW", principal="p", tool="t",
        target="tg", request_fingerprint="f" * 64, arguments_hash="h" * 64,
        policy_id="pol", risk_score=12.5, issued_at=issued, expires_at=None,
        approval_id="appr_123", nonce="n",
    )
    assert "approval_id:appr_123" in payload
    assert "expires_at:" in payload


def test_canonical_payload_no_trailing_newline():
    issued = datetime(2026, 9, 23, 10, 0, 0, tzinfo=timezone.utc)
    payload = build_canonical_payload_v2(
        issuer="iss", key_id="k1", authorization_id="z", action_id="a",
        correlation_id="c", decision="ALLOW", principal="p", tool="t",
        target="", request_fingerprint="f" * 64, arguments_hash="h" * 64,
        policy_id="pol", risk_score=5.0, issued_at=issued, expires_at=None,
        approval_id=None, nonce="n",
    )
    assert not payload.endswith("\n")


# ---------------------------------------------------------------------------
# arguments_hash
# ---------------------------------------------------------------------------

def test_arguments_hash_is_order_independent():
    a = {"operation": "QUERY", "target": "any", "zone": "clock", "n": 1, "flag": True}
    b = dict(reversed(list(a.items())))
    assert compute_arguments_hash(a) == compute_arguments_hash(b)


def test_arguments_hash_matches_manual_canonical_json():
    params = {"operation": "QUERY", "target": "any", "zone": "clock"}
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"))
    assert compute_arguments_hash(params) == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_arguments_hash_empty_dict():
    assert compute_arguments_hash(None) == compute_arguments_hash({})


# ---------------------------------------------------------------------------
# Mint shape
# ---------------------------------------------------------------------------

def _mint_default(tmp_path, **overrides):
    kwargs = dict(
        action_id="act_001",
        correlation_id="corr_001",
        request_fingerprint="a" * 64,
        principal="eos_core",
        tool="system_time",
        target="any",
        parameters={"operation": "QUERY", "target": "any", "zone": "clock"},
        policy_id="policy.risk.low.allow",
        risk_score=10.0,
        approval_id=None,
        manager=_dev_manager(tmp_path),
    )
    kwargs.update(overrides)
    return mint_execution_authorization_v2(**kwargs)


def test_mint_returns_full_protocol_shape(tmp_path):
    token = _mint_default(tmp_path)
    expected_fields = {
        "authorization_id", "action_id", "correlation_id", "decision",
        "request_fingerprint", "policy_id", "risk_score", "issued_at",
        "expires_at", "issuer", "key_id", "signature_algorithm", "principal",
        "tool", "target", "arguments_hash", "approval_id", "nonce",
        "signature", "metadata",
    }
    assert set(token) == expected_fields
    assert token["decision"] == "ALLOW"
    assert token["signature_algorithm"] == SIGNING_ALGORITHM_ED25519
    assert token["issuer"] == "eos.agentshield"
    assert token["key_id"] == "v1"
    assert token["principal"] == "eos_core"
    assert token["tool"] == "system_time"
    assert token["approval_id"] is None
    assert token["signature"] and not token["signature"].endswith("=")


def test_mint_signature_is_64_bytes_ed25519(tmp_path):
    token = _mint_default(tmp_path)
    sig_bytes = base64.urlsafe_b64decode(token["signature"] + "=" * (-len(token["signature"]) % 4))
    assert len(sig_bytes) == 64


def test_mint_arguments_hash_binds_received_parameters(tmp_path):
    params = {"operation": "QUERY", "target": "any", "zone": "clock", "ts": 1700000000}
    token = _mint_default(tmp_path, parameters=params)
    assert token["arguments_hash"] == compute_arguments_hash(params)


def test_mint_ttl_bounded_by_default(tmp_path):
    from datetime import datetime as _dt
    token = _mint_default(tmp_path)
    issued = _dt.fromisoformat(token["issued_at"])
    expires = _dt.fromisoformat(token["expires_at"])
    delta = expires - issued
    assert 0 < delta.total_seconds() <= 120


def test_mint_approval_id_carried(tmp_path):
    token = _mint_default(tmp_path, approval_id="appr_live_1")
    assert token["approval_id"] == "appr_live_1"


def test_mint_fails_closed_without_signing_key(tmp_path):
    with pytest.raises(SigningKeyError):
        _mint_default(tmp_path, manager=_prod_manager(tmp_path))


# ---------------------------------------------------------------------------
# verify_v2_signature (AS self-test loop; EOS performs the real check)
# ---------------------------------------------------------------------------

def test_verify_accepts_valid_token(tmp_path):
    token = _mint_default(tmp_path)
    assert verify_v2_signature(token, "eos.agentshield", "eos_core", manager=_dev_manager(tmp_path)) == ""


def test_verify_rejects_tampered_signature(tmp_path):
    token = _mint_default(tmp_path)
    tampered = dict(token)
    bad_sig = ("A" if token["signature"][0] != "A" else "B") + token["signature"][1:]
    tampered["signature"] = bad_sig
    assert verify_v2_signature(tampered, "eos.agentshield", "eos_core", manager=_dev_manager(tmp_path)) == "token_signature_invalid"


def test_verify_rejects_tampered_fingerprint(tmp_path):
    token = _mint_default(tmp_path)
    tampered = dict(token)
    tampered["request_fingerprint"] = "0" * 64
    assert verify_v2_signature(tampered, "eos.agentshield", "eos_core", manager=_dev_manager(tmp_path)) == "token_signature_invalid"


def test_verify_rejects_legacy_hmac_marker(tmp_path):
    token = _mint_default(tmp_path)
    legacy = dict(token)
    legacy["signature_algorithm"] = "hmac-sha256"
    assert verify_v2_signature(legacy, "eos.agentshield", "eos_core", manager=_dev_manager(tmp_path)) == "token_signature_legacy"


def test_verify_rejects_wrong_issuer(tmp_path):
    token = _mint_default(tmp_path)
    assert verify_v2_signature(token, "evil.issuer", "eos_core", manager=_dev_manager(tmp_path)) == "token_issuer_mismatch"


def test_verify_rejects_wrong_principal(tmp_path):
    token = _mint_default(tmp_path)
    assert verify_v2_signature(token, "eos.agentshield", "orion", manager=_dev_manager(tmp_path)) == "principal_mismatch"