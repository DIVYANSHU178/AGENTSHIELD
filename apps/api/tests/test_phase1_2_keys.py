"""
Phase 1.2 Key Infrastructure Tests (AgentShield).

Covers the Ed25519 signing plane:
- dev auto-generation of the keypair under .keys/
- public-key publication (protocol §3.2 shapes) and rotation map
- sign/verify roundtrip, tamper rejection
- production fail-closed when no signing key material is configured
- /api/v1/security/signing/public-key and /public-keys endpoint behaviour
  (200 with key, 503 without)

EOS verifies with PUBLIC keys only — none of these tests ever expose a private
key over an interface.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config.settings import Settings
from app.security.keys import SigningKeyManager, SIGNING_ALGORITHM_ED25519
from app.security.keys.service import SigningKeyError
import app.api.signing_router as signing_router_module


from types import SimpleNamespace


def _production_settings() -> SimpleNamespace:
    """Production configuration with NO signing key material configured.

    Uses a lightweight config object because constructing a real pydantic
    ``Settings(ENVIRONMENT="production")`` triggers the production secret
    validators (expected fail-closed behaviour); the SigningKeyManager only
    reads its relevant attributes.
    """
    return SimpleNamespace(
        ENVIRONMENT="production",
        AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64=None,
        AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE=None,
        AGENTSHIELD_SIGNING_PUBLIC_KEYS=None,
        AGENTSHIELD_SIGNING_KEY_ID="v1",
        AGENTSHIELD_SIGNING_ISSUER="eos.agentshield",
        AGENTSHIELD_SIGNING_DEV_AUTOGEN=False,
    )


def _development_settings() -> Settings:
    return Settings(ENVIRONMENT="development", _env_file=None)


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# Dev auto-generation
# ---------------------------------------------------------------------------

def test_dev_autogen_creates_keypair_files(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    assert mgr.has_signing_key() is True
    assert (tmp_path / "as_signing_ed25519.key").exists()
    assert (tmp_path / "as_signing_ed25519.pub").exists()


def test_dev_autogen_is_stable_across_reload(tmp_path):
    mgr_a = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    mgr_b = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    assert mgr_a.active_public_key_raw_b64() == mgr_b.active_public_key_raw_b64()


def test_distinct_keys_dirs_produce_distinct_keys(tmp_path):
    mgr_a = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path / "a"))
    mgr_b = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path / "b"))
    assert mgr_a.active_public_key_raw_b64() != mgr_b.active_public_key_raw_b64()


# ---------------------------------------------------------------------------
# Public-key shape (protocol §3.2)
# ---------------------------------------------------------------------------

def test_public_key_info_shape(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    info = mgr.public_key_info()
    assert set(info) == {"key_id", "algorithm", "public_key_base64", "issuer"}
    assert info["algorithm"] == SIGNING_ALGORITHM_ED25519
    assert info["key_id"] == "v1"
    assert info["issuer"] == "eos.agentshield"
    raw = base64.b64decode(info["public_key_base64"])
    assert len(raw) == 32  # raw 32-byte Ed25519 public key


def test_issuer_and_kid_identity(tmp_path):
    s = Settings(
        ENVIRONMENT="development",
        AGENTSHIELD_SIGNING_KEY_ID="v9",
        AGENTSHIELD_SIGNING_ISSUER="custom.issuer.test",
        _env_file=None,
    )
    mgr = SigningKeyManager(configured_settings=s, keys_dir=str(tmp_path))
    assert mgr.active_key_id == "v9"
    assert mgr.issuer == "custom.issuer.test"


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def test_sign_verify_roundtrip(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    sig = mgr.sign(b"canonical-payload-bytes")
    assert isinstance(sig, str) and sig
    # base64url without padding; Ed25519 signatures decode to 64 bytes
    decoded = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    assert len(decoded) == 64
    assert mgr.verify(b"canonical-payload-bytes", sig) is True


def test_verify_rejects_tampered_payload(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    sig = mgr.sign(b"original")
    assert mgr.verify(b"tampered", sig) is False


def test_verify_rejects_tampered_signature(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    sig = mgr.sign(b"original")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert mgr.verify(b"original", flipped) is False


def test_verify_rejects_unknown_key_id(tmp_path):
    mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    sig = mgr.sign(b"original")
    assert mgr.verify(b"original", sig, key_id="nope") is False


def test_rotation_map_publishes_extra_keys(tmp_path):
    import base64 as b64
    extra_pub = base64.b64encode(b"\x01" * 32).decode()
    s = Settings(
        ENVIRONMENT="development",
        AGENTSHIELD_SIGNING_PUBLIC_KEYS=json.dumps({"v2_legacy": extra_pub}),
        _env_file=None,
    )
    mgr = SigningKeyManager(configured_settings=s, keys_dir=str(tmp_path))
    pub_map = mgr.public_key_map()
    assert "v1" in pub_map
    assert pub_map["v2_legacy"] == extra_pub


# ---------------------------------------------------------------------------
# Production fail-closed
# ---------------------------------------------------------------------------

def test_production_missing_key_fails_closed(tmp_path):
    mgr = SigningKeyManager(configured_settings=_production_settings(), keys_dir=str(tmp_path))
    assert mgr.has_signing_key() is False
    assert mgr.signing_unavailable_reason() is not None
    with pytest.raises(SigningKeyError):
        mgr.sign(b"payload")
    assert mgr.public_key_map() == {}


def test_production_file_key_loads(tmp_path):
    dev_mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    assert dev_mgr.has_signing_key() is True  # materialize the dev keypair on disk
    key_file = tmp_path / "as_signing_ed25519.key"
    s = SimpleNamespace(
        ENVIRONMENT="production",
        AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64=None,
        AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE=str(key_file),
        AGENTSHIELD_SIGNING_PUBLIC_KEYS=None,
        AGENTSHIELD_SIGNING_KEY_ID="v1",
        AGENTSHIELD_SIGNING_ISSUER="eos.agentshield",
        AGENTSHIELD_SIGNING_DEV_AUTOGEN=False,
    )
    prod_mgr = SigningKeyManager(configured_settings=s, keys_dir=str(tmp_path / "prod"))
    assert prod_mgr.has_signing_key() is True
    assert prod_mgr.active_public_key_raw_b64() == dev_mgr.active_public_key_raw_b64()


def test_production_env_base64_key_loads(tmp_path):
    dev_mgr = SigningKeyManager(configured_settings=_development_settings(), keys_dir=str(tmp_path))
    assert dev_mgr.has_signing_key() is True  # materialize the dev keypair on disk
    key_file = tmp_path / "as_signing_ed25519.key"
    priv_b64 = base64.b64encode(key_file.read_bytes()).decode()
    s = SimpleNamespace(
        ENVIRONMENT="production",
        AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64=priv_b64,
        AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE=None,
        AGENTSHIELD_SIGNING_PUBLIC_KEYS=None,
        AGENTSHIELD_SIGNING_KEY_ID="v1",
        AGENTSHIELD_SIGNING_ISSUER="eos.agentshield",
        AGENTSHIELD_SIGNING_DEV_AUTOGEN=False,
    )
    prod_mgr = SigningKeyManager(configured_settings=s, keys_dir=str(tmp_path / "prod2"))
    assert prod_mgr.has_signing_key() is True


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

def test_public_key_endpoint_returns_key_identity(client):
    resp = client.get("/api/v1/security/signing/public-key")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"key_id", "algorithm", "public_key_base64", "issuer"}
    assert body["algorithm"] == SIGNING_ALGORITHM_ED25519


def test_public_keys_endpoint_returns_map(client):
    resp = client.get("/api/v1/security/signing/public-keys")
    assert resp.status_code == 200
    body = resp.json()
    assert body["issuer"] == "eos.agentshield"
    assert body["active_key_id"] == "v1"
    assert "v1" in body["public_keys"]


def test_public_key_endpoint_503_when_signing_unavailable(monkeypatch, tmp_path):
    unavailable = SigningKeyManager(configured_settings=_production_settings(), keys_dir=str(tmp_path / "none"))
    monkeypatch.setattr(signing_router_module, "get_signing_key_manager", lambda: unavailable)
    resp = TestClient(app).get("/api/v1/security/signing/public-key")
    assert resp.status_code == 503


def test_public_keys_endpoint_503_when_signing_unavailable(monkeypatch, tmp_path):
    unavailable = SigningKeyManager(configured_settings=_production_settings(), keys_dir=str(tmp_path / "none"))
    monkeypatch.setattr(signing_router_module, "get_signing_key_manager", lambda: unavailable)
    resp = TestClient(app).get("/api/v1/security/signing/public-keys")
    assert resp.status_code == 503