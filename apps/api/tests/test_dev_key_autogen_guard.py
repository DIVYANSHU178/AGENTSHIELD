"""
Phase 2.0 / F11 — development signing-key AUTO-GENERATION GUARD.

Development Ed25519 keypairs on disk are acceptable for development, but the
auto-generation of an AgentShield signing authority key must NEVER silently
become production authority. This suite proves:

  * autogen is allowed ONLY in explicit dev/test/QA/CI environments;
  * production and prod-like env names never autogen (fail closed);
  * previously-dangerous UNKNOWN environments (e.g. "staging", "live", "prd",
    empty string) are now rejected instead of silently autogenerating;
  * the AGENTSHIELD_SIGNING_DEV_AUTOGEN switch can disable autogen entirely;
  * a missing production key material -> has_signing_key() == False
    (fail closed, no key material auto-created).
"""

from types import SimpleNamespace

import pytest

from app.security.keys.service import SigningKeyManager


def _settings(environment, autogen=True):
    return SimpleNamespace(
        ENVIRONMENT=environment,
        AGENTSHIELD_SIGNING_DEV_AUTOGEN=autogen,
        AGENTSHIELD_SIGNING_PRIVATE_KEY_BASE64=None,
        AGENTSHIELD_SIGNING_PRIVATE_KEY_FILE=None,
        AGENTSHIELD_SIGNING_KEY_ID="v1",
        AGENTSHIELD_SIGNING_ISSUER="eos.agentshield",
    )


@pytest.mark.parametrize("env", ["development", "dev", "local", "test", "testing", "qa", "test_qa", "ci"])
def test_autogen_allowed_in_explicit_dev_contexts(env):
    mgr = SigningKeyManager(configured_settings=_settings(env), keys_dir="ignored")
    assert mgr._dev_autogen_allowed() is True


@pytest.mark.parametrize("env", ["production", "prod"])
def test_autogen_never_allowed_in_production(env):
    mgr = SigningKeyManager(configured_settings=_settings(env), keys_dir="ignored")
    assert mgr._dev_autogen_allowed() is False


@pytest.mark.parametrize("env", ["staging", "live", "prd", "production2", "Prod ", "PRODUCTION", "Dev ", "devOps"])
def test_autogen_rejected_in_unknown_or_ambiguous_environments(env):
    """Fail closed: an unrecognized environment must never auto-generate.

    NOTE: an empty/unset ENVIRONMENT is the documented development default in
    AgentShield settings (``ENVIRONMENT: str = "development"``), so it is NOT
    an ambiguous case here — that is consistent with ``is_dev_mode()``.
    """
    mgr = SigningKeyManager(configured_settings=_settings(env), keys_dir="ignored")
    assert mgr._dev_autogen_allowed() is False


def test_autogen_switch_can_disable_even_in_dev():
    mgr = SigningKeyManager(
        configured_settings=_settings("development", autogen=False), keys_dir="ignored"
    )
    assert mgr._dev_autogen_allowed() is False


def test_production_without_key_material_fails_closed(tmp_path):
    """No signing key configured + production = fail closed, NO key created."""
    keys_dir = tmp_path / "prod_keys"
    mgr = SigningKeyManager(
        configured_settings=_settings("production"), keys_dir=str(keys_dir)
    )
    assert mgr.has_signing_key() is False
    assert mgr.signing_unavailable_reason() is not None
    assert not list(keys_dir.rglob("*")), "production must never create key material"


def test_staging_without_key_material_fails_closed(tmp_path):
    """Ambiguous environments behave like production: fail closed, NO autogen."""
    keys_dir = tmp_path / "stage_keys"
    mgr = SigningKeyManager(
        configured_settings=_settings("staging"), keys_dir=str(keys_dir)
    )
    assert mgr.has_signing_key() is False
    assert mgr.signing_unavailable_reason() is not None
    assert not list(keys_dir.rglob("*")), "staging must never create key material"


def test_dev_without_key_material_may_autogen_into_dev_keys(tmp_path):
    keys_dir = tmp_path / "dev_keys"
    mgr = SigningKeyManager(
        configured_settings=_settings("development"), keys_dir=str(keys_dir)
    )
    assert mgr._dev_autogen_allowed() is True
    assert mgr.has_signing_key() is True
    assert list(keys_dir.rglob("*")), "dev autogen should materialize a keypair"