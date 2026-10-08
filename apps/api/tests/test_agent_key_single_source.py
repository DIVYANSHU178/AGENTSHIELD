"""
Phase 2.0 / F4 — single authoritative dev-agent-key configuration source.

The dev agent key for ``eos_core`` previously existed as a bare literal in
multiple locations. This suite proves:

  * ``settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY`` is the single authoritative
    value on the AgentShield side;
  * the agent registry seeds ``eos_core`` from that setting (no duplicated
    literal in the seed path);
  * the registry authenticates the EOS client key through the same value
    (stable E2E dev behavior);
  * the cross-repo contract value remains the documented dev key, and
    production registration never depends on it (operator-provisioned).
"""

import pytest

from app.agent.registry import AgentRegistry, get_agent_registry, hash_agent_key
from app.config.settings import settings


def _no_db_session():
    raise RuntimeError("hermetic test: no database session")


@pytest.fixture()
def memory_registry():
    return AgentRegistry(session_factory=_no_db_session, auto_seed=True)


def test_setting_is_the_canonical_value():
    assert settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY == "agk_eos_core_dev_key"
    # It must remain a string (contract with EOS utils/config).
    assert isinstance(settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY, str)


def test_registry_seeds_eos_core_from_settings(memory_registry):
    agent = memory_registry.get("eos_core")
    assert agent is not None
    assert agent.api_key_hash == hash_agent_key(settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY)


def test_registry_authenticates_client_key_from_settings(memory_registry):
    found = memory_registry.get_by_api_key(settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY)
    assert found is not None
    assert found.agent_id == "eos_core"


def test_registry_seed_contains_no_duplicated_literal():
    """The seed path must reference the setting, not a second literal copy."""
    import inspect
    from app.agent.registry import AgentRegistry
    src = inspect.getsource(AgentRegistry.seed_default_agents)
    # The setting is referenced; the source no longer embeds the literal.
    assert "AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY" in src
    assert src.count('"agk_eos_core_dev_key"') == 0


def test_singleton_registry_still_resolves_eos_core():
    ag = get_agent_registry()
    assert ag is not None
    assert ag.get_by_api_key(settings.AGENTSHIELD_EOS_CORE_DEV_AGENT_KEY) is not None