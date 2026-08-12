import pytest
from pydantic import ValidationError
from app.security import AgentIdentity

def test_agent_identity_valid():
    agent = AgentIdentity(name="TestAgent", version="1.2.0")
    assert agent.name == "TestAgent"
    assert agent.version == "1.2.0"
    assert agent.agent_id is not None
    assert agent.provider == "internal"

def test_agent_identity_missing_name():
    with pytest.raises(ValidationError):
        AgentIdentity()

def test_agent_identity_empty_name():
    with pytest.raises(ValidationError):
        AgentIdentity(name="   ")

def test_agent_identity_immutability():
    agent = AgentIdentity(name="ImmutableAgent")
    with pytest.raises(ValidationError):
        agent.name = "MutatedAgent"
