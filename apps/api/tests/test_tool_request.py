import pytest
from datetime import datetime, timezone
from pydantic import ValidationError
from app.security import AgentIdentity, ToolRequest, ToolCategory, ActionType

def test_tool_request_valid():
    agent = AgentIdentity(name="SearchAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
        parameters={"path": "sandbox/public/sample.txt"},
    )
    assert req.request_id is not None
    assert req.tool_name == "filesystem.read"
    assert req.tool_category == ToolCategory.FILESYSTEM
    assert req.action == ActionType.READ
    assert req.timestamp.tzinfo == timezone.utc

def test_tool_request_invalid_enum():
    agent = AgentIdentity(name="SearchAgent")
    with pytest.raises(ValidationError):
        ToolRequest(
            agent=agent,
            tool_name="filesystem.read",
            tool_category="INVALID_CAT",
            action=ActionType.READ,
            target="sandbox/public/sample.txt",
        )

def test_tool_request_empty_target():
    agent = AgentIdentity(name="SearchAgent")
    with pytest.raises(ValidationError):
        ToolRequest(
            agent=agent,
            tool_name="filesystem.read",
            tool_category=ToolCategory.FILESYSTEM,
            action=ActionType.READ,
            target="",
        )
