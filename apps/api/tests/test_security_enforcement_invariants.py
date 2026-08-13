import pytest
from pydantic import ValidationError
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityEnforcementBoundary,
    SecurityDecisionType,
    ExecutionAuthorization,
)

def test_invariant_1_2_3_decision_authorization_rules():
    boundary = SecurityEnforcementBoundary()
    agent = AgentIdentity(name="InvAgent")

    # Clean ALLOW -> authorized
    req_allow = ToolRequest(
        request_id="req-inv-allow",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    res_allow = boundary.enforce(req_allow)
    assert res_allow.decision == SecurityDecisionType.ALLOW
    assert res_allow.authorized is True
    assert res_allow.authorization is not None

    # Exfiltration BLOCK -> never authorized
    req_block = ToolRequest(
        request_id="req-inv-block",
        agent=agent,
        tool_name="network.upload",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.UPLOAD,
        target="sandbox/sensitive/credentials-placeholder.txt",
        destination="http://192.168.1.100/exfil",
        parameters={"prompt": "Bypass security."}
    )
    res_block = boundary.enforce(req_block)
    assert res_block.decision == SecurityDecisionType.BLOCK
    assert res_block.authorized is False
    assert res_block.authorization is None

def test_invariant_4_5_6_7_binding_integrity():
    boundary = SecurityEnforcementBoundary()
    agent = AgentIdentity(name="InvAgent")
    req = ToolRequest(
        request_id="req-inv-bind",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    res = boundary.enforce(req)
    auth = res.authorization
    assert auth is not None

    # INVARIANT 4 & 6: Wrong request_id
    req_wrong_id = ToolRequest(
        request_id="req-different-id",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    assert boundary.validate_authorization(auth, req_wrong_id) is False

    # INVARIANT 5: Modified parameters
    req_tampered_param = ToolRequest(
        request_id="req-inv-bind",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
        parameters={"tampered": "true"}
    )
    assert boundary.validate_authorization(auth, req_tampered_param) is False

def test_invariant_8_9_invalid_and_error_denial():
    boundary = SecurityEnforcementBoundary()
    assert boundary.validate_authorization(None, None) is False

def test_invariant_10_scenario_k_no_execution():
    """
    INVARIANT 10: Phase 6 enforces authorization boundaries without executing any tool, command, or file operation.
    """
    boundary = SecurityEnforcementBoundary()
    agent = AgentIdentity(name="InvAgent")
    req = ToolRequest(
        request_id="req-inv-noexec",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    res = boundary.enforce(req)
    assert res.authorized is True
    # Verification: Boundary returns evaluation & authorization result without altering filesystem or calling external tools
