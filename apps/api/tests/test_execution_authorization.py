from datetime import timedelta
import pytest
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecisionType,
)
from app.security.enforcement import (
    SecurityEnforcementBoundary,
    ExecutionAuthorization,
    calculate_request_fingerprint,
    calculate_authorization_signature,
)
from app.security.execution.executor import SecureExecutionAdapter
from app.security.execution.registry import ToolExecutionRegistry
from app.security.execution.contracts import ToolExecutionContract
from app.security.models.utils import utc_now

def test_missing_authorization_denied():
    adapter = SecureExecutionAdapter()
    req = ToolRequest(
        request_id="req-no-auth",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )

    res = adapter.execute(req, None)
    assert res.executed is False
    assert res.success is False
    assert "null" in res.error.lower()

def test_tampered_authorization_signature_denied():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    req = ToolRequest(
        request_id="req-tamper-sig",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )
    enf_res = boundary.enforce(req)
    valid_auth = enf_res.authorization

    # Create a forged authorization with fake signature
    forged_auth = ExecutionAuthorization(
        authorization_id=valid_auth.authorization_id,
        request_id=valid_auth.request_id,
        correlation_id=valid_auth.correlation_id,
        decision=valid_auth.decision,
        request_fingerprint=valid_auth.request_fingerprint,
        policy_id=valid_auth.policy_id,
        risk_score=valid_auth.risk_score,
        issued_at=valid_auth.issued_at,
        expires_at=valid_auth.expires_at,
        signature="bad_forged_hmac_signature",
    )

    res = adapter.execute(req, forged_auth)
    assert res.executed is False
    assert res.success is False
    assert "verification failed" in res.error.lower()

def test_tampered_request_parameters_denied():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    original_req = ToolRequest(
        request_id="req-tamper-req",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calc",
        parameters={"op": "add", "a": 1, "b": 2},
    )
    enf_res = boundary.enforce(original_req)
    auth = enf_res.authorization

    # Caller modifies request parameters after authorization
    tampered_req = ToolRequest(
        request_id="req-tamper-req",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calc",
        parameters={"op": "add", "a": 999999, "b": 888888},
    )

    res = adapter.execute(tampered_req, auth)
    assert res.executed is False
    assert res.success is False
    assert "verification failed" in res.error.lower()

def test_wrong_request_id_mismatch_denied():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    req1 = ToolRequest(
        request_id="req-original-1",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )
    enf_res = boundary.enforce(req1)
    auth1 = enf_res.authorization

    req2 = ToolRequest(
        request_id="req-different-2",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )

    # Replay authorization on different request_id
    res = adapter.execute(req2, auth1)
    assert res.executed is False
    assert res.success is False

def test_expired_authorization_denied():
    boundary = SecurityEnforcementBoundary()
    adapter = SecureExecutionAdapter(boundary=boundary)

    req = ToolRequest(
        request_id="req-expired",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )
    fingerprint = calculate_request_fingerprint(req)

    now = utc_now()
    issued_at = now - timedelta(minutes=10)
    expires_at = now - timedelta(minutes=5)  # Already expired 5 minutes ago

    secret_key = boundary._secret_key
    sig = calculate_authorization_signature(
        authorization_id="auth-expired-1",
        request_id=req.request_id,
        correlation_id=req.request_id,
        decision_value="ALLOW",
        request_fingerprint=fingerprint,
        policy_id="policy.allow",
        risk_score=0.0,
        issued_at=issued_at,
        expires_at=expires_at,
        secret_key=secret_key,
    )

    expired_auth = ExecutionAuthorization(
        authorization_id="auth-expired-1",
        request_id=req.request_id,
        correlation_id=req.request_id,
        decision=SecurityDecisionType.ALLOW,
        request_fingerprint=fingerprint,
        policy_id="policy.allow",
        risk_score=0.0,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=sig,
    )

    res = adapter.execute(req, expired_auth)
    assert res.executed is False
    assert res.success is False

def test_handler_never_invoked_on_authorization_failure():
    invocations = []
    def spy_handler(r: ToolRequest):
        invocations.append(r)
        return {"done": True}

    reg = ToolExecutionRegistry()
    reg.register(
        ToolExecutionContract(
            tool_name="spy.tool",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE},
            handler=spy_handler,
        )
    )
    adapter = SecureExecutionAdapter(registry=reg)

    req = ToolRequest(
        request_id="req-spy-fail",
        agent=AgentIdentity(name="Agent"),
        tool_name="spy.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="test",
    )

    res = adapter.execute(req, None)
    assert res.executed is False
    # Handler MUST NOT have been called!
    assert len(invocations) == 0
