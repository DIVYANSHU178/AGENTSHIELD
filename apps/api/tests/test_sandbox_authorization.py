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
from app.security.sandbox.boundary import SandboxExecutionBoundary
from app.security.sandbox.contracts import SandboxStatus
from app.security.execution import ToolExecutionRegistry, ToolExecutionContract
from app.security.models.utils import utc_now

def test_valid_allow_authorization_enters_sandbox_and_executes():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-sb-auth-01",
        agent=AgentIdentity(name="MathAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True

    result = sandbox.execute(req, enf_res.authorization)
    assert result.status == SandboxStatus.COMPLETED
    assert result.executed is True
    assert result.success is True
    assert result.result["result"] == 30.0

def test_missing_authorization_denied_before_sandbox():
    sandbox = SandboxExecutionBoundary()
    req = ToolRequest(
        request_id="req-no-auth",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )

    result = sandbox.execute(req, None)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert result.success is False

def test_tampered_authorization_signature_denied():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

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
        signature="forged_bad_hmac_signature",
    )

    result = sandbox.execute(req, forged_auth)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert result.success is False

def test_tampered_request_parameters_denied():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    original_req = ToolRequest(
        request_id="req-tamper-params",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calc",
        parameters={"op": "add", "a": 1, "b": 2},
    )
    enf_res = boundary.enforce(original_req)

    tampered_req = ToolRequest(
        request_id="req-tamper-params",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calc",
        parameters={"op": "add", "a": 999999, "b": 888888},
    )

    result = sandbox.execute(tampered_req, enf_res.authorization)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False

def test_expired_authorization_denied():
    boundary = SecurityEnforcementBoundary()
    sandbox = SandboxExecutionBoundary(boundary=boundary)

    req = ToolRequest(
        request_id="req-sb-expired",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="system",
    )
    fingerprint = calculate_request_fingerprint(req)

    now = utc_now()
    issued_at = now - timedelta(minutes=10)
    expires_at = now - timedelta(minutes=5)

    sig = calculate_authorization_signature(
        authorization_id="auth-sb-exp",
        request_id=req.request_id,
        correlation_id=req.request_id,
        decision_value="ALLOW",
        request_fingerprint=fingerprint,
        policy_id="policy.allow",
        risk_score=0.0,
        issued_at=issued_at,
        expires_at=expires_at,
        secret_key=boundary._secret_key,
    )

    expired_auth = ExecutionAuthorization(
        authorization_id="auth-sb-exp",
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

    result = sandbox.execute(req, expired_auth)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False

def test_sandbox_handler_never_invoked_on_authorization_failure():
    invocations = []
    def spy_handler(r: ToolRequest):
        invocations.append(r)
        return {"done": True}

    from app.security.execution import SecureExecutionAdapter
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
    sandbox = SandboxExecutionBoundary(adapter=adapter)

    req = ToolRequest(
        request_id="req-spy-fail",
        agent=AgentIdentity(name="Agent"),
        tool_name="spy.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="test",
    )

    result = sandbox.execute(req, None)
    assert result.status == SandboxStatus.DENIED
    assert result.executed is False
    assert len(invocations) == 0
