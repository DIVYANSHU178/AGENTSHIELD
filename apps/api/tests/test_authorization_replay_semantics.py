from datetime import timedelta
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
from app.security.models.utils import utc_now

def test_authorization_reusable_for_identical_request_within_validity_window():
    boundary = SecurityEnforcementBoundary()

    req = ToolRequest(
        request_id="req-replay-01",
        agent=AgentIdentity(name="ReplayAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
    )

    enf_res = boundary.enforce(req)
    assert enf_res.authorized is True
    auth = enf_res.authorization

    # First validation: True
    assert boundary.validate_authorization(auth, req) is True

    # Second validation of exact same request: True (Stateless capability within validity window)
    assert boundary.validate_authorization(auth, req) is True

    # Third validation: True
    assert boundary.validate_authorization(auth, req) is True

def test_replay_with_tampered_request_parameters_fails():
    boundary = SecurityEnforcementBoundary()

    original_req = ToolRequest(
        request_id="req-tamper-rep",
        agent=AgentIdentity(name="ReplayAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 10, "b": 20},
    )
    enf_res = boundary.enforce(original_req)
    auth = enf_res.authorization

    # Replay attempt against tampered parameters
    tampered_req = ToolRequest(
        request_id="req-tamper-rep",
        agent=AgentIdentity(name="ReplayAgent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 999999, "b": 20},
    )

    assert boundary.validate_authorization(auth, tampered_req) is False

def test_none_expiry_fails_validation_fail_closed():
    boundary = SecurityEnforcementBoundary()

    req = ToolRequest(
        request_id="req-none-exp",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="engine",
    )
    enf_res = boundary.enforce(req)
    auth = enf_res.authorization

    # Model with None expires_at
    none_exp_auth = auth.model_copy(update={"expires_at": None})
    assert boundary.validate_authorization(none_exp_auth, req) is False

def test_expired_authorization_fails_validation():
    boundary = SecurityEnforcementBoundary()

    req = ToolRequest(
        request_id="req-exp-test",
        agent=AgentIdentity(name="Agent"),
        tool_name="health.check",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.READ,
        target="engine",
    )
    fingerprint = calculate_request_fingerprint(req)
    now = utc_now()
    issued_at = now - timedelta(minutes=20)
    expires_at = now - timedelta(minutes=10)

    sig = calculate_authorization_signature(
        authorization_id="auth-exp",
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
        authorization_id="auth-exp",
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

    assert boundary.validate_authorization(expired_auth, req) is False
