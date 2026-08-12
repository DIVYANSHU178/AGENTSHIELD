from app.security import SecurityDecision, SecurityDecisionType

def test_security_decision_types():
    d_allow = SecurityDecision(
        request_id="req-001",
        decision=SecurityDecisionType.ALLOW,
        reason="Tool request within safe parameters"
    )
    assert d_allow.decision == SecurityDecisionType.ALLOW

    d_block = SecurityDecision(
        request_id="req-002",
        decision=SecurityDecisionType.BLOCK,
        reason="Unauthorized credential access attempt"
    )
    assert d_block.decision == SecurityDecisionType.BLOCK

    d_approval = SecurityDecision(
        request_id="req-003",
        decision=SecurityDecisionType.REQUIRE_APPROVAL,
        reason="Action requires human verification"
    )
    assert d_approval.decision == SecurityDecisionType.REQUIRE_APPROVAL
