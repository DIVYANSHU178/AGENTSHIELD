from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    ThreatSignal,
    ThreatReport,
    ThreatType,
    Severity,
    RiskAssessment,
    SecurityDecision,
    SecurityDecisionType,
    SecurityEvent,
    EventType,
)

def test_full_chain_correlation():
    # 1. Agent
    agent = AgentIdentity(agent_id="agent-007", name="BrowserBot")
    
    # 2. ToolRequest
    req = ToolRequest(
        request_id="req-999",
        agent=agent,
        tool_name="browser.navigate",
        tool_category=ToolCategory.BROWSER,
        action=ActionType.NAVIGATE,
        target="https://example.com"
    )

    # 3. ThreatSignal & Report
    signal = ThreatSignal(
        signal_id="sig-001",
        threat_type=ThreatType.MALICIOUS_DESTINATION,
        severity=Severity.MEDIUM,
        title="Unverified URL",
        description="URL host not in white-list",
        confidence=0.75
    )
    report = ThreatReport(
        report_id="rep-111",
        request_id=req.request_id,
        signals=[signal],
        overall_severity=Severity.MEDIUM,
        summary="Unverified external domain target"
    )

    # 4. RiskAssessment
    assessment = RiskAssessment(
        assessment_id="risk-222",
        request_id=req.request_id,
        risk_score=55.0,
        severity=Severity.MEDIUM,
        contributing_signals=[signal.signal_id],
        rationale="Moderate risk due to untrusted destination"
    )

    # 5. SecurityDecision
    decision = SecurityDecision(
        decision_id="dec-333",
        request_id=req.request_id,
        decision=SecurityDecisionType.REQUIRE_APPROVAL,
        risk_assessment_id=assessment.assessment_id,
        reason="Requires explicit user authorization before external navigation"
    )

    # 6. SecurityEvent
    event = SecurityEvent(
        event_id="evt-444",
        request_id=req.request_id,
        event_type=EventType.APPROVAL_REQUIRED,
        actor="policy_engine",
        details={"decision_id": decision.decision_id}
    )

    # Correlation assertions
    assert req.agent.agent_id == "agent-007"
    assert report.request_id == req.request_id
    assert assessment.request_id == req.request_id
    assert decision.request_id == req.request_id
    assert event.request_id == req.request_id
    assert decision.risk_assessment_id == assessment.assessment_id
    assert assessment.contributing_signals[0] == signal.signal_id
