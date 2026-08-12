import pytest
from pydantic import ValidationError
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
    RiskEngine,
    RiskEngineError,
    build_threat_report,
)

def make_sample_request() -> ToolRequest:
    agent = AgentIdentity(agent_id="ag-001", name="RiskTestAgent")
    return ToolRequest(
        request_id="req-risk-100",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

def test_risk_engine_empty_report():
    engine = RiskEngine()
    req = make_sample_request()
    report = ThreatReport(request_id=req.request_id, signals=[])

    assessment = engine.assess(req, report)
    assert isinstance(assessment, RiskAssessment)
    assert assessment.request_id == req.request_id
    assert assessment.risk_score == 0.0
    assert assessment.severity == Severity.INFO
    assert assessment.contributing_signals == []
    assert "No threat signals were detected" in assessment.rationale
    assert assessment.metadata["signal_count"] == 0

def test_risk_engine_single_signal_severities():
    engine = RiskEngine()
    req = make_sample_request()

    severities_expected = [
        (Severity.INFO, 0.0, Severity.INFO),
        (Severity.LOW, 15.0, Severity.LOW),
        (Severity.MEDIUM, 35.0, Severity.MEDIUM),
        (Severity.HIGH, 60.0, Severity.HIGH),
        (Severity.CRITICAL, 90.0, Severity.CRITICAL),
    ]

    for sev, expected_base, expected_sev_level in severities_expected:
        sig = ThreatSignal(
            signal_id=f"sig-{sev.value}",
            threat_type=ThreatType.PROMPT_INJECTION,  # multiplier 1.0
            severity=sev,
            title=f"Test {sev.value}",
            description="Test signal",
            confidence=1.0,
        )
        report = ThreatReport(request_id=req.request_id, signals=[sig])
        assessment = engine.assess(req, report)

        assert assessment.risk_score == expected_base
        assert assessment.severity == expected_sev_level
        assert assessment.contributing_signals == [sig.signal_id]

def test_risk_engine_confidence_scaling():
    engine = RiskEngine()
    req = make_sample_request()

    # HIGH base weight = 60.0
    # Confidence 0.0 -> 0.0
    # Confidence 0.5 -> 30.0
    # Confidence 1.0 -> 60.0
    for conf, expected_score in [(0.0, 0.0), (0.5, 30.0), (1.0, 60.0)]:
        sig = ThreatSignal(
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=Severity.HIGH,
            title="High Threat",
            description="Test",
            confidence=conf,
        )
        report = ThreatReport(request_id=req.request_id, signals=[sig])
        assessment = engine.assess(req, report)
        assert assessment.risk_score == expected_score

def test_risk_engine_threat_type_multiplier():
    engine = RiskEngine()
    req = make_sample_request()

    # DATA_EXFILTRATION multiplier = 1.35
    # HIGH base = 60.0 * 1.0 * 1.35 = 81.0 (Severity HIGH)
    sig_exfil = ThreatSignal(
        threat_type=ThreatType.DATA_EXFILTRATION,
        severity=Severity.HIGH,
        title="Exfiltration Signal",
        description="Test",
        confidence=1.0,
    )
    report = ThreatReport(request_id=req.request_id, signals=[sig_exfil])
    assessment = engine.assess(req, report)

    assert assessment.risk_score == 81.0
    assert assessment.severity == Severity.HIGH

def test_risk_engine_multiple_signals_diminishing_returns():
    engine = RiskEngine()
    req = make_sample_request()

    # HIGH (60.0) + MEDIUM (35.0)
    # Combined = 100 * (1 - (1 - 0.60) * (1 - 0.35)) = 100 * (1 - 0.40 * 0.65) = 100 * (1 - 0.26) = 74.0
    sig1 = ThreatSignal(
        signal_id="sig-high",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="High Prompt Injection",
        description="Test",
        confidence=1.0,
    )
    sig2 = ThreatSignal(
        signal_id="sig-medium",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        title="Medium Prompt Injection",
        description="Test",
        confidence=1.0,
    )

    report = ThreatReport(request_id=req.request_id, signals=[sig1, sig2])
    assessment = engine.assess(req, report)

    assert assessment.risk_score == 74.0
    assert assessment.severity == Severity.HIGH
    assert set(assessment.contributing_signals) == {"sig-high", "sig-medium"}

def test_risk_engine_critical_plus_high_score_clamping():
    engine = RiskEngine()
    req = make_sample_request()

    # CRITICAL (90.0) + HIGH (60.0)
    # Combined = 100 * (1 - 0.10 * 0.40) = 100 * (1 - 0.04) = 96.0
    sig_crit = ThreatSignal(
        signal_id="sig-crit",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.CRITICAL,
        title="Critical Signal",
        description="Test",
        confidence=1.0,
    )
    sig_high = ThreatSignal(
        signal_id="sig-high",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="High Signal",
        description="Test",
        confidence=1.0,
    )

    report = ThreatReport(request_id=req.request_id, signals=[sig_crit, sig_high])
    assessment = engine.assess(req, report)

    assert assessment.risk_score == 96.0
    assert assessment.severity == Severity.CRITICAL
    assert assessment.risk_score <= 100.0

def test_risk_engine_monotonicity():
    engine = RiskEngine()
    req = make_sample_request()

    sig_low = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION, severity=Severity.LOW, title="Low", description="", confidence=0.5
    )
    sig_med = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION, severity=Severity.MEDIUM, title="Med", description="", confidence=0.5
    )
    sig_high = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION, severity=Severity.HIGH, title="High", description="", confidence=0.5
    )

    r_low = engine.assess(req, ThreatReport(request_id=req.request_id, signals=[sig_low])).risk_score
    r_med = engine.assess(req, ThreatReport(request_id=req.request_id, signals=[sig_med])).risk_score
    r_high = engine.assess(req, ThreatReport(request_id=req.request_id, signals=[sig_high])).risk_score

    assert r_low < r_med < r_high

def test_risk_engine_determinism():
    engine = RiskEngine()
    req = make_sample_request()

    sig1 = ThreatSignal(
        signal_id="sig-det-1",
        threat_type=ThreatType.CREDENTIAL_ACCESS,
        severity=Severity.HIGH,
        title="Cred Access",
        description="",
        confidence=0.9,
    )
    sig2 = ThreatSignal(
        signal_id="sig-det-2",
        threat_type=ThreatType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        title="Exfil",
        description="",
        confidence=0.95,
    )
    report = ThreatReport(request_id=req.request_id, signals=[sig1, sig2])

    a1 = engine.assess(req, report)
    a2 = engine.assess(req, report)

    assert a1.risk_score == a2.risk_score
    assert a1.severity == a2.severity
    assert a1.contributing_signals == a2.contributing_signals
    assert a1.rationale == a2.rationale

def test_risk_engine_input_immutability():
    engine = RiskEngine()
    req = make_sample_request()
    sig = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION, severity=Severity.HIGH, title="High", description="", confidence=0.8
    )
    report = ThreatReport(request_id=req.request_id, signals=[sig])

    _ = engine.assess(req, report)

    # Verify input objects remain unmutated
    assert req.request_id == "req-risk-100"
    assert len(report.signals) == 1
    assert sig.confidence == 0.8

def test_risk_engine_invalid_input_raises():
    engine = RiskEngine()
    req = make_sample_request()
    report = ThreatReport(request_id=req.request_id, signals=[])

    with pytest.raises(RiskEngineError):
        engine.assess(None, report)  # type: ignore

    with pytest.raises(RiskEngineError):
        engine.assess(req, None)  # type: ignore

def test_risk_assessment_serialization_compatibility():
    engine = RiskEngine()
    req = make_sample_request()
    sig = ThreatSignal(
        threat_type=ThreatType.PROMPT_INJECTION, severity=Severity.HIGH, title="High", description="", confidence=1.0
    )
    report = ThreatReport(request_id=req.request_id, signals=[sig])

    assessment = engine.assess(req, report)
    json_str = assessment.model_dump_json()

    restored = RiskAssessment.model_validate_json(json_str)
    assert restored.request_id == req.request_id
    assert restored.risk_score == 60.0
    assert restored.severity == Severity.HIGH
