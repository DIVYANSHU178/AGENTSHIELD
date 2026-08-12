from app.security import ThreatReport, ThreatSignal, ThreatType, Severity

def test_threat_report_with_signals():
    sig1 = ThreatSignal(
        threat_type=ThreatType.CREDENTIAL_ACCESS,
        severity=Severity.CRITICAL,
        title="Credential Access",
        description="Targeting credentials placeholder",
        confidence=0.95
    )
    report = ThreatReport(
        request_id="req-123",
        signals=[sig1],
        overall_severity=Severity.CRITICAL,
        summary="High risk credential access detected"
    )
    assert report.request_id == "req-123"
    assert len(report.signals) == 1
    assert report.overall_severity == Severity.CRITICAL
    assert report.analyzed_at.tzinfo is not None
