from app.security import (
    ThreatSignal,
    ThreatType,
    Severity,
    build_threat_report,
)

def test_builder_empty_signals():
    report = build_threat_report("req-001", [])
    assert report.request_id == "req-001"
    assert len(report.signals) == 0
    assert report.overall_severity == Severity.INFO
    assert report.summary == "No threats detected."

def test_builder_highest_severity_selection():
    s_low = ThreatSignal(
        threat_type=ThreatType.SENSITIVE_DATA_ACCESS,
        severity=Severity.LOW,
        title="Email Address",
        description="Found email address",
        confidence=0.5
    )
    s_critical = ThreatSignal(
        threat_type=ThreatType.DATA_EXFILTRATION,
        severity=Severity.CRITICAL,
        title="Data Exfiltration",
        description="Exfiltration vector detected",
        confidence=0.95
    )
    s_medium = ThreatSignal(
        threat_type=ThreatType.MALICIOUS_DESTINATION,
        severity=Severity.MEDIUM,
        title="Raw IP",
        description="Raw IP targeted",
        confidence=0.8
    )

    report = build_threat_report("req-002", [s_low, s_critical, s_medium])
    assert report.overall_severity == Severity.CRITICAL
    assert "Detected 3 security signal(s)" in report.summary
    assert "1 CRITICAL" in report.summary
    assert "1 MEDIUM" in report.summary
    assert "1 LOW" in report.summary
