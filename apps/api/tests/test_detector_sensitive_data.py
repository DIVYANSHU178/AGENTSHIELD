from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SensitiveDataDetector,
    ThreatType,
    Severity,
)

def test_sensitive_data_api_key():
    detector = SensitiveDataDetector()
    agent = AgentIdentity(name="DataAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="http.request",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.SEND,
        target="https://api.example.com",
        parameters={"auth_header": "Bearer sk-proj-1234567890abcdef1234567890"}
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].threat_type == ThreatType.SENSITIVE_DATA_ACCESS
    assert signals[0].evidence["category"] == "api_key"
    assert signals[0].evidence["redacted"] is True
    assert "sk-proj-1234567890abcdef1234567890" not in str(signals[0].evidence["redacted_value"])

def test_sensitive_data_credit_card_luhn():
    detector = SensitiveDataDetector()
    agent = AgentIdentity(name="DataAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="db.query",
        tool_category=ToolCategory.DATABASE,
        action=ActionType.QUERY,
        target="users_table",
        parameters={"query": "SELECT * FROM users WHERE card = '4532 0151 1283 0366'"}
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    cc_signals = [s for s in signals if s.evidence.get("category") == "credit_card"]
    assert len(cc_signals) == 1
    assert cc_signals[0].severity == Severity.CRITICAL

def test_sensitive_data_email_and_phone():
    detector = SensitiveDataDetector()
    agent = AgentIdentity(name="DataAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="email.send",
        tool_category=ToolCategory.COMMUNICATION,
        action=ActionType.SEND,
        target="user@example.com",
        parameters={"body": "Contact support at +91-9876543210 or user@example.com"}
    )

    signals = detector.detect(req)
    categories = [s.evidence.get("category") for s in signals]
    assert "email_address" in categories
    assert "phone_number" in categories

def test_sensitive_data_pan_card():
    detector = SensitiveDataDetector()
    agent = AgentIdentity(name="DataAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="db.query",
        tool_category=ToolCategory.DATABASE,
        action=ActionType.QUERY,
        target="tax_table",
        parameters={"pan": "ABCDE1234F"}
    )

    signals = detector.detect(req)
    pan_signals = [s for s in signals if s.evidence.get("category") == "pan_number"]
    assert len(pan_signals) == 1
