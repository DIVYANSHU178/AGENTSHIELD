from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    CredentialDetector,
    ThreatType,
    Severity,
)

def test_credential_detector_clean_target():
    detector = CredentialDetector()
    agent = AgentIdentity(name="CleanAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    signals = detector.detect(req)
    assert len(signals) == 0

def test_credential_detector_env_file():
    detector = CredentialDetector()
    agent = AgentIdentity(name="CredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=".env",
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].threat_type == ThreatType.CREDENTIAL_ACCESS
    assert signals[0].evidence["category"] == "sensitive_file_target"

def test_credential_detector_sandbox_sensitive_placeholder():
    detector = CredentialDetector()
    agent = AgentIdentity(name="CredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/sensitive/credentials-placeholder.txt",
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].threat_type == ThreatType.CREDENTIAL_ACCESS

def test_credential_detector_ssh_private_key():
    detector = CredentialDetector()
    agent = AgentIdentity(name="CredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="~/.ssh/id_rsa",
    )

    signals = detector.detect(req)
    assert len(signals) >= 1
    assert signals[0].severity == Severity.CRITICAL
