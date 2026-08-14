import pytest
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    CredentialDetector,
    ThreatType,
    Severity,
)

@pytest.mark.parametrize(
    "clean_target",
    [
        "sandbox/public/sample.txt",
        "docs/aws/overview.txt",
        "cloud/aws/readme.txt",
        "gcp/application_default_notes.txt",
        "azure/documentation.txt",
        "secrets/example.txt",
    ],
)
def test_credential_detector_negative_cases(clean_target: str):
    detector = CredentialDetector()
    agent = AgentIdentity(name="CleanAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=clean_target,
    )

    signals = detector.detect(req)
    cred_signals = [s for s in signals if s.threat_type == ThreatType.CREDENTIAL_ACCESS]
    assert len(cred_signals) == 0

@pytest.mark.parametrize(
    "target_path,expected_category,expected_severity",
    [
        (".env", "sensitive_file_target", Severity.HIGH),
        (".env.local", "sensitive_file_target", Severity.HIGH),
        (".env.production", "sensitive_file_target", Severity.HIGH),
        ("credentials.json", "sensitive_file_target", Severity.HIGH),
        ("secrets.json", "sensitive_file_target", Severity.HIGH),
        ("~/.ssh/id_rsa", "ssh_private_key", Severity.CRITICAL),
        ("~/.ssh/id_ed25519", "ssh_private_key", Severity.CRITICAL),
        ("private_key", "ssh_private_key", Severity.CRITICAL),
        ("api_key", "cloud_api_credentials", Severity.HIGH),
        ("password", "password_store", Severity.HIGH),
        ("sandbox/sensitive/credentials-placeholder.txt", "sensitive_sandbox_path", Severity.HIGH),
    ],
)
def test_credential_detector_existing_categories(target_path: str, expected_category: str, expected_severity: Severity):
    detector = CredentialDetector()
    agent = AgentIdentity(name="CredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=target_path,
    )

    signals = detector.detect(req)
    cred_signals = [s for s in signals if s.threat_type == ThreatType.CREDENTIAL_ACCESS]
    assert len(cred_signals) >= 1
    assert any(s.evidence.get("category") == expected_category for s in cred_signals)
    assert any(s.severity == expected_severity for s in cred_signals)

@pytest.mark.parametrize(
    "cloud_target",
    [
        "cloud/aws/credentials",
        "cloud/aws/config",
        "aws/credentials",
        "aws/config",
        "gcp/application_default_credentials.json",
        "azure/credentials",
        "secrets/cloud_api_key.txt",
    ],
)
def test_credential_detector_cloud_targets(cloud_target: str):
    detector = CredentialDetector()
    agent = AgentIdentity(name="CloudCredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target=cloud_target,
    )

    signals = detector.detect(req)
    cred_signals = [s for s in signals if s.threat_type == ThreatType.CREDENTIAL_ACCESS]
    assert len(cred_signals) >= 1
    assert all(s.threat_type == ThreatType.CREDENTIAL_ACCESS for s in cred_signals)
    assert all(s.source == CredentialDetector.NAME for s in cred_signals)

@pytest.mark.parametrize(
    "cloud_path",
    [
        "cloud/aws/credentials",
        "cloud/aws/config",
        "aws/credentials",
        "aws/config",
        "gcp/application_default_credentials.json",
        "azure/credentials",
        "secrets/cloud_api_key.txt",
    ],
)
def test_credential_detector_parameter_inspection(cloud_path: str):
    detector = CredentialDetector()
    agent = AgentIdentity(name="ParamCredAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="system.process",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="script.py",
        parameters={"source_config": cloud_path, "env_var": "PRODUCTION"},
    )

    signals = detector.detect(req)
    cred_signals = [s for s in signals if s.threat_type == ThreatType.CREDENTIAL_ACCESS]
    assert len(cred_signals) >= 1
    assert any("parameters.source_config" in s.evidence.get("field", "") for s in cred_signals)

def test_credential_detector_deduplication_per_field():
    detector = CredentialDetector()
    agent = AgentIdentity(name="DedupAgent")
    # Target containing multiple terms from the same category
    req = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="aws/credentials and credentials.json and secrets.json",
    )

    signals = detector.detect(req)
    target_signals = [s for s in signals if s.evidence.get("field") == "target" and s.evidence.get("category") == "sensitive_file_target"]
    # Per-field deduplication should ensure exactly 1 signal for this category on field 'target'
    assert len(target_signals) == 1
