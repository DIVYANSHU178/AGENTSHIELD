import json
from datetime import datetime, timedelta
import pytest
from pydantic import ValidationError
from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityEnforcementBoundary,
    SecurityDecisionType,
    ExecutionAuthorization,
    calculate_authorization_signature,
)
from app.security.models.utils import utc_now
from app.config.settings import settings

def make_sample_allow_request_and_auth():
    boundary = SecurityEnforcementBoundary()
    agent = AgentIdentity(agent_id="ag-attack-001", name="AuthAttackAgent")
    req = ToolRequest(
        request_id="req-attack-100",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    res = boundary.enforce(req)
    assert res.authorized is True
    assert res.authorization is not None
    return boundary, req, res.authorization

# ============================================================
# PART 4 — POSITIVE INTEGRITY CASES & SERIALIZATION
# ============================================================

def test_authorization_positive_untouched_legitimate_credential():
    """POSITIVE CASE: Untouched legitimate authorization created by boundary must validate True."""
    boundary, req, auth = make_sample_allow_request_and_auth()
    assert boundary.validate_authorization(auth, req) is True

def test_authorization_positive_serialization_roundtrip():
    """SERIALIZATION: Legitimate roundtripped credential (model_dump_json -> model_validate_json) remains valid True."""
    boundary, req, auth = make_sample_allow_request_and_auth()
    
    json_str = auth.model_dump_json()
    restored_auth = ExecutionAuthorization.model_validate_json(json_str)

    assert boundary.validate_authorization(restored_auth, req) is True

def test_authorization_modified_serialized_credential_invalidated():
    boundary, req, auth = make_sample_allow_request_and_auth()
    json_data = json.loads(auth.model_dump_json())
    json_data["risk_score"] = 85.0  # Modify score in JSON payload
    tampered_json = json.dumps(json_data)
    
    restored_auth = ExecutionAuthorization.model_validate_json(tampered_json)
    assert boundary.validate_authorization(restored_auth, req) is False

# ============================================================
# PART 3 — AUTHORIZATION INTEGRITY TEST MATRIX (F1 - F16)
# ============================================================

def test_F1_decision_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"decision": SecurityDecisionType.BLOCK})
    assert boundary.validate_authorization(forged, req) is False

def test_F2_policy_id_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"policy_id": "policy.forged.bypass"})
    assert boundary.validate_authorization(forged, req) is False

def test_F3_risk_score_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"risk_score": 99.9})
    assert boundary.validate_authorization(forged, req) is False

def test_F4_correlation_id_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"correlation_id": "corr-tampered-id"})
    assert boundary.validate_authorization(forged, req) is False

def test_F5_authorization_id_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"authorization_id": "auth-forged-uuid-999"})
    assert boundary.validate_authorization(forged, req) is False

def test_F6_issued_at_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"issued_at": auth.issued_at - timedelta(hours=5)})
    assert boundary.validate_authorization(forged, req) is False

def test_F7_expires_at_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"expires_at": auth.expires_at + timedelta(days=365)})
    assert boundary.validate_authorization(forged, req) is False

def test_F8_request_fingerprint_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"request_fingerprint": "f" * 64})
    assert boundary.validate_authorization(forged, req) is False

def test_F9_request_id_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"request_id": "req-different-id-123"})
    assert boundary.validate_authorization(forged, req) is False

def test_F10_serialized_json_field_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    data = json.loads(auth.model_dump_json())
    data["policy_id"] = "policy.hacked"
    restored = ExecutionAuthorization.model_validate_json(json.dumps(data))
    assert boundary.validate_authorization(restored, req) is False

def test_F11_serialized_json_signature_tampering():
    boundary, req, auth = make_sample_allow_request_and_auth()
    data = json.loads(auth.model_dump_json())
    data["signature"] = "0" * 64
    restored = ExecutionAuthorization.model_validate_json(json.dumps(data))
    assert boundary.validate_authorization(restored, req) is False

def test_F12_missing_signature_raises():
    boundary, req, auth = make_sample_allow_request_and_auth()
    data = json.loads(auth.model_dump_json())
    del data["signature"]
    with pytest.raises(ValidationError):
        ExecutionAuthorization.model_validate(data)

def test_F13_empty_signature():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"signature": "   "})
    assert boundary.validate_authorization(forged, req) is False

def test_F14_malformed_signature():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"signature": "not-a-valid-hex-signature"})
    assert boundary.validate_authorization(forged, req) is False

def test_F15_random_signature():
    boundary, req, auth = make_sample_allow_request_and_auth()
    forged = auth.model_copy(update={"signature": "a1b2c3d4e5f67890" * 4})
    assert boundary.validate_authorization(forged, req) is False

def test_F16_signature_generated_with_wrong_secret():
    boundary, req, auth = make_sample_allow_request_and_auth()
    wrong_sig = calculate_authorization_signature(
        authorization_id=auth.authorization_id,
        request_id=auth.request_id,
        correlation_id=auth.correlation_id,
        decision_value=auth.decision.value,
        request_fingerprint=auth.request_fingerprint,
        policy_id=auth.policy_id,
        risk_score=auth.risk_score,
        issued_at=auth.issued_at,
        expires_at=auth.expires_at,
        secret_key="attacker-wrong-secret-key",
    )
    forged = auth.model_copy(update={"signature": wrong_sig})
    assert boundary.validate_authorization(forged, req) is False

# ============================================================
# PART 5 — REQUEST TAMPERING MATRIX
# ============================================================

def test_request_tampering_target():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target="sandbox/sensitive/credentials-placeholder.txt", # Modified
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_action():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=ActionType.DELETE, # Modified
        target=req.target,
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_tool_name():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name="filesystem.delete", # Modified
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_tool_category():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=ToolCategory.SYSTEM, # Modified
        action=req.action,
        target=req.target,
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_destination():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
        destination="http://malicious-attacker.com/exfil", # Modified
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_parameters():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
        parameters={"injected": "override"}, # Modified
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_agent_id():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id=req.request_id,
        agent=AgentIdentity(agent_id="ag-malicious-999", name="AuthAttackAgent"), # Modified agent_id
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_tampering_request_id():
    boundary, req, auth = make_sample_allow_request_and_auth()
    tampered = ToolRequest(
        request_id="req-tampered-999", # Modified request_id
        agent=req.agent,
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
    )
    assert boundary.validate_authorization(auth, tampered) is False

def test_request_agent_name_change_preserves_validity():
    """
    DOCUMENTED BEHAVIOR: Security identity contract binds agent.agent_id.
    Changing only agent.name (display name) while preserving agent.agent_id retains valid fingerprint.
    """
    boundary, req, auth = make_sample_allow_request_and_auth()
    req_new_name = ToolRequest(
        request_id=req.request_id,
        agent=AgentIdentity(agent_id=req.agent.agent_id, name="RenamedAgentDisplay"),
        tool_name=req.tool_name,
        tool_category=req.tool_category,
        action=req.action,
        target=req.target,
    )
    assert boundary.validate_authorization(auth, req_new_name) is True

# ============================================================
# PART 6 & 7 — REPLAY & CORRELATION BINDING
# ============================================================

def test_replay_protection_different_request_id():
    boundary = SecurityEnforcementBoundary()
    agent = AgentIdentity(name="ReplayAgent")
    req_a = ToolRequest(
        request_id="req-A",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )
    req_b = ToolRequest(
        request_id="req-B",
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
    )

    res_a = boundary.enforce(req_a)
    assert res_a.authorized is True
    assert boundary.validate_authorization(res_a.authorization, req_b) is False

# ============================================================
# PART 9 & 10 — TYPE ROBUSTNESS & FAIL-CLOSED SAFETY
# ============================================================

def test_validate_authorization_malformed_runtime_input_types():
    boundary, req, auth = make_sample_allow_request_and_auth()

    # None inputs
    assert boundary.validate_authorization(None, req) is False
    assert boundary.validate_authorization(auth, None) is False
    assert boundary.validate_authorization(None, None) is False

    # String / Dict malformed input types
    assert boundary.validate_authorization("invalid_string", req) is False
    assert boundary.validate_authorization(auth, "invalid_string") is False
    assert boundary.validate_authorization({}, req) is False
    assert boundary.validate_authorization(auth, {}) is False
