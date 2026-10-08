"""
Phase 1.2 Gateway Actions Tests (AgentShield server side).

Exercises handle_action with executor="eos" (EOS runs its own handler after
local v2 verification) plus the remote-approval lifecycle:
  PENDING  -> REQUIRE_APPROVAL (no execution)
  APPROVED + exact-match request -> single v2 mint + ALLOW(EVALUATED)
  REJECTED -> DENY
  EXPIRED  -> REQUIRE_APPROVAL (approval_status=EXPIRED)

Also verifies eos_core seeding, its dedicated dev key, the system_time
allowlist, and that the AS-native sandbox path is unchanged for non-eos
executors.
"""

import uuid

import pytest

from app.agent.models import (
    AgentActionRequest,
    GatewayDecision,
    ExecutionStatus,
)
from app.agent.registry import get_agent_registry
from app.agent.service import AgentGatewayService
from app.security.approval.contracts import ReviewerIdentity
from app.security.approval.service import get_approval_service
from app.security.enforcement.authorization_v2 import compute_arguments_hash, verify_v2_signature
from app.security.execution.tool_registry_service import get_tool_registry_repository
from app.config.settings import settings


@pytest.fixture
def gateway():
    return AgentGatewayService(
        agent_registry=get_agent_registry(),
        tool_repository=get_tool_registry_repository(),
        approval_service=get_approval_service(),
    )


REVIEWER = ReviewerIdentity(
    reviewer_id="qa-reviewer",
    reviewer_name="QA Reviewer",
    role="SECURITY_REVIEWER",
)


def _probe_request(idempotency: str, *, run_tag: str, zone: str = "approval-probe", fingerprint: str = "a" * 64) -> AgentActionRequest:
    return AgentActionRequest(
        agent_id="eos_core",
        target="system_time",
        parameters={"operation": "QUERY", "target": "any", "zone": zone, "probe_run": run_tag},
        context={
            "executor": "eos",
            "fingerprint": fingerprint,
            "correlation_id": f"corr_{idempotency}",
        },
        idempotency_key=idempotency,
    )


# ---------------------------------------------------------------------------
# eos_core seeding / identity
# ---------------------------------------------------------------------------

def test_eos_core_seeded_with_allowlist():
    agent = get_agent_registry().get("eos_core")
    assert agent is not None
    assert agent.agent_id == "eos_core"
    assert "system_time" in agent.allowed_tools
    assert get_agent_registry().validate_key("eos_core", "agk_eos_core_dev_key") is True


def test_eos_core_key_lookup_by_api_key():
    agent = get_agent_registry().get_by_api_key("agk_eos_core_dev_key")
    assert agent is not None and agent.agent_id == "eos_core"


def test_eos_core_denies_unallowed_tool(gateway):
    resp = gateway.handle_action(
        AgentActionRequest(
            agent_id="eos_core",
            target="calculator",
            parameters={},
            context={"executor": "eos", "fingerprint": "a" * 64},
            idempotency_key=f"idem_{uuid.uuid4().hex}",
        ),
        agent_key="agk_eos_core_dev_key",
    )
    assert resp.decision == GatewayDecision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED


# ---------------------------------------------------------------------------
# ALLOW -> EVALUATED + v2 authorization (executor="eos")
# ---------------------------------------------------------------------------

def test_system_time_allow_returns_verified_v2_token(gateway):
    idem = f"idem_{uuid.uuid4().hex}"
    req = AgentActionRequest(
        agent_id="eos_core",
        target="system_time",
        parameters={"operation": "QUERY", "target": "any", "zone": "clock"},
        context={"executor": "eos", "fingerprint": "a" * 64, "correlation_id": f"corr_{idem}"},
        idempotency_key=idem,
    )
    resp = gateway.handle_action(req, agent_key="agk_eos_core_dev_key")
    assert resp.decision == GatewayDecision.ALLOW
    assert resp.execution_status == ExecutionStatus.EVALUATED
    assert resp.protocol_version == "v2"
    assert resp.authorization is not None
    token = resp.authorization
    assert token["action_id"] == idem  # idempotency echoed as action_id
    assert token["principal"] == "eos_core"
    assert token["tool"] == "system_time"
    assert compute_arguments_hash(req.parameters) == token["arguments_hash"]
    assert verify_v2_signature(token, "eos.agentshield", "eos_core") == ""
    assert resp.decision_details["executor"] == "eos"


def test_eos_missing_fingerprint_fails_closed(gateway):
    idem = f"idem_{uuid.uuid4().hex}"
    req = AgentActionRequest(
        agent_id="eos_core",
        target="system_time",
        parameters={"operation": "QUERY", "target": "any"},
        context={"executor": "eos"},  # no fingerprint => cannot bind the v2 token
        idempotency_key=idem,
    )
    resp = gateway.handle_action(req, agent_key="agk_eos_core_dev_key")
    assert resp.decision == GatewayDecision.DENY
    assert resp.execution_status == ExecutionStatus.BLOCKED
    assert resp.decision_details.get("rejection") == "authorization_mint_failed"


def test_native_executor_path_unchanged(gateway):
    idem = f"idem_{uuid.uuid4().hex}"
    resp = gateway.handle_action(
        AgentActionRequest(
            agent_id="reference-autonomous-agent",
            target="calculator",
            parameters={"a": 2, "b": 3, "op": "add"},
            context={},
            idempotency_key=idem,
        ),
        agent_key="agk_reference_agent_secret_key",
    )
    assert resp.decision == GatewayDecision.ALLOW
    assert resp.execution_status == ExecutionStatus.EXECUTED
    assert resp.authorization is None  # native HMAC credential path, no v2 artifact


# ---------------------------------------------------------------------------
# Remote approval lifecycle
# ---------------------------------------------------------------------------

def test_approval_probe_lifecycle(gateway, monkeypatch):
    monkeypatch.setattr(settings, "AGENTSHIELD_PHASE12_TEST_POLICY", True)
    approval_service = get_approval_service()
    idem = f"idem_{uuid.uuid4().hex}"
    run_tag = f"run_{uuid.uuid4().hex}"

    # 1. First submission -> REQUIRE_APPROVAL (PENDING), no execution.
    r1 = gateway.handle_action(_probe_request(idem, run_tag=run_tag), agent_key="agk_eos_core_dev_key")
    assert r1.decision == GatewayDecision.REQUIRE_APPROVAL
    assert r1.execution_status == ExecutionStatus.PENDING_APPROVAL
    assert r1.approval_id
    approval_id = r1.approval_id
    assert r1.decision_details["approval_status"] == "PENDING"

    # 2. Re-submission with a NEW action_id but identical content -> same PENDING approval (structural match).
    r2 = gateway.handle_action(
        _probe_request(f"{idem}-resubmit", run_tag=run_tag), agent_key="agk_eos_core_dev_key"
    )
    assert r2.decision == GatewayDecision.REQUIRE_APPROVAL
    assert r2.approval_id == approval_id

    # 3. Human approval via the approval service (EOS proxy).
    approved = approval_service.approve(approval_id, REVIEWER, "QA approved probe")
    assert approved.status.value == "APPROVED"

    # 4. Resume with identical content, fresh action_id -> ALLOW + v2 mint (single mint site).
    r3 = gateway.handle_action(
        _probe_request(f"{idem}-resume", run_tag=run_tag), agent_key="agk_eos_core_dev_key"
    )
    assert r3.decision == GatewayDecision.ALLOW
    assert r3.execution_status == ExecutionStatus.EVALUATED
    assert r3.protocol_version == "v2"
    assert r3.authorization is not None
    assert r3.authorization["approval_id"] == approval_id
    assert r3.authorization["policy_id"] == "approval.human_authorized"
    assert r3.decision_details["approval_status"] == "APPROVED"
    assert verify_v2_signature(r3.authorization, "eos.agentshield", "eos_core") == ""
    # EOS-side execution must never have happened server-side.
    assert approved.execution_result["executed"] is False


def test_approval_probe_rejected_blocks(gateway, monkeypatch):
    monkeypatch.setattr(settings, "AGENTSHIELD_PHASE12_TEST_POLICY", True)
    approval_service = get_approval_service()
    idem = f"idem_{uuid.uuid4().hex}"
    run_tag = f"run_{uuid.uuid4().hex}"
    r1 = gateway.handle_action(_probe_request(idem, run_tag=run_tag), agent_key="agk_eos_core_dev_key")
    approval_service.reject(r1.approval_id, REVIEWER, "QA rejected probe")

    r2 = gateway.handle_action(
        _probe_request(f"{idem}-resume", run_tag=run_tag), agent_key="agk_eos_core_dev_key"
    )
    assert r2.decision == GatewayDecision.DENY
    assert r2.execution_status == ExecutionStatus.BLOCKED
    assert r2.decision_details.get("rejection") == "approval_rejected"


def test_approval_probe_pristine_when_probe_disabled(gateway):
    idem = f"idem_{uuid.uuid4().hex}"
    resp = gateway.handle_action(_probe_request(idem, run_tag=f"run_{uuid.uuid4().hex}"), agent_key="agk_eos_core_dev_key")
    # Without the test-policy gate the probe is a benign system_time ALLOW.
    assert resp.decision == GatewayDecision.ALLOW


def test_approval_probe_fingerprint_mismatch_blocks_resume(gateway, monkeypatch):
    monkeypatch.setattr(settings, "AGENTSHIELD_PHASE12_TEST_POLICY", True)
    approval_service = get_approval_service()
    idem = f"idem_{uuid.uuid4().hex}"
    run_tag = f"run_{uuid.uuid4().hex}"
    r1 = gateway.handle_action(_probe_request(idem, run_tag=run_tag), agent_key="agk_eos_core_dev_key")
    approval_service.approve(r1.approval_id, REVIEWER, "QA approved probe")

    # Idempotent REPLAY tamper: same action_id/idempotency_key but altered
    # parameters => the approval re-validation must refuse to satisfy.
    tampered = _probe_request(idem, run_tag=run_tag)
    tampered.parameters["extra"] = True
    r2 = gateway.handle_action(tampered, agent_key="agk_eos_core_dev_key")
    assert r2.decision == GatewayDecision.REQUIRE_APPROVAL
    assert r2.decision_details.get("rejection") == "approval_fingerprint_mismatch"


def test_approval_probe_expired_requires_fresh(gateway, monkeypatch):
    monkeypatch.setattr(settings, "AGENTSHIELD_PHASE12_TEST_POLICY", True)
    approval_service = get_approval_service()

    # Approvals are repository-backed in the runtime singleton; force expiry by
    # making the policy engine calculate a past expiration for every approval.
    from datetime import timedelta
    from app.security.models.utils import utc_now

    def _past_expiry(created_at, ttl_seconds=None):
        return utc_now() - timedelta(seconds=1)

    monkeypatch.setattr(approval_service.policy_engine, "calculate_expiration", _past_expiry)

    idem = f"idem_{uuid.uuid4().hex}"
    run_tag = f"run_{uuid.uuid4().hex}"
    r1 = gateway.handle_action(_probe_request(idem, run_tag=run_tag), agent_key="agk_eos_core_dev_key")
    assert r1.decision == GatewayDecision.REQUIRE_APPROVAL

    # Resume with identical content; the pending approval has already expired.
    r2 = gateway.handle_action(
        _probe_request(f"{idem}-resume", run_tag=run_tag), agent_key="agk_eos_core_dev_key"
    )
    assert r2.decision == GatewayDecision.REQUIRE_APPROVAL
    assert r2.decision_details.get("approval_status") == "EXPIRED"