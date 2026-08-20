import uuid
import pytest
from app.security.models import SecurityDecisionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import ApprovalStatus, ReviewerIdentity
from app.security.approval.errors import InvalidApprovalStateTransitionError
from app.security.laboratory.runner import ScenarioRunner
from app.security.laboratory.registry import create_default_scenario_registry

@pytest.fixture
def runner():
    return ScenarioRunner(registry=create_default_scenario_registry())

@pytest.fixture
def req_id():
    test_uid = uuid.uuid4().hex[:8]
    return lambda name: f"test-lab-{test_uid}-{name}"

def test_scenario_allow_clean(runner, req_id):
    res = runner.run("ALLOW_CLEAN", request_id=req_id("allow-clean"))
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.ALLOW
    assert res.actual_status == RuntimeExecutionStatus.COMPLETED
    assert res.actual_executed is True
    assert res.approval_id is None
    assert res.metadata["result"]["result"] == 30.0

def test_scenario_require_approval_prompt_injection(runner, req_id):
    res = runner.run("REQUIRE_APPROVAL_PROMPT_INJECTION", request_id=req_id("prompt"))
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is not None
    assert res.actual_approval_status == ApprovalStatus.PENDING

def test_scenario_require_approval_credential_access(runner, req_id):
    res = runner.run("REQUIRE_APPROVAL_CREDENTIAL_ACCESS", request_id=req_id("cred"))
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is not None
    assert res.actual_approval_status == ApprovalStatus.PENDING

def test_scenario_block_exfiltration(runner, req_id):
    res = runner.run("BLOCK_EXFILTRATION", request_id=req_id("exfil"))
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.BLOCK
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is None
    # Verify secret is not in metadata
    raw = str(res.model_dump())
    assert "sk-proj" not in raw

def test_scenario_approved_execution(runner, req_id):
    res = runner.run("APPROVED_EXECUTION", request_id=req_id("approved"))
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.ALLOW
    assert res.actual_status == RuntimeExecutionStatus.COMPLETED
    assert res.actual_executed is True
    assert res.actual_approval_status == ApprovalStatus.APPROVED
    assert res.metadata["result"]["result"] == 42.0

def test_scenario_approval_reject(runner, req_id):
    res = runner.run("APPROVAL_REJECT", request_id=req_id("reject"))
    assert res.passed is True
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.REJECTED

def test_scenario_approval_cancel(runner, req_id):
    res = runner.run("APPROVAL_CANCEL", request_id=req_id("cancel"))
    assert res.passed is True
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.CANCELLED

def test_scenario_approval_expire(runner, req_id):
    res = runner.run("APPROVAL_EXPIRE", request_id=req_id("expire"))
    assert res.passed is True
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.EXPIRED

@pytest.mark.parametrize("tamper_scenario", [
    "TAMPER_REQUEST_ID",
    "TAMPER_AGENT",
    "TAMPER_TARGET",
    "TAMPER_PARAMETERS",
    "TAMPER_TOOL",
    "TAMPER_CATEGORY",
    "TAMPER_ACTION",
    "TAMPER_DESTINATION",
])
def test_all_tamper_scenarios(runner, tamper_scenario):
    res = runner.run(tamper_scenario)
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.expected_executed is False
    assert res.actual_executed is False

def test_scenario_unknown_approval_invariants(runner, req_id):
    res = runner.run("UNKNOWN_APPROVAL", request_id=req_id("unknown-app"))
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.expected_executed is False
    assert res.actual_executed is False
    assert res.expected_approval_status == ApprovalStatus.PENDING
    assert res.actual_approval_status == ApprovalStatus.PENDING
    assert res.approval_id == "non-existent-uuid-0000-0000"

    # Legitimate approval record remains PENDING in approval service
    legit_id = res.metadata["legitimate_approval_id"]
    legit_app = runner.approval_service.get_approval(legit_id)
    assert legit_app is not None
    assert legit_app.status == ApprovalStatus.PENDING

def test_scenario_double_approval(runner, req_id):
    res = runner.run("DOUBLE_APPROVAL", request_id=req_id("double-app"))
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.APPROVED

def test_scenario_double_rejection(runner, req_id):
    res = runner.run("DOUBLE_REJECTION", request_id=req_id("double-rej"))
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.REJECTED

def test_scenario_terminal_non_resurrection(runner, req_id):
    res = runner.run("TERMINAL_NON_RESURRECTION", request_id=req_id("term-res"))
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False

@pytest.mark.parametrize("scenario_defn", create_default_scenario_registry().list_scenarios(), ids=lambda s: s.scenario_id)
def test_all_20_scenarios_generic_passed_consistency_invariants(runner, scenario_defn):
    """
    GENERIC CONSISTENCY INVARIANT FOR ALL 20 SCENARIOS:
    passed=True MUST imply:
    - expected_decision == actual_decision
    - expected_status == actual_status
    - expected_executed == actual_executed
    - (if expected_approval_status is set) expected_approval_status == actual_approval_status
    """
    res = runner.run(scenario_defn.scenario_id)
    assert res.passed is True
    assert res.expected_decision == res.actual_decision
    assert res.expected_status == res.actual_status
    assert res.expected_executed == res.actual_executed
    if res.expected_approval_status is not None:
        assert res.expected_approval_status == res.actual_approval_status

def test_repeated_scenario_runs_do_not_reuse_stale_approvals(runner):
    """Prove that consecutive scenario runs generate fresh isolated approvals under persistence."""
    res1 = runner.run("APPROVED_EXECUTION")
    res2 = runner.run("APPROVED_EXECUTION")
    assert res1.passed is True
    assert res2.passed is True
    assert res1.request_id != res2.request_id
    assert res1.approval_id != res2.approval_id

def test_persisted_terminal_approvals_remain_immutable_under_intentional_reuse(runner):
    """Prove that intentionally reusing a request_id returns the existing terminal approval and rejects re-transition."""
    unique_req_id = f"test-reuse-immutability-{uuid.uuid4().hex[:8]}"
    res = runner.run("APPROVED_EXECUTION", request_id=unique_req_id)
    assert res.passed is True
    app_id = res.approval_id

    # Retrieve from approval service
    app = runner.approval_service.get_approval(app_id)
    assert app.status == ApprovalStatus.APPROVED

    # Attempting to re-approve or reject must fail state transition validation
    with pytest.raises(InvalidApprovalStateTransitionError):
        runner.approval_service.approve(app_id, reviewer=ReviewerIdentity(reviewer_id="rev-test"), reason="Illegal second approve")

    with pytest.raises(InvalidApprovalStateTransitionError):
        runner.approval_service.reject(app_id, reviewer=ReviewerIdentity(reviewer_id="rev-test"), reason="Illegal reject on approved")
