import pytest
from app.security.models import SecurityDecisionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import ApprovalStatus
from app.security.laboratory.runner import ScenarioRunner
from app.security.laboratory.registry import create_default_scenario_registry

@pytest.fixture
def runner():
    return ScenarioRunner(registry=create_default_scenario_registry())

def test_scenario_allow_clean(runner):
    res = runner.run("ALLOW_CLEAN", request_id="req-allow-clean-01")
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.ALLOW
    assert res.actual_status == RuntimeExecutionStatus.COMPLETED
    assert res.actual_executed is True
    assert res.approval_id is None
    assert res.metadata["result"]["result"] == 30.0

def test_scenario_require_approval_prompt_injection(runner):
    res = runner.run("REQUIRE_APPROVAL_PROMPT_INJECTION", request_id="req-prompt-01")
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is not None
    assert res.actual_approval_status == ApprovalStatus.PENDING

def test_scenario_require_approval_credential_access(runner):
    res = runner.run("REQUIRE_APPROVAL_CREDENTIAL_ACCESS", request_id="req-cred-01")
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is not None
    assert res.actual_approval_status == ApprovalStatus.PENDING

def test_scenario_block_exfiltration(runner):
    res = runner.run("BLOCK_EXFILTRATION", request_id="req-exfil-01")
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.BLOCK
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.approval_id is None
    # Verify secret is not in metadata
    raw = str(res.model_dump())
    assert "sk-proj" not in raw

def test_scenario_approved_execution(runner):
    res = runner.run("APPROVED_EXECUTION", request_id="req-approved-01")
    assert res.passed is True
    assert res.actual_decision == SecurityDecisionType.ALLOW
    assert res.actual_status == RuntimeExecutionStatus.COMPLETED
    assert res.actual_executed is True
    assert res.actual_approval_status == ApprovalStatus.APPROVED
    assert res.metadata["result"]["result"] == 42.0

def test_scenario_approval_reject(runner):
    res = runner.run("APPROVAL_REJECT", request_id="req-reject-01")
    assert res.passed is True
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.REJECTED

def test_scenario_approval_cancel(runner):
    res = runner.run("APPROVAL_CANCEL", request_id="req-cancel-01")
    assert res.passed is True
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.CANCELLED

def test_scenario_approval_expire(runner):
    res = runner.run("APPROVAL_EXPIRE", request_id="req-expire-01")
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

def test_scenario_unknown_approval_invariants(runner):
    res = runner.run("UNKNOWN_APPROVAL", request_id="req-unknown-app-01")
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

def test_scenario_double_approval(runner):
    res = runner.run("DOUBLE_APPROVAL", request_id="req-double-app-01")
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.APPROVED

def test_scenario_double_rejection(runner):
    res = runner.run("DOUBLE_REJECTION", request_id="req-double-rej-01")
    assert res.passed is True
    assert res.expected_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.actual_decision == SecurityDecisionType.REQUIRE_APPROVAL
    assert res.expected_status == RuntimeExecutionStatus.DENIED
    assert res.actual_status == RuntimeExecutionStatus.DENIED
    assert res.actual_executed is False
    assert res.actual_approval_status == ApprovalStatus.REJECTED

def test_scenario_terminal_non_resurrection(runner):
    res = runner.run("TERMINAL_NON_RESURRECTION", request_id="req-term-res-01")
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
