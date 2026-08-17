import pytest
from pydantic import ValidationError
from app.security.models import SecurityDecisionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import ApprovalStatus
from app.security.laboratory.contracts import (
    ScenarioCategory,
    ScenarioDefinition,
    ScenarioRunRequest,
    ScenarioResult,
)

def test_scenario_definition_valid_and_immutable():
    d = ScenarioDefinition(
        scenario_id="TEST_SCENARIO",
        name="Test Scenario",
        description="A test scenario definition",
        category=ScenarioCategory.BASELINE,
        expected_decision=SecurityDecisionType.ALLOW,
        expected_status=RuntimeExecutionStatus.COMPLETED,
        expected_executed=True,
        requires_approval=False,
        metadata={"key": "val"},
    )
    assert d.scenario_id == "TEST_SCENARIO"
    assert d.category == ScenarioCategory.BASELINE
    assert d.expected_decision == SecurityDecisionType.ALLOW
    assert d.expected_status == RuntimeExecutionStatus.COMPLETED
    assert d.expected_executed is True
    assert d.requires_approval is False
    assert d.metadata["key"] == "val"

    # Verify frozen immutability
    with pytest.raises(ValidationError):
        d.name = "Mutated"

def test_scenario_run_request_validation():
    # Valid
    req1 = ScenarioRunRequest(scenario_id="ALLOW_CLEAN", request_id="custom-1")
    assert req1.scenario_id == "ALLOW_CLEAN"
    assert req1.request_id == "custom-1"

    # Optional request_id
    req2 = ScenarioRunRequest(scenario_id="ALLOW_CLEAN")
    assert req2.scenario_id == "ALLOW_CLEAN"
    assert req2.request_id is None

    # Empty / whitespace-only scenario_id raises ValidationError
    with pytest.raises(ValidationError):
        ScenarioRunRequest(scenario_id="")

    with pytest.raises(ValidationError):
        ScenarioRunRequest(scenario_id="   ")

    with pytest.raises(ValidationError):
        ScenarioRunRequest(scenario_id=None)

    with pytest.raises(ValidationError):
        ScenarioRunRequest(scenario_id=123)

def test_scenario_result_serialization_and_immutability():
    res = ScenarioResult(
        scenario_id="ALLOW_CLEAN",
        scenario_name="Clean Arithmetic Computation",
        category=ScenarioCategory.BASELINE,
        request_id="req-123",
        expected_decision=SecurityDecisionType.ALLOW,
        actual_decision=SecurityDecisionType.ALLOW,
        expected_status=RuntimeExecutionStatus.COMPLETED,
        actual_status=RuntimeExecutionStatus.COMPLETED,
        expected_executed=True,
        actual_executed=True,
        expected_approval_status=None,
        actual_approval_status=None,
        approval_id=None,
        passed=True,
        message="Verification successful.",
        metadata={"result": {"result": 30.0}},
    )
    assert res.passed is True
    assert res.expected_decision == res.actual_decision
    assert res.expected_status == res.actual_status
    assert res.expected_executed == res.actual_executed
    assert res.metadata["result"]["result"] == 30.0

    # Test serialization
    dumped = res.model_dump()
    assert dumped["scenario_id"] == "ALLOW_CLEAN"
    assert dumped["passed"] is True

    # Test frozen immutability
    with pytest.raises(ValidationError):
        res.passed = False

def test_scenario_result_passed_consistency_invariants():
    # 1. Mismatched decision cannot have passed=True
    with pytest.raises(ValidationError, match="expected_decision"):
        ScenarioResult(
            scenario_id="TEST",
            scenario_name="Test",
            category=ScenarioCategory.BASELINE,
            request_id="req-1",
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            actual_decision=SecurityDecisionType.BLOCK,
            expected_status=RuntimeExecutionStatus.DENIED,
            actual_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            actual_executed=False,
            passed=True,  # INVALID: decision mismatch
            message="Mismatch",
        )

    # 2. Mismatched status cannot have passed=True
    with pytest.raises(ValidationError, match="expected_status"):
        ScenarioResult(
            scenario_id="TEST",
            scenario_name="Test",
            category=ScenarioCategory.BASELINE,
            request_id="req-1",
            expected_decision=SecurityDecisionType.ALLOW,
            actual_decision=SecurityDecisionType.ALLOW,
            expected_status=RuntimeExecutionStatus.COMPLETED,
            actual_status=RuntimeExecutionStatus.DENIED,
            expected_executed=True,
            actual_executed=True,
            passed=True,  # INVALID: status mismatch
            message="Mismatch",
        )

    # 3. Mismatched executed cannot have passed=True
    with pytest.raises(ValidationError, match="expected_executed"):
        ScenarioResult(
            scenario_id="TEST",
            scenario_name="Test",
            category=ScenarioCategory.BASELINE,
            request_id="req-1",
            expected_decision=SecurityDecisionType.ALLOW,
            actual_decision=SecurityDecisionType.ALLOW,
            expected_status=RuntimeExecutionStatus.COMPLETED,
            actual_status=RuntimeExecutionStatus.COMPLETED,
            expected_executed=True,
            actual_executed=False,
            passed=True,  # INVALID: executed mismatch
            message="Mismatch",
        )

    # 4. Mismatched approval status cannot have passed=True
    with pytest.raises(ValidationError, match="expected_approval_status"):
        ScenarioResult(
            scenario_id="TEST",
            scenario_name="Test",
            category=ScenarioCategory.BASELINE,
            request_id="req-1",
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            actual_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            actual_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            actual_executed=False,
            expected_approval_status=ApprovalStatus.PENDING,
            actual_approval_status=ApprovalStatus.APPROVED,
            passed=True,  # INVALID: approval status mismatch
            message="Mismatch",
        )

    # 5. passed=False is valid when fields mismatch (legitimate failure reporting)
    fail_res = ScenarioResult(
        scenario_id="TEST",
        scenario_name="Test",
        category=ScenarioCategory.BASELINE,
        request_id="req-1",
        expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
        actual_decision=SecurityDecisionType.BLOCK,
        expected_status=RuntimeExecutionStatus.DENIED,
        actual_status=RuntimeExecutionStatus.DENIED,
        expected_executed=False,
        actual_executed=False,
        passed=False,  # VALID: legitimately failed
        message="Legitimate mismatch failure",
    )
    assert fail_res.passed is False
    assert fail_res.expected_decision != fail_res.actual_decision

