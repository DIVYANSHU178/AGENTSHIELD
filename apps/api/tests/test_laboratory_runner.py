import pytest
from app.security.laboratory.runner import ScenarioRunner
from app.security.laboratory.errors import UnknownScenarioError

def test_runner_determinism_10_runs():
    runner = ScenarioRunner()
    results = []
    for _ in range(10):
        r = runner.run("ALLOW_CLEAN")
        assert r.passed is True
        results.append((r.actual_decision, r.actual_status, r.actual_executed, r.metadata["result"]["result"]))

    # Require identical semantic outcomes across all 10 runs
    first = results[0]
    for other in results[1:]:
        assert other == first

def test_runner_custom_request_id_preserved():
    runner = ScenarioRunner()
    custom_id = "my-custom-test-req-007"
    res = runner.run("ALLOW_CLEAN", request_id=custom_id)
    assert res.request_id == custom_id

def test_runner_unknown_scenario_raises():
    runner = ScenarioRunner()
    with pytest.raises(UnknownScenarioError):
        runner.run("INVALID_NON_EXISTENT_SCENARIO")
