import os
import sys

# Ensure app package is importable
sys.path.insert(0, os.path.abspath("."))

import uuid
from app.security.laboratory.runner import ScenarioRunner
from app.security.laboratory.registry import create_default_scenario_registry

TARGET_SCENARIOS = [
    "ALLOW_CLEAN",
    "REQUIRE_APPROVAL_PROMPT_INJECTION",
    "REQUIRE_APPROVAL_CREDENTIAL_ACCESS",
    "BLOCK_EXFILTRATION",
    "APPROVED_EXECUTION",
    "APPROVAL_REJECT",
    "APPROVAL_CANCEL",
    "APPROVAL_EXPIRE",
    "TAMPER_REQUEST_ID",
    "TAMPER_AGENT",
    "TAMPER_TARGET",
    "TAMPER_PARAMETERS",
    "TAMPER_TOOL",
    "TAMPER_CATEGORY",
    "TAMPER_ACTION",
    "TAMPER_DESTINATION",
    "UNKNOWN_APPROVAL",
    "DOUBLE_APPROVAL",
    "DOUBLE_REJECTION",
    "TERMINAL_NON_RESURRECTION",
]

def main() -> int:
    print("=" * 80)
    print("AGENTSHIELD PHASE 12: SCENARIO / ATTACK LABORATORY DEMONSTRATION")
    print("=" * 80)

    registry = create_default_scenario_registry()
    runner = ScenarioRunner(registry=registry)
    run_id = uuid.uuid4().hex[:6]

    failed_count = 0

    for idx, sid in enumerate(TARGET_SCENARIOS, 1):
        defn = registry.get(sid)
        print(f"\n--- [{idx:02d}/20] Running Scenario: {defn.name} ({sid}) ---")
        print(f"  Description : {defn.description}")
        print(f"  Category    : {defn.category.value}")
        print(f"  Expected    : Decision={defn.expected_decision.value}, Status={defn.expected_status.value}, Executed={defn.expected_executed}")

        res = runner.run(sid, request_id=f"demo12-{run_id}-{idx:02d}-{sid.lower()}")

        status_tag = "[PASS]" if res.passed else "[FAIL]"
        print(f"  Outcome     : {status_tag} Actual Decision={res.actual_decision.value}, Status={res.actual_status.value}, Executed={res.actual_executed}")
        print(f"  Verification: {res.message}")
        if res.approval_id:
            print(f"  Approval ID : {res.approval_id} (Status: {res.actual_approval_status.value if res.actual_approval_status else 'None'})")

        if not res.passed:
            failed_count += 1

    print("\n" + "=" * 80)
    if failed_count == 0:
        print("AGENTSHIELD PHASE 12 SCENARIO / ATTACK LABORATORY")
        print("ALL SCENARIOS VERIFIED")
        print("=" * 80)
        return 0
    else:
        print(f"LABORATORY VERIFICATION FAILED: {failed_count} scenario(s) failed.")
        print("=" * 80)
        return 1

if __name__ == "__main__":
    sys.exit(main())
