import copy
from typing import Dict, List, Optional
from app.security.models import SecurityDecisionType
from app.security.runtime.contracts import RuntimeExecutionStatus
from app.security.approval.contracts import ApprovalStatus
from app.security.laboratory.contracts import (
    ScenarioCategory,
    ScenarioDefinition,
)
from app.security.laboratory.errors import UnknownScenarioError

class ScenarioRegistry:
    """
    Deterministic in-memory registry for authoritative Scenario and Attack Laboratory definitions.
    
    CRITICAL CONTRACT INVARIANTS:
    - Holds static metadata definitions only.
    - Zero live execution handles, tokens, authorizations, or mutable credentials.
    - Deterministic lookups and registration.
    """

    def __init__(self) -> None:
        self._scenarios: Dict[str, ScenarioDefinition] = {}

    def register(self, definition: ScenarioDefinition) -> None:
        """Register a scenario definition. Raises ValueError on invalid or duplicate input."""
        if definition is None or not isinstance(definition, ScenarioDefinition):
            raise ValueError("Expected valid ScenarioDefinition instance.")

        scenario_id = definition.scenario_id.strip().upper()
        if scenario_id in self._scenarios:
            raise ValueError(f"Scenario '{scenario_id}' is already registered.")

        self._scenarios[scenario_id] = definition

    def get(self, scenario_id: str) -> ScenarioDefinition:
        """Retrieve a registered scenario definition by ID. Raises UnknownScenarioError if not found."""
        if not scenario_id or not isinstance(scenario_id, str):
            raise UnknownScenarioError(f"Invalid scenario ID '{scenario_id}'.")

        key = scenario_id.strip().upper()
        if key not in self._scenarios:
            raise UnknownScenarioError(f"Scenario '{scenario_id}' is not registered in the Laboratory Registry.")

        return copy.deepcopy(self._scenarios[key])

    def has(self, scenario_id: str) -> bool:
        """Check if a scenario is registered."""
        if not scenario_id or not isinstance(scenario_id, str):
            return False
        return scenario_id.strip().upper() in self._scenarios

    def list_scenarios(self, category: Optional[ScenarioCategory] = None) -> List[ScenarioDefinition]:
        """Return list copies of registered scenario definitions, optionally filtered by category."""
        scenarios = list(self._scenarios.values())
        if category is not None:
            scenarios = [s for s in scenarios if s.category == category]
        return [copy.deepcopy(s) for s in scenarios]

    def __len__(self) -> int:
        return len(self._scenarios)

def create_default_scenario_registry() -> ScenarioRegistry:
    """Construct and populate a ScenarioRegistry with the 20 authoritative Phase 12 laboratory scenarios."""
    registry = ScenarioRegistry()

    # =========================================================================
    # 1. BASELINE SCENARIOS (4 Scenarios)
    # =========================================================================
    registry.register(
        ScenarioDefinition(
            scenario_id="ALLOW_CLEAN",
            name="Clean Arithmetic Computation",
            description="Harmless arithmetic addition tool request that evaluates to ALLOW and executes safely in Sandbox.",
            category=ScenarioCategory.BASELINE,
            expected_decision=SecurityDecisionType.ALLOW,
            expected_status=RuntimeExecutionStatus.COMPLETED,
            expected_executed=True,
            requires_approval=False,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="REQUIRE_APPROVAL_PROMPT_INJECTION",
            name="Prompt Injection Instruction Override",
            description="Agent request containing instruction override pattern triggering REQUIRE_APPROVAL and pending review.",
            category=ScenarioCategory.BASELINE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="REQUIRE_APPROVAL_CREDENTIAL_ACCESS",
            name="Sensitive Credential Target Inspection",
            description="Request attempting to read credential placeholder file triggering REQUIRE_APPROVAL.",
            category=ScenarioCategory.BASELINE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="BLOCK_EXFILTRATION",
            name="Critical Credential Exfiltration Attack",
            description="Multi-vector upload of sensitive credentials to external destination triggering terminal BLOCK.",
            category=ScenarioCategory.BASELINE,
            expected_decision=SecurityDecisionType.BLOCK,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=False,
        )
    )

    # =========================================================================
    # 2. APPROVAL LIFECYCLE SCENARIOS (4 Scenarios)
    # =========================================================================
    registry.register(
        ScenarioDefinition(
            scenario_id="APPROVED_EXECUTION",
            name="Approved Request Execution Flow",
            description="Full approval flow: REQUIRE_APPROVAL -> Operator APPROVE -> Enforcement Authorization -> Sandbox Execution.",
            category=ScenarioCategory.APPROVAL_LIFECYCLE,
            expected_decision=SecurityDecisionType.ALLOW,
            expected_status=RuntimeExecutionStatus.COMPLETED,
            expected_executed=True,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="APPROVAL_REJECT",
            name="Operator Rejection Flow",
            description="Approval request is explicitly rejected by operator and subsequent execution is strictly denied.",
            category=ScenarioCategory.APPROVAL_LIFECYCLE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="APPROVAL_CANCEL",
            name="Operator Cancellation Flow",
            description="Approval request is cancelled and subsequent execution is strictly denied.",
            category=ScenarioCategory.APPROVAL_LIFECYCLE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="APPROVAL_EXPIRE",
            name="Approval Expiration Flow",
            description="Approval request reaches expiration TTL and subsequent execution is strictly denied.",
            category=ScenarioCategory.APPROVAL_LIFECYCLE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    # =========================================================================
    # 3. ANTI-TAMPER SCENARIOS (8 Scenarios)
    # =========================================================================
    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_REQUEST_ID",
            name="Request ID Tampering",
            description="Approved request executed against candidate with altered request_id is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_AGENT",
            name="Agent Identity Tampering",
            description="Approved request executed against candidate with altered agent_id is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_TARGET",
            name="Target Resource Tampering",
            description="Approved request executed against candidate with altered target path is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_PARAMETERS",
            name="Parameters Payload Tampering",
            description="Approved request executed against candidate with modified parameters (fingerprint mismatch) is denied.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_TOOL",
            name="Tool Name Tampering",
            description="Approved request executed against candidate with altered tool_name is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_CATEGORY",
            name="Tool Category Tampering",
            description="Approved request executed against candidate with altered tool_category is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_ACTION",
            name="Action Type Tampering",
            description="Approved request executed against candidate with altered action is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TAMPER_DESTINATION",
            name="Destination Endpoint Tampering",
            description="Approved request executed against candidate with altered destination is denied by enforcement.",
            category=ScenarioCategory.ANTI_TAMPER,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    # =========================================================================
    # 4. FAILURE AND ABUSE SCENARIOS (4 Scenarios)
    # =========================================================================
    registry.register(
        ScenarioDefinition(
            scenario_id="UNKNOWN_APPROVAL",
            name="Non-Existent Approval ID Execution",
            description="Attempting to resume execution with a forged or non-existent approval ID fails closed safely.",
            category=ScenarioCategory.FAILURE_ABUSE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="DOUBLE_APPROVAL",
            name="Double Approval Resolution Abuse",
            description="Attempting to approve an already approved request safely raises state transition rejection.",
            category=ScenarioCategory.FAILURE_ABUSE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="DOUBLE_REJECTION",
            name="Double Rejection Resolution Abuse",
            description="Attempting to reject an already rejected request safely raises state transition rejection.",
            category=ScenarioCategory.FAILURE_ABUSE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    registry.register(
        ScenarioDefinition(
            scenario_id="TERMINAL_NON_RESURRECTION",
            name="Terminal State Non-Resurrection Enforced",
            description="Verifies that terminal approval states (APPROVED, REJECTED, CANCELLED, EXPIRED) cannot transition.",
            category=ScenarioCategory.FAILURE_ABUSE,
            expected_decision=SecurityDecisionType.REQUIRE_APPROVAL,
            expected_status=RuntimeExecutionStatus.DENIED,
            expected_executed=False,
            requires_approval=True,
        )
    )

    return registry

# Singleton pattern for ScenarioRegistry
_GLOBAL_SCENARIO_REGISTRY: Optional[ScenarioRegistry] = None

def get_scenario_registry() -> ScenarioRegistry:
    """Retrieve or initialize the global ScenarioRegistry singleton."""
    global _GLOBAL_SCENARIO_REGISTRY
    if _GLOBAL_SCENARIO_REGISTRY is None:
        _GLOBAL_SCENARIO_REGISTRY = create_default_scenario_registry()
    return _GLOBAL_SCENARIO_REGISTRY
