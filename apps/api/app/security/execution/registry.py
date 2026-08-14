from typing import Dict, List, Optional, Set
from app.security.models import ToolCategory, ActionType
from app.security.execution.contracts import ToolExecutionContract
from app.security.execution.builtins import (
    safe_calculator_handler,
    safe_string_transform_handler,
    safe_health_check_handler,
    failing_demonstration_handler,
    slow_demonstration_handler,
)

class ToolExecutionRegistry:
    """
    Deterministic registry for explicitly approved, safe executable tools.

    CRITICAL CONTRACT RULES:
    - Explicit registration only: Dynamic imports and filesystem/network discovery are strictly forbidden.
    - Duplicate tool names are rejected.
    - Deterministic, encapsulated lookups.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, ToolExecutionContract] = {}

    def register(self, contract: ToolExecutionContract) -> None:
        """Register a ToolExecutionContract. Raises ValueError if already registered or invalid."""
        if contract is None or not isinstance(contract, ToolExecutionContract):
            raise ValueError("Expected valid ToolExecutionContract instance.")

        tool_name = contract.tool_name
        if tool_name in self._tools:
            raise ValueError(f"Tool '{tool_name}' is already registered in ToolExecutionRegistry.")

        self._tools[tool_name] = contract

    def get(self, tool_name: str) -> Optional[ToolExecutionContract]:
        """Retrieve a registered ToolExecutionContract by tool_name, or None."""
        if not tool_name or not isinstance(tool_name, str):
            return None
        return self._tools.get(tool_name.strip())

    def has(self, tool_name: str) -> bool:
        """Check if a tool_name is registered."""
        if not tool_name or not isinstance(tool_name, str):
            return False
        return tool_name.strip() in self._tools

    def list_tools(self) -> List[ToolExecutionContract]:
        """Return a list copy of all registered tool contracts in insertion order."""
        return list(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)

def create_default_execution_registry() -> ToolExecutionRegistry:
    """Construct and populate a ToolExecutionRegistry with default safe demonstration tools."""
    registry = ToolExecutionRegistry()

    # 1. Calculator tool
    registry.register(
        ToolExecutionContract(
            tool_name="calculator.compute",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE, ActionType.READ},
            description="Safe deterministic arithmetic calculator (add, sub, mul, div, pow, mod)",
            handler=safe_calculator_handler,
        )
    )

    # 2. String transform tool
    registry.register(
        ToolExecutionContract(
            tool_name="string.transform",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE, ActionType.READ},
            description="Safe deterministic string transformation (uppercase, lowercase, reverse, trim, length)",
            handler=safe_string_transform_handler,
        )
    )

    # 3. Health check tool
    registry.register(
        ToolExecutionContract(
            tool_name="health.check",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.READ, ActionType.EXECUTE},
            description="Safe in-memory system health and status inspection",
            handler=safe_health_check_handler,
        )
    )

    # 4. Controlled failing tool for failure path verification
    registry.register(
        ToolExecutionContract(
            tool_name="failing.tool",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE},
            description="Demonstration tool that intentionally raises an exception to verify error handling",
            handler=failing_demonstration_handler,
        )
    )

    # 5. Controlled slow tool for timeout verification
    registry.register(
        ToolExecutionContract(
            tool_name="slow.tool",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.EXECUTE, ActionType.READ},
            description="Demonstration tool that delays execution to verify sandbox timeout enforcement",
            handler=slow_demonstration_handler,
        )
    )

    return registry
