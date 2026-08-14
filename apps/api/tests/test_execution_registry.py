import pytest
from app.security.models import ToolCategory, ActionType, ToolRequest
from app.security.execution.contracts import ToolExecutionContract
from app.security.execution.registry import ToolExecutionRegistry, create_default_execution_registry

def dummy_handler(request: ToolRequest):
    return {"status": "ok"}

def test_registry_register_and_lookup():
    registry = ToolExecutionRegistry()
    assert len(registry) == 0

    contract = ToolExecutionContract(
        tool_name="custom.tool",
        tool_category=ToolCategory.SYSTEM,
        supported_actions={ActionType.READ},
        description="A test tool",
        handler=dummy_handler,
    )

    registry.register(contract)
    assert len(registry) == 1
    assert registry.has("custom.tool") is True
    assert registry.has("unknown.tool") is False

    retrieved = registry.get("custom.tool")
    assert retrieved is not None
    assert retrieved.tool_name == "custom.tool"
    assert retrieved.tool_category == ToolCategory.SYSTEM
    assert ActionType.READ in retrieved.supported_actions

def test_registry_rejects_duplicate_tool_name():
    registry = ToolExecutionRegistry()
    contract1 = ToolExecutionContract(
        tool_name="duplicate.tool",
        tool_category=ToolCategory.SYSTEM,
        supported_actions={ActionType.READ},
        handler=dummy_handler,
    )
    contract2 = ToolExecutionContract(
        tool_name="duplicate.tool",
        tool_category=ToolCategory.SYSTEM,
        supported_actions={ActionType.EXECUTE},
        handler=dummy_handler,
    )

    registry.register(contract1)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(contract2)

def test_registry_contract_validation():
    # Empty tool name
    with pytest.raises(ValueError):
        ToolExecutionContract(
            tool_name="",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.READ},
            handler=dummy_handler,
        )

    # Empty supported actions
    with pytest.raises(ValueError):
        ToolExecutionContract(
            tool_name="no.actions",
            tool_category=ToolCategory.SYSTEM,
            supported_actions=set(),
            handler=dummy_handler,
        )

    # Non-callable handler
    with pytest.raises(ValueError):
        ToolExecutionContract(
            tool_name="not.callable",
            tool_category=ToolCategory.SYSTEM,
            supported_actions={ActionType.READ},
            handler="not_a_callable",  # type: ignore
        )

def test_default_execution_registry_contains_safe_tools():
    reg = create_default_execution_registry()
    assert reg.has("calculator.compute") is True
    assert reg.has("string.transform") is True
    assert reg.has("health.check") is True
    assert reg.has("failing.tool") is True

    calc = reg.get("calculator.compute")
    assert calc is not None
    assert ActionType.EXECUTE in calc.supported_actions
    assert ActionType.READ in calc.supported_actions
