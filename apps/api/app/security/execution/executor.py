from datetime import datetime
from typing import Optional, Any
from app.security.models import ToolRequest, SecurityEvent
from app.security.enforcement import SecurityEnforcementBoundary, ExecutionAuthorization
from app.security.audit import SecurityAuditTrail, SecurityEventFactory
from app.security.execution.contracts import ExecutionResult
from app.security.execution.registry import ToolExecutionRegistry, create_default_execution_registry
from app.security.models.utils import utc_now

class SecureExecutionAdapter:
    """
    Authoritative Secure Execution Adapter for AgentShield.

    CRITICAL SECURITY INVARIANT:
    NO VALID PHASE 6 AUTHORIZATION -> NO EXECUTION

    Rules enforced:
    - Validates cryptographic HMAC-SHA256 signature, request fingerprint, decision=ALLOW,
      request_id correlation, and expiration via SecurityEnforcementBoundary.
    - Dispatches ONLY to explicitly registered in-memory demonstration tools in ToolExecutionRegistry.
    - Enforces category binding: request.tool_category == registered_tool_contract.tool_category.
    - User input cannot dynamically load or invoke arbitrary modules/callables.
    - Invariant: executed=False whenever authorization validation fails, tool is unregistered, or category mismatches.
    - Integrates with Phase 7 audit infrastructure, recording EXECUTED or FAILED events post-execution.
    """

    def __init__(
        self,
        registry: Optional[ToolExecutionRegistry] = None,
        boundary: Optional[SecurityEnforcementBoundary] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
    ) -> None:
        self._registry = registry or create_default_execution_registry()
        self._boundary = boundary or SecurityEnforcementBoundary()
        self._audit_trail = audit_trail

    @property
    def registry(self) -> ToolExecutionRegistry:
        return self._registry

    @property
    def boundary(self) -> SecurityEnforcementBoundary:
        return self._boundary

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    def execute(
        self,
        request: Any,
        authorization: Any,
    ) -> ExecutionResult:
        """
        Execute an authorized tool request through the secure execution boundary.
        Fails closed on any invalid input, failed authorization check, or category mismatch.
        """
        started_at = utc_now()

        # 1. Type validation for request
        if request is None:
            return ExecutionResult(
                request_id="req-null",
                tool_name="unknown",
                executed=False,
                success=False,
                started_at=started_at,
                completed_at=utc_now(),
                error="ToolRequest is null; execution denied.",
            )

        if not isinstance(request, ToolRequest):
            return ExecutionResult(
                request_id="req-invalid",
                tool_name="unknown",
                executed=False,
                success=False,
                started_at=started_at,
                completed_at=utc_now(),
                error="Invalid ToolRequest runtime type; execution denied.",
            )

        tool_name = request.tool_name or "unknown"

        # 2. Type validation for authorization
        if authorization is None:
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                started_at=started_at,
                completed_at=utc_now(),
                error="ExecutionAuthorization is null; execution denied.",
            )

        if not isinstance(authorization, ExecutionAuthorization):
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                started_at=started_at,
                completed_at=utc_now(),
                error="Invalid ExecutionAuthorization runtime type; execution denied.",
            )

        # 3. Cryptographic and Integrity Authorization Validation
        if not self._boundary.validate_authorization(authorization, request):
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                authorization_id=getattr(authorization, "authorization_id", None),
                started_at=started_at,
                completed_at=utc_now(),
                error="Execution authorization verification failed or denied; tool execution blocked.",
            )

        # 4. Tool Registry Resolution
        tool_contract = self._registry.get(request.tool_name)
        if tool_contract is None:
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                error=f"Tool '{request.tool_name}' is not registered in ToolExecutionRegistry.",
            )

        # 5. Tool Category Binding Validation
        if request.tool_category != tool_contract.tool_category:
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                error=f"Tool category mismatch: request specifies '{request.tool_category.value}' but tool '{request.tool_name}' is registered under '{tool_contract.tool_category.value}'.",
            )

        # 6. Action Resolution
        if request.action not in tool_contract.supported_actions:
            return ExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                executed=False,
                success=False,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                error=f"Action '{request.action.value}' is not supported by tool '{request.tool_name}'.",
            )

        # 7. Secure Handler Invocation
        try:
            handler_result = tool_contract.handler(request)
            completed_at = utc_now()

            # Record EXECUTED audit event
            if self._audit_trail is not None:
                try:
                    executed_event = SecurityEventFactory.create_executed_event(
                        request_id=request.request_id,
                        actor="secure_execution_adapter",
                        outcome_metadata={
                            "tool_name": request.tool_name,
                            "action": request.action.value,
                            "success": True,
                        },
                    )
                    self._audit_trail.record(executed_event)
                except Exception:
                    # Fail-safe audit recording: does not reverse successful execution
                    pass

            return ExecutionResult(
                request_id=request.request_id,
                tool_name=request.tool_name,
                executed=True,
                success=True,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=completed_at,
                result=handler_result,
                metadata={"tool_category": tool_contract.tool_category.value},
            )

        except Exception as handler_err:
            completed_at = utc_now()
            error_msg = f"Tool handler execution failed: {str(handler_err)}"

            # Record FAILED audit event
            if self._audit_trail is not None:
                try:
                    failed_event = SecurityEventFactory.create_failed_event(
                        request_id=request.request_id,
                        actor="secure_execution_adapter",
                        error_message=str(handler_err),
                        metadata={"tool_name": request.tool_name},
                    )
                    self._audit_trail.record(failed_event)
                except Exception:
                    pass

            return ExecutionResult(
                request_id=request.request_id,
                tool_name=request.tool_name,
                executed=True,
                success=False,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=completed_at,
                error=error_msg,
                metadata={"tool_category": tool_contract.tool_category.value},
            )
