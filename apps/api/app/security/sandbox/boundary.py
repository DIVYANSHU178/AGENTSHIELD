import concurrent.futures
from datetime import datetime
from typing import Optional, Any, Dict
from app.security.models import ToolRequest, SecurityEvent
from app.security.enforcement import SecurityEnforcementBoundary, ExecutionAuthorization
from app.security.audit import SecurityAuditTrail, SecurityEventFactory
from app.security.execution import SecureExecutionAdapter, ToolExecutionRegistry, create_default_execution_registry
from app.security.sandbox.contracts import (
    SandboxStatus,
    SandboxExecutionLimits,
    SandboxExecutionPolicy,
    SandboxExecutionResult,
)
from app.security.models.utils import utc_now

class SandboxExecutionBoundary:
    """
    Authoritative Sandboxed Execution Boundary for AgentShield (Roadmap Phase 7).

    CRITICAL SECURITY INVARIANTS:
    - NO VALID AUTHORIZATION -> NO SANDBOX START -> NO TOOL EXECUTION
    - Strict Phase 6 ExecutionAuthorization validation before sandbox initialization.
    - Category binding: request.tool_category == registered_tool_contract.tool_category.
    - Timeout-governed, resource-contained dispatch to explicitly allowlisted in-memory tools.
    - Zero arbitrary execution: no subprocess, no shell, no eval, no exec, no network, no arbitrary filesystem.
    - Fail-closed safety on any authorization, timeout, or runtime failure.
    - Seamless integration with Phase 7 Security Audit Trail (EXECUTED / FAILED events).
    """

    def __init__(
        self,
        adapter: Optional[SecureExecutionAdapter] = None,
        boundary: Optional[SecurityEnforcementBoundary] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
        default_policy: Optional[SandboxExecutionPolicy] = None,
    ) -> None:
        self._boundary = boundary or SecurityEnforcementBoundary()
        self._adapter = adapter or SecureExecutionAdapter(boundary=self._boundary)
        self._audit_trail = audit_trail
        self._default_policy = default_policy or SandboxExecutionPolicy()

    @property
    def boundary(self) -> SecurityEnforcementBoundary:
        return self._boundary

    @property
    def adapter(self) -> SecureExecutionAdapter:
        return self._adapter

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    @property
    def default_policy(self) -> SandboxExecutionPolicy:
        return self._default_policy

    def execute(
        self,
        request: Any,
        authorization: Any,
        policy: Optional[SandboxExecutionPolicy] = None,
    ) -> SandboxExecutionResult:
        """
        Execute an authorized ToolRequest within the containment boundary of the sandbox.
        Fails closed safely on invalid types, failed authorization, missing tools, category mismatch, or timeouts.
        """
        started_at = utc_now()
        active_policy = policy or self._default_policy
        timeout_sec = active_policy.limits.timeout_seconds

        # 1. Type validation for request
        if request is None:
            return SandboxExecutionResult(
                request_id="req-null",
                tool_name="unknown",
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error="ToolRequest is null; sandbox execution denied.",
                sandbox_policy_id=active_policy.policy_id,
            )

        if not isinstance(request, ToolRequest):
            return SandboxExecutionResult(
                request_id="req-invalid-type",
                tool_name="unknown",
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error="Invalid ToolRequest runtime type; sandbox execution denied.",
                sandbox_policy_id=active_policy.policy_id,
            )

        tool_name = request.tool_name or "unknown"

        # 2. Type validation for authorization
        if authorization is None:
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error="ExecutionAuthorization is null; sandbox execution denied.",
                sandbox_policy_id=active_policy.policy_id,
            )

        if not isinstance(authorization, ExecutionAuthorization):
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error="Invalid ExecutionAuthorization runtime type; sandbox execution denied.",
                sandbox_policy_id=active_policy.policy_id,
            )

        # 3. Cryptographic and Integrity Authorization Validation
        if not self._boundary.validate_authorization(authorization, request):
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                authorization_id=getattr(authorization, "authorization_id", None),
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error="Execution authorization verification failed or denied; sandbox execution blocked.",
                sandbox_policy_id=active_policy.policy_id,
            )

        # 4. Tool Registry Resolution
        tool_contract = self._adapter.registry.get(request.tool_name)
        if tool_contract is None:
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error=f"Tool '{request.tool_name}' is not registered in ToolExecutionRegistry.",
                sandbox_policy_id=active_policy.policy_id,
            )

        # 5. Tool Category Binding Validation
        if request.tool_category != tool_contract.tool_category:
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error=f"Tool category mismatch: request specifies '{request.tool_category.value}' but tool '{request.tool_name}' is registered under '{tool_contract.tool_category.value}'.",
                sandbox_policy_id=active_policy.policy_id,
            )

        # 6. Action Resolution
        if request.action not in tool_contract.supported_actions:
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.DENIED,
                executed=False,
                success=False,
                sandboxed=True,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=utc_now(),
                duration_ms=0.0,
                error=f"Action '{request.action.value}' is not supported by tool '{request.tool_name}'.",
                sandbox_policy_id=active_policy.policy_id,
            )

        # 7. Sandboxed Execution with Enforced Timeout
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(tool_contract.handler, request)
                try:
                    result_data = future.result(timeout=timeout_sec)
                    completed_at = utc_now()
                    duration_ms = (completed_at - started_at).total_seconds() * 1000.0

                    # Record EXECUTED audit event
                    if self._audit_trail is not None:
                        try:
                            ev = SecurityEventFactory.create_executed_event(
                                request_id=request.request_id,
                                actor="sandbox_execution_boundary",
                                outcome_metadata={
                                    "tool_name": request.tool_name,
                                    "action": request.action.value,
                                    "success": True,
                                    "duration_ms": duration_ms,
                                    "sandbox_policy_id": active_policy.policy_id,
                                },
                            )
                            self._audit_trail.record(ev)
                        except Exception:
                            pass

                    return SandboxExecutionResult(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        status=SandboxStatus.COMPLETED,
                        executed=True,
                        success=True,
                        sandboxed=True,
                        timed_out=False,
                        authorization_id=authorization.authorization_id,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        result=result_data,
                        sandbox_policy_id=active_policy.policy_id,
                        containment_metadata={
                            "isolation_level": active_policy.isolation_level,
                            "timeout_seconds": timeout_sec,
                            "tool_category": tool_contract.tool_category.value,
                        },
                    )

                except concurrent.futures.TimeoutError:
                    completed_at = utc_now()
                    duration_ms = (completed_at - started_at).total_seconds() * 1000.0
                    err_msg = f"Tool execution timed out after {timeout_sec} seconds."

                    # Record FAILED audit event
                    if self._audit_trail is not None:
                        try:
                            ev = SecurityEventFactory.create_failed_event(
                                request_id=request.request_id,
                                actor="sandbox_execution_boundary",
                                error_message=err_msg,
                                metadata={
                                    "tool_name": request.tool_name,
                                    "timed_out": True,
                                    "timeout_seconds": timeout_sec,
                                },
                            )
                            self._audit_trail.record(ev)
                        except Exception:
                            pass

                    return SandboxExecutionResult(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        status=SandboxStatus.TIMED_OUT,
                        executed=True,
                        success=False,
                        sandboxed=True,
                        timed_out=True,
                        authorization_id=authorization.authorization_id,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        error=err_msg,
                        sandbox_policy_id=active_policy.policy_id,
                        containment_metadata={
                            "isolation_level": active_policy.isolation_level,
                            "timeout_seconds": timeout_sec,
                            "tool_category": tool_contract.tool_category.value,
                        },
                    )

                except Exception as handler_err:
                    completed_at = utc_now()
                    duration_ms = (completed_at - started_at).total_seconds() * 1000.0
                    err_msg = f"Tool handler execution failed: {str(handler_err)}"

                    if self._audit_trail is not None:
                        try:
                            ev = SecurityEventFactory.create_failed_event(
                                request_id=request.request_id,
                                actor="sandbox_execution_boundary",
                                error_message=str(handler_err),
                                metadata={
                                    "tool_name": request.tool_name,
                                    "timed_out": False,
                                },
                            )
                            self._audit_trail.record(ev)
                        except Exception:
                            pass

                    return SandboxExecutionResult(
                        request_id=request.request_id,
                        tool_name=request.tool_name,
                        status=SandboxStatus.FAILED,
                        executed=True,
                        success=False,
                        sandboxed=True,
                        timed_out=False,
                        authorization_id=authorization.authorization_id,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        error=err_msg,
                        sandbox_policy_id=active_policy.policy_id,
                        containment_metadata={
                            "isolation_level": active_policy.isolation_level,
                            "timeout_seconds": timeout_sec,
                            "tool_category": tool_contract.tool_category.value,
                        },
                    )

        except Exception as boundary_err:
            completed_at = utc_now()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0
            return SandboxExecutionResult(
                request_id=request.request_id,
                tool_name=tool_name,
                status=SandboxStatus.FAILED,
                executed=False,
                success=False,
                sandboxed=True,
                timed_out=False,
                authorization_id=authorization.authorization_id,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                error=f"Sandbox execution boundary failure: {str(boundary_err)}",
                sandbox_policy_id=active_policy.policy_id,
            )
