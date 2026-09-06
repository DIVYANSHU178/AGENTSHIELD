from datetime import datetime
from typing import Optional, Any
from app.security.models import (
    ToolRequest,
    SecurityDecisionType,
)
from app.security.gateway import SecurityDecisionGateway, SecurityEvaluationResult
from app.security.enforcement import SecurityEnforcementBoundary, EnforcementResult
from app.security.sandbox import SandboxExecutionBoundary, SandboxStatus, SandboxExecutionPolicy, SandboxExecutionResult
from app.security.audit import SecurityAuditTrail, record_gateway_lifecycle, record_enforcement_lifecycle
from app.security.runtime.contracts import (
    RuntimeExecutionRequest,
    RuntimeExecutionResult,
    RuntimeExecutionStatus,
)
from app.security.runtime.errors import RuntimeOrchestrationError
from app.security.models.utils import utc_now

class AgentRuntimeOrchestrator:
    """
    Authoritative Agent Runtime Orchestrator for AgentShield (Roadmap Phase 9).
    
    CORE SECURITY PRINCIPLE:
        RUNTIME ORCHESTRATES.
        SECURITY PIPELINE AUTHORIZES.
        SANDBOX EXECUTES.
        AUDIT RECORDS.
        
    MANDATORY SECURITY INVARIANTS:
    - Runtime cannot execute without Phase 6 authorization.
    - Runtime cannot create or forge ExecutionAuthorization.
    - Runtime cannot bypass SecurityDecisionGateway.
    - Runtime cannot bypass SecurityEnforcementBoundary.
    - Runtime cannot bypass SandboxExecutionBoundary.
    - Runtime cannot directly invoke ToolExecutionRegistry handlers.
    - BLOCK means NO execution.
    - REQUIRE_APPROVAL means NO execution.
    - Invalid/tampered runtime input must fail closed.
    - Runtime must preserve request_id across all stages.
    - Audit failures must never convert denial into execution.
    - Zero arbitrary Python execution, subprocess, shell, eval, exec, network, or LLM calls.
    """

    def __init__(
        self,
        gateway: Optional[SecurityDecisionGateway] = None,
        boundary: Optional[SecurityEnforcementBoundary] = None,
        sandbox: Optional[SandboxExecutionBoundary] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
        default_sandbox_policy: Optional[SandboxExecutionPolicy] = None,
        operations_service: Optional[Any] = None,
        approval_service: Optional[Any] = None,
    ) -> None:
        self._operations_service = operations_service
        self._approval_service = approval_service
        if audit_trail is not None:
            self._audit_trail = audit_trail
        elif operations_service is not None and getattr(operations_service, "audit_trail", None) is not None:
            self._audit_trail = operations_service.audit_trail
        elif approval_service is not None and getattr(approval_service, "audit_trail", None) is not None:
            self._audit_trail = approval_service.audit_trail
        else:
            self._audit_trail = None
        self._gateway = gateway or SecurityDecisionGateway()
        self._boundary = boundary or SecurityEnforcementBoundary(gateway=self._gateway)
        self._sandbox = sandbox or SandboxExecutionBoundary(
            boundary=self._boundary,
            audit_trail=self._audit_trail,
            default_policy=default_sandbox_policy,
        )
        self._default_sandbox_policy = default_sandbox_policy or SandboxExecutionPolicy()

    @property
    def gateway(self) -> SecurityDecisionGateway:
        return self._gateway

    @property
    def boundary(self) -> SecurityEnforcementBoundary:
        return self._boundary

    @property
    def sandbox(self) -> SandboxExecutionBoundary:
        return self._sandbox

    @property
    def audit_trail(self) -> Optional[SecurityAuditTrail]:
        return self._audit_trail

    @property
    def approval_service(self) -> Optional[Any]:
        return self._approval_service

    @property
    def default_sandbox_policy(self) -> SandboxExecutionPolicy:
        return self._default_sandbox_policy

    def _finalize_result(self, result: RuntimeExecutionResult) -> RuntimeExecutionResult:
        try:
            from app.core.observability import metrics_registry
            metrics_registry.record_execution(result.status.value)
        except Exception:
            pass

        if self._operations_service is not None:
            try:
                self._operations_service.record_runtime_execution(result)
            except Exception:
                pass
        return result

    def orchestrate(
        self,
        request: Any,
        sandbox_policy: Optional[SandboxExecutionPolicy] = None,
    ) -> RuntimeExecutionResult:
        """
        Orchestrate an incoming runtime request through the complete AgentShield security pipeline.
        Fails closed safely on invalid types, policy denial, missing authorization, or execution errors.
        """
        started_at = utc_now()

        # 1. Type validation and Canonical ToolRequest resolution
        if request is None:
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id="req-null",
                    status=RuntimeExecutionStatus.DENIED,
                    executed=False,
                    success=False,
                    error="Runtime request is null; execution denied.",
                    started_at=started_at,
                    completed_at=utc_now(),
                    duration_ms=0.0,
                )
            )

        if isinstance(request, RuntimeExecutionRequest):
            tool_req = request.to_tool_request()
            req_id = request.request_id
        elif isinstance(request, ToolRequest):
            tool_req = request
            req_id = request.request_id
        else:
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id="req-invalid-type",
                    status=RuntimeExecutionStatus.DENIED,
                    executed=False,
                    success=False,
                    error=f"Invalid runtime request runtime type '{type(request).__name__}'; execution denied.",
                    started_at=started_at,
                    completed_at=utc_now(),
                    duration_ms=0.0,
                )
            )

        try:
            # 2. Phase 5 Gateway Security Evaluation
            eval_res = self._gateway.evaluate(tool_req)

            # Record gateway lifecycle events in audit trail
            if self._audit_trail is not None:
                try:
                    record_gateway_lifecycle(self._audit_trail, eval_res)
                except Exception:
                    # Audit failure isolation: recording failure does not alter decision
                    pass

            decision = eval_res.decision.decision

            # 3. Decision Check: BLOCK or REQUIRE_APPROVAL -> Do NOT execute!
            if decision != SecurityDecisionType.ALLOW:
                enf_res = self._boundary.evaluate_and_enforce(eval_res)
                if self._audit_trail is not None:
                    try:
                        record_enforcement_lifecycle(self._audit_trail, enf_res)
                    except Exception:
                        pass

                approval_id = None
                if decision == SecurityDecisionType.REQUIRE_APPROVAL and self._approval_service is not None:
                    try:
                        approval = self._approval_service.create_approval(eval_res)
                        approval_id = approval.approval_id
                    except Exception:
                        pass

                completed_at = utc_now()
                duration_ms = (completed_at - started_at).total_seconds() * 1000.0

                result_meta = {"policy_id": eval_res.decision.policy_id}
                if approval_id:
                    result_meta["approval_id"] = approval_id
                    result_meta["approval_status"] = "PENDING"

                return self._finalize_result(
                    RuntimeExecutionResult(
                        request_id=req_id,
                        status=RuntimeExecutionStatus.DENIED,
                        decision=decision,
                        authorized=False,
                        executed=False,
                        success=False,
                        evaluation=eval_res,
                        enforcement=enf_res,
                        error=f"Runtime execution denied by security decision: {decision.value}. {eval_res.decision.reason}",
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        metadata=result_meta,
                    )
                )

            # 4. ALLOW Decision -> Obtain Phase 6 Enforcement Authorization
            enf_res = self._boundary.evaluate_and_enforce(eval_res)
            if self._audit_trail is not None:
                try:
                    record_enforcement_lifecycle(self._audit_trail, enf_res)
                except Exception:
                    pass

            if not enf_res.authorized or enf_res.authorization is None:
                completed_at = utc_now()
                duration_ms = (completed_at - started_at).total_seconds() * 1000.0

                return self._finalize_result(
                    RuntimeExecutionResult(
                        request_id=req_id,
                        status=RuntimeExecutionStatus.DENIED,
                        decision=decision,
                        authorized=False,
                        executed=False,
                        success=False,
                        evaluation=eval_res,
                        enforcement=enf_res,
                        error="Execution authorization was denied by enforcement boundary.",
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        metadata={"policy_id": eval_res.decision.policy_id},
                    )
                )

            # 5. Sandboxed Execution via SandboxExecutionBoundary
            active_policy = sandbox_policy or self._default_sandbox_policy
            sandbox_res = self._sandbox.execute(tool_req, enf_res.authorization, policy=active_policy)

            # 6. Map Sandbox Result to RuntimeExecutionResult
            if sandbox_res.status == SandboxStatus.COMPLETED:
                status = RuntimeExecutionStatus.COMPLETED
                executed = True
                success = True
                result = sandbox_res.result
                err_msg = None
            elif sandbox_res.status == SandboxStatus.TIMED_OUT:
                status = RuntimeExecutionStatus.TIMED_OUT
                executed = True
                success = False
                result = None
                err_msg = sandbox_res.error
            elif sandbox_res.status == SandboxStatus.FAILED:
                status = RuntimeExecutionStatus.FAILED
                executed = True
                success = False
                result = None
                err_msg = sandbox_res.error
            else:  # SandboxStatus.DENIED
                status = RuntimeExecutionStatus.DENIED
                executed = False
                success = False
                result = None
                err_msg = sandbox_res.error

            completed_at = utc_now()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0

            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id=req_id,
                    status=status,
                    decision=decision,
                    authorized=True,
                    executed=executed,
                    success=success,
                    authorization_id=enf_res.authorization.authorization_id,
                    evaluation=eval_res,
                    enforcement=enf_res,
                    sandbox_result=sandbox_res,
                    result=result,
                    error=err_msg,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    metadata={
                        "policy_id": eval_res.decision.policy_id,
                        "sandbox_policy_id": active_policy.policy_id,
                    },
                )
            )

        except Exception as exc:
            completed_at = utc_now()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id=req_id,
                    status=RuntimeExecutionStatus.FAILED,
                    executed=False,
                    success=False,
                    error=f"Agent runtime orchestration failure: {str(exc)}",
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                )
            )

    def orchestrate_with_approval(
        self,
        approval_id: str,
        candidate_request: Optional[Any] = None,
        sandbox_policy: Optional[SandboxExecutionPolicy] = None,
    ) -> RuntimeExecutionResult:
        """
        Execute an explicitly approved tool request through the secure execution pipeline.

        INVARIANTS:
        1. Approval is NOT authorization.
        2. Validates approval status is APPROVED and not expired.
        3. Obtains fresh ExecutionAuthorization from SecurityEnforcementBoundary.
        4. Executes solely within SandboxExecutionBoundary.
        5. Records comprehensive audit trail.
        """
        started_at = utc_now()

        if not approval_id:
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id="req-null-approval",
                    status=RuntimeExecutionStatus.DENIED,
                    executed=False,
                    success=False,
                    error="Approval ID is required to orchestrate approved execution.",
                    started_at=started_at,
                    completed_at=utc_now(),
                    duration_ms=0.0,
                )
            )

        if self._approval_service is None:
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id="req-no-approval-service",
                    status=RuntimeExecutionStatus.DENIED,
                    executed=False,
                    success=False,
                    error="Approval service is not configured on runtime orchestrator.",
                    started_at=started_at,
                    completed_at=utc_now(),
                    duration_ms=0.0,
                )
            )

        try:
            approval = self._approval_service.get_approval(approval_id)
        except Exception as exc:
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id="req-approval-not-found",
                    status=RuntimeExecutionStatus.DENIED,
                    executed=False,
                    success=False,
                    error=f"Failed to retrieve approval request: {str(exc)}",
                    started_at=started_at,
                    completed_at=utc_now(),
                    duration_ms=0.0,
                )
            )

        req_id = approval.request_id

        # 1. Resolve ToolRequest
        if candidate_request is not None:
            if isinstance(candidate_request, RuntimeExecutionRequest):
                tool_req = candidate_request.to_tool_request()
            elif isinstance(candidate_request, ToolRequest):
                tool_req = candidate_request
            else:
                return self._finalize_result(
                    RuntimeExecutionResult(
                        request_id=req_id,
                        status=RuntimeExecutionStatus.DENIED,
                        executed=False,
                        success=False,
                        error=f"Invalid candidate request type '{type(candidate_request).__name__}'.",
                        started_at=started_at,
                        completed_at=utc_now(),
                        duration_ms=0.0,
                    )
                )
        else:
            # Reconstruct canonical ToolRequest from bound approval
            tool_req = ToolRequest(
                request_id=approval.request_id,
                agent=approval.agent,
                tool_name=approval.tool_name,
                tool_category=approval.tool_category,
                action=approval.action,
                target=approval.target,
                parameters=approval.parameters,
                destination=approval.destination,
            )

        # 2. Invoke SecurityEnforcementBoundary for fresh authorization
        enf_res = self._boundary.authorize_approval(request=tool_req, approval=approval)
        if self._audit_trail is not None:
            try:
                record_enforcement_lifecycle(self._audit_trail, enf_res)
            except Exception:
                pass

        if not enf_res.authorized or enf_res.authorization is None:
            completed_at = utc_now()
            duration_ms = (completed_at - started_at).total_seconds() * 1000.0
            return self._finalize_result(
                RuntimeExecutionResult(
                    request_id=req_id,
                    status=RuntimeExecutionStatus.DENIED,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    executed=False,
                    success=False,
                    enforcement=enf_res,
                    error=enf_res.reason,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    metadata={"approval_id": approval.approval_id},
                )
            )

        # 3. Execute in SandboxExecutionBoundary with fresh authorization
        active_policy = sandbox_policy or self._default_sandbox_policy
        sandbox_res = self._sandbox.execute(tool_req, enf_res.authorization, policy=active_policy)

        # 4. Map execution status
        if sandbox_res.status == SandboxStatus.COMPLETED:
            status = RuntimeExecutionStatus.COMPLETED
            executed = True
            success = True
            result = sandbox_res.result
            err_msg = None
        elif sandbox_res.status == SandboxStatus.TIMED_OUT:
            status = RuntimeExecutionStatus.TIMED_OUT
            executed = True
            success = False
            result = None
            err_msg = sandbox_res.error
        elif sandbox_res.status == SandboxStatus.FAILED:
            status = RuntimeExecutionStatus.FAILED
            executed = True
            success = False
            result = None
            err_msg = sandbox_res.error
        else:  # SandboxStatus.DENIED
            status = RuntimeExecutionStatus.DENIED
            executed = False
            success = False
            result = None
            err_msg = sandbox_res.error

        completed_at = utc_now()
        duration_ms = (completed_at - started_at).total_seconds() * 1000.0

        return self._finalize_result(
            RuntimeExecutionResult(
                request_id=req_id,
                status=status,
                decision=SecurityDecisionType.ALLOW,
                authorized=True,
                executed=executed,
                success=success,
                authorization_id=enf_res.authorization.authorization_id,
                enforcement=enf_res,
                sandbox_result=sandbox_res,
                result=result,
                error=err_msg,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                metadata={
                    "approval_id": approval.approval_id,
                    "approved_by": approval.resolution.reviewer.reviewer_id if approval.resolution else None,
                    "sandbox_policy_id": active_policy.policy_id,
                },
            )
        )
