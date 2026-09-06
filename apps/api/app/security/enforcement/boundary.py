from datetime import datetime, timedelta
from typing import Optional, Any
from app.security.models import (
    ToolRequest,
    SecurityDecisionType,
)
from app.security.gateway import (
    SecurityDecisionGateway,
    SecurityEvaluationResult,
)
from app.security.enforcement.authorization import (
    ExecutionAuthorization,
    calculate_request_fingerprint,
    calculate_authorization_signature,
)
from app.security.enforcement.result import EnforcementResult
from app.security.models.utils import generate_uuid, utc_now
from app.config.settings import settings

class SecurityEnforcementBoundary:
    """
    Authoritative Enforcement Boundary for AgentShield.

    Establishes the fundamental security boundary between policy decision and execution:
    NO VALID AUTHORIZATION -> NO EXECUTION

    CRITICAL CONTRACT RULES:
    - Must be deterministic, local, explainable, and fail-closed.
    - ONLY SecurityDecisionType.ALLOW decisions may produce ExecutionAuthorization credentials.
    - BLOCK and REQUIRE_APPROVAL decisions MUST refuse authorization.
    - ExecutionAuthorization credentials are bound to specific request_ids and SHA-256 request_fingerprints,
      and protected by an HMAC-SHA256 cryptographic signature.
    - MUST NOT execute tools, shell commands, network calls, browser automation, or child process execution.
    - Public API methods MUST handle malformed runtime input types safely (fail closed / return False).
    """

    def __init__(
        self,
        gateway: Optional[SecurityDecisionGateway] = None,
        default_token_ttl_seconds: int = 300,
        secret_key: Optional[str] = None,
    ) -> None:
        self._gateway = gateway or SecurityDecisionGateway()
        self._default_token_ttl_seconds = default_token_ttl_seconds
        if secret_key:
            self._secret_key = secret_key
        else:
            self._secret_key = settings.get_authorization_secret()

    @property
    def gateway(self) -> SecurityDecisionGateway:
        return self._gateway

    def enforce(self, request: Any) -> EnforcementResult:
        """
        Evaluate a ToolRequest via Phase 5 gateway and enforce authorization boundary.
        Returns EnforcementResult.
        Fails closed safely if input request is None or malformed.
        """
        if request is None:
            return self._fail_closed_result(
                request_id="req-null",
                correlation_id="corr-null",
                reason="ToolRequest is None; failing closed to deny execution authorization.",
            )

        if not isinstance(request, ToolRequest):
            return self._fail_closed_result(
                request_id="req-invalid-type",
                correlation_id="corr-invalid-type",
                reason="Invalid ToolRequest runtime input type; failing closed to deny execution authorization.",
            )

        try:
            eval_result = self._gateway.evaluate(request)
            return self.evaluate_and_enforce(eval_result)
        except Exception:
            return self._fail_closed_result(
                request_id=request.request_id,
                correlation_id=request.request_id,
                reason="Internal gateway processing failure during enforcement; failing closed to deny execution authorization.",
            )

    def evaluate_and_enforce(self, eval_result: Any) -> EnforcementResult:
        """
        Enforce security boundary given a Phase 5 SecurityEvaluationResult.
        Issues ExecutionAuthorization ONLY if decision == ALLOW.
        Fails closed on invalid result or internal errors.
        """
        if eval_result is None or not isinstance(eval_result, SecurityEvaluationResult) or eval_result.request is None or eval_result.decision is None:
            return self._fail_closed_result(
                request_id="req-unknown",
                correlation_id="corr-unknown",
                reason="SecurityEvaluationResult is null or malformed type; failing closed to deny execution authorization.",
            )

        req_id = getattr(eval_result.request, "request_id", "req-unknown")
        corr_id = req_id

        try:
            if not self._secret_key:
                self._secret_key = settings.get_authorization_secret()

            decision_type = eval_result.decision.decision

            if decision_type == SecurityDecisionType.ALLOW:
                # 1. Compute request fingerprint
                fingerprint = calculate_request_fingerprint(eval_result.request)

                # 2. Expiration timestamp
                issued_at = utc_now()
                expires_at = issued_at + timedelta(seconds=self._default_token_ttl_seconds)

                # 3. Generate unique authorization credential ID
                auth_id = generate_uuid()

                policy_id = eval_result.decision.policy_id or "policy.default.allow"
                risk_score = eval_result.risk_assessment.risk_score

                # 4. Calculate HMAC-SHA256 signature for credential integrity
                signature = calculate_authorization_signature(
                    authorization_id=auth_id,
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision_value=SecurityDecisionType.ALLOW.value,
                    request_fingerprint=fingerprint,
                    policy_id=policy_id,
                    risk_score=risk_score,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    secret_key=self._secret_key,
                )

                # 5. Create immutable ExecutionAuthorization credential
                authorization = ExecutionAuthorization(
                    authorization_id=auth_id,
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.ALLOW,
                    request_fingerprint=fingerprint,
                    policy_id=policy_id,
                    risk_score=risk_score,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    signature=signature,
                    metadata={"enforced_by": "SecurityEnforcementBoundary"},
                )

                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.ALLOW,
                    authorized=True,
                    authorization=authorization,
                    reason="Execution authorization granted for ALLOW decision.",
                    metadata={"policy_id": eval_result.decision.policy_id},
                )

            else:
                # BLOCK or REQUIRE_APPROVAL -> Refuse authorization
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=decision_type,
                    authorized=False,
                    authorization=None,
                    reason=f"Execution authorization denied for {decision_type.value} decision: {eval_result.decision.reason}",
                    metadata={"policy_id": eval_result.decision.policy_id},
                )

        except Exception:
            return self._fail_closed_result(
                request_id=req_id,
                correlation_id=corr_id,
                reason="Internal exception occurred during enforcement evaluation; failing closed to deny execution authorization.",
            )

    def validate_authorization(
        self,
        authorization: Any,
        request: Any,
    ) -> bool:
        """
        Validate whether an ExecutionAuthorization credential legitimately grants execution for a ToolRequest.
        Validates:
        1. Non-null presence and correct runtime types for both parameters.
        2. authorization.decision == ALLOW.
        3. authorization.request_id == request.request_id.
        4. HMAC-SHA256 signature verification (detects credential tampering or forgery).
        5. authorization.request_fingerprint matches calculated request fingerprint (detects request tampering).
        6. Token expiration (if expires_at is present).
        Returns True if valid, False otherwise. Fails closed safely on any error.
        """
        if authorization is None or request is None:
            return False

        if not isinstance(authorization, ExecutionAuthorization) or not isinstance(request, ToolRequest):
            return False

        try:
            if authorization.decision != SecurityDecisionType.ALLOW:
                return False

            if authorization.request_id != request.request_id:
                return False

            # 1. Cryptographic Signature Verification
            secret_key = self._secret_key or settings.get_authorization_secret()
            if not authorization.verify_signature(secret_key=secret_key):
                return False

            # 2. Request Fingerprint Tampering Verification
            expected_fingerprint = calculate_request_fingerprint(request)
            if authorization.request_fingerprint != expected_fingerprint:
                return False

            # 3. Expiration Verification
            if authorization.expires_at is None:
                return False
            if utc_now() > authorization.expires_at:
                return False

            return True
        except Exception:
            # FAIL-CLOSED: Any validation calculation error returns False
            return False

    def authorize_approval(
        self,
        request: Any,
        approval: Any,
    ) -> EnforcementResult:
        """
        Authoritatively validate an approved ApprovalRequest against the candidate ToolRequest,
        and issue a fresh, cryptographically signed ExecutionAuthorization.

        INVARIANTS:
        - NEVER reuses an old authorization.
        - NEVER allows unapproved, expired, cancelled, or rejected approvals.
        - Strictly verifies request content matches approval fingerprint (tamper-detection).
        - Issues fresh ExecutionAuthorization with unique ID and fresh expiration window.
        """
        if request is None or approval is None:
            return self._fail_closed_result(
                request_id=getattr(request, "request_id", getattr(approval, "request_id", "req-unknown")),
                correlation_id=getattr(request, "request_id", "req-unknown"),
                reason="Cannot authorize approval: ToolRequest or ApprovalRequest is null.",
            )

        if not isinstance(request, ToolRequest):
            return self._fail_closed_result(
                request_id=getattr(approval, "request_id", "req-unknown"),
                correlation_id="req-unknown",
                reason=f"Invalid request type '{type(request).__name__}', expected ToolRequest.",
            )

        from app.security.approval.contracts import ApprovalRequest, ApprovalStatus, ApprovalDecision
        if not isinstance(approval, ApprovalRequest):
            return self._fail_closed_result(
                request_id=request.request_id,
                correlation_id=request.request_id,
                reason=f"Invalid approval type '{type(approval).__name__}', expected ApprovalRequest.",
            )

        req_id = request.request_id
        corr_id = req_id

        try:
            # 1. Approval Status Check
            if approval.status != ApprovalStatus.APPROVED:
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason=f"Approval request '{approval.approval_id}' has status '{approval.status.value}', expected APPROVED.",
                    metadata={"approval_id": approval.approval_id, "approval_status": approval.status.value},
                )

            # 2. Approval Expiration Check
            if approval.is_expired():
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason=f"Approval request '{approval.approval_id}' has expired.",
                    metadata={"approval_id": approval.approval_id, "expired": True},
                )

            # 3. Request Binding Integrity Check
            if approval.request_id != request.request_id:
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason=f"Request ID mismatch: request specifies '{request.request_id}' but approval is bound to '{approval.request_id}'.",
                    metadata={"approval_id": approval.approval_id},
                )

            if approval.agent.agent_id != request.agent.agent_id:
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason="Agent identity mismatch: approval is bound to a different agent ID.",
                    metadata={"approval_id": approval.approval_id},
                )

            # 4. Fingerprint / Content Tampering Check
            expected_fingerprint = calculate_request_fingerprint(request)
            if approval.request_fingerprint != expected_fingerprint:
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason="Request fingerprint mismatch: request parameters or target were altered after approval.",
                    metadata={"approval_id": approval.approval_id, "tampered": True},
                )

            # 5. Reviewer Resolution Check
            if approval.resolution is None or approval.resolution.decision != ApprovalDecision.APPROVE:
                return EnforcementResult(
                    request_id=req_id,
                    correlation_id=corr_id,
                    decision=SecurityDecisionType.REQUIRE_APPROVAL,
                    authorized=False,
                    authorization=None,
                    reason="Missing or invalid reviewer approval resolution.",
                    metadata={"approval_id": approval.approval_id},
                )

            # 6. Issue FRESH ExecutionAuthorization credential
            if not self._secret_key:
                self._secret_key = settings.get_authorization_secret()

            auth_id = generate_uuid()
            issued_at = utc_now()
            expires_at = issued_at + timedelta(seconds=self._default_token_ttl_seconds)
            policy_id = f"approval.approved.{approval.approval_id[:8]}"
            risk_score = approval.risk_score

            signature = calculate_authorization_signature(
                authorization_id=auth_id,
                request_id=req_id,
                correlation_id=corr_id,
                decision_value=SecurityDecisionType.ALLOW.value,
                request_fingerprint=approval.request_fingerprint,
                policy_id=policy_id,
                risk_score=risk_score,
                issued_at=issued_at,
                expires_at=expires_at,
                secret_key=self._secret_key,
            )

            authorization = ExecutionAuthorization(
                authorization_id=auth_id,
                request_id=req_id,
                correlation_id=corr_id,
                decision=SecurityDecisionType.ALLOW,
                request_fingerprint=approval.request_fingerprint,
                policy_id=policy_id,
                risk_score=risk_score,
                issued_at=issued_at,
                expires_at=expires_at,
                signature=signature,
                metadata={
                    "approved_by": approval.resolution.reviewer.reviewer_id,
                    "approval_id": approval.approval_id,
                    "approval_reason": approval.resolution.reason,
                    "enforced_by": "SecurityEnforcementBoundary",
                },
            )

            return EnforcementResult(
                request_id=req_id,
                correlation_id=corr_id,
                decision=SecurityDecisionType.ALLOW,
                authorized=True,
                authorization=authorization,
                reason=f"Execution authorization granted following verified human approval '{approval.approval_id}'.",
                metadata={
                    "approval_id": approval.approval_id,
                    "reviewer_id": approval.resolution.reviewer.reviewer_id,
                },
            )

        except Exception as exc:
            return self._fail_closed_result(
                request_id=req_id,
                correlation_id=corr_id,
                reason=f"Internal exception during approval authorization: {str(exc)}",
            )

    def _fail_closed_result(
        self,
        request_id: str,
        correlation_id: str,
        reason: str,
    ) -> EnforcementResult:
        """Helper building a safe fail-closed unauthorized EnforcementResult."""
        return EnforcementResult(
            request_id=request_id,
            correlation_id=correlation_id,
            decision=SecurityDecisionType.BLOCK,
            authorized=False,
            authorization=None,
            reason=reason,
            metadata={"fail_closed": True},
        )
