"""
Authoritative AgentGatewayService for AgentShield (AGCP v1).
Orchestrates agent identity verification, threat scanning, policy enforcement, approval gating,
and isolated tool execution.
"""

import time
import uuid
from typing import Dict, Any, Optional
from datetime import datetime

from app.agent.models import (
    AgentActionRequest,
    AgentActionResponse,
    GatewayDecision,
    ExecutionStatus,
    AgentStatus,
)
from app.agent.registry import AgentRegistry, get_agent_registry
from app.security.execution.tool_registry_service import ToolRegistryRepository, get_tool_registry_repository
from app.security.policies.registry import create_fail_closed_policy_registry
from app.security.policies.context import PolicyContext
from app.security.models import (
    ToolRequest,
    ToolCategory,
    ActionType as CoreActionType,
    AgentIdentity,
    SecurityDecisionType,
    Severity,
    RiskAssessment,
)
from app.security.detectors import (
    PromptInjectionDetector,
    CredentialDetector,
    SensitiveDataDetector,
    DestinationDetector,
    create_default_registry,
)
from app.security.approval.service import ApprovalService, get_approval_service
from app.security.approval.contracts import ReviewerIdentity, ApprovalStatus
from app.security.enforcement.authorization_v2 import mint_execution_authorization_v2
from app.security.keys.service import SigningKeyError
from app.security.audit import SecurityAuditTrail, SecurityEventFactory
from app.security.models.utils import utc_now
from app.security.execution.tools import (
    RealCalculatorTool,
    RealFileSystemTool,
    RealHttpTool,
    RealCommandTool,
)
from app.security.sandbox.isolation import ExecutionIsolation


class AgentGatewayService:
    """
    Central orchestration service for autonomous agent interactions through the AgentShield firewall.
    """

    def __init__(
        self,
        agent_registry: Optional[AgentRegistry] = None,
        tool_repository: Optional[ToolRegistryRepository] = None,
        approval_service: Optional[ApprovalService] = None,
        audit_trail: Optional[SecurityAuditTrail] = None,
    ) -> None:
        self._agent_registry = agent_registry or get_agent_registry()
        self._tool_repo = tool_repository or get_tool_registry_repository()
        self._approval_service = approval_service or get_approval_service()
        self._audit_trail = audit_trail
        self._policy_registry = create_fail_closed_policy_registry()

        # Threat detector registry
        self._detector_registry = create_default_registry()

        # Real tool handlers
        self._calculator = RealCalculatorTool()
        self._filesystem = RealFileSystemTool()
        self._http = RealHttpTool()
        self._command = RealCommandTool()
        self._isolation = ExecutionIsolation()

    def handle_action(
        self,
        action_request: AgentActionRequest,
        agent_key: Optional[str] = None,
    ) -> AgentActionResponse:
        """
        Execute full security gateway evaluation pipeline for an agent action request.
        """
        start_time = time.perf_counter()
        # Phase 1.2: the EOS client always submits idempotency_key == EOS
        # ActionRequest.action_id. The server echoes it as action_id and uses it
        # as the approval correlation key so an APPROVED approval can be
        # re-verified on resume.
        raw_idem = (action_request.idempotency_key or "").strip()
        action_id = raw_idem if raw_idem else str(uuid.uuid4())
        agent_id = action_request.agent_id

        # Phase 1.2: executor routing. "eos" means AgentShield evaluates and
        # issues a v2 Ed25519 authorization WITHOUT server-side execution; EOS
        # verifies locally and runs its own handler. Any other/absent value
        # keeps the AS-native sandbox path unchanged.
        executor = str((action_request.context or {}).get("executor") or "native").strip().lower()
        if not executor:
            executor = "native"

        # 1. Agent Authentication & Status Verification
        agent = self._agent_registry.get(agent_id)
        if not agent:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"Unregistered agent ID '{agent_id}'. Action denied.",
                decision_details={"reason": "UNREGISTERED_AGENT", "rule_id": "auth.agent_lookup"},
                duration_ms=duration_ms,
            )

        if agent.status != AgentStatus.ACTIVE:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"Agent '{agent_id}' is currently {agent.status.value}. Action denied.",
                decision_details={"reason": "INACTIVE_AGENT_STATUS", "status": agent.status.value},
                duration_ms=duration_ms,
            )

        if agent_key and not self._agent_registry.validate_key(agent_id, agent_key):
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error="Invalid agent API key credential. Action denied.",
                decision_details={"reason": "INVALID_AGENT_CREDENTIAL"},
                duration_ms=duration_ms,
            )

        # 2. Tool Registration and Capability Validation
        target_tool = action_request.target
        if target_tool not in agent.allowed_tools:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"Tool '{target_tool}' is not in agent '{agent_id}' authorized tool allowlist.",
                decision_details={"reason": "TOOL_NOT_IN_AGENT_ALLOWLIST", "target": target_tool},
                duration_ms=duration_ms,
            )

        tool_meta = self._tool_repo.get_tool(target_tool)
        if not tool_meta or not tool_meta.get("is_enabled", True):
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"Tool '{target_tool}' is disabled or not found in Tool Registry.",
                decision_details={"reason": "TOOL_DISABLED_OR_UNREGISTERED"},
                duration_ms=duration_ms,
            )

        # Map to core request model
        cat_str = str(tool_meta.get("category", "")).upper()
        if "FILE" in cat_str:
            tool_cat = ToolCategory.FILESYSTEM
        elif "NET" in cat_str or "HTTP" in cat_str:
            tool_cat = ToolCategory.NETWORK
        elif "CODE" in cat_str or "SHELL" in cat_str or "CMD" in cat_str:
            tool_cat = ToolCategory.CODE_EXECUTION
        elif "SYS" in cat_str:
            tool_cat = ToolCategory.SYSTEM
        elif "DATA" in cat_str or "DB" in cat_str:
            tool_cat = ToolCategory.DATABASE
        else:
            tool_cat = ToolCategory.OTHER

        core_req = ToolRequest(
            request_id=action_id,
            agent=AgentIdentity(agent_id=agent_id, name=agent.name, capabilities=agent.capabilities),
            tool_name=target_tool,
            tool_category=tool_cat,
            action=CoreActionType.EXECUTE,
            target=target_tool,
            parameters=action_request.parameters,
            metadata=action_request.context,
        )

        # 3. Input Threat Scanning across all registered detectors
        threat_signals = self._detector_registry.detect_all(core_req)

        threat_report_dict = {
            "threat_detected": len(threat_signals) > 0,
            "signals": [
                {
                    "threat_type": s.threat_type.value,
                    "severity": s.severity.value,
                    "title": s.title,
                    "description": s.description,
                }
                for s in threat_signals
            ],
        }

        # 4. Risk Assessment
        if threat_signals:
            risk_score = 95.0
            severity = Severity.CRITICAL
            risk_reasons = [f"Threat detected: {s.threat_type}" for s in threat_signals]
        else:
            cat = str(tool_meta.get("category", "READ_ONLY")).upper()
            target_lower = target_tool.lower()
            op = str(action_request.parameters.get("operation", "")).lower()

            if "read" in target_lower or op in ("read", "list", "stat"):
                risk_score = 10.0
                severity = Severity.LOW
                risk_reasons = ["Standard read-only safe operation"]
            elif cat in ("UNRESTRICTED", "SHELL") or "command" in target_lower:
                cmd_str = str(action_request.parameters.get("command", "")).strip()
                if cmd_str.startswith("echo ") or cmd_str == "echo":
                    risk_score = 10.0
                    severity = Severity.LOW
                    risk_reasons = ["Safe builtin echo command"]
                else:
                    risk_score = 75.0
                    severity = Severity.HIGH
                    risk_reasons = ["High-risk shell execution action"]
            elif cat in ("NETWORK_ACCESS", "NETWORK"):
                risk_score = 45.0
                severity = Severity.MEDIUM
                risk_reasons = ["Outbound network communication"]
            elif "write" in target_lower or "delete" in target_lower or op in ("write", "delete"):
                risk_score = 35.0
                severity = Severity.MEDIUM
                risk_reasons = ["High-impact filesystem mutation operation"]
            elif cat in ("READ_WRITE_ISOLATED", "DATA_MUTATION"):
                risk_score = 35.0
                severity = Severity.MEDIUM
                risk_reasons = ["Filesystem mutation operation"]
            else:
                risk_score = 10.0
                severity = Severity.LOW
                risk_reasons = ["Standard read-only safe operation"]

        risk_assessment = RiskAssessment(
            request_id=action_id,
            risk_score=risk_score,
            severity=severity,
            rationale="; ".join(risk_reasons),
            contributing_signals=[s.signal_id for s in threat_signals] if threat_signals else [],
            metadata={"reasons": risk_reasons},
        )

        policy_ctx = PolicyContext(
            request=core_req,
            risk_assessment=risk_assessment,
            threat_signals=threat_signals,
        )

        # 5. Policy Engine Evaluation
        matched_rule = None
        decision = SecurityDecisionType.BLOCK
        decision_reason = "No matching policy rule (default deny)"

        for rule in self._policy_registry.get_rules():
            eval_result = rule.evaluate(policy_ctx)
            if eval_result is not None:
                decision, decision_reason = eval_result
                matched_rule = rule
                break

        # 6. Act upon Policy Decision
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        if decision == SecurityDecisionType.BLOCK:
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=decision_reason,
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "risk_score": risk_score,
                    "severity": severity.value,
                    "reasons": risk_reasons,
                },
                threat_report=threat_report_dict,
                duration_ms=duration_ms,
            )

        elif decision == SecurityDecisionType.REQUIRE_APPROVAL:
            # Phase 1.2 remote approval lifecycle:
            #   PENDING  -> REQUIRE_APPROVAL (no execution; same approval_id)
            #   APPROVED + matching request -> v2 mint + ALLOW(EVALUATED)
            #   REJECTED / CANCELLED / CLAIMED -> DENY
            #   EXPIRED  -> REQUIRE_APPROVAL (no execution; approval_status=EXPIRED)
            #   none     -> create a fresh pending approval
            from app.security.models import SecurityDecision
            from app.security.detectors.builder import build_threat_report
            from app.security.gateway.result import SecurityEvaluationResult

            existing = self._resolve_existing_approval(core_req, action_id)
            if existing is not None:
                if existing.status == ApprovalStatus.PENDING:
                    # Reuse the pending approval (never spawn duplicate approvals
                    # for the same authorized content across re-submissions).
                    return AgentActionResponse(
                        action_id=action_id,
                        agent_id=agent_id,
                        decision=GatewayDecision.REQUIRE_APPROVAL,
                        execution_status=ExecutionStatus.PENDING_APPROVAL,
                        approval_id=existing.approval_id,
                        error=decision_reason,
                        reason=decision_reason,
                        decision_details={
                            "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                            "risk_score": risk_score,
                            "severity": severity.value,
                            "approval_status": existing.status.value,
                            "approval_id": existing.approval_id,
                            "reason": decision_reason,
                        },
                        threat_report=threat_report_dict,
                        duration_ms=(time.perf_counter() - start_time) * 1000.0,
                    )
                if existing.status in (ApprovalStatus.REJECTED, ApprovalStatus.CANCELLED, ApprovalStatus.CLAIMED):
                    return AgentActionResponse(
                        action_id=action_id,
                        agent_id=agent_id,
                        decision=GatewayDecision.DENY,
                        execution_status=ExecutionStatus.BLOCKED,
                        error=f"Action was {existing.status.value.lower()} by the reviewer; approval cannot satisfy execution.",
                        decision_details={
                            "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                            "risk_score": risk_score,
                            "severity": severity.value,
                            "approval_status": existing.status.value,
                            "approval_id": existing.approval_id,
                            "rejection": "approval_rejected",
                        },
                        threat_report=threat_report_dict,
                        duration_ms=(time.perf_counter() - start_time) * 1000.0,
                    )
                if existing.status == ApprovalStatus.EXPIRED:
                    return AgentActionResponse(
                        action_id=action_id,
                        agent_id=agent_id,
                        decision=GatewayDecision.REQUIRE_APPROVAL,
                        execution_status=ExecutionStatus.PENDING_APPROVAL,
                        approval_id=existing.approval_id,
                        error=decision_reason,
                        reason=decision_reason,
                        decision_details={
                            "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                            "risk_score": risk_score,
                            "severity": severity.value,
                            "approval_status": "EXPIRED",
                            "approval_id": existing.approval_id,
                            "reason": "Prior approval expired; a fresh approval is required.",
                        },
                        threat_report=threat_report_dict,
                        duration_ms=(time.perf_counter() - start_time) * 1000.0,
                    )
                if existing.status == ApprovalStatus.APPROVED:
                    return self._approval_satisfied_response(
                        core_req=core_req,
                        approval=existing,
                        agent_id=agent_id,
                        executor=executor,
                        action_id=action_id,
                        matched_rule=matched_rule,
                        risk_score=risk_score,
                        severity=severity,
                        risk_reasons=risk_reasons,
                        threat_report_dict=threat_report_dict,
                        decision_reason=decision_reason,
                        start_time=start_time,
                    )

            threat_rep = build_threat_report(request_id=action_id, signals=threat_signals)
            sec_dec = SecurityDecision(
                request_id=action_id,
                decision=SecurityDecisionType.REQUIRE_APPROVAL,
                risk_assessment_id=risk_assessment.assessment_id,
                reason=decision_reason,
                policy_id=matched_rule.rule_id if matched_rule else "policy.approval",
            )
            eval_res = SecurityEvaluationResult(
                request=core_req,
                threat_report=threat_rep,
                risk_assessment=risk_assessment,
                decision=sec_dec,
            )
            # executor mode is stored in approval metadata so a post-restart
            # approval resume fails safe (never executes server-side for eos).
            approval = self._approval_service.create_approval(eval_res, metadata={"executor": executor})
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.REQUIRE_APPROVAL,
                execution_status=ExecutionStatus.PENDING_APPROVAL,
                approval_id=approval.approval_id,
                error=decision_reason,
                reason=decision_reason,
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "risk_score": risk_score,
                    "severity": severity.value,
                    "approval_status": approval.status.value,
                    "approval_id": approval.approval_id,
                    "reason": decision_reason,
                },
                threat_report=threat_report_dict,
                duration_ms=duration_ms,
            )

        else:
            # ALLOW
            # Phase 1.2: executor="eos" => AgentShield is the security authority
            # (evaluates + mints the v2 Ed25519 authorization) while EOS runs the
            # handler. NO server-side execution; EVALUATED, not EXECUTED.
            if executor == "eos":
                return self._eos_allow_response(
                    core_req=core_req,
                    agent_id=agent_id,
                    action_id=action_id,
                    matched_rule=matched_rule,
                    risk_score=risk_score,
                    severity=severity,
                    risk_reasons=risk_reasons,
                    threat_report_dict=threat_report_dict,
                    decision_reason=decision_reason,
                    start_time=start_time,
                )

            # AS-native sandbox path (unchanged: internal HMAC credential + isolated subprocess)
            try:
                from app.security.enforcement.authorization import mint_execution_authorization
                auth_token = mint_execution_authorization(
                    request=core_req,
                    policy_id=matched_rule.rule_id if matched_rule else "policy.allow",
                    risk_score=risk_score,
                    correlation_id=action_id,
                )
                exec_result = self._execute_real_tool(
                    target_tool,
                    action_request.parameters,
                    action_request.context,
                    capability=auth_token,
                )
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return AgentActionResponse(
                    action_id=action_id,
                    agent_id=agent_id,
                    decision=GatewayDecision.ALLOW,
                    execution_status=ExecutionStatus.EXECUTED,
                    result=exec_result,
                    decision_details={
                        "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                        "risk_score": risk_score,
                        "severity": severity.value,
                        "authorization_id": auth_token.authorization_id,
                        "isolated": True,
                    },
                    threat_report=threat_report_dict,
                    duration_ms=duration_ms,
                )
            except Exception as exc:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                return AgentActionResponse(
                    action_id=action_id,
                    agent_id=agent_id,
                    decision=GatewayDecision.ALLOW,
                    execution_status=ExecutionStatus.FAILED,
                    error=str(exc),
                    threat_report=threat_report_dict,
                    duration_ms=duration_ms,
                )

    # ----------------------------------------------------------------------
    # Phase 1.2 — v2 authorization + approval-resume helpers
    # ----------------------------------------------------------------------

    def _resolve_existing_approval(self, core_req, action_id):
        """
        Find a prior approval for this action: first by the exact
        idempotency/action_id (idempotent replay), then by structural equality
        of the authorized request (tool/action/category/target/params/agent) so
        an EOS resume — which mints a fresh ActionRequest.action_id — still
        re-verifies the EXACT approved request instead of silently re-gating.
        """
        from app.security.approval.contracts import ApprovalStatus

        by_id = self._approval_service.get_approval_by_request_id(action_id)
        if by_id is not None:
            try:
                return self._approval_service.get_approval(by_id.approval_id)
            except Exception:
                return by_id
        for candidate in self._approval_service.list_approvals(limit=100):
            try:
                fresh = self._approval_service.get_approval(candidate.approval_id)
            except Exception:
                continue
            if self._approval_matches_request(fresh, core_req):
                return fresh
        return None

    def _approval_matches_request(self, approval, core_req) -> bool:
        """Structural re-verification: does this approval bind the CURRENT
        request content (the exact tool/target/params/principal/action fields)?"""
        try:
            if approval.agent.agent_id != core_req.agent.agent_id:
                return False
            if approval.tool_name != core_req.tool_name:
                return False
            if approval.action != core_req.action:
                return False
            if approval.tool_category != core_req.tool_category:
                return False
            if approval.target != core_req.target:
                return False
            if dict(approval.parameters or {}) != dict(core_req.parameters or {}):
                return False
            return True
        except Exception:
            return False

    def _mint_v2_authorization(
        self,
        core_req,
        action_id: str,
        matched_rule,
        risk_score: float,
        approval_id: Optional[str] = None,
        fingerprint: Optional[str] = None,
        policy_id: Optional[str] = None,
    ) -> dict:
        """
        Mint the EOS-facing v2 token (protocol §3.1/§5). Raises SigningKeyError
        when the signing plane is unavailable (mint fails closed).
        """
        principal = core_req.agent.agent_id
        fp = (fingerprint or "").strip()
        if not fp:
            fp = str((core_req.metadata or {}).get("fingerprint") or "")
        # EOS always supplies context.fingerprint; without it there is no
        # trustworthy request binding — fail closed.
        import re
        if not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise ValueError("EOS request fingerprint missing/malformed: cannot bind v2 authorization.")
        issuer = None  # resolved inside mint via key manager
        return mint_execution_authorization_v2(
            action_id=action_id,
            correlation_id=action_id,
            request_fingerprint=fp,
            principal=principal,
            tool=core_req.tool_name,
            target=core_req.target or "",
            parameters=core_req.parameters,
            policy_id=policy_id or (matched_rule.rule_id if matched_rule else "policy.allow"),
            risk_score=risk_score,
            approval_id=approval_id,
        )

    def _eos_allow_response(
        self,
        core_req,
        agent_id: str,
        action_id: str,
        matched_rule,
        risk_score: float,
        severity,
        risk_reasons,
        threat_report_dict: dict,
        decision_reason: str,
        start_time: float,
    ) -> AgentActionResponse:
        try:
            token = self._mint_v2_authorization(
                core_req, action_id, matched_rule, risk_score
            )
        except SigningKeyError:
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error="AgentShield signing key unavailable; authorization mint failed closed.",
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "rejection": "signing_key_missing",
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )
        except Exception as exc:
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"v2 authorization mint failed closed: {exc}",
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "rejection": "authorization_mint_failed",
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return AgentActionResponse(
            action_id=action_id,
            agent_id=agent_id,
            decision=GatewayDecision.ALLOW,
            execution_status=ExecutionStatus.EVALUATED,
            protocol_version="v2",
            authorization=token,
            decision_details={
                "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                "risk_score": risk_score,
                "severity": severity.value,
                "authorization_id": token["authorization_id"],
                "protocol_version": "v2",
                "reason": decision_reason,
                "executor": "eos",
                "isolated": False,
            },
            threat_report=threat_report_dict,
            duration_ms=duration_ms,
        )

    def _approval_satisfied_response(
        self,
        core_req,
        approval,
        agent_id: str,
        executor: str,
        action_id: str,
        matched_rule,
        risk_score: float,
        severity,
        risk_reasons,
        threat_report_dict: dict,
        decision_reason: str,
        start_time: float,
    ) -> AgentActionResponse:
        from app.security.approval.contracts import ApprovalStatus

        # Structural re-validation of the EXACT approved request (fail safe).
        if not self._approval_matches_request(approval, core_req):
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.REQUIRE_APPROVAL,
                execution_status=ExecutionStatus.PENDING_APPROVAL,
                approval_id=approval.approval_id,
                error=decision_reason,
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "approval_status": approval.status.value,
                    "approval_id": approval.approval_id,
                    "reason": "Approval fingerprint mismatch; fresh approval required.",
                    "rejection": "approval_fingerprint_mismatch",
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        if executor != "eos":
            # Native clients resolve approvals through ApprovalService.approve()
            # (server-side execution). Surface the still-valid approval only.
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.REQUIRE_APPROVAL,
                execution_status=ExecutionStatus.PENDING_APPROVAL,
                approval_id=approval.approval_id,
                reason=decision_reason,
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "approval_status": approval.status.value,
                    "approval_id": approval.approval_id,
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        # executor == "eos": approval is APPROVED and matches the exact request
        # => the single mint moment for the v2 token (plan §8.6 / mandate §14).
        try:
            token = self._mint_v2_authorization(
                core_req,
                action_id,
                matched_rule,
                risk_score,
                approval_id=approval.approval_id,
                policy_id="approval.human_authorized",
            )
        except SigningKeyError:
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error="AgentShield signing key unavailable; authorization mint failed closed.",
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "rejection": "signing_key_missing",
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )
        except Exception as exc:
            return AgentActionResponse(
                action_id=action_id,
                agent_id=agent_id,
                decision=GatewayDecision.DENY,
                execution_status=ExecutionStatus.BLOCKED,
                error=f"v2 authorization mint failed closed: {exc}",
                decision_details={
                    "rule_id": matched_rule.rule_id if matched_rule else "unknown",
                    "rejection": "authorization_mint_failed",
                },
                threat_report=threat_report_dict,
                duration_ms=(time.perf_counter() - start_time) * 1000.0,
            )
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        return AgentActionResponse(
            action_id=action_id,
            agent_id=agent_id,
            decision=GatewayDecision.ALLOW,
            execution_status=ExecutionStatus.EVALUATED,
            protocol_version="v2",
            authorization=token,
            approval_id=approval.approval_id,
            decision_details={
                "rule_id": "approval.human_authorized",
                "risk_score": risk_score,
                "severity": severity.value,
                "authorization_id": token["authorization_id"],
                "protocol_version": "v2",
                "approval_status": "APPROVED",
                "approval_id": approval.approval_id,
                "executor": "eos",
                "isolated": False,
            },
            threat_report=threat_report_dict,
            duration_ms=duration_ms,
        )

    def _execute_real_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        context: Optional[Dict[str, Any]],
        capability: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Dispatch to real isolated tool executor via dedicated child subprocess."""
        clean_tool = tool_name.lower().strip()
        params = dict(parameters or {})

        if clean_tool in ("calculator", "math") or clean_tool.startswith("calculator."):
            mod_path = "app.security.execution.tools.real_calculator"
            cls_name = "RealCalculatorTool"
        elif clean_tool in ("filesystem", "fs", "file") or clean_tool.startswith("filesystem."):
            mod_path = "app.security.execution.tools.real_filesystem"
            cls_name = "RealFileSystemTool"
            if "operation" not in params:
                if "read" in clean_tool:
                    params["operation"] = "read"
                elif "write" in clean_tool:
                    params["operation"] = "write"
                elif "list" in clean_tool:
                    params["operation"] = "list"
                elif "delete" in clean_tool:
                    params["operation"] = "delete"
        elif clean_tool in ("http", "network", "web") or clean_tool.startswith("http."):
            mod_path = "app.security.execution.tools.real_http"
            cls_name = "RealHttpTool"
        elif clean_tool in ("command.restricted", "command", "shell") or clean_tool.startswith("command."):
            mod_path = "app.security.execution.tools.real_command"
            cls_name = "RealCommandTool"
        elif clean_tool == "system.health_check":
            return {"status": "healthy", "timestamp": utc_now().isoformat(), "service": "agentshield_gateway"}
        else:
            raise ValueError(f"No executable handler registered for tool '{tool_name}'")

        cap_dict = capability.model_dump(mode="json") if hasattr(capability, "model_dump") else (capability or None)
        iso_res = self._isolation.execute_in_subprocess(
            module_path=mod_path,
            function_name=cls_name,
            parameters=params,
            context=context or {},
            capability=cap_dict,
            require_capability=True if cap_dict else False,
        )

        if not iso_res.get("success"):
            raise RuntimeError(iso_res.get("error", "Subprocess tool execution failed."))

        return iso_res.get("result", {})


# Global singleton
_gateway_service: Optional[AgentGatewayService] = None


def get_agent_gateway_service() -> AgentGatewayService:
    global _gateway_service
    if _gateway_service is None:
        _gateway_service = AgentGatewayService()
    return _gateway_service


get_agent_gateway = get_agent_gateway_service

