"""
Reference Autonomous Agent Runtime Loop for AgentShield (Stage 6).
Executes a multi-step autonomous task objective through the Security Gateway,
observing real tool results, handling approval gates, and defending against threats.
"""

from typing import Dict, Any, List, Optional
from app.agent.adapters.reference import ReferenceAgentAdapter
from app.agent.models import GatewayDecision, ExecutionStatus


class AutonomousAgentRuntime:
    """
    Runnable autonomous agent loop operating under AgentShield gateway supervision.
    """

    def __init__(
        self,
        adapter: Optional[ReferenceAgentAdapter] = None,
        agent_id: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        if adapter is not None:
            self._adapter = adapter
        else:
            self._adapter = ReferenceAgentAdapter(
                agent_id=agent_id or "reference-autonomous-agent",
                agent_key=api_key or "agk_reference_agent_secret_key",
            )
        self._memory: Dict[str, Any] = {}
        self._execution_history: List[Dict[str, Any]] = []

    @property
    def memory(self) -> Dict[str, Any]:
        return self._memory

    @property
    def execution_history(self) -> List[Dict[str, Any]]:
        return self._execution_history

    def execute_step(self, step: Any) -> Any:
        """Execute a single action step through the gateway."""
        if hasattr(step, "target"):
            target = step.target or getattr(step, "tool_name", "")
            parameters = getattr(step, "parameters", {})
            context = getattr(step, "context", {})
            action_type = getattr(step, "action_type", "tool_call")
            act_type_str = action_type.value if hasattr(action_type, "value") else str(action_type)
        else:
            target = step.get("target") or step.get("tool_name", "")
            parameters = step.get("parameters", {})
            context = step.get("context", {})
            act_type_str = step.get("action_type", "tool_call")

        return self._adapter.submit_action(
            action_type=act_type_str,
            target=target,
            parameters=parameters,
            context=context,
        )

    def run_task(
        self,
        objective: Optional[str] = None,
        steps: Optional[List[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Execute an autonomous task consisting of plan steps.
        Each step specifies target tool and parameters.
        Returns comprehensive task execution audit.
        """
        obj = objective or kwargs.get("task_id", "task_objective")
        steps_list = steps if steps is not None else kwargs.get("steps", [])

        self._execution_history.clear()
        self._memory["objective"] = obj
        current_context = dict(context or {})
        current_context["objective"] = obj

        for i, step in enumerate(steps_list):
            if hasattr(step, "target"):
                target = step.target or getattr(step, "tool_name", "")
                raw_params = getattr(step, "parameters", {})
                step_name = f"step_{i+1}"
                act_type_str = getattr(step, "action_type", "tool_call")
                if hasattr(act_type_str, "value"):
                    act_type_str = act_type_str.value
                save_key = step_name
            else:
                step_name = step.get("name", f"step_{i+1}")
                target = step.get("target") or step.get("tool_name", "")
                raw_params = step.get("parameters", {})
                act_type_str = step.get("action_type", "tool_call")
                save_key = step.get("save_as", step_name)

            # Parameter resolution from agent memory (e.g. referencing previous step result)
            resolved_params = dict(raw_params)
            for k, v in resolved_params.items():
                if isinstance(v, str) and v.startswith("$memory."):
                    mem_key = v.replace("$memory.", "")
                    resolved_params[k] = self._memory.get(mem_key, v)

            # Submit intended action to Security Gateway
            resp = self._adapter.submit_action(
                action_type=act_type_str,
                target=target,
                parameters=resolved_params,
                context=current_context,
            )

            record = {
                "step_index": i,
                "step_name": step_name,
                "target": target,
                "parameters": resolved_params,
                "decision": resp.decision.value,
                "execution_status": resp.execution_status.value,
                "result": resp.result,
                "error": resp.error,
                "approval_id": resp.approval_id,
                "details": resp.decision_details,
            }
            self._execution_history.append(record)

            if resp.decision == GatewayDecision.ALLOW and resp.execution_status == ExecutionStatus.EXECUTED:
                # Store result in memory and proceed
                self._memory[save_key] = resp.result
                current_context[f"last_result_{i}"] = resp.result

            elif resp.decision == GatewayDecision.REQUIRE_APPROVAL:
                return {
                    "objective": obj,
                    "status": "SUSPENDED_FOR_APPROVAL",
                    "steps_completed": i,
                    "completed_steps": i,
                    "total_steps": len(steps_list),
                    "pending_approval_id": resp.approval_id,
                    "history": self._execution_history,
                }

            elif resp.decision == GatewayDecision.DENY or resp.execution_status == ExecutionStatus.BLOCKED:
                return {
                    "objective": obj,
                    "status": "HALTED",
                    "steps_completed": i,
                    "completed_steps": i,
                    "total_steps": len(steps_list),
                    "blocked_step": step_name,
                    "reason": resp.error,
                    "history": self._execution_history,
                }

            elif resp.execution_status == ExecutionStatus.FAILED:
                return {
                    "objective": obj,
                    "status": "EXECUTION_FAILED",
                    "steps_completed": i,
                    "completed_steps": i,
                    "total_steps": len(steps_list),
                    "failed_step": step_name,
                    "error": resp.error,
                    "history": self._execution_history,
                }

        return {
            "objective": obj,
            "status": "COMPLETED",
            "steps_completed": len(steps_list),
            "completed_steps": len(steps_list),
            "total_steps": len(steps_list),
            "final_memory": self._memory,
            "history": self._execution_history,
        }
