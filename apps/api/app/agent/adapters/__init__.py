"""
AgentShield Agent Adapters Package.
"""

from typing import Dict, Any, Optional
from app.agent.adapters.base import BaseAgentAdapter
from app.agent.adapters.reference import ReferenceAgentAdapter
from app.agent.adapters.llm_boundary import LLMToolCallBoundary
from app.agent.models import AgentActionRequest, AgentActionResponse


class OpenAIToolCallAdapter:
    """Adapter for OpenAI function and tool calling payloads."""

    @staticmethod
    def from_openai(
        tool_call_dict: Dict[str, Any],
        agent_id: str = "openai_agent",
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        return LLMToolCallBoundary.from_openai(
            agent_id=agent_id,
            tool_call_dict=tool_call_dict,
            context=context,
        )

    @staticmethod
    def to_openai_response(
        action_resp: AgentActionResponse,
        call_id: str = "call_default",
    ) -> Dict[str, Any]:
        if action_resp.result is not None:
            content_val = str(action_resp.result)
        else:
            content_val = action_resp.reason or action_resp.decision.value

        return {
            "tool_call_id": call_id,
            "role": "tool",
            "content": content_val,
        }


class AnthropicToolUseAdapter:
    """Adapter for Anthropic tool_use content blocks."""

    @staticmethod
    def from_anthropic(
        tool_use_block: Dict[str, Any],
        agent_id: str = "anthropic_agent",
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        return LLMToolCallBoundary.from_anthropic(
            agent_id=agent_id,
            tool_use_block=tool_use_block,
            context=context,
        )


class LangChainToolAdapter:
    """Adapter for LangChain tool invocation structures."""

    @staticmethod
    def from_langchain(
        tool_call: Dict[str, Any],
        agent_id: str = "langchain_agent",
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        norm_call = dict(tool_call)
        if "tool" in norm_call and "name" not in norm_call:
            norm_call["name"] = norm_call["tool"]
            norm_call["args"] = norm_call.get("tool_input", {})
        return LLMToolCallBoundary.from_langchain(
            agent_id=agent_id,
            tool_call=norm_call,
            context=context,
        )


__all__ = [
    "BaseAgentAdapter",
    "ReferenceAgentAdapter",
    "LLMToolCallBoundary",
    "OpenAIToolCallAdapter",
    "AnthropicToolUseAdapter",
    "LangChainToolAdapter",
]
