"""
LLM Tool Call Boundary for AgentShield.
Standardizes model outputs from provider SDKs (OpenAI, Anthropic, LangChain, CrewAI)
into authoritative AgentShield AGCP v1 AgentActionRequest contracts.
"""

import json
from typing import Dict, Any, Optional
from app.agent.models import AgentActionRequest, ActionType


class LLMToolCallBoundary:
    """
    Parser and translator for LLM function/tool-calling representations.
    """

    @staticmethod
    def from_openai(
        agent_id: str,
        tool_call_dict: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        """
        Parse OpenAI function call structure:
        {"function": {"name": "calculator", "arguments": "{\"expression\": \"2 + 2\"}"}}
        """
        fn = tool_call_dict.get("function", tool_call_dict)
        name = fn.get("name", "")
        raw_args = fn.get("arguments", {})
        if isinstance(raw_args, str):
            try:
                params = json.loads(raw_args)
            except json.JSONDecodeError:
                params = {"raw_arguments": raw_args}
        else:
            params = raw_args or {}

        return AgentActionRequest(
            agent_id=agent_id,
            action_type=ActionType.TOOL_CALL,
            target=name,
            parameters=params,
            context=context or {},
        )

    @staticmethod
    def from_anthropic(
        agent_id: str,
        tool_use_block: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        """
        Parse Anthropic tool_use content block:
        {"type": "tool_use", "name": "filesystem", "input": {"operation": "read", "path": "report.txt"}}
        """
        name = tool_use_block.get("name", "")
        params = tool_use_block.get("input", {})
        return AgentActionRequest(
            agent_id=agent_id,
            action_type=ActionType.TOOL_CALL,
            target=name,
            parameters=params,
            context=context or {},
        )

    @staticmethod
    def from_langchain(
        agent_id: str,
        tool_call: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AgentActionRequest:
        """
        Parse LangChain tool call:
        {"name": "http", "args": {"url": "https://api.example.com"}}
        """
        name = tool_call.get("name", "")
        params = tool_call.get("args", {})
        return AgentActionRequest(
            agent_id=agent_id,
            action_type=ActionType.TOOL_CALL,
            target=name,
            parameters=params,
            context=context or {},
        )
