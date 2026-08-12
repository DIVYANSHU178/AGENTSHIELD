from app.security import (
    AgentIdentity,
    ToolRequest,
    ToolCategory,
    ActionType,
    SecurityDecision,
    SecurityDecisionType,
)

def test_tool_request_roundtrip():
    agent = AgentIdentity(name="SerializerAgent")
    original = ToolRequest(
        agent=agent,
        tool_name="filesystem.read",
        tool_category=ToolCategory.FILESYSTEM,
        action=ActionType.READ,
        target="sandbox/public/sample.txt",
        parameters={"encoding": "utf-8"}
    )

    # Dump to dict & JSON
    dumped_dict = original.model_dump(mode="json")
    json_str = original.model_dump_json()

    # Reconstruct from dict & JSON
    reconstructed_from_dict = ToolRequest.model_validate(dumped_dict)
    reconstructed_from_json = ToolRequest.model_validate_json(json_str)

    assert reconstructed_from_dict == original
    assert reconstructed_from_json == original
    assert reconstructed_from_json.agent.name == "SerializerAgent"

def test_full_security_decision_chain_roundtrip():
    agent = AgentIdentity(name="ChainAgent")
    req = ToolRequest(
        agent=agent,
        tool_name="network.send",
        tool_category=ToolCategory.NETWORK,
        action=ActionType.SEND,
        target="https://api.external.com"
    )
    decision = SecurityDecision(
        request_id=req.request_id,
        decision=SecurityDecisionType.ALLOW,
        reason="Approved network call"
    )

    json_req = req.model_dump_json()
    json_dec = decision.model_dump_json()

    restored_req = ToolRequest.model_validate_json(json_req)
    restored_dec = SecurityDecision.model_validate_json(json_dec)

    assert restored_req.request_id == restored_dec.request_id
    assert restored_dec.decision == SecurityDecisionType.ALLOW
