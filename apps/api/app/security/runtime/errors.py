class AgentRuntimeError(Exception):
    """Base exception for Agent Runtime Integration errors."""
    pass

class RuntimeValidationError(AgentRuntimeError):
    """Raised when an incoming runtime request is invalid or malformed."""
    pass

class RuntimeExecutionDeniedError(AgentRuntimeError):
    """Raised when runtime execution is denied by security boundary policy."""
    pass

class RuntimeSecurityBypassError(AgentRuntimeError):
    """Raised when an attempt to bypass security gateway, boundary, or sandbox is detected."""
    pass

class RuntimeOrchestrationError(AgentRuntimeError):
    """Raised when runtime orchestration encounters an unrecoverable failure."""
    pass
