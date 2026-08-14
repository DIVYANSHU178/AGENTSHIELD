class ExecutionError(Exception):
    """Base exception for all security execution adapter errors."""
    pass

class ToolNotRegisteredError(ExecutionError):
    """Raised when attempting to execute an unregistered tool."""
    pass

class UnsupportedActionError(ExecutionError):
    """Raised when tool request action is not supported by the registered tool."""
    pass

class ExecutionAuthorizationError(ExecutionError):
    """Raised when execution is attempted without a valid Phase 6 ExecutionAuthorization."""
    pass

class HandlerExecutionError(ExecutionError):
    """Raised when an authorized tool handler fails during execution."""
    pass
