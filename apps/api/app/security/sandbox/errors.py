class SandboxError(Exception):
    """Base exception for all sandboxed execution boundary errors."""
    pass

class SandboxAuthorizationError(SandboxError):
    """Raised when sandbox execution is attempted without a valid ExecutionAuthorization."""
    pass

class SandboxTimeoutError(SandboxError):
    """Raised when a sandboxed tool handler exceeds the configured execution timeout."""
    pass

class SandboxContainmentError(SandboxError):
    """Raised when a containment or policy limit violation occurs."""
    pass

class SandboxStartupError(SandboxError):
    """Raised when the sandbox environment fails to initialize."""
    pass
