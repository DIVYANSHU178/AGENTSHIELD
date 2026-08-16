class ApprovalError(Exception):
    """Base exception for all approval workflow errors."""
    pass

class ApprovalNotFoundError(ApprovalError):
    """Raised when an approval ID cannot be found."""
    pass

class InvalidApprovalStateTransitionError(ApprovalError):
    """Raised when attempting an invalid lifecycle transition or double resolution."""
    pass

class ApprovalExpiredError(ApprovalError):
    """Raised when attempting to resolve or use an expired approval request."""
    pass

class ApprovalCancelledError(ApprovalError):
    """Raised when attempting to resolve or use a cancelled approval request."""
    pass

class ApprovalRejectedError(ApprovalError):
    """Raised when attempting to execute with a rejected approval."""
    pass

class ApprovalTamperingError(ApprovalError):
    """Raised when request content does not match the bound approval fingerprint."""
    pass

class ApprovalPolicyViolationError(ApprovalError):
    """Raised when attempting to create approval for an invalid decision (e.g. ALLOW or BLOCK)."""
    pass

class ApprovalAuthorizationError(ApprovalError):
    """Raised when cryptographic authorization cannot be issued for an approved request."""
    pass
