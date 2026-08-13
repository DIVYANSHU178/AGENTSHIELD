class SecurityEnforcementError(Exception):
    """
    Base domain exception raised when SecurityEnforcementBoundary encounters operational errors.
    """
    pass

class AuthorizationValidationError(SecurityEnforcementError):
    """
    Exception raised when an ExecutionAuthorization fails security validation checks.
    """
    pass

class TamperedRequestError(AuthorizationValidationError):
    """
    Exception raised when a ToolRequest has been modified or tampered with after authorization was issued.
    """
    pass
