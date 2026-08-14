class SecurityAuditError(Exception):
    """Base exception for all security audit and event lifecycle errors."""
    pass

class InvalidSecurityEventError(SecurityAuditError):
    """Raised when an invalid, corrupted, or malformed SecurityEvent is submitted to the audit trail."""
    pass

class AuditRecordingError(SecurityAuditError):
    """Raised when an error occurs during audit event recording or storage."""
    pass
