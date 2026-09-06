"""
Exceptions and Errors for AgentShield Phase 14 Identity, Authentication & Authorization.
"""

class IdentitySecurityError(Exception):
    """Base class for all identity and authentication security errors."""
    pass


class AuthenticationError(IdentitySecurityError):
    """Raised when an authentication attempt fails."""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when invalid username or password credentials are supplied."""
    pass


class InactiveIdentityError(AuthenticationError):
    """Raised when an inactive or disabled user attempts authentication."""
    pass


class SessionExpiredError(AuthenticationError):
    """Raised when an authentication session has expired."""
    pass


class SessionRevokedError(AuthenticationError):
    """Raised when a revoked session / logged out token is used."""
    pass


class AuthorizationDeniedError(IdentitySecurityError):
    """Raised when an authenticated identity lacks required permissions."""
    pass


class IdentityNotFoundError(IdentitySecurityError):
    """Raised when a requested user identity is not found."""
    pass


class IdentityAlreadyExistsError(IdentitySecurityError):
    """Raised when attempting to create a user with an already existing username/email."""
    pass
