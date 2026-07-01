"""
Exceptions for the tempid package.
"""


class TempIDError(Exception):
    """Base exception for all tempid errors."""

    pass


class TempIDExpiredError(TempIDError):
    """Raised when attempting to decode a token that has already expired."""

    pass


class TempIDTamperedError(TempIDError):
    """Raised when the token signature is invalid or tampered with."""

    pass


class TempIDFormatError(TempIDError):
    """Raised when the token format is unrecognized or malformed."""

    pass


class TempIDRevokedError(TempIDError):
    """Raised when the token has been explicitly revoked."""

    pass


class TempIDPayloadTooLargeError(TempIDError):
    """Raised when the payload exceeds the maximum allowed size (512 bytes)."""

    pass
