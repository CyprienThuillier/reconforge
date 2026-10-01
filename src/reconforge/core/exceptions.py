"""Custom type for input error"""


class ReconForgeValidationError(Exception):
    """Base exception for all validation errors raised by validators.py."""


class InvalidTargetError(ReconForgeValidationError):
    """Raised when the target is not a valid hostname or IP address."""


class InvalidPortRangeError(ReconForgeValidationError):
    """Raised when the port range format is invalid or out of bounds (1-65535)."""


class InvalidWordlistError(ReconForgeValidationError):
    """Raised when the wordlist file is missing, not a file, or empty."""


class InvalidOutputError(ReconForgeValidationError):
    """Raised when the output path is not writable (missing/invalid parent dir)."""


class InvalidUrlError(ReconForgeValidationError):
    """Raised when a web target is not a valid http(s) URL."""


class InvalidPathError(ReconForgeValidationError):
    """Raised when an HTTP path to probe is empty or malformed."""


class InvalidCveError(ReconForgeValidationError):
    """Raised when an unknown CVE scanner id is requested."""
