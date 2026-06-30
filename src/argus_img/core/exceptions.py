class ArgusError(Exception):
    """Base exception for expected ARGUS-IMG failures."""


class IntakeRejected(ArgusError):
    """Raised when input cannot safely enter the raster pipeline."""


class ArtifactAccessDenied(ArgusError):
    """Raised when a caller tries to access a quarantined or unknown artifact."""


class ArtifactNotReleased(ArtifactAccessDenied):
    """Raised when an existing artifact lacks a release grant."""


class ConfigurationError(ArgusError):
    """Raised for invalid local configuration or rule bundles."""


class OfflineGuardError(ArgusError):
    """Raised when a runtime path would violate offline execution constraints."""


class ResourceLimitExceeded(ArgusError):
    """Raised when a scan exceeds a configured resource budget."""


class ArtifactIntegrityError(ArgusError):
    """Raised when a stored artifact fails re-verification (wrong content, symlink, etc.)."""
