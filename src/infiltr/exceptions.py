"""Custom exception classes for infiltr."""


class InfiltrError(Exception):
    """Base exception for all infiltr errors."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class TargetConnectionError(InfiltrError):
    """Raised when infiltr cannot connect to the target LLM endpoint."""

    def __init__(self, endpoint: str, reason: str) -> None:
        self.endpoint = endpoint
        self.reason = reason
        super().__init__(f"Failed to connect to target at {endpoint}: {reason}")


class TargetResponseError(InfiltrError):
    """Raised when the target returns an unexpected response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"Target returned HTTP {status_code}: {body[:200]}")


class AttackGenerationError(InfiltrError):
    """Raised when the attack generator fails to produce a valid prompt."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Attack generation failed: {reason}")


class PolicyError(InfiltrError):
    """Raised when the RL policy network encounters an error."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Policy network error: {reason}")


class TaxonomyError(InfiltrError):
    """Raised when ATLAS taxonomy data is missing or malformed."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"ATLAS taxonomy error: {reason}")


class ReportGenerationError(InfiltrError):
    """Raised when report generation fails."""

    def __init__(self, format_name: str, reason: str) -> None:
        self.format_name = format_name
        super().__init__(f"Failed to generate {format_name} report: {reason}")


class ConfigurationError(InfiltrError):
    """Raised when infiltr is misconfigured."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        super().__init__(f"Configuration error in '{field}': {reason}")
