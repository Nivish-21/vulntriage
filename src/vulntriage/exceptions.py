class VulnTriageError(Exception):
    """Base exception for all vulntriage errors."""


class AuditError(VulnTriageError):
    """pip-audit subprocess failed or pip-audit not installed."""


class ParseError(VulnTriageError):
    """Failed to parse pip-audit JSON or Claude response."""


class ContextError(VulnTriageError):
    """Could not read requirements.txt or pyproject.toml."""


class AuthError(VulnTriageError):
    """Invalid or expired Anthropic API key."""
