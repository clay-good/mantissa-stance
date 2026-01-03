"""
Data sanitizer for Mantissa Stance.

Provides privacy protection by sanitizing sensitive data before
sending to LLM providers. This ensures no secrets, credentials,
or PII are leaked to external services.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SanitizationResult:
    """Result of data sanitization."""

    sanitized_text: str
    redactions_made: int
    redaction_types: list[str]
    mapping: dict[str, str] = field(default_factory=dict)


class DataSanitizer:
    """
    Sanitizes sensitive data before sending to LLM providers.

    Detects and redacts:
    - AWS access keys and secret keys
    - API keys and tokens
    - Passwords and credentials
    - Email addresses
    - IP addresses (optional)
    - Account IDs (optional)
    - ARNs (partial redaction)
    """

    # Patterns for sensitive data detection
    PATTERNS = {
        "aws_access_key": (
            r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
            "[REDACTED_AWS_ACCESS_KEY]",
        ),
        "aws_secret_key": (
            r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            "[REDACTED_AWS_SECRET_KEY]",
        ),
        "generic_api_key": (
            r"(?i)(api[_-]?key|apikey|api[_-]?token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{20,})[\"']?",
            r"\1=[REDACTED_API_KEY]",
        ),
        "bearer_token": (
            r"(?i)(bearer\s+)([A-Za-z0-9_\-\.]{20,})",
            r"\1[REDACTED_BEARER_TOKEN]",
        ),
        "password": (
            r"(?i)(password|passwd|pwd|secret)[\"']?\s*[:=]\s*[\"']?([^\s\"']{8,})[\"']?",
            r"\1=[REDACTED_PASSWORD]",
        ),
        "private_key": (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
        ),
        "jwt_token": (
            r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "[REDACTED_JWT_TOKEN]",
        ),
    }

    # Optional patterns (can be enabled/disabled)
    OPTIONAL_PATTERNS = {
        "email": (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[REDACTED_EMAIL]",
        ),
        "ipv4": (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "[REDACTED_IP]",
        ),
        "aws_account_id": (
            r"\b[0-9]{12}\b",
            "[REDACTED_ACCOUNT_ID]",
        ),
    }

    def __init__(
        self,
        redact_emails: bool = False,
        redact_ips: bool = False,
        redact_account_ids: bool = False,
        preserve_structure: bool = True,
    ):
        """
        Initialize the data sanitizer.

        Args:
            redact_emails: Whether to redact email addresses
            redact_ips: Whether to redact IP addresses
            redact_account_ids: Whether to redact AWS account IDs
            preserve_structure: Whether to use consistent replacement tokens
        """
        self._redact_emails = redact_emails
        self._redact_ips = redact_ips
        self._redact_account_ids = redact_account_ids
        self._preserve_structure = preserve_structure

        # Build active patterns
        self._patterns = dict(self.PATTERNS)
        if redact_emails:
            self._patterns["email"] = self.OPTIONAL_PATTERNS["email"]
        if redact_ips:
            self._patterns["ipv4"] = self.OPTIONAL_PATTERNS["ipv4"]
        if redact_account_ids:
            self._patterns["aws_account_id"] = self.OPTIONAL_PATTERNS["aws_account_id"]

    def sanitize(self, text: str) -> str:
        """
        Sanitize text by redacting sensitive data.

        Args:
            text: Text to sanitize

        Returns:
            Sanitized text with sensitive data redacted
        """
        result = self.sanitize_with_details(text)
        return result.sanitized_text

    def sanitize_with_details(self, text: str) -> SanitizationResult:
        """
        Sanitize text and return detailed results.

        Args:
            text: Text to sanitize

        Returns:
            SanitizationResult with sanitized text and metadata
        """
        sanitized = text
        redactions = 0
        types_found: list[str] = []
        mapping: dict[str, str] = {}

        for pattern_name, (pattern, replacement) in self._patterns.items():
            matches = list(re.finditer(pattern, sanitized))
            if matches:
                types_found.append(pattern_name)
                redactions += len(matches)

                if self._preserve_structure:
                    # Create consistent tokens for each unique match
                    for match in matches:
                        original = match.group(0)
                        if original not in mapping:
                            token = self._create_token(pattern_name, original)
                            mapping[original] = token

                    # Replace using mapping
                    for original, token in mapping.items():
                        sanitized = sanitized.replace(original, token)
                else:
                    # Simple replacement
                    sanitized = re.sub(pattern, replacement, sanitized)

        return SanitizationResult(
            sanitized_text=sanitized,
            redactions_made=redactions,
            redaction_types=types_found,
            mapping=mapping,
        )

    def sanitize_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Recursively sanitize a dictionary.

        Args:
            data: Dictionary to sanitize

        Returns:
            Sanitized dictionary copy
        """
        return self._sanitize_value(data)

    def desanitize(
        self,
        text: str,
        mapping: dict[str, str],
    ) -> str:
        """
        Restore original values using a mapping.

        Args:
            text: Sanitized text
            mapping: Original to token mapping

        Returns:
            Text with original values restored
        """
        result = text
        # Reverse the mapping
        reverse_mapping = {v: k for k, v in mapping.items()}
        for token, original in reverse_mapping.items():
            result = result.replace(token, original)
        return result

    def is_sensitive(self, text: str) -> bool:
        """
        Check if text contains sensitive data.

        Args:
            text: Text to check

        Returns:
            True if sensitive data is detected
        """
        for pattern, _ in self._patterns.values():
            if re.search(pattern, text):
                return True
        return False

    def get_sensitive_types(self, text: str) -> list[str]:
        """
        Get list of sensitive data types found in text.

        Args:
            text: Text to analyze

        Returns:
            List of sensitive data type names
        """
        types_found = []
        for pattern_name, (pattern, _) in self._patterns.items():
            if re.search(pattern, text):
                types_found.append(pattern_name)
        return types_found

    def _sanitize_value(self, value: Any) -> Any:
        """
        Recursively sanitize a value.

        Args:
            value: Value to sanitize

        Returns:
            Sanitized value
        """
        if isinstance(value, str):
            return self.sanitize(value)
        elif isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        else:
            return value

    def _create_token(self, pattern_name: str, original: str) -> str:
        """
        Create a consistent replacement token.

        Args:
            pattern_name: Name of the pattern matched
            original: Original matched text

        Returns:
            Replacement token
        """
        # Create a short hash of the original
        hash_val = hashlib.sha256(original.encode()).hexdigest()[:8]
        return f"[REDACTED_{pattern_name.upper()}_{hash_val}]"


def create_sanitizer(
    redact_emails: bool = False,
    redact_ips: bool = False,
    redact_account_ids: bool = False,
) -> DataSanitizer:
    """
    Create a DataSanitizer with specified configuration.

    Args:
        redact_emails: Whether to redact email addresses
        redact_ips: Whether to redact IP addresses
        redact_account_ids: Whether to redact AWS account IDs

    Returns:
        Configured DataSanitizer instance
    """
    return DataSanitizer(
        redact_emails=redact_emails,
        redact_ips=redact_ips,
        redact_account_ids=redact_account_ids,
    )
