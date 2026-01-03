"""
Secrets detector for Mantissa Stance.

Provides deterministic secrets detection in cloud configurations using:
- Pattern-based detection (regex for known secret formats)
- Entropy analysis (for high-entropy strings)
- Context analysis (field names suggesting secrets)

This module generates findings for detected secrets in cloud assets.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime

from stance.models.finding import Finding, FindingType, Severity, FindingStatus
from stance.models.asset import Asset


@dataclass
class SecretMatch:
    """A detected secret match."""

    secret_type: str
    field_path: str
    matched_value: str
    confidence: str  # high, medium, low
    entropy: float | None = None
    line_number: int | None = None


@dataclass
class SecretsResult:
    """Result of secrets detection on an asset."""

    asset_id: str
    secrets_found: int
    matches: list[SecretMatch] = field(default_factory=list)
    scan_duration_seconds: float = 0.0


# Secret patterns organized by type
SECRET_PATTERNS = {
    # AWS Secrets
    "aws_access_key_id": {
        "pattern": r"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key ID",
    },
    "aws_secret_access_key": {
        "pattern": r"(?<![A-Za-z0-9/+])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        "severity": Severity.CRITICAL,
        "description": "AWS Secret Access Key",
        "entropy_threshold": 4.5,  # Require high entropy to reduce false positives
    },
    "aws_session_token": {
        "pattern": r"(?i)aws[_-]?session[_-]?token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        "severity": Severity.HIGH,
        "description": "AWS Session Token",
    },
    # GCP Secrets
    "gcp_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": Severity.HIGH,
        "description": "GCP API Key",
    },
    "gcp_service_account_key": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": Severity.CRITICAL,
        "description": "GCP Service Account Key (JSON)",
    },
    "gcp_private_key": {
        "pattern": r"-----BEGIN (RSA )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "Private Key",
    },
    # Azure Secrets
    "azure_storage_key": {
        "pattern": r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=([A-Za-z0-9/+=]{88})",
        "severity": Severity.CRITICAL,
        "description": "Azure Storage Account Key",
    },
    "azure_connection_string": {
        "pattern": r"(?i)(Server|Data Source)=[^;]+;.*Password=([^;]+)",
        "severity": Severity.HIGH,
        "description": "Azure Connection String with Password",
    },
    "azure_sas_token": {
        "pattern": r"sv=\d{4}-\d{2}-\d{2}&s[a-z]=[^&]+&sig=[A-Za-z0-9%/+=]+",
        "severity": Severity.HIGH,
        "description": "Azure SAS Token",
    },
    # Generic Secrets
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
        "severity": Severity.HIGH,
        "description": "Generic API Key",
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|password|passwd|pwd|token|auth[_-]?key)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
        "severity": Severity.HIGH,
        "description": "Generic Secret/Password",
    },
    "bearer_token": {
        "pattern": r"(?i)bearer\s+([A-Za-z0-9_-]{20,})",
        "severity": Severity.HIGH,
        "description": "Bearer Token",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "severity": Severity.MEDIUM,
        "description": "JWT Token",
    },
    "basic_auth": {
        "pattern": r"(?i)basic\s+([A-Za-z0-9+/]+=*)",
        "severity": Severity.HIGH,
        "description": "Basic Authentication Header",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "Private Key",
    },
    "ssh_private_key": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "description": "SSH Private Key",
    },
    # Database Secrets
    "mysql_connection": {
        "pattern": r"mysql://[^:]+:([^@]+)@",
        "severity": Severity.HIGH,
        "description": "MySQL Connection String with Password",
    },
    "postgres_connection": {
        "pattern": r"postgres(?:ql)?://[^:]+:([^@]+)@",
        "severity": Severity.HIGH,
        "description": "PostgreSQL Connection String with Password",
    },
    "mongodb_connection": {
        "pattern": r"mongodb(?:\+srv)?://[^:]+:([^@]+)@",
        "severity": Severity.HIGH,
        "description": "MongoDB Connection String with Password",
    },
    "redis_connection": {
        "pattern": r"redis://:[^@]+@",
        "severity": Severity.HIGH,
        "description": "Redis Connection String with Password",
    },
    # CI/CD Secrets
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "severity": Severity.HIGH,
        "description": "GitHub Token",
    },
    "gitlab_token": {
        "pattern": r"glpat-[A-Za-z0-9_-]{20,}",
        "severity": Severity.HIGH,
        "description": "GitLab Personal Access Token",
    },
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "severity": Severity.HIGH,
        "description": "NPM Token",
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[A-Za-z0-9-]{10,}",
        "severity": Severity.MEDIUM,
        "description": "Slack Token",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": Severity.MEDIUM,
        "description": "Slack Webhook URL",
    },
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": Severity.HIGH,
        "description": "SendGrid API Key",
    },
    "twilio_api_key": {
        "pattern": r"SK[a-f0-9]{32}",
        "severity": Severity.HIGH,
        "description": "Twilio API Key",
    },
    "stripe_api_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}",
        "severity": Severity.CRITICAL,
        "description": "Stripe API Key",
    },
}

# Field names that suggest secrets (for context analysis)
SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd", "pass",
    "secret", "api_key", "apikey", "api-key",
    "token", "auth_token", "access_token", "refresh_token",
    "private_key", "privatekey", "private-key",
    "credentials", "creds", "credential",
    "connection_string", "connectionstring", "connection-string",
    "database_url", "db_password", "db_pass",
    "aws_secret", "azure_key", "gcp_key",
    "encryption_key", "master_key", "signing_key",
]


class SecretsDetector:
    """
    Detects secrets in cloud configurations.

    Uses a combination of:
    - Pattern matching (regex)
    - Entropy analysis
    - Context analysis (field names)

    This is a deterministic detector (no LLM required).
    """

    def __init__(
        self,
        patterns: dict[str, dict] | None = None,
        min_entropy: float = 3.5,
        scan_environment_vars: bool = True,
        scan_tags: bool = True,
        scan_raw_config: bool = True,
    ):
        """
        Initialize the secrets detector.

        Args:
            patterns: Custom patterns to use (defaults to SECRET_PATTERNS)
            min_entropy: Minimum entropy for high-entropy detection
            scan_environment_vars: Whether to scan environment variables
            scan_tags: Whether to scan resource tags
            scan_raw_config: Whether to scan raw configuration
        """
        self._patterns = patterns or SECRET_PATTERNS
        self._min_entropy = min_entropy
        self._scan_env_vars = scan_environment_vars
        self._scan_tags = scan_tags
        self._scan_raw_config = scan_raw_config

    def detect_in_asset(self, asset: Asset) -> SecretsResult:
        """
        Detect secrets in an asset's configuration.

        Args:
            asset: Asset to scan

        Returns:
            SecretsResult with detected secrets
        """
        import time
        start_time = time.time()

        matches: list[SecretMatch] = []

        # Scan raw configuration
        if self._scan_raw_config and asset.raw_config:
            config_matches = self._scan_dict(asset.raw_config, "raw_config")
            matches.extend(config_matches)

        # Scan tags
        if self._scan_tags and asset.tags:
            for key, value in asset.tags.items():
                tag_matches = self._scan_string(value, f"tags.{key}")
                matches.extend(tag_matches)
                # Also check if tag key suggests a secret
                if self._is_sensitive_field_name(key):
                    tag_matches = self._scan_for_high_entropy(
                        value, f"tags.{key}"
                    )
                    matches.extend(tag_matches)

        duration = time.time() - start_time

        return SecretsResult(
            asset_id=asset.id,
            secrets_found=len(matches),
            matches=matches,
            scan_duration_seconds=duration,
        )

    def detect_in_text(self, text: str, source: str = "text") -> list[SecretMatch]:
        """
        Detect secrets in a text string.

        Args:
            text: Text to scan
            source: Source identifier for the text

        Returns:
            List of SecretMatch objects
        """
        return self._scan_string(text, source)

    def detect_in_dict(
        self, data: dict[str, Any], source: str = "config"
    ) -> list[SecretMatch]:
        """
        Detect secrets in a dictionary.

        Args:
            data: Dictionary to scan
            source: Source identifier

        Returns:
            List of SecretMatch objects
        """
        return self._scan_dict(data, source)

    def generate_findings(
        self,
        asset: Asset,
        result: SecretsResult,
    ) -> list[Finding]:
        """
        Generate findings from secrets detection results.

        Args:
            asset: Asset that was scanned
            result: Secrets detection result

        Returns:
            List of Finding objects
        """
        findings = []
        now = datetime.now()

        for match in result.matches:
            # Get severity from pattern or default to HIGH
            pattern_info = self._patterns.get(match.secret_type, {})
            severity = pattern_info.get("severity", Severity.HIGH)

            # Create finding
            finding = Finding(
                id=self._generate_finding_id(asset.id, match),
                asset_id=asset.id,
                finding_type=FindingType.MISCONFIGURATION,
                severity=severity,
                status=FindingStatus.OPEN,
                title=f"Exposed Secret: {pattern_info.get('description', match.secret_type)}",
                description=(
                    f"A potential secret of type '{match.secret_type}' was detected "
                    f"in the field '{match.field_path}'. This could expose sensitive "
                    f"credentials if the configuration is logged or accessible."
                ),
                first_seen=now,
                last_seen=now,
                rule_id=f"secrets-{match.secret_type}",
                resource_path=match.field_path,
                actual_value=self._redact_value(match.matched_value),
                expected_value="No secrets in configuration",
                remediation_guidance=(
                    "1. Rotate the exposed credential immediately\n"
                    "2. Use a secrets manager (AWS Secrets Manager, Azure Key Vault, "
                    "GCP Secret Manager) instead of hardcoding secrets\n"
                    "3. Reference secrets via environment variables from secrets manager\n"
                    "4. Review access logs for any unauthorized usage"
                ),
            )
            findings.append(finding)

        return findings

    def _scan_dict(
        self, data: dict[str, Any], prefix: str = ""
    ) -> list[SecretMatch]:
        """
        Recursively scan a dictionary for secrets.

        Args:
            data: Dictionary to scan
            prefix: Path prefix for field names

        Returns:
            List of SecretMatch objects
        """
        matches: list[SecretMatch] = []

        for key, value in data.items():
            field_path = f"{prefix}.{key}" if prefix else key

            if isinstance(value, str):
                # Scan the string value
                string_matches = self._scan_string(value, field_path)
                matches.extend(string_matches)

                # Check if field name suggests a secret
                if self._is_sensitive_field_name(key):
                    entropy_matches = self._scan_for_high_entropy(
                        value, field_path
                    )
                    # Avoid duplicates
                    for m in entropy_matches:
                        if not any(
                            em.field_path == m.field_path and
                            em.secret_type == m.secret_type
                            for em in matches
                        ):
                            matches.append(m)

            elif isinstance(value, dict):
                # Recurse into nested dictionary
                nested_matches = self._scan_dict(value, field_path)
                matches.extend(nested_matches)

            elif isinstance(value, list):
                # Scan list items
                for i, item in enumerate(value):
                    item_path = f"{field_path}[{i}]"
                    if isinstance(item, str):
                        string_matches = self._scan_string(item, item_path)
                        matches.extend(string_matches)
                    elif isinstance(item, dict):
                        nested_matches = self._scan_dict(item, item_path)
                        matches.extend(nested_matches)

        return matches

    def _scan_string(self, text: str, field_path: str) -> list[SecretMatch]:
        """
        Scan a string for secrets using patterns.

        Args:
            text: String to scan
            field_path: Field path for context

        Returns:
            List of SecretMatch objects
        """
        matches: list[SecretMatch] = []

        for secret_type, pattern_info in self._patterns.items():
            pattern = pattern_info["pattern"]
            try:
                regex_matches = list(re.finditer(pattern, text))
                for regex_match in regex_matches:
                    matched_value = regex_match.group(0)

                    # Check entropy threshold if specified
                    entropy_threshold = pattern_info.get("entropy_threshold")
                    if entropy_threshold:
                        entropy = self._calculate_entropy(matched_value)
                        if entropy < entropy_threshold:
                            continue
                    else:
                        entropy = None

                    matches.append(
                        SecretMatch(
                            secret_type=secret_type,
                            field_path=field_path,
                            matched_value=matched_value,
                            confidence="high",
                            entropy=entropy,
                        )
                    )
            except re.error:
                # Invalid regex pattern
                continue

        return matches

    def _scan_for_high_entropy(
        self, text: str, field_path: str
    ) -> list[SecretMatch]:
        """
        Scan for high-entropy strings that might be secrets.

        Args:
            text: String to analyze
            field_path: Field path for context

        Returns:
            List of SecretMatch objects
        """
        matches: list[SecretMatch] = []

        # Only analyze strings of reasonable length
        if len(text) < 8 or len(text) > 1000:
            return matches

        entropy = self._calculate_entropy(text)

        if entropy >= self._min_entropy:
            matches.append(
                SecretMatch(
                    secret_type="high_entropy_string",
                    field_path=field_path,
                    matched_value=text,
                    confidence="medium",
                    entropy=entropy,
                )
            )

        return matches

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            text: String to analyze

        Returns:
            Entropy value (higher = more random)
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_sensitive_field_name(self, field_name: str) -> bool:
        """
        Check if a field name suggests it might contain a secret.

        Args:
            field_name: Field name to check

        Returns:
            True if field name suggests a secret
        """
        lower_name = field_name.lower()
        for sensitive in SENSITIVE_FIELD_NAMES:
            if sensitive in lower_name:
                return True
        return False

    def _generate_finding_id(self, asset_id: str, match: SecretMatch) -> str:
        """
        Generate a deterministic finding ID.

        Args:
            asset_id: Asset ID
            match: Secret match

        Returns:
            Finding ID
        """
        import hashlib
        content = f"{asset_id}:{match.secret_type}:{match.field_path}"
        hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"secrets-{hash_val}"

    def _redact_value(self, value: str, visible_chars: int = 4) -> str:
        """
        Redact a secret value for safe display.

        Args:
            value: Value to redact
            visible_chars: Number of characters to show at start/end

        Returns:
            Redacted value
        """
        if len(value) <= visible_chars * 2:
            return "*" * len(value)

        return f"{value[:visible_chars]}{'*' * (len(value) - visible_chars * 2)}{value[-visible_chars:]}"


def create_secrets_detector(
    min_entropy: float = 3.5,
    scan_environment_vars: bool = True,
    scan_tags: bool = True,
    scan_raw_config: bool = True,
) -> SecretsDetector:
    """
    Create a SecretsDetector with specified configuration.

    Args:
        min_entropy: Minimum entropy for high-entropy detection
        scan_environment_vars: Whether to scan environment variables
        scan_tags: Whether to scan resource tags
        scan_raw_config: Whether to scan raw configuration

    Returns:
        Configured SecretsDetector instance
    """
    return SecretsDetector(
        min_entropy=min_entropy,
        scan_environment_vars=scan_environment_vars,
        scan_tags=scan_tags,
        scan_raw_config=scan_raw_config,
    )


def scan_assets_for_secrets(
    assets: list[Asset],
    detector: SecretsDetector | None = None,
) -> tuple[list[SecretsResult], list[Finding]]:
    """
    Scan multiple assets for secrets.

    Args:
        assets: List of assets to scan
        detector: Optional SecretsDetector instance

    Returns:
        Tuple of (results, findings)
    """
    if detector is None:
        detector = SecretsDetector()

    results: list[SecretsResult] = []
    all_findings: list[Finding] = []

    for asset in assets:
        result = detector.detect_in_asset(asset)
        results.append(result)

        if result.secrets_found > 0:
            findings = detector.generate_findings(asset, result)
            all_findings.extend(findings)

    return results, all_findings
