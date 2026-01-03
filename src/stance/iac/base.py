"""
Base classes for Infrastructure as Code (IaC) scanning.

Provides abstract base classes and data structures for IaC parsing
and policy evaluation across different IaC formats.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from stance.models import (
    Finding,
    FindingCollection,
    FindingType,
    FindingStatus,
    Severity,
)

logger = logging.getLogger(__name__)


class IaCFormat(Enum):
    """Supported IaC formats."""

    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    ARM = "arm"
    KUBERNETES = "kubernetes"
    HELM = "helm"
    PULUMI = "pulumi"


@dataclass(frozen=True)
class IaCLocation:
    """
    Location information for an IaC element.

    Attributes:
        file_path: Path to the IaC file
        line_start: Starting line number (1-indexed)
        line_end: Ending line number (1-indexed)
        column_start: Starting column (optional)
        column_end: Ending column (optional)
    """

    file_path: str
    line_start: int
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None

    def __str__(self) -> str:
        """Return a human-readable location string."""
        if self.line_end and self.line_end != self.line_start:
            return f"{self.file_path}:{self.line_start}-{self.line_end}"
        return f"{self.file_path}:{self.line_start}"


@dataclass
class IaCResource:
    """
    Represents a resource defined in an IaC file.

    Attributes:
        resource_type: Type of the resource (e.g., "aws_s3_bucket")
        name: Name/identifier of the resource in the IaC file
        provider: Cloud provider (aws, gcp, azure, kubernetes)
        config: Resource configuration as a dictionary
        location: Location in the source file
        labels: Resource labels/tags if defined
        dependencies: List of resource references this depends on
    """

    resource_type: str
    name: str
    provider: str
    config: dict[str, Any]
    location: IaCLocation
    labels: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)

    @property
    def full_address(self) -> str:
        """Return the full resource address (e.g., aws_s3_bucket.my_bucket)."""
        return f"{self.resource_type}.{self.name}"

    def get_config_value(self, path: str, default: Any = None) -> Any:
        """
        Get a nested configuration value using dot notation.

        Args:
            path: Dot-separated path (e.g., "encryption.enabled")
            default: Default value if path not found

        Returns:
            Configuration value or default
        """
        parts = path.split(".")
        current = self.config

        for part in parts:
            if isinstance(current, dict):
                if part in current:
                    current = current[part]
                else:
                    return default
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return default
            else:
                return default

        return current

    def has_config(self, path: str) -> bool:
        """Check if a configuration path exists."""
        return self.get_config_value(path, _MISSING) is not _MISSING


# Sentinel for missing values
_MISSING = object()


@dataclass
class IaCFile:
    """
    Represents a parsed IaC file.

    Attributes:
        file_path: Path to the file
        format: IaC format type
        resources: List of resources defined in the file
        variables: Variables defined in the file
        outputs: Outputs defined in the file
        locals: Local values defined in the file
        data_sources: Data sources referenced in the file
        modules: Module references in the file
        providers: Provider configurations
        raw_content: Original file content
        parse_errors: Any parsing errors encountered
    """

    file_path: str
    format: IaCFormat
    resources: list[IaCResource] = field(default_factory=list)
    variables: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    locals: dict[str, Any] = field(default_factory=dict)
    data_sources: list[IaCResource] = field(default_factory=list)
    modules: dict[str, Any] = field(default_factory=dict)
    providers: dict[str, Any] = field(default_factory=dict)
    raw_content: str = ""
    parse_errors: list[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Check if parsing had errors."""
        return len(self.parse_errors) > 0

    @property
    def resource_count(self) -> int:
        """Get total number of resources."""
        return len(self.resources)

    def get_resources_by_type(self, resource_type: str) -> list[IaCResource]:
        """Get all resources of a specific type."""
        return [r for r in self.resources if r.resource_type == resource_type]

    def get_resources_by_provider(self, provider: str) -> list[IaCResource]:
        """Get all resources for a specific provider."""
        return [r for r in self.resources if r.provider == provider]


@dataclass
class IaCParseResult:
    """
    Result from parsing IaC files.

    Attributes:
        files: List of parsed IaC files
        total_resources: Total number of resources across all files
        total_errors: Total number of parse errors
        duration_seconds: Time taken to parse
    """

    files: list[IaCFile] = field(default_factory=list)
    total_resources: int = 0
    total_errors: int = 0
    duration_seconds: float = 0.0

    def add_file(self, iac_file: IaCFile) -> None:
        """Add a parsed file to the result."""
        self.files.append(iac_file)
        self.total_resources += iac_file.resource_count
        self.total_errors += len(iac_file.parse_errors)

    def get_all_resources(self) -> Iterator[IaCResource]:
        """Iterate over all resources across all files."""
        for iac_file in self.files:
            yield from iac_file.resources

    def get_resources_by_type(self, resource_type: str) -> list[IaCResource]:
        """Get all resources of a specific type across all files."""
        return [r for r in self.get_all_resources() if r.resource_type == resource_type]


@dataclass
class IaCFinding:
    """
    A security finding in an IaC file.

    Attributes:
        rule_id: Policy rule that triggered
        resource: The resource with the issue
        severity: Finding severity
        title: Short description
        description: Detailed explanation
        remediation: How to fix the issue
        expected_value: What the value should be
        actual_value: What the value actually is
    """

    rule_id: str
    resource: IaCResource
    severity: Severity
    title: str
    description: str
    remediation: str = ""
    expected_value: str | None = None
    actual_value: str | None = None

    def to_finding(self) -> Finding:
        """Convert to a standard Finding object."""
        now = datetime.now(timezone.utc)
        return Finding(
            id=f"iac-{self.rule_id}-{self.resource.full_address}",
            asset_id=f"iac:{self.resource.location.file_path}:{self.resource.full_address}",
            finding_type=FindingType.MISCONFIGURATION,
            severity=self.severity,
            status=FindingStatus.OPEN,
            title=self.title,
            description=f"{self.description}\n\nLocation: {self.resource.location}",
            first_seen=now,
            last_seen=now,
            rule_id=self.rule_id,
            resource_path=self.resource.full_address,
            expected_value=self.expected_value,
            actual_value=self.actual_value,
            compliance_frameworks=[],
            remediation_guidance=self.remediation,
        )


class IaCParser(ABC):
    """
    Abstract base class for IaC parsers.

    All IaC format parsers must inherit from this class and implement
    the parse_file and parse_content methods.
    """

    @property
    @abstractmethod
    def format(self) -> IaCFormat:
        """Return the IaC format this parser handles."""
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> list[str]:
        """Return list of file extensions this parser handles."""
        pass

    @abstractmethod
    def parse_file(self, file_path: str | Path) -> IaCFile:
        """
        Parse an IaC file.

        Args:
            file_path: Path to the file to parse

        Returns:
            Parsed IaCFile object
        """
        pass

    @abstractmethod
    def parse_content(self, content: str, file_path: str = "<string>") -> IaCFile:
        """
        Parse IaC content from a string.

        Args:
            content: The IaC content to parse
            file_path: Virtual file path for error reporting

        Returns:
            Parsed IaCFile object
        """
        pass

    def parse_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> IaCParseResult:
        """
        Parse all matching files in a directory.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            IaCParseResult with all parsed files
        """
        import time

        start_time = time.time()
        result = IaCParseResult()
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.warning(f"Directory does not exist: {directory}")
            return result

        pattern = "**/*" if recursive else "*"

        for ext in self.file_extensions:
            for file_path in dir_path.glob(f"{pattern}{ext}"):
                if file_path.is_file():
                    try:
                        iac_file = self.parse_file(file_path)
                        result.add_file(iac_file)
                    except Exception as e:
                        logger.warning(f"Failed to parse {file_path}: {e}")
                        # Add a file with error
                        error_file = IaCFile(
                            file_path=str(file_path),
                            format=self.format,
                            parse_errors=[str(e)],
                        )
                        result.add_file(error_file)

        result.duration_seconds = time.time() - start_time
        return result

    def can_parse(self, file_path: str | Path) -> bool:
        """Check if this parser can handle the given file."""
        path = Path(file_path)
        return any(path.suffix == ext for ext in self.file_extensions)


class IaCScanner:
    """
    Scans IaC files for security issues.

    Combines parsing with policy evaluation to find security
    misconfigurations in infrastructure code.
    """

    def __init__(
        self,
        parsers: list[IaCParser] | None = None,
        policy_evaluator: Any | None = None,
    ) -> None:
        """
        Initialize the IaC scanner.

        Args:
            parsers: List of IaC parsers to use
            policy_evaluator: Optional policy evaluator instance
        """
        self._parsers: list[IaCParser] = parsers or []
        self._policy_evaluator = policy_evaluator

    def register_parser(self, parser: IaCParser) -> None:
        """Register an IaC parser."""
        self._parsers.append(parser)

    def set_policy_evaluator(self, evaluator: Any) -> None:
        """Set the policy evaluator."""
        self._policy_evaluator = evaluator

    def get_parser_for_file(self, file_path: str | Path) -> IaCParser | None:
        """Get a parser that can handle the given file."""
        for parser in self._parsers:
            if parser.can_parse(file_path):
                return parser
        return None

    def scan_file(self, file_path: str | Path) -> list[IaCFinding]:
        """
        Scan a single IaC file for security issues.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of findings
        """
        parser = self.get_parser_for_file(file_path)
        if parser is None:
            logger.warning(f"No parser available for {file_path}")
            return []

        iac_file = parser.parse_file(file_path)
        return self._evaluate_file(iac_file)

    def scan_directory(
        self,
        directory: str | Path,
        recursive: bool = True,
    ) -> tuple[IaCParseResult, list[IaCFinding]]:
        """
        Scan a directory for IaC security issues.

        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            Tuple of (parse result, findings)
        """
        all_findings: list[IaCFinding] = []
        combined_result = IaCParseResult()

        for parser in self._parsers:
            result = parser.parse_directory(directory, recursive)
            for iac_file in result.files:
                combined_result.add_file(iac_file)
                findings = self._evaluate_file(iac_file)
                all_findings.extend(findings)

        return combined_result, all_findings

    def _evaluate_file(self, iac_file: IaCFile) -> list[IaCFinding]:
        """Evaluate policies against a parsed IaC file."""
        findings: list[IaCFinding] = []

        # Use policy evaluator if available
        if self._policy_evaluator is not None:
            policy_findings = self._policy_evaluator.evaluate_file(iac_file)
            findings.extend(policy_findings)

        # Also run built-in checks
        for resource in iac_file.resources:
            resource_findings = self._check_resource(resource)
            findings.extend(resource_findings)

        return findings

    def _check_resource(self, resource: IaCResource) -> list[IaCFinding]:
        """Run built-in security checks on a resource."""
        findings: list[IaCFinding] = []

        # Check for hardcoded secrets patterns
        secret_findings = self._check_hardcoded_secrets(resource)
        findings.extend(secret_findings)

        return findings

    def _check_hardcoded_secrets(self, resource: IaCResource) -> list[IaCFinding]:
        """Check for hardcoded secrets in resource configuration."""
        import re

        findings: list[IaCFinding] = []

        # Patterns that may indicate hardcoded secrets
        secret_patterns = [
            (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]+['\"]", "password"),
            (r"(?i)(secret|api_key|apikey)\s*=\s*['\"][^'\"]+['\"]", "secret"),
            (r"(?i)(access_key|accesskey)\s*=\s*['\"][A-Z0-9]{16,}['\"]", "access_key"),
            (r"AKIA[0-9A-Z]{16}", "AWS access key"),
        ]

        # Convert config to string for pattern matching
        config_str = str(resource.config)

        for pattern, secret_type in secret_patterns:
            if re.search(pattern, config_str):
                findings.append(IaCFinding(
                    rule_id="iac-hardcoded-secret",
                    resource=resource,
                    severity=Severity.CRITICAL,
                    title=f"Potential hardcoded {secret_type} detected",
                    description=f"The resource configuration may contain a hardcoded {secret_type}. "
                                "Hardcoded secrets pose a security risk and should be stored in a "
                                "secrets manager or passed via environment variables.",
                    remediation=f"Remove the hardcoded {secret_type} and use a secrets manager like "
                                "AWS Secrets Manager, HashiCorp Vault, or environment variables.",
                ))
                break  # Only report one secret finding per resource

        return findings
