"""
Finding data model for Mantissa Stance.

This module defines the Finding class representing security findings
(both CSPM misconfigurations and vulnerabilities) and FindingCollection
for managing groups of findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Iterator


class FindingType(Enum):
    """Type of security finding."""

    MISCONFIGURATION = "misconfiguration"
    VULNERABILITY = "vulnerability"


class Severity(Enum):
    """Severity level of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        """
        Create Severity from string value.

        Args:
            value: String representation (case-insensitive)

        Returns:
            Matching Severity enum value

        Raises:
            ValueError: If value is not a valid severity
        """
        value_lower = value.lower()
        for severity in cls:
            if severity.value == value_lower:
                return severity
        raise ValueError(f"Invalid severity: {value}")


class FindingStatus(Enum):
    """Status of a finding."""

    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"

    @classmethod
    def from_string(cls, value: str) -> FindingStatus:
        """
        Create FindingStatus from string value.

        Args:
            value: String representation (case-insensitive)

        Returns:
            Matching FindingStatus enum value

        Raises:
            ValueError: If value is not a valid status
        """
        value_lower = value.lower()
        for status in cls:
            if status.value == value_lower:
                return status
        raise ValueError(f"Invalid status: {value}")


@dataclass(frozen=True)
class Finding:
    """
    Represents a security finding (misconfiguration or vulnerability).

    Findings are generated when a policy evaluation fails or when
    vulnerability data is collected from security services. This is
    a unified model that handles both CSPM and vulnerability findings.

    Attributes:
        id: Unique finding identifier
        asset_id: Reference to the affected asset
        finding_type: Type of finding (misconfiguration or vulnerability)
        severity: Severity level
        status: Current status of the finding
        title: Short description of the finding
        description: Detailed explanation
        first_seen: When the finding was first detected
        last_seen: When the finding was last observed
        rule_id: Policy rule that triggered (for misconfigurations)
        resource_path: Path to non-compliant field (for misconfigurations)
        expected_value: Expected configuration value
        actual_value: Actual configuration value found
        cve_id: CVE identifier (for vulnerabilities)
        cvss_score: CVSS score (for vulnerabilities)
        package_name: Affected package name (for vulnerabilities)
        installed_version: Currently installed version
        fixed_version: Version that fixes the vulnerability
        compliance_frameworks: List of compliance framework controls
        remediation_guidance: Steps to remediate the finding
    """

    # Required fields
    id: str
    asset_id: str
    finding_type: FindingType
    severity: Severity
    status: FindingStatus
    title: str
    description: str

    # Timestamp fields
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # CSPM-specific fields
    rule_id: str | None = None
    resource_path: str | None = None
    expected_value: str | None = None
    actual_value: str | None = None

    # Vulnerability-specific fields
    cve_id: str | None = None
    cvss_score: float | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None

    # Compliance and remediation
    compliance_frameworks: list[str] = field(default_factory=list)
    remediation_guidance: str = ""

    def is_critical(self) -> bool:
        """
        Check if this finding has critical severity.

        Returns:
            True if severity is CRITICAL
        """
        return self.severity == Severity.CRITICAL

    def is_high_or_critical(self) -> bool:
        """
        Check if this finding has high or critical severity.

        Returns:
            True if severity is HIGH or CRITICAL
        """
        return self.severity in (Severity.CRITICAL, Severity.HIGH)

    def is_vulnerability(self) -> bool:
        """
        Check if this is a vulnerability finding.

        Returns:
            True if finding_type is VULNERABILITY
        """
        return self.finding_type == FindingType.VULNERABILITY

    def is_misconfiguration(self) -> bool:
        """
        Check if this is a misconfiguration finding.

        Returns:
            True if finding_type is MISCONFIGURATION
        """
        return self.finding_type == FindingType.MISCONFIGURATION

    def is_open(self) -> bool:
        """
        Check if this finding is still open.

        Returns:
            True if status is OPEN
        """
        return self.status == FindingStatus.OPEN

    def has_fix_available(self) -> bool:
        """
        Check if a fix is available (for vulnerabilities).

        Returns:
            True if fixed_version is set
        """
        return self.fixed_version is not None and self.fixed_version != ""

    def to_dict(self) -> dict[str, Any]:
        """
        Convert finding to dictionary representation.

        Returns:
            Dictionary with all finding fields
        """
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "title": self.title,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "rule_id": self.rule_id,
            "resource_path": self.resource_path,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "compliance_frameworks": self.compliance_frameworks,
            "remediation_guidance": self.remediation_guidance,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """
        Create a Finding from a dictionary.

        Args:
            data: Dictionary with finding fields

        Returns:
            New Finding instance
        """
        first_seen = None
        if data.get("first_seen"):
            first_seen = datetime.fromisoformat(data["first_seen"])

        last_seen = None
        if data.get("last_seen"):
            last_seen = datetime.fromisoformat(data["last_seen"])

        # Handle finding_type
        finding_type_val = data.get("finding_type", "misconfiguration")
        if isinstance(finding_type_val, str):
            finding_type = FindingType(finding_type_val)
        else:
            finding_type = finding_type_val

        # Handle severity
        severity_val = data.get("severity", "medium")
        if isinstance(severity_val, str):
            severity = Severity.from_string(severity_val)
        else:
            severity = severity_val

        # Handle status
        status_val = data.get("status", "open")
        if isinstance(status_val, str):
            status = FindingStatus.from_string(status_val)
        else:
            status = status_val

        return cls(
            id=data["id"],
            asset_id=data.get("asset_id", ""),
            finding_type=finding_type,
            severity=severity,
            status=status,
            title=data.get("title", ""),
            description=data.get("description", ""),
            first_seen=first_seen,
            last_seen=last_seen,
            rule_id=data.get("rule_id"),
            resource_path=data.get("resource_path"),
            expected_value=data.get("expected_value"),
            actual_value=data.get("actual_value"),
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            package_name=data.get("package_name"),
            installed_version=data.get("installed_version"),
            fixed_version=data.get("fixed_version"),
            compliance_frameworks=data.get("compliance_frameworks", []),
            remediation_guidance=data.get("remediation_guidance", ""),
        )


class FindingCollection:
    """
    A collection of Finding objects with filtering capabilities.

    Provides methods to filter findings by various criteria,
    count by severity, and convert to different formats.

    Attributes:
        findings: List of Finding objects in this collection
    """

    def __init__(self, findings: list[Finding] | None = None) -> None:
        """
        Initialize collection with optional list of findings.

        Args:
            findings: Initial list of findings (defaults to empty list)
        """
        self._findings: list[Finding] = findings if findings is not None else []

    @property
    def findings(self) -> list[Finding]:
        """Get the list of findings."""
        return self._findings

    def __len__(self) -> int:
        """Return number of findings in collection."""
        return len(self._findings)

    def __iter__(self) -> Iterator[Finding]:
        """Iterate over findings in collection."""
        return iter(self._findings)

    def __getitem__(self, index: int) -> Finding:
        """Get finding by index."""
        return self._findings[index]

    def add(self, finding: Finding) -> None:
        """
        Add a finding to the collection.

        Args:
            finding: Finding to add
        """
        self._findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        """
        Add multiple findings to the collection.

        Args:
            findings: List of findings to add
        """
        self._findings.extend(findings)

    def filter_by_severity(self, severity: Severity) -> FindingCollection:
        """
        Filter findings by severity.

        Args:
            severity: Severity level to filter by

        Returns:
            New FindingCollection containing only matching findings
        """
        filtered = [f for f in self._findings if f.severity == severity]
        return FindingCollection(filtered)

    def filter_by_status(self, status: FindingStatus) -> FindingCollection:
        """
        Filter findings by status.

        Args:
            status: Status to filter by

        Returns:
            New FindingCollection containing only matching findings
        """
        filtered = [f for f in self._findings if f.status == status]
        return FindingCollection(filtered)

    def filter_by_type(self, finding_type: FindingType) -> FindingCollection:
        """
        Filter findings by type.

        Args:
            finding_type: Finding type to filter by

        Returns:
            New FindingCollection containing only matching findings
        """
        filtered = [f for f in self._findings if f.finding_type == finding_type]
        return FindingCollection(filtered)

    def filter_by_asset(self, asset_id: str) -> FindingCollection:
        """
        Filter findings by asset ID.

        Args:
            asset_id: Asset ID to filter by

        Returns:
            New FindingCollection containing only matching findings
        """
        filtered = [f for f in self._findings if f.asset_id == asset_id]
        return FindingCollection(filtered)

    def filter_by_rule(self, rule_id: str) -> FindingCollection:
        """
        Filter findings by rule ID.

        Args:
            rule_id: Rule ID to filter by

        Returns:
            New FindingCollection containing only matching findings
        """
        filtered = [f for f in self._findings if f.rule_id == rule_id]
        return FindingCollection(filtered)

    def filter_critical(self) -> FindingCollection:
        """
        Filter to only critical findings.

        Returns:
            New FindingCollection containing only critical findings
        """
        return self.filter_by_severity(Severity.CRITICAL)

    def filter_open(self) -> FindingCollection:
        """
        Filter to only open findings.

        Returns:
            New FindingCollection containing only open findings
        """
        return self.filter_by_status(FindingStatus.OPEN)

    def filter_vulnerabilities(self) -> FindingCollection:
        """
        Filter to only vulnerability findings.

        Returns:
            New FindingCollection containing only vulnerabilities
        """
        return self.filter_by_type(FindingType.VULNERABILITY)

    def filter_misconfigurations(self) -> FindingCollection:
        """
        Filter to only misconfiguration findings.

        Returns:
            New FindingCollection containing only misconfigurations
        """
        return self.filter_by_type(FindingType.MISCONFIGURATION)

    def get_by_id(self, finding_id: str) -> Finding | None:
        """
        Get a finding by its ID.

        Args:
            finding_id: Finding ID to find

        Returns:
            Finding if found, None otherwise
        """
        for finding in self._findings:
            if finding.id == finding_id:
                return finding
        return None

    def count_by_severity(self) -> dict[Severity, int]:
        """
        Count findings grouped by severity.

        Returns:
            Dictionary mapping Severity to count
        """
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for finding in self._findings:
            counts[finding.severity] += 1
        return counts

    def count_by_severity_dict(self) -> dict[str, int]:
        """
        Count findings grouped by severity (string keys).

        Returns:
            Dictionary mapping severity string to count
        """
        counts = self.count_by_severity()
        return {severity.value: count for severity, count in counts.items()}

    def count_by_status(self) -> dict[FindingStatus, int]:
        """
        Count findings grouped by status.

        Returns:
            Dictionary mapping FindingStatus to count
        """
        counts: dict[FindingStatus, int] = {s: 0 for s in FindingStatus}
        for finding in self._findings:
            counts[finding.status] += 1
        return counts

    def count_by_type(self) -> dict[FindingType, int]:
        """
        Count findings grouped by type.

        Returns:
            Dictionary mapping FindingType to count
        """
        counts: dict[FindingType, int] = {t: 0 for t in FindingType}
        for finding in self._findings:
            counts[finding.finding_type] += 1
        return counts

    def to_list(self) -> list[dict[str, Any]]:
        """
        Convert collection to list of dictionaries.

        Returns:
            List of finding dictionaries
        """
        return [finding.to_dict() for finding in self._findings]

    def to_json(self) -> str:
        """
        Convert collection to JSON string.

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_list(), indent=2, default=str)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> FindingCollection:
        """
        Create collection from list of dictionaries.

        Args:
            data: List of finding dictionaries

        Returns:
            New FindingCollection
        """
        findings = [Finding.from_dict(item) for item in data]
        return cls(findings)

    def merge(self, other: FindingCollection) -> FindingCollection:
        """
        Merge with another collection.

        Args:
            other: Another FindingCollection to merge

        Returns:
            New FindingCollection with findings from both collections
        """
        return FindingCollection(self._findings + other._findings)
