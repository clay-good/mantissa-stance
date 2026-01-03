"""
Base classes for container image scanning.

This module provides the abstract base class and data models for
container image vulnerability scanning.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.models import Finding, FindingType, FindingStatus, Severity

logger = logging.getLogger(__name__)


class VulnerabilitySeverity(Enum):
    """Severity levels for vulnerabilities."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_string(cls, value: str) -> "VulnerabilitySeverity":
        """Convert string to severity enum."""
        value_upper = value.upper().strip()
        try:
            return cls(value_upper)
        except ValueError:
            return cls.UNKNOWN

    def to_stance_severity(self) -> Severity:
        """Convert to Stance Severity enum."""
        mapping = {
            VulnerabilitySeverity.CRITICAL: Severity.CRITICAL,
            VulnerabilitySeverity.HIGH: Severity.HIGH,
            VulnerabilitySeverity.MEDIUM: Severity.MEDIUM,
            VulnerabilitySeverity.LOW: Severity.LOW,
            VulnerabilitySeverity.UNKNOWN: Severity.INFO,
        }
        return mapping.get(self, Severity.INFO)


@dataclass
class Vulnerability:
    """Represents a single vulnerability in a container image."""

    # Core identification
    vulnerability_id: str  # CVE-2021-12345, GHSA-xxx, etc.
    package_name: str
    installed_version: str

    # Severity and scoring
    severity: VulnerabilitySeverity
    cvss_score: float | None = None
    cvss_vector: str | None = None

    # Fix information
    fixed_version: str | None = None
    is_fixable: bool = False

    # Description and references
    title: str | None = None
    description: str | None = None
    references: list[str] = field(default_factory=list)

    # Package details
    package_type: str | None = None  # npm, pip, gem, apk, deb, rpm, etc.
    package_path: str | None = None  # Path in container filesystem

    # Timestamps
    published_date: datetime | None = None
    last_modified_date: datetime | None = None

    # Additional metadata
    data_source: str | None = None  # nvd, redhat, debian, etc.
    primary_url: str | None = None  # Primary reference URL
    cwe_ids: list[str] = field(default_factory=list)  # CWE-79, CWE-89, etc.

    def to_finding(
        self,
        image_reference: str,
        asset_id: str | None = None,
        scan_timestamp: datetime | None = None,
    ) -> Finding:
        """Convert vulnerability to a Stance Finding."""
        # Build finding ID
        finding_id = f"vuln:{image_reference}:{self.vulnerability_id}:{self.package_name}"

        # Build description
        description_parts = []
        if self.title:
            description_parts.append(self.title)
        if self.description:
            description_parts.append(self.description)
        description = "\n\n".join(description_parts) if description_parts else (
            f"Vulnerability {self.vulnerability_id} found in {self.package_name}"
        )

        # Build remediation guidance
        remediation = None
        if self.fixed_version:
            remediation = f"Update {self.package_name} from {self.installed_version} to {self.fixed_version}"
        elif not self.is_fixable:
            remediation = f"No fix available for {self.vulnerability_id} in {self.package_name}. Consider using an alternative package or base image."

        # Build raw config with all vulnerability details
        raw_config = {
            "vulnerability_id": self.vulnerability_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "fixed_version": self.fixed_version,
            "is_fixable": self.is_fixable,
            "package_type": self.package_type,
            "package_path": self.package_path,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "data_source": self.data_source,
            "image_reference": image_reference,
        }

        return Finding(
            id=finding_id,
            finding_type=FindingType.VULNERABILITY,
            status=FindingStatus.OPEN,
            severity=self.severity.to_stance_severity(),
            title=f"{self.vulnerability_id}: {self.package_name} ({self.installed_version})",
            description=description,
            asset_id=asset_id or f"image:{image_reference}",
            cve_id=self.vulnerability_id if self.vulnerability_id.upper().startswith("CVE-") else None,
            cvss_score=self.cvss_score,
            package_name=self.package_name,
            installed_version=self.installed_version,
            fixed_version=self.fixed_version,
            remediation_guidance=remediation or "",
            first_seen=scan_timestamp or datetime.utcnow(),
            last_seen=scan_timestamp or datetime.utcnow(),
        )


@dataclass
class ScanResult:
    """Result from scanning a container image."""

    # Image identification
    image_reference: str  # e.g., nginx:latest, ghcr.io/org/app:v1.2.3
    image_digest: str | None = None  # sha256:abc123...

    # Scan metadata
    scanner_name: str = "unknown"
    scanner_version: str | None = None
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    scan_duration_seconds: float = 0.0

    # Results
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Image metadata
    os_family: str | None = None  # debian, alpine, rhel, etc.
    os_version: str | None = None
    architecture: str | None = None  # amd64, arm64
    image_size_bytes: int | None = None

    # Scan configuration
    skip_db_update: bool = False
    ignore_unfixed: bool = False

    @property
    def success(self) -> bool:
        """Check if scan completed without errors."""
        return len(self.errors) == 0

    @property
    def vulnerability_count(self) -> int:
        """Total number of vulnerabilities found."""
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        """Number of critical vulnerabilities."""
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == VulnerabilitySeverity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        """Number of high severity vulnerabilities."""
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == VulnerabilitySeverity.HIGH
        )

    @property
    def medium_count(self) -> int:
        """Number of medium severity vulnerabilities."""
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == VulnerabilitySeverity.MEDIUM
        )

    @property
    def low_count(self) -> int:
        """Number of low severity vulnerabilities."""
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == VulnerabilitySeverity.LOW
        )

    @property
    def fixable_count(self) -> int:
        """Number of vulnerabilities with available fixes."""
        return sum(1 for v in self.vulnerabilities if v.is_fixable)

    def get_vulnerabilities_by_severity(
        self, severity: VulnerabilitySeverity
    ) -> list[Vulnerability]:
        """Get vulnerabilities filtered by severity."""
        return [v for v in self.vulnerabilities if v.severity == severity]

    def get_vulnerabilities_by_package(self, package_name: str) -> list[Vulnerability]:
        """Get vulnerabilities for a specific package."""
        return [v for v in self.vulnerabilities if v.package_name == package_name]

    def to_findings(self, asset_id: str | None = None) -> list[Finding]:
        """Convert all vulnerabilities to Stance Findings."""
        return [
            v.to_finding(
                image_reference=self.image_reference,
                asset_id=asset_id,
                scan_timestamp=self.scan_timestamp,
            )
            for v in self.vulnerabilities
        ]

    def summary(self) -> dict[str, Any]:
        """Get a summary of scan results."""
        return {
            "image_reference": self.image_reference,
            "image_digest": self.image_digest,
            "scanner": self.scanner_name,
            "scanner_version": self.scanner_version,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "scan_duration_seconds": self.scan_duration_seconds,
            "total_vulnerabilities": self.vulnerability_count,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "fixable": self.fixable_count,
            "os": f"{self.os_family or 'unknown'} {self.os_version or ''}".strip(),
            "success": self.success,
            "errors": self.errors,
        }


class ScannerError(Exception):
    """Base exception for scanner errors."""

    pass


class ScannerNotAvailableError(ScannerError):
    """Raised when the scanner binary is not available."""

    pass


class ScannerTimeoutError(ScannerError):
    """Raised when a scan times out."""

    pass


class ImageScanner(ABC):
    """
    Abstract base class for container image scanners.

    Implementations should wrap external scanning tools like Trivy or Grype
    to provide vulnerability scanning for container images.
    """

    scanner_name: str = "unknown"

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the scanner is available on the system.

        Returns:
            True if scanner is installed and functional
        """
        pass

    @abstractmethod
    def get_version(self) -> str | None:
        """
        Get the scanner version.

        Returns:
            Version string or None if not available
        """
        pass

    @abstractmethod
    def scan(
        self,
        image_reference: str,
        timeout_seconds: int = 300,
        skip_db_update: bool = False,
        ignore_unfixed: bool = False,
    ) -> ScanResult:
        """
        Scan a container image for vulnerabilities.

        Args:
            image_reference: Image to scan (e.g., nginx:latest, ghcr.io/org/app:v1)
            timeout_seconds: Maximum time to wait for scan
            skip_db_update: Skip vulnerability database update
            ignore_unfixed: Exclude vulnerabilities without fixes

        Returns:
            ScanResult with vulnerabilities found

        Raises:
            ScannerNotAvailableError: Scanner not installed
            ScannerTimeoutError: Scan exceeded timeout
            ScannerError: Other scanning errors
        """
        pass

    def scan_batch(
        self,
        image_references: list[str],
        timeout_seconds: int = 300,
        skip_db_update: bool = False,
        ignore_unfixed: bool = False,
        continue_on_error: bool = True,
    ) -> list[ScanResult]:
        """
        Scan multiple container images.

        Args:
            image_references: List of images to scan
            timeout_seconds: Maximum time per scan
            skip_db_update: Skip vulnerability database update
            ignore_unfixed: Exclude vulnerabilities without fixes
            continue_on_error: Continue scanning if one image fails

        Returns:
            List of ScanResults (one per image)
        """
        results: list[ScanResult] = []

        for i, image_ref in enumerate(image_references):
            # Only update DB on first scan if not skipping
            skip_update = skip_db_update or (i > 0)

            try:
                result = self.scan(
                    image_reference=image_ref,
                    timeout_seconds=timeout_seconds,
                    skip_db_update=skip_update,
                    ignore_unfixed=ignore_unfixed,
                )
                results.append(result)
            except ScannerError as e:
                if continue_on_error:
                    # Create error result
                    error_result = ScanResult(
                        image_reference=image_ref,
                        scanner_name=self.scanner_name,
                        errors=[str(e)],
                    )
                    results.append(error_result)
                    logger.warning(f"Failed to scan {image_ref}: {e}")
                else:
                    raise

        return results
