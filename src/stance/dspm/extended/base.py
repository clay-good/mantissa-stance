"""
Base classes for DSPM extended source scanners.

Provides abstract base class and common data models for scanning
extended data sources (data warehouses, SaaS, databases).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.dspm.classifier import ClassificationLevel, DataCategory
from stance.dspm.detector import SensitiveDataDetector, DetectionResult
from stance.dspm.scanners.base import FindingSeverity

logger = logging.getLogger(__name__)


class ExtendedSourceType(Enum):
    """Types of extended data sources."""

    SNOWFLAKE = "snowflake"
    GOOGLE_DRIVE = "google_drive"
    RDS = "rds"
    CLOUD_SQL = "cloud_sql"
    AZURE_SQL = "azure_sql"
    BIGQUERY = "bigquery"
    REDSHIFT = "redshift"


@dataclass
class ExtendedScanConfig:
    """
    Configuration for extended source scans.

    Attributes:
        sample_size: Maximum number of rows/files to sample
        max_tables: Maximum number of tables to scan (for databases)
        max_columns_per_table: Maximum columns to sample per table
        include_schemas: Schemas to include (None for all)
        exclude_schemas: Schemas to exclude
        include_tables: Tables to include (None for all)
        exclude_tables: Tables to exclude
        file_extensions: File extensions to scan (for drive)
        timeout_seconds: Timeout for entire scan
        sample_rows_per_column: Rows to sample per column
    """

    sample_size: int = 100
    max_tables: int = 50
    max_columns_per_table: int = 100
    include_schemas: list[str] | None = None
    exclude_schemas: list[str] = field(default_factory=lambda: ["information_schema", "pg_catalog", "sys"])
    include_tables: list[str] | None = None
    exclude_tables: list[str] = field(default_factory=list)
    file_extensions: list[str] | None = None
    timeout_seconds: int = 600
    sample_rows_per_column: int = 100

    def __post_init__(self):
        """Normalize file extensions."""
        if self.file_extensions:
            self.file_extensions = [
                ext.lower().lstrip(".") for ext in self.file_extensions
            ]


@dataclass
class ExtendedScanFinding:
    """
    A sensitive data finding from an extended source scan.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level
        title: Short title
        description: Detailed description
        source_type: Type of source (snowflake, google_drive, etc.)
        source_location: Full path/identifier of the source
        object_type: Type of object (table, column, file, etc.)
        object_name: Name of the specific object
        classification_level: Data classification level
        categories: Data categories detected
        sample_matches: Sample of pattern matches
        remediation: Suggested remediation
        metadata: Additional context
        detected_at: When finding was created
    """

    finding_id: str
    finding_type: str
    severity: FindingSeverity
    title: str
    description: str
    source_type: ExtendedSourceType
    source_location: str
    object_type: str
    object_name: str
    classification_level: ClassificationLevel
    categories: list[DataCategory] = field(default_factory=list)
    sample_matches: list[dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_type": self.source_type.value,
            "source_location": self.source_location,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "classification_level": self.classification_level.value,
            "categories": [c.value for c in self.categories],
            "sample_matches": self.sample_matches,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ExtendedScanSummary:
    """
    Summary statistics for an extended source scan.

    Attributes:
        total_objects_scanned: Number of objects scanned
        total_objects_skipped: Number of objects skipped
        total_rows_sampled: Total rows sampled (for databases)
        total_files_scanned: Total files scanned (for drive)
        total_findings: Number of findings
        findings_by_severity: Count by severity
        findings_by_category: Count by category
        scan_duration_seconds: Total duration
        errors: Errors encountered
    """

    total_objects_scanned: int = 0
    total_objects_skipped: int = 0
    total_rows_sampled: int = 0
    total_files_scanned: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_category: dict[str, int] = field(default_factory=dict)
    scan_duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert summary to dictionary."""
        return {
            "total_objects_scanned": self.total_objects_scanned,
            "total_objects_skipped": self.total_objects_skipped,
            "total_rows_sampled": self.total_rows_sampled,
            "total_files_scanned": self.total_files_scanned,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
        }


@dataclass
class ExtendedScanResult:
    """
    Complete result of an extended source scan.

    Attributes:
        scan_id: Unique identifier
        source_type: Type of source scanned
        target: Target identifier
        config: Configuration used
        findings: List of findings
        summary: Summary statistics
        started_at: When scan started
        completed_at: When scan completed
    """

    scan_id: str
    source_type: ExtendedSourceType
    target: str
    config: ExtendedScanConfig
    findings: list[ExtendedScanFinding] = field(default_factory=list)
    summary: ExtendedScanSummary = field(default_factory=ExtendedScanSummary)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    @property
    def has_findings(self) -> bool:
        """Check if scan found any sensitive data."""
        return len(self.findings) > 0

    @property
    def highest_severity(self) -> FindingSeverity | None:
        """Get the highest severity finding."""
        if not self.findings:
            return None

        severity_order = [
            FindingSeverity.CRITICAL,
            FindingSeverity.HIGH,
            FindingSeverity.MEDIUM,
            FindingSeverity.LOW,
            FindingSeverity.INFO,
        ]
        for severity in severity_order:
            if any(f.severity == severity for f in self.findings):
                return severity
        return None

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "scan_id": self.scan_id,
            "source_type": self.source_type.value,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class BaseExtendedScanner(ABC):
    """
    Abstract base class for extended source scanners.

    Scanners sample data from extended sources (data warehouses, SaaS,
    databases) and detect sensitive data patterns.

    All scanners are read-only and do not modify source data.
    """

    source_type: ExtendedSourceType

    def __init__(self, config: ExtendedScanConfig | None = None):
        """
        Initialize the scanner.

        Args:
            config: Optional scan configuration
        """
        self._config = config or ExtendedScanConfig()
        self._detector = SensitiveDataDetector()

    @property
    def config(self) -> ExtendedScanConfig:
        """Get scan configuration."""
        return self._config

    @property
    def detector(self) -> SensitiveDataDetector:
        """Get sensitive data detector."""
        return self._detector

    @abstractmethod
    def scan(self, target: str) -> ExtendedScanResult:
        """
        Scan a target for sensitive data.

        Args:
            target: Target identifier (database name, drive folder, etc.)

        Returns:
            Scan result with findings and summary
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to the data source.

        Returns:
            True if connection successful
        """
        pass

    @abstractmethod
    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        """
        List objects that can be scanned in the target.

        Args:
            target: Target identifier

        Returns:
            List of scannable object metadata
        """
        pass

    def _generate_finding_id(self, source_location: str, object_name: str) -> str:
        """Generate a unique finding ID."""
        import hashlib
        content = f"{self.source_type.value}:{source_location}:{object_name}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _create_finding_from_detection(
        self,
        source_location: str,
        object_type: str,
        object_name: str,
        detection_result: DetectionResult,
        metadata: dict[str, Any],
    ) -> ExtendedScanFinding | None:
        """
        Create a finding from a detection result.

        Args:
            source_location: Full source path
            object_type: Type of object (table, column, file)
            object_name: Name of the object
            detection_result: Detection result from detector
            metadata: Additional metadata

        Returns:
            ExtendedScanFinding if sensitive data found
        """
        if not detection_result.has_sensitive_data:
            return None

        severity = FindingSeverity.from_classification(
            detection_result.highest_classification
        )

        categories_str = ", ".join(
            c.value for c in detection_result.categories_found[:3]
        )
        if len(detection_result.categories_found) > 3:
            categories_str += f" (+{len(detection_result.categories_found) - 3} more)"

        title = f"Sensitive data in {object_type}: {categories_str}"

        description = (
            f"Detected {detection_result.match_count} instances of sensitive data "
            f"in {object_type} '{object_name}'. "
            f"Highest classification: {detection_result.highest_classification.value}."
        )

        remediation = self._get_remediation_guidance(
            detection_result.highest_classification,
            object_type,
            metadata,
        )

        sample_matches = [
            {
                "pattern": m.pattern_name,
                "category": m.category.value,
                "redacted_value": m.redacted_value,
                "confidence": m.confidence,
            }
            for m in detection_result.matches[:5]
        ]

        return ExtendedScanFinding(
            finding_id=self._generate_finding_id(source_location, object_name),
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=severity,
            title=title,
            description=description,
            source_type=self.source_type,
            source_location=source_location,
            object_type=object_type,
            object_name=object_name,
            classification_level=detection_result.highest_classification,
            categories=detection_result.categories_found,
            sample_matches=sample_matches,
            remediation=remediation,
            metadata={
                "total_matches": detection_result.match_count,
                "scan_coverage": detection_result.scan_coverage,
                **metadata,
            },
        )

    def _get_remediation_guidance(
        self,
        classification: ClassificationLevel,
        object_type: str,
        metadata: dict[str, Any],
    ) -> str:
        """Get remediation guidance based on classification and object type."""
        steps = []

        if classification.severity_score >= 75:
            steps.append("Review and assess the business need for this sensitive data")
            steps.append("Consider data masking or tokenization for non-production use")

        if object_type in ("table", "column"):
            steps.append("Implement column-level encryption if supported")
            steps.append("Review and restrict access permissions")
            if not metadata.get("encrypted", True):
                steps.append("Enable encryption at rest")

        if object_type == "file":
            steps.append("Consider moving to secure storage with encryption")
            steps.append("Review sharing permissions")

        return ". ".join(steps) if steps else ""
