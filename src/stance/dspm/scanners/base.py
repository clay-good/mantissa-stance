"""
Base classes for DSPM storage scanners.

Provides abstract base class and common data models for scanning
cloud storage services to detect sensitive data.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

from stance.dspm.classifier import ClassificationLevel, DataCategory
from stance.dspm.detector import (
    SensitiveDataDetector,
    DetectionResult,
    PatternMatch,
)

logger = logging.getLogger(__name__)


class FindingSeverity(Enum):
    """Severity levels for DSPM findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_classification(cls, level: ClassificationLevel) -> "FindingSeverity":
        """Map classification level to finding severity."""
        mapping = {
            ClassificationLevel.TOP_SECRET: cls.CRITICAL,
            ClassificationLevel.RESTRICTED: cls.HIGH,
            ClassificationLevel.CONFIDENTIAL: cls.MEDIUM,
            ClassificationLevel.INTERNAL: cls.LOW,
            ClassificationLevel.PUBLIC: cls.INFO,
        }
        return mapping.get(level, cls.INFO)


@dataclass
class ScanConfig:
    """
    Configuration for a DSPM storage scan.

    Attributes:
        sample_size: Maximum number of objects to sample (None for all)
        max_object_size_bytes: Maximum object size to scan (skip larger)
        file_extensions: File extensions to scan (None for all)
        exclude_patterns: Glob patterns to exclude
        include_metadata: Whether to scan object metadata
        timeout_seconds: Timeout for entire scan operation
        content_sample_bytes: Bytes to read from each object for sampling
    """

    sample_size: int | None = 100
    max_object_size_bytes: int = 10 * 1024 * 1024  # 10MB
    file_extensions: list[str] | None = None
    exclude_patterns: list[str] = field(default_factory=list)
    include_metadata: bool = True
    timeout_seconds: int = 300
    content_sample_bytes: int = 64 * 1024  # 64KB sample per object

    def __post_init__(self):
        """Normalize file extensions."""
        if self.file_extensions:
            self.file_extensions = [
                ext.lower().lstrip(".") for ext in self.file_extensions
            ]


@dataclass
class ScanFinding:
    """
    A sensitive data finding from a storage scan.

    Attributes:
        finding_id: Unique identifier for this finding
        finding_type: Type of finding (e.g., SENSITIVE_DATA_DETECTED)
        severity: Severity level
        title: Short title for the finding
        description: Detailed description
        storage_location: Full path to the affected object
        bucket_name: Name of the bucket/container
        object_key: Object key within the bucket
        classification_level: Data classification level detected
        categories: Data categories detected
        sample_matches: Sample of pattern matches found
        remediation: Suggested remediation steps
        metadata: Additional context metadata
        detected_at: When the finding was created
    """

    finding_id: str
    finding_type: str
    severity: FindingSeverity
    title: str
    description: str
    storage_location: str
    bucket_name: str
    object_key: str
    classification_level: ClassificationLevel
    categories: list[DataCategory] = field(default_factory=list)
    sample_matches: list[dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "storage_location": self.storage_location,
            "bucket_name": self.bucket_name,
            "object_key": self.object_key,
            "classification_level": self.classification_level.value,
            "categories": [c.value for c in self.categories],
            "sample_matches": self.sample_matches,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ScanSummary:
    """
    Summary statistics for a storage scan.

    Attributes:
        total_objects_scanned: Number of objects scanned
        total_objects_skipped: Number of objects skipped
        total_bytes_scanned: Total bytes of data scanned
        total_findings: Number of findings generated
        findings_by_severity: Count of findings by severity
        findings_by_category: Count of findings by data category
        scan_duration_seconds: Total scan duration
        errors: List of errors encountered
    """

    total_objects_scanned: int = 0
    total_objects_skipped: int = 0
    total_bytes_scanned: int = 0
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
            "total_bytes_scanned": self.total_bytes_scanned,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
        }


@dataclass
class ScanResult:
    """
    Complete result of a DSPM storage scan.

    Attributes:
        scan_id: Unique identifier for this scan
        storage_type: Type of storage scanned (s3, gcs, azure_blob)
        target: Target storage identifier (bucket name, etc.)
        config: Configuration used for the scan
        findings: List of sensitive data findings
        summary: Summary statistics
        started_at: When the scan started
        completed_at: When the scan completed
    """

    scan_id: str
    storage_type: str
    target: str
    config: ScanConfig
    findings: list[ScanFinding] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
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
            "storage_type": self.storage_type,
            "target": self.target,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class BaseDataScanner(ABC):
    """
    Abstract base class for DSPM storage scanners.

    Scanners sample data from cloud storage services and use the
    sensitive data detector to identify PII, PCI, PHI, and other
    sensitive information.

    All scanners are read-only and do not modify stored data.
    """

    storage_type: str = "base"

    def __init__(self, config: ScanConfig | None = None):
        """
        Initialize the scanner.

        Args:
            config: Optional scan configuration
        """
        self._config = config or ScanConfig()
        self._detector = SensitiveDataDetector()

    @property
    def config(self) -> ScanConfig:
        """Get the scan configuration."""
        return self._config

    @property
    def detector(self) -> SensitiveDataDetector:
        """Get the sensitive data detector."""
        return self._detector

    @abstractmethod
    def scan_bucket(self, bucket_name: str) -> ScanResult:
        """
        Scan a storage bucket/container for sensitive data.

        Args:
            bucket_name: Name of the bucket to scan

        Returns:
            Scan result with findings and summary
        """
        pass

    @abstractmethod
    def scan_object(self, bucket_name: str, object_key: str) -> ScanFinding | None:
        """
        Scan a specific object for sensitive data.

        Args:
            bucket_name: Name of the bucket
            object_key: Key of the object to scan

        Returns:
            Finding if sensitive data detected, None otherwise
        """
        pass

    @abstractmethod
    def list_objects(
        self, bucket_name: str, prefix: str = ""
    ) -> Iterator[dict[str, Any]]:
        """
        List objects in a bucket.

        Args:
            bucket_name: Name of the bucket
            prefix: Optional prefix to filter objects

        Yields:
            Object metadata dictionaries
        """
        pass

    @abstractmethod
    def get_object_content(
        self, bucket_name: str, object_key: str, max_bytes: int | None = None
    ) -> bytes | None:
        """
        Get object content (or sample).

        Args:
            bucket_name: Name of the bucket
            object_key: Key of the object
            max_bytes: Maximum bytes to read

        Returns:
            Object content as bytes, or None if not accessible
        """
        pass

    @abstractmethod
    def get_bucket_metadata(self, bucket_name: str) -> dict[str, Any]:
        """
        Get bucket/container metadata.

        Args:
            bucket_name: Name of the bucket

        Returns:
            Bucket metadata including encryption, public access, etc.
        """
        pass

    def _should_scan_object(
        self, object_key: str, object_size: int
    ) -> tuple[bool, str]:
        """
        Determine if an object should be scanned.

        Args:
            object_key: Object key
            object_size: Object size in bytes

        Returns:
            Tuple of (should_scan, skip_reason)
        """
        # Check size limit
        if object_size > self._config.max_object_size_bytes:
            return False, f"Object size {object_size} exceeds limit"

        # Check file extension if configured
        if self._config.file_extensions:
            ext = object_key.rsplit(".", 1)[-1].lower() if "." in object_key else ""
            if ext not in self._config.file_extensions:
                return False, f"Extension .{ext} not in allowed list"

        # Check exclude patterns
        for pattern in self._config.exclude_patterns:
            if self._matches_pattern(object_key, pattern):
                return False, f"Matches exclude pattern: {pattern}"

        return True, ""

    def _matches_pattern(self, object_key: str, pattern: str) -> bool:
        """Check if object key matches a glob pattern."""
        import fnmatch
        return fnmatch.fnmatch(object_key, pattern)

    def _generate_finding_id(self, bucket_name: str, object_key: str) -> str:
        """Generate a unique finding ID."""
        import hashlib
        content = f"{self.storage_type}:{bucket_name}:{object_key}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _create_finding_from_detection(
        self,
        bucket_name: str,
        object_key: str,
        detection_result: DetectionResult,
        bucket_metadata: dict[str, Any],
    ) -> ScanFinding | None:
        """
        Create a scan finding from a detection result.

        Args:
            bucket_name: Bucket name
            object_key: Object key
            detection_result: Detection result from detector
            bucket_metadata: Bucket metadata for context

        Returns:
            ScanFinding if sensitive data found, None otherwise
        """
        if not detection_result.has_sensitive_data:
            return None

        # Determine severity from classification
        severity = FindingSeverity.from_classification(
            detection_result.highest_classification
        )

        # Build title based on categories found
        categories_str = ", ".join(
            c.value for c in detection_result.categories_found[:3]
        )
        if len(detection_result.categories_found) > 3:
            categories_str += f" (+{len(detection_result.categories_found) - 3} more)"

        title = f"Sensitive data detected: {categories_str}"

        # Build description
        description = (
            f"Detected {detection_result.match_count} instances of sensitive data "
            f"in object {object_key}. "
            f"Highest classification: {detection_result.highest_classification.value}."
        )

        # Check for additional risks
        risks = []
        if not bucket_metadata.get("encrypted", True):
            risks.append("bucket is not encrypted")
        if bucket_metadata.get("public_access", False):
            risks.append("bucket has public access enabled")

        if risks:
            description += f" Additional risks: {', '.join(risks)}."

        # Build remediation guidance
        remediation_steps = []
        if detection_result.highest_classification.severity_score >= 75:
            remediation_steps.append(
                "Review and remove or encrypt highly sensitive data"
            )
        if not bucket_metadata.get("encrypted", True):
            remediation_steps.append("Enable encryption for the storage bucket")
        if bucket_metadata.get("public_access", False):
            remediation_steps.append("Disable public access to the bucket")

        remediation = ". ".join(remediation_steps) if remediation_steps else ""

        # Sample matches (redacted)
        sample_matches = [
            {
                "pattern": m.pattern_name,
                "category": m.category.value,
                "redacted_value": m.redacted_value,
                "confidence": m.confidence,
            }
            for m in detection_result.matches[:5]  # Limit to 5 samples
        ]

        storage_location = f"{self.storage_type}://{bucket_name}/{object_key}"

        return ScanFinding(
            finding_id=self._generate_finding_id(bucket_name, object_key),
            finding_type="SENSITIVE_DATA_DETECTED",
            severity=severity,
            title=title,
            description=description,
            storage_location=storage_location,
            bucket_name=bucket_name,
            object_key=object_key,
            classification_level=detection_result.highest_classification,
            categories=detection_result.categories_found,
            sample_matches=sample_matches,
            remediation=remediation,
            metadata={
                "total_matches": detection_result.match_count,
                "scan_coverage": detection_result.scan_coverage,
                "bucket_encrypted": bucket_metadata.get("encrypted", "unknown"),
                "public_access": bucket_metadata.get("public_access", "unknown"),
            },
        )

    def _decode_content(self, content: bytes) -> str | None:
        """
        Attempt to decode binary content to text.

        Args:
            content: Binary content

        Returns:
            Decoded text or None if not text
        """
        encodings = ["utf-8", "latin-1", "cp1252"]
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return None
