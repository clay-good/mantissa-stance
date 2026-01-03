"""
Base classes for DSPM access review.

Provides abstract base class and common data models for analyzing
cloud access logs to detect stale and unused permissions.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class FindingType(Enum):
    """Types of access review findings."""

    STALE_ACCESS = "stale_access"
    UNUSED_ROLE = "unused_role"
    OVER_PRIVILEGED = "over_privileged"
    NO_RECENT_ACCESS = "no_recent_access"
    WRITE_NEVER_USED = "write_never_used"
    DELETE_NEVER_USED = "delete_never_used"


@dataclass
class AccessReviewConfig:
    """
    Configuration for access review analysis.

    Attributes:
        stale_days: Days without access to consider stale (default: 90)
        include_service_accounts: Whether to include service accounts
        include_roles: Whether to include IAM roles
        include_users: Whether to include users
        lookback_days: Days of logs to analyze (default: 180)
        min_access_count: Minimum accesses to not flag as unused
    """

    stale_days: int = 90
    include_service_accounts: bool = True
    include_roles: bool = True
    include_users: bool = True
    lookback_days: int = 180
    min_access_count: int = 1


@dataclass
class AccessEvent:
    """
    A single access event from cloud logs.

    Attributes:
        event_id: Unique event identifier
        timestamp: When the event occurred
        principal_id: Who performed the action
        principal_type: Type of principal (user, role, service_account)
        resource_id: Resource being accessed (e.g., bucket/object path)
        action: Action performed (read, write, delete, list, etc.)
        source_ip: Source IP address
        user_agent: User agent string
        success: Whether the action succeeded
        metadata: Additional event metadata
    """

    event_id: str
    timestamp: datetime
    principal_id: str
    principal_type: str
    resource_id: str
    action: str
    source_ip: str | None = None
    user_agent: str | None = None
    success: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary representation."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "resource_id": self.resource_id,
            "action": self.action,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "success": self.success,
            "metadata": self.metadata,
        }


@dataclass
class AccessSummary:
    """
    Summary of access patterns for a principal-resource pair.

    Attributes:
        principal_id: Principal identifier
        principal_type: Type of principal
        resource_id: Resource identifier
        total_access_count: Total number of accesses
        read_count: Number of read operations
        write_count: Number of write operations
        delete_count: Number of delete operations
        list_count: Number of list operations
        first_access: First recorded access
        last_access: Most recent access
        days_since_last_access: Days since last access
        has_permission: Whether principal currently has permission
        permission_level: Level of permission (read, write, admin)
    """

    principal_id: str
    principal_type: str
    resource_id: str
    total_access_count: int = 0
    read_count: int = 0
    write_count: int = 0
    delete_count: int = 0
    list_count: int = 0
    first_access: datetime | None = None
    last_access: datetime | None = None
    days_since_last_access: int | None = None
    has_permission: bool = True
    permission_level: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        """Convert summary to dictionary representation."""
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "resource_id": self.resource_id,
            "total_access_count": self.total_access_count,
            "read_count": self.read_count,
            "write_count": self.write_count,
            "delete_count": self.delete_count,
            "list_count": self.list_count,
            "first_access": self.first_access.isoformat() if self.first_access else None,
            "last_access": self.last_access.isoformat() if self.last_access else None,
            "days_since_last_access": self.days_since_last_access,
            "has_permission": self.has_permission,
            "permission_level": self.permission_level,
        }


@dataclass
class StaleAccessFinding:
    """
    A finding from access review analysis.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level (critical, high, medium, low)
        title: Short title for the finding
        description: Detailed description
        principal_id: Affected principal
        principal_type: Type of principal
        resource_id: Affected resource
        days_since_last_access: Days since last access
        permission_level: Current permission level
        recommended_action: Suggested action
        metadata: Additional context
        detected_at: When finding was generated
    """

    finding_id: str
    finding_type: FindingType
    severity: str
    title: str
    description: str
    principal_id: str
    principal_type: str
    resource_id: str
    days_since_last_access: int | None = None
    permission_level: str = "unknown"
    recommended_action: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type,
            "resource_id": self.resource_id,
            "days_since_last_access": self.days_since_last_access,
            "permission_level": self.permission_level,
            "recommended_action": self.recommended_action,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class AccessReviewResult:
    """
    Result of an access review analysis.

    Attributes:
        review_id: Unique identifier for this review
        resource_id: Resource that was reviewed
        config: Configuration used
        started_at: When review started
        completed_at: When review completed
        total_principals_analyzed: Number of principals analyzed
        total_events_analyzed: Number of access events analyzed
        findings: List of findings generated
        summaries: Access summaries by principal
        errors: Errors encountered during analysis
    """

    review_id: str
    resource_id: str
    config: AccessReviewConfig
    started_at: datetime
    completed_at: datetime | None = None
    total_principals_analyzed: int = 0
    total_events_analyzed: int = 0
    findings: list[StaleAccessFinding] = field(default_factory=list)
    summaries: list[AccessSummary] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if review has any findings."""
        return len(self.findings) > 0

    @property
    def findings_by_type(self) -> dict[str, int]:
        """Get count of findings by type."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            type_val = finding.finding_type.value
            counts[type_val] = counts.get(type_val, 0) + 1
        return counts

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Get count of findings by severity."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    @property
    def stale_principals(self) -> list[str]:
        """Get list of principals with stale access."""
        return [
            f.principal_id for f in self.findings
            if f.finding_type == FindingType.STALE_ACCESS
        ]

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "review_id": self.review_id,
            "resource_id": self.resource_id,
            "config": {
                "stale_days": self.config.stale_days,
                "lookback_days": self.config.lookback_days,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_principals_analyzed": self.total_principals_analyzed,
            "total_events_analyzed": self.total_events_analyzed,
            "findings_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "summaries": [s.to_dict() for s in self.summaries],
            "errors": self.errors,
        }


class BaseAccessAnalyzer(ABC):
    """
    Abstract base class for cloud access log analyzers.

    Subclasses implement cloud-specific logic for parsing access logs
    and correlating with IAM permissions.
    """

    cloud_provider = "unknown"

    def __init__(self, config: AccessReviewConfig | None = None):
        """
        Initialize the access analyzer.

        Args:
            config: Optional configuration for access review
        """
        self._config = config or AccessReviewConfig()

    @abstractmethod
    def analyze_resource(self, resource_id: str) -> AccessReviewResult:
        """
        Analyze access patterns for a specific resource.

        Args:
            resource_id: Resource to analyze (e.g., bucket name, container name)

        Returns:
            Access review result with findings and summaries
        """
        pass

    @abstractmethod
    def get_access_events(
        self,
        resource_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[AccessEvent]:
        """
        Retrieve access events for a resource within a time range.

        Args:
            resource_id: Resource to get events for
            start_time: Start of time range
            end_time: End of time range

        Yields:
            Access events matching the criteria
        """
        pass

    @abstractmethod
    def get_resource_permissions(
        self,
        resource_id: str,
    ) -> dict[str, dict[str, Any]]:
        """
        Get current permissions for a resource.

        Args:
            resource_id: Resource to get permissions for

        Returns:
            Dictionary mapping principal_id to permission details
        """
        pass

    def _aggregate_events(
        self,
        events: Iterator[AccessEvent],
    ) -> dict[str, AccessSummary]:
        """
        Aggregate access events into summaries by principal-resource pair.

        Args:
            events: Iterator of access events

        Returns:
            Dictionary of access summaries keyed by principal_id
        """
        summaries: dict[str, AccessSummary] = {}
        now = datetime.now(timezone.utc)

        for event in events:
            key = event.principal_id

            if key not in summaries:
                summaries[key] = AccessSummary(
                    principal_id=event.principal_id,
                    principal_type=event.principal_type,
                    resource_id=event.resource_id,
                )

            summary = summaries[key]
            summary.total_access_count += 1

            # Categorize by action type
            action_lower = event.action.lower()
            if "get" in action_lower or "read" in action_lower or "head" in action_lower:
                summary.read_count += 1
            elif "put" in action_lower or "write" in action_lower or "upload" in action_lower:
                summary.write_count += 1
            elif "delete" in action_lower or "remove" in action_lower:
                summary.delete_count += 1
            elif "list" in action_lower:
                summary.list_count += 1

            # Track first and last access
            if summary.first_access is None or event.timestamp < summary.first_access:
                summary.first_access = event.timestamp
            if summary.last_access is None or event.timestamp > summary.last_access:
                summary.last_access = event.timestamp

        # Calculate days since last access
        for summary in summaries.values():
            if summary.last_access:
                delta = now - summary.last_access
                summary.days_since_last_access = delta.days

        return summaries

    def _generate_findings(
        self,
        summaries: dict[str, AccessSummary],
        permissions: dict[str, dict[str, Any]],
        resource_id: str,
    ) -> list[StaleAccessFinding]:
        """
        Generate findings from access summaries and permissions.

        Args:
            summaries: Access summaries by principal
            permissions: Current permissions by principal
            resource_id: Resource being analyzed

        Returns:
            List of findings
        """
        findings: list[StaleAccessFinding] = []
        finding_counter = 0

        # Check each principal with permissions
        for principal_id, perm_info in permissions.items():
            # Skip if filtering by principal type
            principal_type = perm_info.get("type", "unknown")
            if principal_type == "service_account" and not self._config.include_service_accounts:
                continue
            if principal_type == "role" and not self._config.include_roles:
                continue
            if principal_type == "user" and not self._config.include_users:
                continue

            permission_level = perm_info.get("level", "unknown")
            summary = summaries.get(principal_id)

            if summary is None:
                # Principal has permissions but no recorded access
                finding_counter += 1
                findings.append(
                    StaleAccessFinding(
                        finding_id=f"{resource_id}-access-{finding_counter:04d}",
                        finding_type=FindingType.NO_RECENT_ACCESS,
                        severity=self._get_severity_for_unused(permission_level),
                        title=f"No access recorded for {principal_id}",
                        description=(
                            f"Principal '{principal_id}' has {permission_level} permission "
                            f"to {resource_id} but no access was recorded in the last "
                            f"{self._config.lookback_days} days."
                        ),
                        principal_id=principal_id,
                        principal_type=principal_type,
                        resource_id=resource_id,
                        permission_level=permission_level,
                        recommended_action=f"Consider removing {permission_level} access for {principal_id}",
                    )
                )
            elif summary.days_since_last_access and summary.days_since_last_access >= self._config.stale_days:
                # Principal has permissions but hasn't accessed in stale_days
                finding_counter += 1
                findings.append(
                    StaleAccessFinding(
                        finding_id=f"{resource_id}-access-{finding_counter:04d}",
                        finding_type=FindingType.STALE_ACCESS,
                        severity=self._get_severity_for_stale(
                            summary.days_since_last_access, permission_level
                        ),
                        title=f"Stale access for {principal_id}",
                        description=(
                            f"Principal '{principal_id}' has {permission_level} permission "
                            f"to {resource_id} but hasn't accessed it in "
                            f"{summary.days_since_last_access} days."
                        ),
                        principal_id=principal_id,
                        principal_type=principal_type,
                        resource_id=resource_id,
                        days_since_last_access=summary.days_since_last_access,
                        permission_level=permission_level,
                        recommended_action=f"Review if {principal_id} still needs {permission_level} access",
                    )
                )

            # Check for over-privileged access (write permission but only reads)
            if summary and permission_level in ("write", "admin", "full"):
                if summary.write_count == 0 and summary.delete_count == 0 and summary.read_count > 0:
                    finding_counter += 1
                    findings.append(
                        StaleAccessFinding(
                            finding_id=f"{resource_id}-access-{finding_counter:04d}",
                            finding_type=FindingType.OVER_PRIVILEGED,
                            severity="medium",
                            title=f"Over-privileged access for {principal_id}",
                            description=(
                                f"Principal '{principal_id}' has {permission_level} permission "
                                f"but only performed read operations ({summary.read_count} reads, "
                                f"0 writes)."
                            ),
                            principal_id=principal_id,
                            principal_type=principal_type,
                            resource_id=resource_id,
                            days_since_last_access=summary.days_since_last_access,
                            permission_level=permission_level,
                            recommended_action=f"Consider downgrading {principal_id} to read-only access",
                            metadata={
                                "read_count": summary.read_count,
                                "write_count": summary.write_count,
                            },
                        )
                    )

        return findings

    def _get_severity_for_stale(self, days: int, permission_level: str) -> str:
        """Determine severity for stale access finding."""
        # Higher severity for more privileged access and longer staleness
        if permission_level in ("admin", "full", "owner"):
            if days >= 365:
                return "critical"
            if days >= 180:
                return "high"
            return "medium"
        if permission_level == "write":
            if days >= 365:
                return "high"
            if days >= 180:
                return "medium"
            return "low"
        # Read-only
        if days >= 365:
            return "medium"
        return "low"

    def _get_severity_for_unused(self, permission_level: str) -> str:
        """Determine severity for unused permission finding."""
        if permission_level in ("admin", "full", "owner"):
            return "high"
        if permission_level == "write":
            return "medium"
        return "low"

    def _calculate_lookback_range(self) -> tuple[datetime, datetime]:
        """Calculate the time range for log analysis."""
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self._config.lookback_days)
        return start_time, end_time
