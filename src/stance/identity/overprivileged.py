"""
Over-Privileged Access Detection for Identity Security.

Detects principals with permissions that exceed their actual usage patterns
by comparing granted permissions against access log analysis.

Integrates with:
- Identity data access mappers (Phase 32) for permission information
- DSPM access review (Phase 23-25) for usage patterns from access logs
- Principal exposure analysis (Phase 33) for sensitivity context
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.identity.base import (
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
    IdentityConfig,
)
from stance.dspm.access.base import (
    AccessSummary,
    AccessReviewConfig,
)

logger = logging.getLogger(__name__)


class OverPrivilegedFindingType(Enum):
    """Types of over-privileged access findings."""

    UNUSED_WRITE_ACCESS = "unused_write_access"  # Write permission but only reads
    UNUSED_DELETE_ACCESS = "unused_delete_access"  # Delete permission never used
    UNUSED_ADMIN_ACCESS = "unused_admin_access"  # Admin permission but limited usage
    BROAD_SENSITIVE_ACCESS = "broad_sensitive_access"  # Access to many sensitive resources
    STALE_ELEVATED_ACCESS = "stale_elevated_access"  # Elevated access not used recently
    NEVER_USED_ACCESS = "never_used_access"  # Permission with no observed usage


class OverPrivilegedSeverity(Enum):
    """Severity levels for over-privileged findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more severe)."""
        ranks = {
            OverPrivilegedSeverity.CRITICAL: 5,
            OverPrivilegedSeverity.HIGH: 4,
            OverPrivilegedSeverity.MEDIUM: 3,
            OverPrivilegedSeverity.LOW: 2,
            OverPrivilegedSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def __gt__(self, other: "OverPrivilegedSeverity") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "OverPrivilegedSeverity") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: "OverPrivilegedSeverity") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "OverPrivilegedSeverity") -> bool:
        return self.rank <= other.rank


@dataclass
class OverPrivilegedConfig:
    """
    Configuration for over-privileged detection.

    Attributes:
        lookback_days: Days of access logs to analyze
        stale_days: Days without usage to consider permission stale
        sensitive_resource_threshold: Number of sensitive resources to flag broad access
        include_service_accounts: Whether to analyze service accounts
        include_roles: Whether to analyze IAM roles
        include_users: Whether to analyze users
        min_sensitivity_level: Minimum data sensitivity to consider "sensitive"
    """

    lookback_days: int = 90
    stale_days: int = 30
    sensitive_resource_threshold: int = 5
    include_service_accounts: bool = True
    include_roles: bool = True
    include_users: bool = True
    min_sensitivity_level: str = "confidential"  # public, internal, confidential, restricted


@dataclass
class UsagePattern:
    """
    Observed usage pattern for a principal-resource pair.

    Attributes:
        principal_id: Principal identifier
        resource_id: Resource identifier
        granted_permission: Permission level granted
        observed_read_count: Number of read operations observed
        observed_write_count: Number of write operations observed
        observed_delete_count: Number of delete operations observed
        observed_list_count: Number of list operations observed
        first_access: First observed access
        last_access: Most recent access
        days_since_last_access: Days since last access
        total_access_count: Total number of accesses
    """

    principal_id: str
    resource_id: str
    granted_permission: PermissionLevel
    observed_read_count: int = 0
    observed_write_count: int = 0
    observed_delete_count: int = 0
    observed_list_count: int = 0
    first_access: datetime | None = None
    last_access: datetime | None = None
    days_since_last_access: int | None = None
    total_access_count: int = 0

    @property
    def highest_observed_permission(self) -> PermissionLevel:
        """Determine the highest permission level actually used."""
        if self.observed_delete_count > 0 or self.observed_write_count > 0:
            return PermissionLevel.WRITE
        if self.observed_read_count > 0:
            return PermissionLevel.READ
        if self.observed_list_count > 0:
            return PermissionLevel.LIST
        return PermissionLevel.NONE

    @property
    def has_unused_write(self) -> bool:
        """Check if write permission is unused."""
        return (
            self.granted_permission >= PermissionLevel.WRITE
            and self.observed_write_count == 0
            and self.observed_delete_count == 0
        )

    @property
    def has_unused_delete(self) -> bool:
        """Check if delete capability is unused (has write but no deletes)."""
        return (
            self.granted_permission >= PermissionLevel.WRITE
            and self.observed_delete_count == 0
            and self.total_access_count > 0
        )

    @property
    def has_unused_admin(self) -> bool:
        """Check if admin permission is underutilized."""
        return (
            self.granted_permission == PermissionLevel.ADMIN
            and self.highest_observed_permission < PermissionLevel.ADMIN
        )

    @property
    def is_stale(self) -> bool:
        """Check if access is stale (no recent usage)."""
        return self.last_access is None or (
            self.days_since_last_access is not None
            and self.days_since_last_access > 30
        )

    @property
    def is_never_used(self) -> bool:
        """Check if permission has never been used."""
        return self.total_access_count == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "principal_id": self.principal_id,
            "resource_id": self.resource_id,
            "granted_permission": self.granted_permission.value,
            "highest_observed_permission": self.highest_observed_permission.value,
            "observed_read_count": self.observed_read_count,
            "observed_write_count": self.observed_write_count,
            "observed_delete_count": self.observed_delete_count,
            "observed_list_count": self.observed_list_count,
            "first_access": self.first_access.isoformat() if self.first_access else None,
            "last_access": self.last_access.isoformat() if self.last_access else None,
            "days_since_last_access": self.days_since_last_access,
            "total_access_count": self.total_access_count,
            "has_unused_write": self.has_unused_write,
            "has_unused_delete": self.has_unused_delete,
            "has_unused_admin": self.has_unused_admin,
            "is_stale": self.is_stale,
            "is_never_used": self.is_never_used,
        }


@dataclass
class OverPrivilegedFinding:
    """
    A finding of over-privileged access.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of over-privileged finding
        severity: Severity level
        title: Short title
        description: Detailed description
        principal_id: Affected principal
        principal_type: Type of principal
        resource_id: Affected resource
        resource_type: Type of resource
        granted_permission: Permission level granted
        observed_permission: Highest permission level observed in usage
        data_classification: Data sensitivity if known
        usage_pattern: Detailed usage pattern
        recommended_action: Suggested action
        risk_score: Numeric risk score (0-100)
        metadata: Additional context
        detected_at: When finding was generated
    """

    finding_id: str
    finding_type: OverPrivilegedFindingType
    severity: OverPrivilegedSeverity
    title: str
    description: str
    principal_id: str
    principal_type: PrincipalType
    resource_id: str
    resource_type: str
    granted_permission: PermissionLevel
    observed_permission: PermissionLevel
    data_classification: str | None = None
    usage_pattern: UsagePattern | None = None
    recommended_action: str = ""
    risk_score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "granted_permission": self.granted_permission.value,
            "observed_permission": self.observed_permission.value,
            "data_classification": self.data_classification,
            "usage_pattern": self.usage_pattern.to_dict() if self.usage_pattern else None,
            "recommended_action": self.recommended_action,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class OverPrivilegedSummary:
    """
    Summary of over-privileged access for a principal.

    Attributes:
        principal_id: Principal identifier
        principal_type: Type of principal
        total_resources_accessed: Number of resources principal can access
        over_privileged_resources: Number of resources with over-privileged access
        unused_write_count: Number of resources with unused write access
        unused_delete_count: Number of resources with unused delete access
        unused_admin_count: Number of resources with unused admin access
        stale_access_count: Number of resources with stale access
        never_used_count: Number of resources with never-used permissions
        sensitive_resource_count: Number of sensitive resources accessible
        average_risk_score: Average risk score across findings
        highest_severity: Highest severity finding
    """

    principal_id: str
    principal_type: PrincipalType
    total_resources_accessed: int = 0
    over_privileged_resources: int = 0
    unused_write_count: int = 0
    unused_delete_count: int = 0
    unused_admin_count: int = 0
    stale_access_count: int = 0
    never_used_count: int = 0
    sensitive_resource_count: int = 0
    average_risk_score: float = 0.0
    highest_severity: OverPrivilegedSeverity = OverPrivilegedSeverity.INFO

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "principal_id": self.principal_id,
            "principal_type": self.principal_type.value,
            "total_resources_accessed": self.total_resources_accessed,
            "over_privileged_resources": self.over_privileged_resources,
            "unused_write_count": self.unused_write_count,
            "unused_delete_count": self.unused_delete_count,
            "unused_admin_count": self.unused_admin_count,
            "stale_access_count": self.stale_access_count,
            "never_used_count": self.never_used_count,
            "sensitive_resource_count": self.sensitive_resource_count,
            "average_risk_score": self.average_risk_score,
            "highest_severity": self.highest_severity.value,
        }


@dataclass
class OverPrivilegedResult:
    """
    Result of over-privileged access analysis.

    Attributes:
        analysis_id: Unique identifier
        config: Configuration used
        started_at: Analysis start time
        completed_at: Analysis completion time
        principals_analyzed: Number of principals analyzed
        resources_analyzed: Number of resources analyzed
        findings: List of findings
        summaries: Summaries by principal
        total_over_privileged: Total over-privileged access instances
        findings_by_type: Count of findings by type
        findings_by_severity: Count of findings by severity
        errors: Errors encountered
    """

    analysis_id: str
    config: OverPrivilegedConfig
    started_at: datetime
    completed_at: datetime | None = None
    principals_analyzed: int = 0
    resources_analyzed: int = 0
    findings: list[OverPrivilegedFinding] = field(default_factory=list)
    summaries: list[OverPrivilegedSummary] = field(default_factory=list)
    total_over_privileged: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if analysis has any findings."""
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
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts

    @property
    def critical_findings(self) -> list[OverPrivilegedFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == OverPrivilegedSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[OverPrivilegedFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == OverPrivilegedSeverity.HIGH]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "analysis_id": self.analysis_id,
            "config": {
                "lookback_days": self.config.lookback_days,
                "stale_days": self.config.stale_days,
                "sensitive_resource_threshold": self.config.sensitive_resource_threshold,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "principals_analyzed": self.principals_analyzed,
            "resources_analyzed": self.resources_analyzed,
            "total_over_privileged": self.total_over_privileged,
            "findings_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "summaries": [s.to_dict() for s in self.summaries],
            "errors": self.errors,
        }


class OverPrivilegedAnalyzer:
    """
    Analyzer for detecting over-privileged access.

    Compares granted permissions from identity mappers with actual usage
    patterns from access log analysis to identify principals with more
    permissions than they need.

    Integrates with:
    - Identity data access mappers for permission information
    - DSPM access review for access log analysis
    - Principal exposure analyzer for sensitivity context
    """

    def __init__(self, config: OverPrivilegedConfig | None = None):
        """
        Initialize the over-privileged analyzer.

        Args:
            config: Optional configuration for analysis
        """
        self._config = config or OverPrivilegedConfig()
        self._finding_counter = 0

    @property
    def config(self) -> OverPrivilegedConfig:
        """Get the analysis configuration."""
        return self._config

    def analyze_principal(
        self,
        principal: Principal,
        resource_accesses: list[ResourceAccess],
        access_summaries: list[AccessSummary],
        resource_classifications: dict[str, str] | None = None,
    ) -> OverPrivilegedResult:
        """
        Analyze a principal for over-privileged access.

        Compares granted permissions with actual usage patterns to find
        unused or underutilized permissions.

        Args:
            principal: Principal to analyze
            resource_accesses: List of resources principal can access
            access_summaries: Access log summaries for this principal
            resource_classifications: Optional mapping of resource_id to classification

        Returns:
            Over-privileged analysis result
        """
        result = OverPrivilegedResult(
            analysis_id=f"op-{uuid.uuid4().hex[:12]}",
            config=self._config,
            started_at=datetime.now(timezone.utc),
        )

        if not self._should_include_principal(principal):
            result.completed_at = datetime.now(timezone.utc)
            return result

        # Build access summary lookup by resource
        summary_by_resource: dict[str, AccessSummary] = {}
        for summary in access_summaries:
            summary_by_resource[summary.resource_id] = summary

        resource_classifications = resource_classifications or {}
        usage_patterns: list[UsagePattern] = []
        findings: list[OverPrivilegedFinding] = []
        sensitive_count = 0

        for access in resource_accesses:
            # Get usage pattern for this resource
            summary = summary_by_resource.get(access.resource_id)
            pattern = self._build_usage_pattern(
                principal.id, access, summary
            )
            usage_patterns.append(pattern)

            # Get data classification
            classification = resource_classifications.get(
                access.resource_id, access.data_classification
            )
            is_sensitive = self._is_sensitive(classification)
            if is_sensitive:
                sensitive_count += 1

            # Generate findings for this resource
            resource_findings = self._generate_findings_for_resource(
                principal, access, pattern, classification
            )
            findings.extend(resource_findings)

        # Check for broad sensitive access
        if sensitive_count >= self._config.sensitive_resource_threshold:
            findings.append(self._create_broad_access_finding(
                principal, sensitive_count, resource_accesses
            ))

        # Build summary
        summary = self._build_summary(principal, findings, usage_patterns, sensitive_count)

        result.findings = findings
        result.summaries = [summary]
        result.principals_analyzed = 1
        result.resources_analyzed = len(resource_accesses)
        result.total_over_privileged = summary.over_privileged_resources
        result.completed_at = datetime.now(timezone.utc)

        return result

    def analyze_multiple_principals(
        self,
        principals_data: list[tuple[Principal, list[ResourceAccess], list[AccessSummary]]],
        resource_classifications: dict[str, str] | None = None,
    ) -> OverPrivilegedResult:
        """
        Analyze multiple principals for over-privileged access.

        Args:
            principals_data: List of (principal, resource_accesses, access_summaries)
            resource_classifications: Optional mapping of resource_id to classification

        Returns:
            Combined over-privileged analysis result
        """
        result = OverPrivilegedResult(
            analysis_id=f"op-{uuid.uuid4().hex[:12]}",
            config=self._config,
            started_at=datetime.now(timezone.utc),
        )

        all_findings: list[OverPrivilegedFinding] = []
        all_summaries: list[OverPrivilegedSummary] = []
        all_resources: set[str] = set()

        for principal, resource_accesses, access_summaries in principals_data:
            principal_result = self.analyze_principal(
                principal, resource_accesses, access_summaries, resource_classifications
            )
            all_findings.extend(principal_result.findings)
            all_summaries.extend(principal_result.summaries)
            for access in resource_accesses:
                all_resources.add(access.resource_id)

        result.findings = all_findings
        result.summaries = all_summaries
        result.principals_analyzed = len(principals_data)
        result.resources_analyzed = len(all_resources)
        result.total_over_privileged = sum(s.over_privileged_resources for s in all_summaries)
        result.completed_at = datetime.now(timezone.utc)

        return result

    def compare_permission_vs_usage(
        self,
        granted_permission: PermissionLevel,
        access_summary: AccessSummary | None,
    ) -> tuple[bool, PermissionLevel]:
        """
        Compare granted permission with observed usage.

        Args:
            granted_permission: Permission level granted
            access_summary: Access log summary (None if no access observed)

        Returns:
            Tuple of (is_over_privileged, observed_permission_level)
        """
        if access_summary is None:
            # No usage observed - permission is never used
            return granted_permission > PermissionLevel.NONE, PermissionLevel.NONE

        # Determine observed permission level from usage
        if access_summary.delete_count > 0:
            observed = PermissionLevel.ADMIN
        elif access_summary.write_count > 0:
            observed = PermissionLevel.WRITE
        elif access_summary.read_count > 0:
            observed = PermissionLevel.READ
        elif access_summary.list_count > 0:
            observed = PermissionLevel.LIST
        else:
            observed = PermissionLevel.NONE

        is_over_privileged = granted_permission > observed
        return is_over_privileged, observed

    def _build_usage_pattern(
        self,
        principal_id: str,
        access: ResourceAccess,
        summary: AccessSummary | None,
    ) -> UsagePattern:
        """Build a usage pattern from access and summary data."""
        if summary is None:
            return UsagePattern(
                principal_id=principal_id,
                resource_id=access.resource_id,
                granted_permission=access.permission_level,
            )

        return UsagePattern(
            principal_id=principal_id,
            resource_id=access.resource_id,
            granted_permission=access.permission_level,
            observed_read_count=summary.read_count,
            observed_write_count=summary.write_count,
            observed_delete_count=summary.delete_count,
            observed_list_count=summary.list_count,
            first_access=summary.first_access,
            last_access=summary.last_access,
            days_since_last_access=summary.days_since_last_access,
            total_access_count=summary.total_access_count,
        )

    def _generate_findings_for_resource(
        self,
        principal: Principal,
        access: ResourceAccess,
        pattern: UsagePattern,
        classification: str | None,
    ) -> list[OverPrivilegedFinding]:
        """Generate findings for a single resource."""
        findings: list[OverPrivilegedFinding] = []
        is_sensitive = self._is_sensitive(classification)

        # Check for never-used access
        if pattern.is_never_used and access.permission_level > PermissionLevel.NONE:
            findings.append(self._create_finding(
                finding_type=OverPrivilegedFindingType.NEVER_USED_ACCESS,
                principal=principal,
                access=access,
                pattern=pattern,
                classification=classification,
                title=f"Never-used {access.permission_level.value} access",
                description=(
                    f"Principal '{principal.name}' has {access.permission_level.value} "
                    f"permission to '{access.resource_id}' but has never accessed it "
                    f"in the lookback period."
                ),
                severity=self._calculate_severity(
                    OverPrivilegedFindingType.NEVER_USED_ACCESS,
                    access.permission_level,
                    is_sensitive,
                    principal.principal_type,
                ),
            ))
            return findings  # Don't generate other findings for never-used

        # Check for unused write access
        if pattern.has_unused_write:
            findings.append(self._create_finding(
                finding_type=OverPrivilegedFindingType.UNUSED_WRITE_ACCESS,
                principal=principal,
                access=access,
                pattern=pattern,
                classification=classification,
                title=f"Unused write access to {access.resource_id}",
                description=(
                    f"Principal '{principal.name}' has {access.permission_level.value} "
                    f"permission but only performed read operations "
                    f"({pattern.observed_read_count} reads, 0 writes)."
                ),
                severity=self._calculate_severity(
                    OverPrivilegedFindingType.UNUSED_WRITE_ACCESS,
                    access.permission_level,
                    is_sensitive,
                    principal.principal_type,
                ),
            ))

        # Check for unused delete access (separate from write)
        if pattern.has_unused_delete and not pattern.has_unused_write:
            findings.append(self._create_finding(
                finding_type=OverPrivilegedFindingType.UNUSED_DELETE_ACCESS,
                principal=principal,
                access=access,
                pattern=pattern,
                classification=classification,
                title=f"Unused delete capability on {access.resource_id}",
                description=(
                    f"Principal '{principal.name}' has delete capability but has "
                    f"only performed writes ({pattern.observed_write_count} writes, 0 deletes)."
                ),
                severity=self._calculate_severity(
                    OverPrivilegedFindingType.UNUSED_DELETE_ACCESS,
                    access.permission_level,
                    is_sensitive,
                    principal.principal_type,
                ),
            ))

        # Check for unused admin access
        if pattern.has_unused_admin:
            findings.append(self._create_finding(
                finding_type=OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS,
                principal=principal,
                access=access,
                pattern=pattern,
                classification=classification,
                title=f"Unused admin access to {access.resource_id}",
                description=(
                    f"Principal '{principal.name}' has admin permission but only "
                    f"used {pattern.highest_observed_permission.value} level operations."
                ),
                severity=self._calculate_severity(
                    OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS,
                    access.permission_level,
                    is_sensitive,
                    principal.principal_type,
                ),
            ))

        # Check for stale elevated access
        if (
            pattern.is_stale
            and access.permission_level >= PermissionLevel.WRITE
            and not pattern.is_never_used
        ):
            findings.append(self._create_finding(
                finding_type=OverPrivilegedFindingType.STALE_ELEVATED_ACCESS,
                principal=principal,
                access=access,
                pattern=pattern,
                classification=classification,
                title=f"Stale elevated access to {access.resource_id}",
                description=(
                    f"Principal '{principal.name}' has {access.permission_level.value} "
                    f"permission but hasn't accessed the resource in "
                    f"{pattern.days_since_last_access or 'many'} days."
                ),
                severity=self._calculate_severity(
                    OverPrivilegedFindingType.STALE_ELEVATED_ACCESS,
                    access.permission_level,
                    is_sensitive,
                    principal.principal_type,
                ),
            ))

        return findings

    def _create_finding(
        self,
        finding_type: OverPrivilegedFindingType,
        principal: Principal,
        access: ResourceAccess,
        pattern: UsagePattern,
        classification: str | None,
        title: str,
        description: str,
        severity: OverPrivilegedSeverity,
    ) -> OverPrivilegedFinding:
        """Create a finding with risk score calculation."""
        self._finding_counter += 1
        risk_score = self._calculate_risk_score(
            finding_type, access.permission_level, classification, principal.principal_type
        )

        return OverPrivilegedFinding(
            finding_id=f"{access.resource_id}-op-{self._finding_counter:04d}",
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=description,
            principal_id=principal.id,
            principal_type=principal.principal_type,
            resource_id=access.resource_id,
            resource_type=access.resource_type,
            granted_permission=access.permission_level,
            observed_permission=pattern.highest_observed_permission,
            data_classification=classification,
            usage_pattern=pattern,
            recommended_action=self._get_recommended_action(finding_type, access, pattern),
            risk_score=risk_score,
        )

    def _create_broad_access_finding(
        self,
        principal: Principal,
        sensitive_count: int,
        resource_accesses: list[ResourceAccess],
    ) -> OverPrivilegedFinding:
        """Create a broad sensitive access finding."""
        self._finding_counter += 1

        # Find highest permission level across sensitive resources
        highest_perm = PermissionLevel.NONE
        for access in resource_accesses:
            if access.permission_level > highest_perm:
                highest_perm = access.permission_level

        severity = OverPrivilegedSeverity.HIGH
        if sensitive_count >= 10:
            severity = OverPrivilegedSeverity.CRITICAL
        if principal.principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.SERVICE_PRINCIPAL,
        ):
            severity = OverPrivilegedSeverity.CRITICAL

        return OverPrivilegedFinding(
            finding_id=f"broad-access-{principal.id}-op-{self._finding_counter:04d}",
            finding_type=OverPrivilegedFindingType.BROAD_SENSITIVE_ACCESS,
            severity=severity,
            title=f"Broad access to {sensitive_count} sensitive resources",
            description=(
                f"Principal '{principal.name}' has access to {sensitive_count} "
                f"sensitive resources, which may indicate overly permissive access. "
                f"Consider applying least privilege principles."
            ),
            principal_id=principal.id,
            principal_type=principal.principal_type,
            resource_id="multiple",
            resource_type="multiple",
            granted_permission=highest_perm,
            observed_permission=PermissionLevel.UNKNOWN,
            recommended_action=(
                f"Review if {principal.name} requires access to all {sensitive_count} "
                f"sensitive resources and remove unnecessary permissions."
            ),
            risk_score=min(100.0, 50.0 + sensitive_count * 5.0),
            metadata={"sensitive_resource_count": sensitive_count},
        )

    def _build_summary(
        self,
        principal: Principal,
        findings: list[OverPrivilegedFinding],
        patterns: list[UsagePattern],
        sensitive_count: int,
    ) -> OverPrivilegedSummary:
        """Build a summary for a principal."""
        summary = OverPrivilegedSummary(
            principal_id=principal.id,
            principal_type=principal.principal_type,
            total_resources_accessed=len(patterns),
            sensitive_resource_count=sensitive_count,
        )

        # Count finding types
        for pattern in patterns:
            if pattern.has_unused_write or pattern.has_unused_delete or pattern.has_unused_admin:
                summary.over_privileged_resources += 1
            if pattern.has_unused_write:
                summary.unused_write_count += 1
            if pattern.has_unused_delete:
                summary.unused_delete_count += 1
            if pattern.has_unused_admin:
                summary.unused_admin_count += 1
            if pattern.is_stale and pattern.granted_permission >= PermissionLevel.WRITE:
                summary.stale_access_count += 1
            if pattern.is_never_used:
                summary.never_used_count += 1

        # Calculate average risk score
        if findings:
            summary.average_risk_score = sum(f.risk_score for f in findings) / len(findings)
            summary.highest_severity = max(f.severity for f in findings)

        return summary

    def _calculate_severity(
        self,
        finding_type: OverPrivilegedFindingType,
        permission_level: PermissionLevel,
        is_sensitive: bool,
        principal_type: PrincipalType,
    ) -> OverPrivilegedSeverity:
        """Calculate severity for a finding."""
        # Base severity by finding type
        base_severities = {
            OverPrivilegedFindingType.UNUSED_WRITE_ACCESS: OverPrivilegedSeverity.MEDIUM,
            OverPrivilegedFindingType.UNUSED_DELETE_ACCESS: OverPrivilegedSeverity.LOW,
            OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS: OverPrivilegedSeverity.HIGH,
            OverPrivilegedFindingType.BROAD_SENSITIVE_ACCESS: OverPrivilegedSeverity.HIGH,
            OverPrivilegedFindingType.STALE_ELEVATED_ACCESS: OverPrivilegedSeverity.LOW,
            OverPrivilegedFindingType.NEVER_USED_ACCESS: OverPrivilegedSeverity.MEDIUM,
        }
        severity = base_severities.get(finding_type, OverPrivilegedSeverity.LOW)

        # Elevate for sensitive data
        if is_sensitive:
            if severity == OverPrivilegedSeverity.LOW:
                severity = OverPrivilegedSeverity.MEDIUM
            elif severity == OverPrivilegedSeverity.MEDIUM:
                severity = OverPrivilegedSeverity.HIGH

        # Elevate for admin permission
        if permission_level == PermissionLevel.ADMIN:
            if severity < OverPrivilegedSeverity.HIGH:
                severity = OverPrivilegedSeverity.HIGH

        # Elevate for service accounts
        if principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.SERVICE_PRINCIPAL,
            PrincipalType.MANAGED_IDENTITY,
        ):
            if severity == OverPrivilegedSeverity.MEDIUM:
                severity = OverPrivilegedSeverity.HIGH
            elif severity == OverPrivilegedSeverity.HIGH and is_sensitive:
                severity = OverPrivilegedSeverity.CRITICAL

        return severity

    def _calculate_risk_score(
        self,
        finding_type: OverPrivilegedFindingType,
        permission_level: PermissionLevel,
        classification: str | None,
        principal_type: PrincipalType,
    ) -> float:
        """Calculate numeric risk score (0-100)."""
        # Base score by finding type
        base_scores = {
            OverPrivilegedFindingType.UNUSED_WRITE_ACCESS: 40.0,
            OverPrivilegedFindingType.UNUSED_DELETE_ACCESS: 30.0,
            OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS: 60.0,
            OverPrivilegedFindingType.BROAD_SENSITIVE_ACCESS: 70.0,
            OverPrivilegedFindingType.STALE_ELEVATED_ACCESS: 25.0,
            OverPrivilegedFindingType.NEVER_USED_ACCESS: 35.0,
        }
        score = base_scores.get(finding_type, 20.0)

        # Add for permission level
        permission_scores = {
            PermissionLevel.ADMIN: 20.0,
            PermissionLevel.WRITE: 10.0,
            PermissionLevel.READ: 5.0,
            PermissionLevel.LIST: 2.0,
        }
        score += permission_scores.get(permission_level, 0.0)

        # Add for data sensitivity
        classification_scores = {
            "top_secret": 25.0,
            "restricted": 20.0,
            "confidential": 15.0,
            "internal": 5.0,
            "public": 0.0,
        }
        if classification:
            score += classification_scores.get(classification.lower(), 5.0)

        # Add for service account type
        if principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.SERVICE_PRINCIPAL,
            PrincipalType.MANAGED_IDENTITY,
        ):
            score += 10.0

        return min(100.0, score)

    def _get_recommended_action(
        self,
        finding_type: OverPrivilegedFindingType,
        access: ResourceAccess,
        pattern: UsagePattern,
    ) -> str:
        """Get recommended action for a finding type."""
        actions = {
            OverPrivilegedFindingType.UNUSED_WRITE_ACCESS: (
                f"Downgrade permission to read-only for '{access.resource_id}'"
            ),
            OverPrivilegedFindingType.UNUSED_DELETE_ACCESS: (
                f"Restrict delete capability on '{access.resource_id}' if not required"
            ),
            OverPrivilegedFindingType.UNUSED_ADMIN_ACCESS: (
                f"Reduce admin permission to {pattern.highest_observed_permission.value} "
                f"for '{access.resource_id}'"
            ),
            OverPrivilegedFindingType.BROAD_SENSITIVE_ACCESS: (
                "Review and reduce access to sensitive resources based on need"
            ),
            OverPrivilegedFindingType.STALE_ELEVATED_ACCESS: (
                f"Review if elevated access to '{access.resource_id}' is still required"
            ),
            OverPrivilegedFindingType.NEVER_USED_ACCESS: (
                f"Remove unused permission to '{access.resource_id}'"
            ),
        }
        return actions.get(finding_type, "Review and reduce permissions as appropriate")

    def _is_sensitive(self, classification: str | None) -> bool:
        """Check if classification indicates sensitive data."""
        if not classification:
            return False
        sensitive_levels = {"confidential", "restricted", "top_secret"}
        return classification.lower() in sensitive_levels

    def _should_include_principal(self, principal: Principal) -> bool:
        """Check if principal should be included based on config."""
        if principal.principal_type == PrincipalType.USER:
            return self._config.include_users
        if principal.principal_type == PrincipalType.ROLE:
            return self._config.include_roles
        if principal.principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.SERVICE_PRINCIPAL,
            PrincipalType.MANAGED_IDENTITY,
        ):
            return self._config.include_service_accounts
        return True


def create_usage_patterns_from_access_review(
    principal_id: str,
    resource_accesses: list[ResourceAccess],
    access_summaries: list[AccessSummary],
) -> list[UsagePattern]:
    """
    Create usage patterns from access review data.

    Helper function to convert DSPM access review results into
    usage patterns for over-privileged analysis.

    Args:
        principal_id: Principal identifier
        resource_accesses: List of resources principal can access
        access_summaries: Access log summaries

    Returns:
        List of usage patterns
    """
    summary_by_resource: dict[str, AccessSummary] = {}
    for summary in access_summaries:
        summary_by_resource[summary.resource_id] = summary

    patterns: list[UsagePattern] = []
    for access in resource_accesses:
        summary = summary_by_resource.get(access.resource_id)
        if summary:
            pattern = UsagePattern(
                principal_id=principal_id,
                resource_id=access.resource_id,
                granted_permission=access.permission_level,
                observed_read_count=summary.read_count,
                observed_write_count=summary.write_count,
                observed_delete_count=summary.delete_count,
                observed_list_count=summary.list_count,
                first_access=summary.first_access,
                last_access=summary.last_access,
                days_since_last_access=summary.days_since_last_access,
                total_access_count=summary.total_access_count,
            )
        else:
            pattern = UsagePattern(
                principal_id=principal_id,
                resource_id=access.resource_id,
                granted_permission=access.permission_level,
            )
        patterns.append(pattern)

    return patterns
