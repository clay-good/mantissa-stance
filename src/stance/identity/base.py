"""
Base classes for Identity Security data access mapping.

Provides abstract base class and common data models for mapping
which principals can access which data resources.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class PrincipalType(Enum):
    """Types of identity principals."""

    USER = "user"
    ROLE = "role"
    GROUP = "group"
    SERVICE_ACCOUNT = "service_account"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    FEDERATED = "federated"
    UNKNOWN = "unknown"


class PermissionLevel(Enum):
    """Permission levels for resource access."""

    ADMIN = "admin"  # Full control (create/delete bucket, modify IAM)
    WRITE = "write"  # Read + write objects
    READ = "read"  # Read objects only
    LIST = "list"  # List objects only
    NONE = "none"  # No access
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison (higher = more privileged)."""
        ranks = {
            PermissionLevel.ADMIN: 4,
            PermissionLevel.WRITE: 3,
            PermissionLevel.READ: 2,
            PermissionLevel.LIST: 1,
            PermissionLevel.NONE: 0,
            PermissionLevel.UNKNOWN: -1,
        }
        return ranks.get(self, -1)

    def __gt__(self, other: "PermissionLevel") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "PermissionLevel") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: "PermissionLevel") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "PermissionLevel") -> bool:
        return self.rank <= other.rank


class FindingType(Enum):
    """Types of identity security findings."""

    BROAD_ACCESS = "broad_access"  # Access to many sensitive resources
    UNUSED_ACCESS = "unused_access"  # Has access but never used
    OVER_PRIVILEGED = "over_privileged"  # Write access with only reads
    SENSITIVE_DATA_ACCESS = "sensitive_data_access"  # Access to classified data
    SERVICE_ACCOUNT_RISK = "service_account_risk"  # Service account with broad access
    CROSS_ACCOUNT_ACCESS = "cross_account_access"  # External principal access


@dataclass
class IdentityConfig:
    """
    Configuration for identity security analysis.

    Attributes:
        include_users: Whether to include user principals
        include_roles: Whether to include IAM roles
        include_service_accounts: Whether to include service accounts
        include_groups: Whether to include groups
        include_inherited: Whether to include inherited permissions (via groups)
        min_sensitivity_level: Minimum data sensitivity to flag
        stale_days: Days without access to consider stale
    """

    include_users: bool = True
    include_roles: bool = True
    include_service_accounts: bool = True
    include_groups: bool = True
    include_inherited: bool = True
    min_sensitivity_level: str = "internal"  # public, internal, confidential, restricted
    stale_days: int = 90


@dataclass
class Principal:
    """
    An identity principal (user, role, service account, etc.).

    Attributes:
        id: Unique identifier (ARN, email, etc.)
        name: Display name
        principal_type: Type of principal
        cloud_provider: Cloud provider (aws, gcp, azure)
        account_id: Cloud account/project ID
        created_at: When the principal was created
        last_authenticated: Last authentication time
        metadata: Additional metadata
    """

    id: str
    name: str
    principal_type: PrincipalType
    cloud_provider: str
    account_id: str | None = None
    created_at: datetime | None = None
    last_authenticated: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert principal to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "principal_type": self.principal_type.value,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_authenticated": (
                self.last_authenticated.isoformat()
                if self.last_authenticated
                else None
            ),
            "metadata": self.metadata,
        }


@dataclass
class ResourceAccess:
    """
    Access to a specific resource.

    Attributes:
        resource_id: Resource identifier (bucket name, ARN, etc.)
        resource_type: Type of resource (s3_bucket, gcs_bucket, etc.)
        permission_level: Level of access
        permission_source: How permission is granted (direct, via_group, via_role)
        policy_ids: Policy IDs granting this access
        conditions: Any conditions on the access
        data_classification: DSPM classification if available
        last_accessed: Last access time if available
    """

    resource_id: str
    resource_type: str
    permission_level: PermissionLevel
    permission_source: str = "direct"
    policy_ids: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)
    data_classification: str | None = None
    last_accessed: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "permission_level": self.permission_level.value,
            "permission_source": self.permission_source,
            "policy_ids": self.policy_ids,
            "conditions": self.conditions,
            "data_classification": self.data_classification,
            "last_accessed": (
                self.last_accessed.isoformat() if self.last_accessed else None
            ),
        }


@dataclass
class DataAccessMapping:
    """
    Mapping of who can access a resource.

    Attributes:
        resource_id: Resource being analyzed
        resource_type: Type of resource
        cloud_provider: Cloud provider
        data_classification: DSPM classification if available
        principals: List of principals with access
        total_principals: Total count of principals
        principals_by_type: Count by principal type
        principals_by_level: Count by permission level
        highest_risk_principal: Principal with highest risk
    """

    resource_id: str
    resource_type: str
    cloud_provider: str
    data_classification: str | None = None
    principals: list[tuple[Principal, ResourceAccess]] = field(default_factory=list)
    total_principals: int = 0
    principals_by_type: dict[str, int] = field(default_factory=dict)
    principals_by_level: dict[str, int] = field(default_factory=dict)
    highest_risk_principal: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "cloud_provider": self.cloud_provider,
            "data_classification": self.data_classification,
            "total_principals": self.total_principals,
            "principals_by_type": self.principals_by_type,
            "principals_by_level": self.principals_by_level,
            "highest_risk_principal": self.highest_risk_principal,
            "principals": [
                {
                    "principal": p.to_dict(),
                    "access": a.to_dict(),
                }
                for p, a in self.principals
            ],
        }


@dataclass
class DataAccessFinding:
    """
    A finding from identity security analysis.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level (critical, high, medium, low)
        title: Short title
        description: Detailed description
        principal_id: Affected principal
        principal_type: Type of principal
        resource_id: Affected resource
        resource_type: Type of resource
        permission_level: Current permission level
        data_classification: Data sensitivity if known
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
    principal_type: PrincipalType
    resource_id: str
    resource_type: str
    permission_level: PermissionLevel = PermissionLevel.UNKNOWN
    data_classification: str | None = None
    recommended_action: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "principal_id": self.principal_id,
            "principal_type": self.principal_type.value,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "permission_level": self.permission_level.value,
            "data_classification": self.data_classification,
            "recommended_action": self.recommended_action,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class DataAccessResult:
    """
    Result of data access mapping analysis.

    Attributes:
        analysis_id: Unique identifier
        resource_id: Resource analyzed
        config: Configuration used
        started_at: Analysis start time
        completed_at: Analysis completion time
        mapping: Data access mapping
        findings: List of findings
        total_principals: Total principals with access
        principals_with_sensitive_access: Principals accessing sensitive data
        errors: Errors encountered
    """

    analysis_id: str
    resource_id: str
    config: IdentityConfig
    started_at: datetime
    completed_at: datetime | None = None
    mapping: DataAccessMapping | None = None
    findings: list[DataAccessFinding] = field(default_factory=list)
    total_principals: int = 0
    principals_with_sensitive_access: int = 0
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
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "analysis_id": self.analysis_id,
            "resource_id": self.resource_id,
            "config": {
                "include_users": self.config.include_users,
                "include_roles": self.config.include_roles,
                "include_service_accounts": self.config.include_service_accounts,
                "stale_days": self.config.stale_days,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "mapping": self.mapping.to_dict() if self.mapping else None,
            "findings_count": len(self.findings),
            "findings_by_type": self.findings_by_type,
            "findings_by_severity": self.findings_by_severity,
            "total_principals": self.total_principals,
            "principals_with_sensitive_access": self.principals_with_sensitive_access,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


class BaseDataAccessMapper(ABC):
    """
    Abstract base class for data access mappers.

    Subclasses implement cloud-specific logic for determining
    which principals can access which resources.

    All operations are read-only.
    """

    cloud_provider = "unknown"

    def __init__(self, config: IdentityConfig | None = None):
        """
        Initialize the data access mapper.

        Args:
            config: Optional configuration for identity analysis
        """
        self._config = config or IdentityConfig()

    @property
    def config(self) -> IdentityConfig:
        """Get the analysis configuration."""
        return self._config

    @abstractmethod
    def who_can_access(self, resource_id: str) -> DataAccessResult:
        """
        Determine who can access a specific resource.

        Args:
            resource_id: Resource to analyze (bucket name, ARN, etc.)

        Returns:
            Data access result with mapping and findings
        """
        pass

    @abstractmethod
    def get_principal_access(
        self, principal_id: str
    ) -> list[ResourceAccess]:
        """
        Get all resources a principal can access.

        Args:
            principal_id: Principal to analyze

        Returns:
            List of resource access entries
        """
        pass

    @abstractmethod
    def list_principals(self) -> Iterator[Principal]:
        """
        List all principals in the account/project.

        Yields:
            Principal objects
        """
        pass

    @abstractmethod
    def get_resource_policy(
        self, resource_id: str
    ) -> dict[str, Any] | None:
        """
        Get the resource-based policy for a resource.

        Args:
            resource_id: Resource identifier

        Returns:
            Policy document or None
        """
        pass

    def _get_severity_for_access(
        self,
        permission_level: PermissionLevel,
        data_classification: str | None,
        principal_type: PrincipalType,
    ) -> str:
        """
        Determine severity based on access characteristics.

        Args:
            permission_level: Level of access
            data_classification: Data sensitivity
            principal_type: Type of principal

        Returns:
            Severity level string
        """
        # High sensitivity data with write access
        if data_classification in ("restricted", "confidential"):
            if permission_level >= PermissionLevel.WRITE:
                return "critical"
            if permission_level == PermissionLevel.READ:
                return "high"

        # Service accounts with broad access are risky
        if principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.MANAGED_IDENTITY,
        ):
            if permission_level >= PermissionLevel.WRITE:
                return "high"
            if permission_level == PermissionLevel.READ:
                return "medium"

        # Admin access is always elevated
        if permission_level == PermissionLevel.ADMIN:
            return "high"

        # Write access to internal data
        if permission_level >= PermissionLevel.WRITE:
            return "medium"

        return "low"

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
        if principal.principal_type == PrincipalType.GROUP:
            return self._config.include_groups
        return True

    def _generate_findings(
        self,
        mapping: DataAccessMapping,
    ) -> list[DataAccessFinding]:
        """
        Generate findings from a data access mapping.

        Args:
            mapping: Data access mapping

        Returns:
            List of findings
        """
        findings: list[DataAccessFinding] = []
        finding_counter = 0

        # Count service accounts with access
        service_account_count = 0
        admin_count = 0

        for principal, access in mapping.principals:
            # Check for service account access to sensitive data
            if principal.principal_type in (
                PrincipalType.SERVICE_ACCOUNT,
                PrincipalType.SERVICE_PRINCIPAL,
                PrincipalType.MANAGED_IDENTITY,
            ):
                service_account_count += 1
                if (
                    mapping.data_classification in ("restricted", "confidential")
                    and access.permission_level >= PermissionLevel.READ
                ):
                    finding_counter += 1
                    findings.append(
                        DataAccessFinding(
                            finding_id=f"{mapping.resource_id}-identity-{finding_counter:04d}",
                            finding_type=FindingType.SERVICE_ACCOUNT_RISK,
                            severity=self._get_severity_for_access(
                                access.permission_level,
                                mapping.data_classification,
                                principal.principal_type,
                            ),
                            title=f"Service account with {mapping.data_classification} data access",
                            description=(
                                f"Service account '{principal.name}' has {access.permission_level.value} "
                                f"access to {mapping.resource_id} which contains {mapping.data_classification} data."
                            ),
                            principal_id=principal.id,
                            principal_type=principal.principal_type,
                            resource_id=mapping.resource_id,
                            resource_type=mapping.resource_type,
                            permission_level=access.permission_level,
                            data_classification=mapping.data_classification,
                            recommended_action=(
                                f"Review if {principal.name} requires {access.permission_level.value} "
                                f"access to {mapping.data_classification} data"
                            ),
                        )
                    )

            # Count admins
            if access.permission_level == PermissionLevel.ADMIN:
                admin_count += 1

        # Finding for many principals with sensitive data access
        if (
            mapping.data_classification in ("restricted", "confidential")
            and mapping.total_principals > 10
        ):
            finding_counter += 1
            findings.append(
                DataAccessFinding(
                    finding_id=f"{mapping.resource_id}-identity-{finding_counter:04d}",
                    finding_type=FindingType.BROAD_ACCESS,
                    severity="high",
                    title=f"Broad access to {mapping.data_classification} data",
                    description=(
                        f"{mapping.total_principals} principals can access {mapping.resource_id} "
                        f"which contains {mapping.data_classification} data. "
                        f"Consider applying least privilege principles."
                    ),
                    principal_id="multiple",
                    principal_type=PrincipalType.UNKNOWN,
                    resource_id=mapping.resource_id,
                    resource_type=mapping.resource_type,
                    data_classification=mapping.data_classification,
                    recommended_action=(
                        f"Review access policies for {mapping.resource_id} and remove unnecessary permissions"
                    ),
                    metadata={
                        "principal_count": mapping.total_principals,
                        "admin_count": admin_count,
                        "service_account_count": service_account_count,
                    },
                )
            )

        # Finding for many admin principals
        if admin_count > 5:
            finding_counter += 1
            findings.append(
                DataAccessFinding(
                    finding_id=f"{mapping.resource_id}-identity-{finding_counter:04d}",
                    finding_type=FindingType.BROAD_ACCESS,
                    severity="medium",
                    title=f"Many principals with admin access",
                    description=(
                        f"{admin_count} principals have admin access to {mapping.resource_id}. "
                        f"Consider reducing the number of administrators."
                    ),
                    principal_id="multiple",
                    principal_type=PrincipalType.UNKNOWN,
                    resource_id=mapping.resource_id,
                    resource_type=mapping.resource_type,
                    permission_level=PermissionLevel.ADMIN,
                    data_classification=mapping.data_classification,
                    recommended_action="Review and reduce admin access where possible",
                    metadata={"admin_count": admin_count},
                )
            )

        return findings

    def _parse_permission_level(self, actions: list[str]) -> PermissionLevel:
        """
        Parse permission level from a list of actions.

        Args:
            actions: List of action strings

        Returns:
            Permission level
        """
        has_admin = False
        has_write = False
        has_read = False
        has_list = False

        for action in actions:
            action_lower = action.lower()

            # Check for wildcard
            if action == "*" or action.endswith(":*"):
                return PermissionLevel.ADMIN

            # Admin actions
            if any(
                x in action_lower
                for x in [
                    "deletebucket",
                    "putbucketpolicy",
                    "createbucket",
                    "admin",
                    "fullcontrol",
                    "putbucketacl",
                ]
            ):
                has_admin = True

            # Write actions
            elif any(
                x in action_lower
                for x in [
                    "put",
                    "write",
                    "upload",
                    "create",
                    "delete",
                    "update",
                    "modify",
                ]
            ):
                has_write = True

            # Read actions
            elif any(x in action_lower for x in ["get", "read", "head", "download"]):
                has_read = True

            # List actions
            elif "list" in action_lower:
                has_list = True

        if has_admin:
            return PermissionLevel.ADMIN
        if has_write:
            return PermissionLevel.WRITE
        if has_read:
            return PermissionLevel.READ
        if has_list:
            return PermissionLevel.LIST

        return PermissionLevel.UNKNOWN
