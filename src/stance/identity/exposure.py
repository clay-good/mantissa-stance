"""
Principal Data Exposure Analyzer for Identity Security.

Analyzes what sensitive data each principal can access by correlating
identity permissions with DSPM classification results.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

from stance.identity.base import (
    Principal,
    PrincipalType,
    PermissionLevel,
    ResourceAccess,
    IdentityConfig,
    FindingType,
)
from stance.dspm.classifier import ClassificationLevel, DataCategory

logger = logging.getLogger(__name__)


class ExposureSeverity(Enum):
    """Severity levels for exposure findings."""

    CRITICAL = "critical"  # Access to TOP_SECRET/RESTRICTED with ADMIN
    HIGH = "high"  # Access to CONFIDENTIAL+ with WRITE
    MEDIUM = "medium"  # Access to CONFIDENTIAL with READ
    LOW = "low"  # Access to INTERNAL data
    INFO = "info"  # Access to PUBLIC data

    @classmethod
    def from_classification_and_permission(
        cls,
        classification: ClassificationLevel,
        permission: PermissionLevel,
    ) -> "ExposureSeverity":
        """Calculate severity from classification and permission level."""
        # ADMIN access to sensitive data is always critical
        if permission == PermissionLevel.ADMIN:
            if classification in (ClassificationLevel.TOP_SECRET, ClassificationLevel.RESTRICTED):
                return cls.CRITICAL
            if classification == ClassificationLevel.CONFIDENTIAL:
                return cls.HIGH
            return cls.MEDIUM

        # WRITE access
        if permission == PermissionLevel.WRITE:
            if classification in (ClassificationLevel.TOP_SECRET, ClassificationLevel.RESTRICTED):
                return cls.CRITICAL
            if classification == ClassificationLevel.CONFIDENTIAL:
                return cls.HIGH
            return cls.MEDIUM

        # READ access
        if permission == PermissionLevel.READ:
            if classification in (ClassificationLevel.TOP_SECRET, ClassificationLevel.RESTRICTED):
                return cls.HIGH
            if classification == ClassificationLevel.CONFIDENTIAL:
                return cls.MEDIUM
            return cls.LOW

        # LIST access or lower
        return cls.INFO


@dataclass
class ResourceClassification:
    """
    Classification information for a resource.

    Attributes:
        resource_id: Resource identifier (bucket name, etc.)
        resource_type: Type of resource (s3_bucket, gcs_bucket, etc.)
        classification_level: Data classification level
        categories: Data categories found in the resource
        last_scanned: When the resource was last scanned
        finding_count: Number of DSPM findings in this resource
        metadata: Additional metadata from DSPM scan
    """

    resource_id: str
    resource_type: str
    classification_level: ClassificationLevel
    categories: list[DataCategory] = field(default_factory=list)
    last_scanned: datetime | None = None
    finding_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "classification_level": self.classification_level.value,
            "categories": [c.value for c in self.categories],
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
            "finding_count": self.finding_count,
            "metadata": self.metadata,
        }


@dataclass
class ExposedResource:
    """
    A resource that a principal has access to with classification info.

    Attributes:
        resource_id: Resource identifier
        resource_type: Type of resource
        permission_level: Level of access the principal has
        permission_source: Where the permission comes from (policy, role, etc.)
        classification: Classification information for the resource
        risk_score: Calculated risk score based on classification and access
        policy_ids: Policies granting access
    """

    resource_id: str
    resource_type: str
    permission_level: PermissionLevel
    permission_source: str
    classification: ResourceClassification | None = None
    risk_score: int = 0
    policy_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "permission_level": self.permission_level.value,
            "permission_source": self.permission_source,
            "classification": self.classification.to_dict() if self.classification else None,
            "risk_score": self.risk_score,
            "policy_ids": self.policy_ids,
        }


@dataclass
class ExposureFinding:
    """
    A finding about a principal's exposure to sensitive data.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level
        title: Short title
        description: Detailed description
        principal_id: Principal that has access
        principal_type: Type of principal
        resource_id: Resource with sensitive data
        resource_type: Type of resource
        permission_level: Access level the principal has
        classification_level: Data classification in the resource
        categories: Data categories accessible
        recommended_action: Suggested remediation
        metadata: Additional context
        detected_at: When the finding was created
    """

    finding_id: str
    finding_type: FindingType
    severity: ExposureSeverity
    title: str
    description: str
    principal_id: str
    principal_type: PrincipalType
    resource_id: str
    resource_type: str
    permission_level: PermissionLevel
    classification_level: ClassificationLevel
    categories: list[DataCategory] = field(default_factory=list)
    recommended_action: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
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
            "permission_level": self.permission_level.value,
            "classification_level": self.classification_level.value,
            "categories": [c.value for c in self.categories],
            "recommended_action": self.recommended_action,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class ExposureSummary:
    """
    Summary of a principal's data exposure.

    Attributes:
        principal: The principal being analyzed
        total_resources: Total number of resources accessible
        classified_resources: Number of resources with classification data
        sensitive_resources: Number of resources with CONFIDENTIAL+ data
        resources_by_classification: Count by classification level
        resources_by_category: Count by data category
        highest_classification: Highest classification level accessible
        highest_permission: Highest permission level held
        risk_score: Overall risk score for this principal
    """

    principal: Principal
    total_resources: int = 0
    classified_resources: int = 0
    sensitive_resources: int = 0
    resources_by_classification: dict[str, int] = field(default_factory=dict)
    resources_by_category: dict[str, int] = field(default_factory=dict)
    highest_classification: ClassificationLevel | None = None
    highest_permission: PermissionLevel = PermissionLevel.NONE
    risk_score: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "principal": self.principal.to_dict(),
            "total_resources": self.total_resources,
            "classified_resources": self.classified_resources,
            "sensitive_resources": self.sensitive_resources,
            "resources_by_classification": self.resources_by_classification,
            "resources_by_category": self.resources_by_category,
            "highest_classification": (
                self.highest_classification.value if self.highest_classification else None
            ),
            "highest_permission": self.highest_permission.value,
            "risk_score": self.risk_score,
        }


@dataclass
class ExposureResult:
    """
    Complete result of exposure analysis for a principal.

    Attributes:
        analysis_id: Unique analysis identifier
        principal_id: Principal being analyzed
        summary: Summary of exposure
        exposed_resources: List of accessible resources with classifications
        findings: Security findings
        errors: Any errors during analysis
        started_at: When analysis started
        completed_at: When analysis completed
    """

    analysis_id: str
    principal_id: str
    summary: ExposureSummary | None = None
    exposed_resources: list[ExposedResource] = field(default_factory=list)
    findings: list[ExposureFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "analysis_id": self.analysis_id,
            "principal_id": self.principal_id,
            "summary": self.summary.to_dict() if self.summary else None,
            "exposed_resources": [r.to_dict() for r in self.exposed_resources],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class PrincipalExposureAnalyzer:
    """
    Analyzes what sensitive data a principal can access.

    Combines identity permissions from data access mappers with
    DSPM classification results to determine exposure.
    """

    def __init__(
        self,
        config: IdentityConfig | None = None,
        min_classification: ClassificationLevel = ClassificationLevel.INTERNAL,
    ):
        """
        Initialize the exposure analyzer.

        Args:
            config: Optional identity configuration
            min_classification: Minimum classification level to report
        """
        self._config = config or IdentityConfig()
        self._min_classification = min_classification
        self._classification_cache: dict[str, ResourceClassification] = {}

    def register_classification(
        self,
        resource_id: str,
        classification: ResourceClassification,
    ) -> None:
        """
        Register a resource classification from DSPM scan results.

        Args:
            resource_id: Resource identifier
            classification: Classification information
        """
        self._classification_cache[resource_id] = classification

    def register_classifications(
        self,
        classifications: list[ResourceClassification],
    ) -> None:
        """
        Register multiple resource classifications.

        Args:
            classifications: List of classification information
        """
        for classification in classifications:
            self._classification_cache[classification.resource_id] = classification

    def clear_classifications(self) -> None:
        """Clear the classification cache."""
        self._classification_cache.clear()

    def get_classification(self, resource_id: str) -> ResourceClassification | None:
        """
        Get classification for a resource.

        Args:
            resource_id: Resource identifier

        Returns:
            Classification information or None
        """
        return self._classification_cache.get(resource_id)

    def analyze_principal_exposure(
        self,
        principal: Principal,
        resource_access_list: list[ResourceAccess],
    ) -> ExposureResult:
        """
        Analyze what sensitive data a principal can access.

        Args:
            principal: The principal to analyze
            resource_access_list: List of resources the principal can access

        Returns:
            Exposure analysis result
        """
        analysis_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting exposure analysis for principal={principal.id}, id={analysis_id}"
        )

        result = ExposureResult(
            analysis_id=analysis_id,
            principal_id=principal.id,
            started_at=started_at,
        )

        try:
            exposed_resources: list[ExposedResource] = []
            findings: list[ExposureFinding] = []

            # Process each resource access
            for access in resource_access_list:
                # Get classification if available
                classification = self._classification_cache.get(access.resource_id)

                # Calculate risk score
                risk_score = self._calculate_risk_score(
                    access.permission_level,
                    classification,
                )

                exposed_resource = ExposedResource(
                    resource_id=access.resource_id,
                    resource_type=access.resource_type,
                    permission_level=access.permission_level,
                    permission_source=access.permission_source,
                    classification=classification,
                    risk_score=risk_score,
                    policy_ids=access.policy_ids,
                )
                exposed_resources.append(exposed_resource)

                # Generate findings for sensitive data exposure
                if classification and self._should_generate_finding(classification):
                    finding = self._generate_exposure_finding(
                        principal, access, classification
                    )
                    if finding:
                        findings.append(finding)

            # Generate summary
            summary = self._generate_summary(principal, exposed_resources)

            # Generate additional findings based on summary
            additional_findings = self._generate_summary_findings(principal, summary)
            findings.extend(additional_findings)

            result.exposed_resources = exposed_resources
            result.summary = summary
            result.findings = findings

        except Exception as e:
            error_msg = f"Exposure analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"Exposure analysis complete: {len(result.exposed_resources)} resources, "
            f"{len(result.findings)} findings"
        )

        return result

    def _calculate_risk_score(
        self,
        permission_level: PermissionLevel,
        classification: ResourceClassification | None,
    ) -> int:
        """
        Calculate risk score for a resource access.

        Args:
            permission_level: Permission level
            classification: Resource classification

        Returns:
            Risk score (0-100)
        """
        if not classification:
            return 0

        # Base score from classification level
        classification_scores = {
            ClassificationLevel.PUBLIC: 0,
            ClassificationLevel.INTERNAL: 10,
            ClassificationLevel.CONFIDENTIAL: 40,
            ClassificationLevel.RESTRICTED: 70,
            ClassificationLevel.TOP_SECRET: 90,
        }
        base_score = classification_scores.get(classification.classification_level, 0)

        # Permission multiplier
        permission_multipliers = {
            PermissionLevel.ADMIN: 1.0,
            PermissionLevel.WRITE: 0.9,
            PermissionLevel.READ: 0.7,
            PermissionLevel.LIST: 0.3,
            PermissionLevel.NONE: 0.0,
            PermissionLevel.UNKNOWN: 0.5,
        }
        multiplier = permission_multipliers.get(permission_level, 0.5)

        # Category bonus for high-risk categories
        category_bonus = 0
        high_risk_categories = {
            DataCategory.PII_SSN,
            DataCategory.PCI_CARD_NUMBER,
            DataCategory.PHI_MEDICAL_RECORD,
            DataCategory.CREDENTIALS_PRIVATE_KEY,
            DataCategory.CREDENTIALS_PASSWORD,
        }
        if any(cat in high_risk_categories for cat in classification.categories):
            category_bonus = 10

        return min(100, int(base_score * multiplier + category_bonus))

    def _should_generate_finding(
        self,
        classification: ResourceClassification,
    ) -> bool:
        """
        Determine if a finding should be generated for a classification.

        Args:
            classification: Resource classification

        Returns:
            True if finding should be generated
        """
        classification_order = [
            ClassificationLevel.PUBLIC,
            ClassificationLevel.INTERNAL,
            ClassificationLevel.CONFIDENTIAL,
            ClassificationLevel.RESTRICTED,
            ClassificationLevel.TOP_SECRET,
        ]

        try:
            min_index = classification_order.index(self._min_classification)
            current_index = classification_order.index(classification.classification_level)
            return current_index >= min_index
        except ValueError:
            return False

    def _generate_exposure_finding(
        self,
        principal: Principal,
        access: ResourceAccess,
        classification: ResourceClassification,
    ) -> ExposureFinding | None:
        """
        Generate an exposure finding for sensitive data access.

        Args:
            principal: Principal with access
            access: Resource access
            classification: Resource classification

        Returns:
            Exposure finding or None
        """
        severity = ExposureSeverity.from_classification_and_permission(
            classification.classification_level,
            access.permission_level,
        )

        # Build description
        categories_str = ", ".join(c.value for c in classification.categories[:5])
        if len(classification.categories) > 5:
            categories_str += f" (+{len(classification.categories) - 5} more)"

        description = (
            f"Principal '{principal.name}' ({principal.principal_type.value}) "
            f"has {access.permission_level.value} access to resource '{access.resource_id}' "
            f"which contains {classification.classification_level.value} data"
        )
        if categories_str:
            description += f" including: {categories_str}"

        # Determine finding type
        if principal.principal_type in (
            PrincipalType.SERVICE_ACCOUNT,
            PrincipalType.SERVICE_PRINCIPAL,
            PrincipalType.MANAGED_IDENTITY,
        ):
            finding_type = FindingType.SERVICE_ACCOUNT_RISK
            title = f"Service account has access to {classification.classification_level.value} data"
        else:
            finding_type = FindingType.SENSITIVE_DATA_ACCESS
            title = f"Principal has {access.permission_level.value} access to {classification.classification_level.value} data"

        # Recommended action
        if severity == ExposureSeverity.CRITICAL:
            action = (
                f"Review and restrict {principal.principal_type.value} access to "
                f"{classification.classification_level.value} data immediately. "
                f"Consider implementing least privilege access."
            )
        elif severity == ExposureSeverity.HIGH:
            action = (
                f"Evaluate whether {access.permission_level.value} access is necessary. "
                f"Consider reducing to read-only if write access is not required."
            )
        else:
            action = "Review access periodically and ensure it aligns with job function."

        return ExposureFinding(
            finding_id=f"EXP-{str(uuid.uuid4())[:8]}",
            finding_type=finding_type,
            severity=severity,
            title=title,
            description=description,
            principal_id=principal.id,
            principal_type=principal.principal_type,
            resource_id=access.resource_id,
            resource_type=access.resource_type,
            permission_level=access.permission_level,
            classification_level=classification.classification_level,
            categories=classification.categories,
            recommended_action=action,
        )

    def _generate_summary(
        self,
        principal: Principal,
        exposed_resources: list[ExposedResource],
    ) -> ExposureSummary:
        """
        Generate summary statistics for exposure analysis.

        Args:
            principal: Principal being analyzed
            exposed_resources: List of exposed resources

        Returns:
            Exposure summary
        """
        summary = ExposureSummary(principal=principal)
        summary.total_resources = len(exposed_resources)

        classification_order = [
            ClassificationLevel.PUBLIC,
            ClassificationLevel.INTERNAL,
            ClassificationLevel.CONFIDENTIAL,
            ClassificationLevel.RESTRICTED,
            ClassificationLevel.TOP_SECRET,
        ]

        highest_classification_index = -1
        highest_permission_rank = -1

        for resource in exposed_resources:
            # Track highest permission
            if resource.permission_level.rank > highest_permission_rank:
                highest_permission_rank = resource.permission_level.rank
                summary.highest_permission = resource.permission_level

            if resource.classification:
                summary.classified_resources += 1

                # Count by classification level
                level = resource.classification.classification_level.value
                summary.resources_by_classification[level] = (
                    summary.resources_by_classification.get(level, 0) + 1
                )

                # Track highest classification
                try:
                    level_index = classification_order.index(
                        resource.classification.classification_level
                    )
                    if level_index > highest_classification_index:
                        highest_classification_index = level_index
                        summary.highest_classification = resource.classification.classification_level
                except ValueError:
                    pass

                # Count sensitive resources (CONFIDENTIAL+)
                if resource.classification.classification_level in (
                    ClassificationLevel.CONFIDENTIAL,
                    ClassificationLevel.RESTRICTED,
                    ClassificationLevel.TOP_SECRET,
                ):
                    summary.sensitive_resources += 1

                # Count by category
                for category in resource.classification.categories:
                    cat_value = category.value
                    summary.resources_by_category[cat_value] = (
                        summary.resources_by_category.get(cat_value, 0) + 1
                    )

        # Calculate overall risk score
        summary.risk_score = self._calculate_principal_risk_score(summary)

        return summary

    def _calculate_principal_risk_score(
        self,
        summary: ExposureSummary,
    ) -> int:
        """
        Calculate overall risk score for a principal.

        Args:
            summary: Exposure summary

        Returns:
            Risk score (0-100)
        """
        if summary.total_resources == 0:
            return 0

        # Base score from highest classification
        classification_scores = {
            ClassificationLevel.PUBLIC: 0,
            ClassificationLevel.INTERNAL: 20,
            ClassificationLevel.CONFIDENTIAL: 50,
            ClassificationLevel.RESTRICTED: 80,
            ClassificationLevel.TOP_SECRET: 100,
        }
        base_score = 0
        if summary.highest_classification:
            base_score = classification_scores.get(summary.highest_classification, 0)

        # Permission modifier
        permission_modifiers = {
            PermissionLevel.ADMIN: 1.0,
            PermissionLevel.WRITE: 0.9,
            PermissionLevel.READ: 0.7,
            PermissionLevel.LIST: 0.3,
            PermissionLevel.NONE: 0.0,
            PermissionLevel.UNKNOWN: 0.5,
        }
        permission_modifier = permission_modifiers.get(summary.highest_permission, 0.5)

        # Breadth modifier (access to many sensitive resources increases risk)
        breadth_modifier = 1.0
        if summary.sensitive_resources >= 10:
            breadth_modifier = 1.2
        elif summary.sensitive_resources >= 5:
            breadth_modifier = 1.1

        return min(100, int(base_score * permission_modifier * breadth_modifier))

    def _generate_summary_findings(
        self,
        principal: Principal,
        summary: ExposureSummary,
    ) -> list[ExposureFinding]:
        """
        Generate findings based on summary analysis.

        Args:
            principal: Principal being analyzed
            summary: Exposure summary

        Returns:
            List of findings
        """
        findings: list[ExposureFinding] = []

        # Check for broad access to sensitive data
        if summary.sensitive_resources >= 5:
            severity = (
                ExposureSeverity.CRITICAL
                if summary.sensitive_resources >= 10
                else ExposureSeverity.HIGH
            )

            findings.append(
                ExposureFinding(
                    finding_id=f"EXP-{str(uuid.uuid4())[:8]}",
                    finding_type=FindingType.BROAD_ACCESS,
                    severity=severity,
                    title=f"Principal has broad access to sensitive data",
                    description=(
                        f"Principal '{principal.name}' ({principal.principal_type.value}) "
                        f"has access to {summary.sensitive_resources} resources containing "
                        f"sensitive data (CONFIDENTIAL or higher). This broad access "
                        f"increases the risk of data exposure."
                    ),
                    principal_id=principal.id,
                    principal_type=principal.principal_type,
                    resource_id="multiple",
                    resource_type="various",
                    permission_level=summary.highest_permission,
                    classification_level=(
                        summary.highest_classification or ClassificationLevel.CONFIDENTIAL
                    ),
                    recommended_action=(
                        "Review and reduce access scope. Implement least privilege "
                        "access by limiting access to only required resources."
                    ),
                )
            )

        # Service account with admin access to sensitive data
        if (
            principal.principal_type
            in (
                PrincipalType.SERVICE_ACCOUNT,
                PrincipalType.SERVICE_PRINCIPAL,
                PrincipalType.MANAGED_IDENTITY,
            )
            and summary.highest_permission == PermissionLevel.ADMIN
            and summary.highest_classification
            in (
                ClassificationLevel.CONFIDENTIAL,
                ClassificationLevel.RESTRICTED,
                ClassificationLevel.TOP_SECRET,
            )
        ):
            findings.append(
                ExposureFinding(
                    finding_id=f"EXP-{str(uuid.uuid4())[:8]}",
                    finding_type=FindingType.SERVICE_ACCOUNT_RISK,
                    severity=ExposureSeverity.CRITICAL,
                    title=f"Service account has admin access to sensitive data",
                    description=(
                        f"Service account '{principal.name}' has admin-level access to "
                        f"resources containing {summary.highest_classification.value} data. "
                        f"Service accounts with excessive privileges pose significant security risks."
                    ),
                    principal_id=principal.id,
                    principal_type=principal.principal_type,
                    resource_id="multiple",
                    resource_type="various",
                    permission_level=PermissionLevel.ADMIN,
                    classification_level=summary.highest_classification,
                    recommended_action=(
                        "Reduce service account permissions to minimum required. "
                        "Consider using separate service accounts for different functions."
                    ),
                )
            )

        return findings


def create_classifications_from_scan_results(
    scan_results: list[dict[str, Any]],
) -> list[ResourceClassification]:
    """
    Create ResourceClassification objects from DSPM scan results.

    This helper function converts DSPM ScanResult dictionaries
    into ResourceClassification objects for use with the exposure analyzer.

    Args:
        scan_results: List of DSPM scan result dictionaries

    Returns:
        List of ResourceClassification objects
    """
    classifications: list[ResourceClassification] = []

    for result in scan_results:
        # Extract bucket name from result
        bucket_name = result.get("bucket_name", result.get("resource_id", ""))
        if not bucket_name:
            continue

        # Determine resource type
        resource_type = result.get("resource_type", "unknown")

        # Get highest classification from findings
        classification_level = ClassificationLevel.PUBLIC
        categories: list[DataCategory] = []
        finding_count = 0

        findings = result.get("findings", [])
        for finding in findings:
            finding_count += 1

            # Parse classification level
            level_str = finding.get("classification_level", "public")
            try:
                level = ClassificationLevel(level_str)
                # Track highest classification
                if level.severity_score > classification_level.severity_score:
                    classification_level = level
            except ValueError:
                pass

            # Collect categories
            for cat_str in finding.get("categories", []):
                try:
                    cat = DataCategory(cat_str)
                    if cat not in categories:
                        categories.append(cat)
                except ValueError:
                    pass

        # Parse last scanned time
        last_scanned = None
        scanned_str = result.get("completed_at")
        if scanned_str:
            try:
                last_scanned = datetime.fromisoformat(scanned_str.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        classifications.append(
            ResourceClassification(
                resource_id=bucket_name,
                resource_type=resource_type,
                classification_level=classification_level,
                categories=categories,
                last_scanned=last_scanned,
                finding_count=finding_count,
                metadata=result.get("metadata", {}),
            )
        )

    return classifications
