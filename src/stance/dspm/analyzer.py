"""
Data flow and access analysis for Mantissa Stance DSPM.

Analyzes how sensitive data flows between systems and who has access.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.dspm.classifier import (
    ClassificationLevel,
    DataCategory,
)

logger = logging.getLogger(__name__)


class FlowDirection(Enum):
    """Direction of data flow."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    CROSS_REGION = "cross_region"
    CROSS_ACCOUNT = "cross_account"


class AccessType(Enum):
    """Type of data access."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    UNKNOWN = "unknown"


@dataclass
class DataFlow:
    """
    Represents a data flow between systems.

    Attributes:
        flow_id: Unique identifier for this flow
        source_asset: Source asset ID
        destination_asset: Destination asset ID
        direction: Direction of flow
        data_categories: Categories of data flowing
        classification_level: Highest classification in flow
        encryption_in_transit: Whether data is encrypted in transit
        volume_estimate: Estimated data volume
        frequency: How often flow occurs
        last_observed: When flow was last observed
    """

    flow_id: str
    source_asset: str
    destination_asset: str
    direction: FlowDirection
    data_categories: list[DataCategory] = field(default_factory=list)
    classification_level: ClassificationLevel = ClassificationLevel.PUBLIC
    encryption_in_transit: bool = False
    volume_estimate: str = "unknown"
    frequency: str = "unknown"
    last_observed: datetime | None = None

    @property
    def is_cross_boundary(self) -> bool:
        """Check if flow crosses security boundaries."""
        return self.direction in (
            FlowDirection.CROSS_REGION,
            FlowDirection.CROSS_ACCOUNT,
            FlowDirection.OUTBOUND,
        )

    @property
    def requires_encryption(self) -> bool:
        """Check if flow should require encryption."""
        return self.classification_level.severity_score >= 50


@dataclass
class ResidencyViolation:
    """
    Data residency compliance violation.

    Attributes:
        violation_id: Unique identifier
        asset_id: Asset with violation
        data_categories: Categories of data affected
        required_regions: Regions where data should reside
        actual_region: Where data actually resides
        compliance_frameworks: Affected compliance frameworks
        severity: Severity of violation
        remediation: Suggested remediation
    """

    violation_id: str
    asset_id: str
    data_categories: list[DataCategory]
    required_regions: list[str]
    actual_region: str
    compliance_frameworks: list[str] = field(default_factory=list)
    severity: str = "high"
    remediation: str = ""


@dataclass
class AccessPattern:
    """
    Data access pattern analysis.

    Attributes:
        asset_id: Asset being accessed
        principal_id: Who is accessing
        principal_type: Type of principal (user, role, service)
        access_type: Type of access
        frequency: Access frequency
        last_access: When last accessed
        is_anomalous: Whether access pattern is anomalous
        risk_score: Risk score for this pattern
    """

    asset_id: str
    principal_id: str
    principal_type: str
    access_type: AccessType
    frequency: str = "unknown"
    last_access: datetime | None = None
    is_anomalous: bool = False
    risk_score: float = 0.0


class DataFlowAnalyzer:
    """
    Analyzes data flows between systems to identify risks.

    Tracks how sensitive data moves through the environment
    and identifies potential security and compliance issues.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize data flow analyzer.

        Args:
            config: Optional configuration
        """
        self._config = config or {}
        self._flows: dict[str, DataFlow] = {}

    def add_flow(self, flow: DataFlow) -> None:
        """
        Register a data flow.

        Args:
            flow: Data flow to register
        """
        self._flows[flow.flow_id] = flow

    def get_flow(self, flow_id: str) -> DataFlow | None:
        """Get a specific flow by ID."""
        return self._flows.get(flow_id)

    def get_flows_for_asset(self, asset_id: str) -> list[DataFlow]:
        """Get all flows involving an asset."""
        return [
            f for f in self._flows.values()
            if f.source_asset == asset_id or f.destination_asset == asset_id
        ]

    def analyze_flow_risks(self, flow: DataFlow) -> list[dict[str, Any]]:
        """
        Analyze risks associated with a data flow.

        Args:
            flow: Data flow to analyze

        Returns:
            List of identified risks
        """
        risks: list[dict[str, Any]] = []

        # Check for unencrypted sensitive data in transit
        if flow.requires_encryption and not flow.encryption_in_transit:
            risks.append({
                "type": "unencrypted_sensitive_data",
                "severity": "high",
                "description": f"Sensitive data ({flow.classification_level.value}) "
                              f"flows without encryption in transit",
                "flow_id": flow.flow_id,
                "remediation": "Enable TLS/encryption for data in transit",
            })

        # Check for cross-boundary flows of sensitive data
        if flow.is_cross_boundary:
            if flow.classification_level.severity_score >= 75:
                risks.append({
                    "type": "cross_boundary_sensitive_data",
                    "severity": "high",
                    "description": f"Restricted/Top-secret data crosses "
                                  f"{flow.direction.value} boundary",
                    "flow_id": flow.flow_id,
                    "remediation": "Review data flow necessity and add controls",
                })

        # Check for PCI data flows
        pci_categories = {
            DataCategory.PCI,
            DataCategory.PCI_CARD_NUMBER,
            DataCategory.PCI_CVV,
        }
        if pci_categories.intersection(flow.data_categories):
            if flow.direction == FlowDirection.OUTBOUND:
                risks.append({
                    "type": "pci_data_outbound",
                    "severity": "critical",
                    "description": "PCI card data flows to external destination",
                    "flow_id": flow.flow_id,
                    "remediation": "Ensure PCI-DSS compliance for data flows",
                })

        # Check for PHI data flows
        phi_categories = {
            DataCategory.PHI,
            DataCategory.PHI_MEDICAL_RECORD,
            DataCategory.PHI_DIAGNOSIS,
        }
        if phi_categories.intersection(flow.data_categories):
            if not flow.encryption_in_transit:
                risks.append({
                    "type": "phi_unencrypted",
                    "severity": "critical",
                    "description": "Protected health information flows without encryption",
                    "flow_id": flow.flow_id,
                    "remediation": "Encrypt all PHI in transit per HIPAA requirements",
                })

        return risks

    def get_all_risks(self) -> list[dict[str, Any]]:
        """Analyze risks for all registered flows."""
        all_risks: list[dict[str, Any]] = []
        for flow in self._flows.values():
            all_risks.extend(self.analyze_flow_risks(flow))
        return all_risks

    def get_flow_graph(self) -> dict[str, Any]:
        """
        Generate a graph representation of data flows.

        Returns:
            Graph with nodes (assets) and edges (flows)
        """
        nodes: set[str] = set()
        edges: list[dict[str, Any]] = []

        for flow in self._flows.values():
            nodes.add(flow.source_asset)
            nodes.add(flow.destination_asset)
            edges.append({
                "source": flow.source_asset,
                "target": flow.destination_asset,
                "direction": flow.direction.value,
                "classification": flow.classification_level.value,
                "encrypted": flow.encryption_in_transit,
            })

        return {
            "nodes": list(nodes),
            "edges": edges,
        }


class DataResidencyChecker:
    """
    Checks data residency compliance.

    Ensures sensitive data resides in approved geographic regions
    based on compliance requirements.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize residency checker.

        Args:
            config: Optional configuration with residency rules
        """
        self._config = config or {}
        self._rules: dict[str, list[str]] = {}
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load default residency rules by compliance framework."""
        # GDPR requires EU data to stay in EU/approved countries
        self._rules["GDPR"] = [
            "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-central-1", "eu-north-1", "eu-south-1",
            "europe-west1", "europe-west2", "europe-west3",
            "europe-west4", "europe-west6", "europe-north1",
            "westeurope", "northeurope", "germanywestcentral",
            "francecentral", "swedencentral",
        ]

        # China data localization
        self._rules["CHINA_PIPL"] = [
            "cn-north-1", "cn-northwest-1",
            "asia-east2",
            "chinaeast", "chinanorth",
        ]

        # Russia data localization
        self._rules["RUSSIA_DPL"] = [
            # No major cloud regions in Russia
        ]

        # US Federal (FedRAMP)
        self._rules["FEDRAMP"] = [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "us-gov-east-1", "us-gov-west-1",
            "us-central1", "us-east1", "us-east4", "us-west1",
            "eastus", "eastus2", "westus", "westus2", "centralus",
            "usgovvirginia", "usgovarizona",
        ]

    def add_rule(self, framework: str, allowed_regions: list[str]) -> None:
        """
        Add a residency rule.

        Args:
            framework: Compliance framework name
            allowed_regions: List of allowed regions
        """
        self._rules[framework] = allowed_regions

    def check_compliance(
        self,
        asset_id: str,
        actual_region: str,
        data_categories: list[DataCategory],
    ) -> list[ResidencyViolation]:
        """
        Check if asset location complies with residency requirements.

        Args:
            asset_id: Asset to check
            actual_region: Where asset is located
            data_categories: Categories of data in asset

        Returns:
            List of residency violations
        """
        violations: list[ResidencyViolation] = []

        # Determine applicable frameworks based on data categories
        applicable_frameworks = self._get_applicable_frameworks(data_categories)

        for framework in applicable_frameworks:
            if framework not in self._rules:
                continue

            allowed_regions = self._rules[framework]
            if not allowed_regions:
                continue

            # Normalize region name for comparison
            region_lower = actual_region.lower()
            allowed_lower = [r.lower() for r in allowed_regions]

            if region_lower not in allowed_lower:
                violations.append(
                    ResidencyViolation(
                        violation_id=f"{asset_id}-{framework}-residency",
                        asset_id=asset_id,
                        data_categories=data_categories,
                        required_regions=allowed_regions,
                        actual_region=actual_region,
                        compliance_frameworks=[framework],
                        severity="high",
                        remediation=f"Migrate data to approved region for {framework} compliance",
                    )
                )

        return violations

    def _get_applicable_frameworks(
        self, categories: list[DataCategory]
    ) -> list[str]:
        """Determine applicable compliance frameworks."""
        frameworks: set[str] = set()

        # PII triggers GDPR for EU subjects
        pii_categories = {
            DataCategory.PII,
            DataCategory.PII_SSN,
            DataCategory.PII_EMAIL,
            DataCategory.PII_PHONE,
            DataCategory.PII_DOB,
        }
        if pii_categories.intersection(categories):
            frameworks.add("GDPR")

        # PHI triggers HIPAA
        phi_categories = {
            DataCategory.PHI,
            DataCategory.PHI_MEDICAL_RECORD,
            DataCategory.PHI_DIAGNOSIS,
        }
        if phi_categories.intersection(categories):
            frameworks.add("HIPAA")

        return list(frameworks)


class DataAccessAnalyzer:
    """
    Analyzes data access patterns to identify risks.

    Tracks who accesses sensitive data and identifies
    anomalous or risky access patterns.
    """

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize access analyzer.

        Args:
            config: Optional configuration
        """
        self._config = config or {}
        self._patterns: list[AccessPattern] = []
        self._baseline: dict[str, dict[str, Any]] = {}

    def record_access(self, pattern: AccessPattern) -> None:
        """
        Record an access pattern.

        Args:
            pattern: Access pattern to record
        """
        self._patterns.append(pattern)
        self._update_baseline(pattern)

    def _update_baseline(self, pattern: AccessPattern) -> None:
        """Update baseline for anomaly detection."""
        key = f"{pattern.asset_id}:{pattern.principal_id}"

        if key not in self._baseline:
            self._baseline[key] = {
                "access_count": 0,
                "access_types": set(),
                "first_seen": pattern.last_access,
                "last_seen": pattern.last_access,
            }

        baseline = self._baseline[key]
        baseline["access_count"] += 1
        baseline["access_types"].add(pattern.access_type)
        baseline["last_seen"] = pattern.last_access

    def analyze_access_risks(
        self,
        asset_id: str,
        classification_level: ClassificationLevel,
    ) -> list[dict[str, Any]]:
        """
        Analyze access risks for an asset.

        Args:
            asset_id: Asset to analyze
            classification_level: Classification level of asset

        Returns:
            List of identified access risks
        """
        risks: list[dict[str, Any]] = []
        asset_patterns = [p for p in self._patterns if p.asset_id == asset_id]

        # Count unique principals
        principals = set(p.principal_id for p in asset_patterns)

        # Check for excessive access
        if len(principals) > 50 and classification_level.severity_score >= 50:
            risks.append({
                "type": "excessive_access",
                "severity": "medium",
                "description": f"{len(principals)} principals have access to "
                              f"{classification_level.value} data",
                "asset_id": asset_id,
                "remediation": "Review and restrict access to need-to-know basis",
            })

        # Check for anomalous patterns
        for pattern in asset_patterns:
            if pattern.is_anomalous:
                risks.append({
                    "type": "anomalous_access",
                    "severity": "high",
                    "description": f"Anomalous access by {pattern.principal_id}",
                    "asset_id": asset_id,
                    "principal": pattern.principal_id,
                    "remediation": "Investigate unusual access pattern",
                })

        # Check for admin access to sensitive data
        admin_access = [
            p for p in asset_patterns
            if p.access_type == AccessType.ADMIN
        ]
        if admin_access and classification_level.severity_score >= 75:
            risks.append({
                "type": "admin_access_sensitive",
                "severity": "medium",
                "description": f"{len(admin_access)} admin access patterns to "
                              f"restricted data",
                "asset_id": asset_id,
                "remediation": "Implement privileged access management",
            })

        return risks

    def get_access_summary(self, asset_id: str) -> dict[str, Any]:
        """
        Get access summary for an asset.

        Args:
            asset_id: Asset to summarize

        Returns:
            Summary of access patterns
        """
        asset_patterns = [p for p in self._patterns if p.asset_id == asset_id]

        if not asset_patterns:
            return {
                "asset_id": asset_id,
                "total_access_events": 0,
                "unique_principals": 0,
                "access_types": [],
            }

        access_types = set()
        principals = set()
        risk_scores: list[float] = []

        for pattern in asset_patterns:
            access_types.add(pattern.access_type.value)
            principals.add(pattern.principal_id)
            risk_scores.append(pattern.risk_score)

        return {
            "asset_id": asset_id,
            "total_access_events": len(asset_patterns),
            "unique_principals": len(principals),
            "access_types": list(access_types),
            "average_risk_score": sum(risk_scores) / len(risk_scores) if risk_scores else 0,
            "high_risk_count": sum(1 for s in risk_scores if s > 0.7),
        }

    def detect_anomalies(
        self,
        pattern: AccessPattern,
        threshold: float = 2.0,
    ) -> bool:
        """
        Detect if an access pattern is anomalous.

        Args:
            pattern: Access pattern to check
            threshold: Standard deviation threshold

        Returns:
            True if pattern is anomalous
        """
        key = f"{pattern.asset_id}:{pattern.principal_id}"

        if key not in self._baseline:
            # New principal accessing asset - potentially anomalous
            return True

        baseline = self._baseline[key]

        # Check for new access type
        if pattern.access_type not in baseline["access_types"]:
            return True

        # Check for access outside normal hours (simplified)
        if pattern.last_access:
            hour = pattern.last_access.hour
            if hour < 6 or hour > 22:  # Outside 6 AM - 10 PM
                return True

        return False

    def get_patterns(self) -> list[AccessPattern]:
        """Get all recorded access patterns."""
        return self._patterns.copy()

    def clear_patterns(self) -> None:
        """Clear all recorded patterns."""
        self._patterns.clear()
        self._baseline.clear()
