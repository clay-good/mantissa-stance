"""
Blast Radius Calculator for Mantissa Stance.

Calculates the potential impact of security findings by analyzing
the scope of affected resources through asset relationships.

The blast radius helps prioritize findings based on their potential
downstream impact rather than just the severity of the finding itself.

Reference: Wiz/Orca blast radius analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.analytics.asset_graph import AssetGraph, AssetNode, RelationshipType
from stance.models.finding import Finding, FindingCollection, Severity


class ImpactCategory(Enum):
    """Categories of potential impact from a security finding."""

    DATA_EXPOSURE = "data_exposure"
    SERVICE_DISRUPTION = "service_disruption"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    COMPLIANCE_VIOLATION = "compliance_violation"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"


@dataclass
class AffectedResource:
    """
    A resource affected by a finding's blast radius.

    Attributes:
        asset_id: ID of the affected asset
        asset_name: Human-readable name of the asset
        resource_type: Type of the resource
        impact_type: How the resource is impacted
        relationship_path: Path from the finding to this resource
        distance: Number of hops from the source finding
        impact_score: Calculated impact score for this resource
    """

    asset_id: str
    asset_name: str
    resource_type: str
    impact_type: str
    relationship_path: list[str] = field(default_factory=list)
    distance: int = 0
    impact_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "resource_type": self.resource_type,
            "impact_type": self.impact_type,
            "relationship_path": self.relationship_path,
            "distance": self.distance,
            "impact_score": self.impact_score,
        }


@dataclass
class BlastRadius:
    """
    Represents the calculated blast radius of a security finding.

    Attributes:
        finding_id: ID of the source finding
        finding_severity: Original severity of the finding
        source_asset_id: ID of the asset with the finding
        source_asset_name: Name of the asset with the finding
        directly_affected: Resources directly affected (distance=1)
        indirectly_affected: Resources indirectly affected (distance>1)
        impact_categories: Categories of impact detected
        data_exposure_risk: Data exposure risk assessment
        service_disruption_risk: Service disruption risk assessment
        compliance_implications: List of compliance implications
        total_affected_count: Total number of affected resources
        blast_radius_score: Overall blast radius score (0-100)
        adjusted_severity: Severity adjusted based on blast radius
    """

    finding_id: str
    finding_severity: Severity
    source_asset_id: str
    source_asset_name: str
    directly_affected: list[AffectedResource] = field(default_factory=list)
    indirectly_affected: list[AffectedResource] = field(default_factory=list)
    impact_categories: list[ImpactCategory] = field(default_factory=list)
    data_exposure_risk: str = "none"
    service_disruption_risk: str = "none"
    compliance_implications: list[str] = field(default_factory=list)
    total_affected_count: int = 0
    blast_radius_score: float = 0.0
    adjusted_severity: Severity = Severity.INFO

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_severity": self.finding_severity.value,
            "source_asset_id": self.source_asset_id,
            "source_asset_name": self.source_asset_name,
            "directly_affected": [r.to_dict() for r in self.directly_affected],
            "indirectly_affected": [r.to_dict() for r in self.indirectly_affected],
            "impact_categories": [c.value for c in self.impact_categories],
            "data_exposure_risk": self.data_exposure_risk,
            "service_disruption_risk": self.service_disruption_risk,
            "compliance_implications": self.compliance_implications,
            "total_affected_count": self.total_affected_count,
            "blast_radius_score": self.blast_radius_score,
            "adjusted_severity": self.adjusted_severity.value,
        }


class BlastRadiusCalculator:
    """
    Calculates the blast radius of security findings.

    Analyzes asset relationships to determine the potential
    downstream impact of security findings.
    """

    # Data store types that indicate data exposure risk
    DATA_STORE_TYPES = {
        "aws_s3_bucket",
        "aws_rds_instance",
        "aws_dynamodb_table",
        "aws_redshift_cluster",
        "aws_elasticache_cluster",
        "aws_elasticsearch_domain",
        "gcp_storage_bucket",
        "gcp_sql_instance",
        "gcp_bigtable_instance",
        "gcp_bigquery_dataset",
        "azure_storage_account",
        "azure_sql_database",
        "azure_cosmosdb_account",
    }

    # Compute types that indicate service disruption risk
    COMPUTE_TYPES = {
        "aws_ec2_instance",
        "aws_lambda_function",
        "aws_ecs_service",
        "aws_ecs_task",
        "aws_eks_cluster",
        "aws_autoscaling_group",
        "gcp_compute_instance",
        "gcp_cloud_function",
        "gcp_cloud_run",
        "gcp_gke_cluster",
        "azure_virtual_machine",
        "azure_function_app",
        "azure_container_instance",
        "azure_aks_cluster",
    }

    # Identity types that indicate credential/privilege risk
    IDENTITY_TYPES = {
        "aws_iam_role",
        "aws_iam_user",
        "aws_iam_group",
        "aws_iam_policy",
        "gcp_service_account",
        "gcp_iam_policy",
        "azure_service_principal",
        "azure_managed_identity",
        "azure_role_assignment",
    }

    # Secrets/credential types
    SECRETS_TYPES = {
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_kms_key",
        "gcp_secret",
        "gcp_kms_key",
        "azure_key_vault",
        "azure_key_vault_secret",
    }

    # Network types that can enable lateral movement
    NETWORK_TYPES = {
        "aws_vpc",
        "aws_subnet",
        "aws_security_group",
        "aws_network_acl",
        "gcp_network",
        "gcp_subnetwork",
        "gcp_firewall",
        "azure_virtual_network",
        "azure_subnet",
        "azure_network_security_group",
    }

    # Compliance framework mapping by resource type
    COMPLIANCE_MAPPING = {
        "aws_s3_bucket": ["PCI-DSS", "SOC2", "HIPAA", "GDPR"],
        "aws_rds_instance": ["PCI-DSS", "SOC2", "HIPAA"],
        "aws_iam_user": ["CIS", "SOC2", "NIST"],
        "aws_iam_role": ["CIS", "SOC2", "NIST"],
        "aws_ec2_instance": ["CIS", "PCI-DSS", "HIPAA"],
        "aws_kms_key": ["PCI-DSS", "HIPAA", "SOC2"],
        "aws_secretsmanager_secret": ["PCI-DSS", "SOC2"],
        "gcp_storage_bucket": ["PCI-DSS", "SOC2", "HIPAA", "GDPR"],
        "gcp_sql_instance": ["PCI-DSS", "SOC2", "HIPAA"],
        "azure_storage_account": ["PCI-DSS", "SOC2", "HIPAA", "GDPR"],
        "azure_sql_database": ["PCI-DSS", "SOC2", "HIPAA"],
    }

    def __init__(
        self,
        graph: AssetGraph,
        findings: FindingCollection | None = None,
        max_depth: int = 5,
    ) -> None:
        """
        Initialize the blast radius calculator.

        Args:
            graph: Asset graph to analyze
            findings: Optional findings collection
            max_depth: Maximum depth to traverse for blast radius
        """
        self._graph = graph
        self._findings = findings
        self._max_depth = max_depth
        self._findings_by_asset: dict[str, list[Finding]] = {}

        if findings:
            for finding in findings.findings:
                if finding.asset_id not in self._findings_by_asset:
                    self._findings_by_asset[finding.asset_id] = []
                self._findings_by_asset[finding.asset_id].append(finding)

    def calculate(self, finding: Finding) -> BlastRadius:
        """
        Calculate the blast radius for a single finding.

        Args:
            finding: The finding to calculate blast radius for

        Returns:
            BlastRadius object with impact analysis
        """
        source_node = self._graph.get_node(finding.asset_id)
        if not source_node:
            # Return minimal blast radius if asset not in graph
            return BlastRadius(
                finding_id=finding.id,
                finding_severity=finding.severity,
                source_asset_id=finding.asset_id,
                source_asset_name="unknown",
                adjusted_severity=finding.severity,
            )

        # Get directly affected resources (distance=1)
        directly_affected = self._get_directly_affected(source_node, finding)

        # Get indirectly affected resources (distance>1)
        indirectly_affected = self._get_indirectly_affected(
            source_node, finding, directly_affected
        )

        # Determine impact categories
        impact_categories = self._determine_impact_categories(
            source_node, directly_affected, indirectly_affected
        )

        # Assess data exposure risk
        data_exposure_risk = self._assess_data_exposure_risk(
            source_node, directly_affected, indirectly_affected
        )

        # Assess service disruption risk
        service_disruption_risk = self._assess_service_disruption_risk(
            source_node, directly_affected, indirectly_affected
        )

        # Determine compliance implications
        compliance_implications = self._determine_compliance_implications(
            source_node, directly_affected, indirectly_affected
        )

        # Calculate total affected count
        total_affected_count = len(directly_affected) + len(indirectly_affected)

        # Calculate blast radius score
        blast_radius_score = self._calculate_blast_radius_score(
            finding,
            directly_affected,
            indirectly_affected,
            impact_categories,
            data_exposure_risk,
            service_disruption_risk,
        )

        # Adjust severity based on blast radius
        adjusted_severity = self._adjust_severity(finding.severity, blast_radius_score)

        return BlastRadius(
            finding_id=finding.id,
            finding_severity=finding.severity,
            source_asset_id=source_node.id,
            source_asset_name=source_node.asset.name,
            directly_affected=directly_affected,
            indirectly_affected=indirectly_affected,
            impact_categories=impact_categories,
            data_exposure_risk=data_exposure_risk,
            service_disruption_risk=service_disruption_risk,
            compliance_implications=compliance_implications,
            total_affected_count=total_affected_count,
            blast_radius_score=blast_radius_score,
            adjusted_severity=adjusted_severity,
        )

    def calculate_all(self) -> list[BlastRadius]:
        """
        Calculate blast radius for all findings.

        Returns:
            List of BlastRadius objects, sorted by blast_radius_score
        """
        if not self._findings:
            return []

        results: list[BlastRadius] = []
        for finding in self._findings.findings:
            blast_radius = self.calculate(finding)
            results.append(blast_radius)

        # Sort by blast radius score (highest first)
        results.sort(key=lambda br: br.blast_radius_score, reverse=True)

        return results

    def _get_directly_affected(
        self, source_node: AssetNode, finding: Finding
    ) -> list[AffectedResource]:
        """Get resources directly affected by the finding (distance=1)."""
        affected: list[AffectedResource] = []

        # Check outbound relationships
        for rel in source_node.outbound:
            target_node = self._graph.get_node(rel.target_id)
            if not target_node:
                continue

            impact_type = self._determine_impact_type(
                source_node, target_node, rel.relationship_type
            )
            impact_score = self._calculate_resource_impact_score(
                target_node, 1, rel.relationship_type
            )

            affected.append(
                AffectedResource(
                    asset_id=target_node.id,
                    asset_name=target_node.asset.name,
                    resource_type=target_node.asset.resource_type,
                    impact_type=impact_type,
                    relationship_path=[source_node.id, target_node.id],
                    distance=1,
                    impact_score=impact_score,
                )
            )

        # Check inbound relationships (resources that depend on this one)
        for rel in source_node.inbound:
            source_rel_node = self._graph.get_node(rel.source_id)
            if not source_rel_node:
                continue

            impact_type = self._determine_impact_type(
                source_node, source_rel_node, rel.relationship_type, inbound=True
            )
            impact_score = self._calculate_resource_impact_score(
                source_rel_node, 1, rel.relationship_type
            )

            affected.append(
                AffectedResource(
                    asset_id=source_rel_node.id,
                    asset_name=source_rel_node.asset.name,
                    resource_type=source_rel_node.asset.resource_type,
                    impact_type=impact_type,
                    relationship_path=[source_node.id, source_rel_node.id],
                    distance=1,
                    impact_score=impact_score,
                )
            )

        return affected

    def _get_indirectly_affected(
        self,
        source_node: AssetNode,
        finding: Finding,
        directly_affected: list[AffectedResource],
    ) -> list[AffectedResource]:
        """Get resources indirectly affected (distance > 1)."""
        affected: list[AffectedResource] = []
        visited = {source_node.id}
        visited.update(r.asset_id for r in directly_affected)

        # BFS to find resources at distance > 1
        from collections import deque

        # Start from directly affected resources
        queue: deque[tuple[str, list[str], int]] = deque()
        for direct in directly_affected:
            queue.append((direct.asset_id, direct.relationship_path.copy(), 1))

        while queue:
            current_id, path, distance = queue.popleft()

            if distance >= self._max_depth:
                continue

            current_node = self._graph.get_node(current_id)
            if not current_node:
                continue

            # Explore neighbors
            for rel in current_node.outbound + current_node.inbound:
                neighbor_id = (
                    rel.target_id
                    if rel.source_id == current_id
                    else rel.source_id
                )

                if neighbor_id in visited:
                    continue

                visited.add(neighbor_id)
                neighbor_node = self._graph.get_node(neighbor_id)
                if not neighbor_node:
                    continue

                new_path = path + [neighbor_id]
                new_distance = distance + 1

                impact_type = self._determine_impact_type(
                    source_node, neighbor_node, rel.relationship_type
                )
                impact_score = self._calculate_resource_impact_score(
                    neighbor_node, new_distance, rel.relationship_type
                )

                affected.append(
                    AffectedResource(
                        asset_id=neighbor_id,
                        asset_name=neighbor_node.asset.name,
                        resource_type=neighbor_node.asset.resource_type,
                        impact_type=impact_type,
                        relationship_path=new_path,
                        distance=new_distance,
                        impact_score=impact_score,
                    )
                )

                queue.append((neighbor_id, new_path, new_distance))

        return affected

    def _determine_impact_type(
        self,
        source_node: AssetNode,
        target_node: AssetNode,
        rel_type: RelationshipType,
        inbound: bool = False,
    ) -> str:
        """Determine how a target resource is impacted."""
        target_type = target_node.asset.resource_type

        if target_type in self.DATA_STORE_TYPES:
            return "data_exposure"
        if target_type in self.COMPUTE_TYPES:
            return "service_disruption"
        if target_type in self.IDENTITY_TYPES:
            return "credential_compromise" if inbound else "privilege_escalation"
        if target_type in self.SECRETS_TYPES:
            return "credential_compromise"
        if target_type in self.NETWORK_TYPES:
            return "lateral_movement"

        # Default based on relationship type
        if rel_type == RelationshipType.IAM_ATTACHED:
            return "privilege_escalation"
        if rel_type == RelationshipType.NETWORK_CONNECTED:
            return "lateral_movement"
        if rel_type == RelationshipType.CONTAINS:
            return "cascading_impact"

        return "unknown_impact"

    def _calculate_resource_impact_score(
        self,
        node: AssetNode,
        distance: int,
        rel_type: RelationshipType,
    ) -> float:
        """Calculate impact score for a single resource."""
        base_score = 50.0

        # Decay based on distance
        distance_multiplier = 1.0 / (distance ** 0.5)

        # Increase for sensitive resource types
        if node.asset.resource_type in self.DATA_STORE_TYPES:
            base_score += 30.0
        elif node.asset.resource_type in self.SECRETS_TYPES:
            base_score += 35.0
        elif node.asset.resource_type in self.IDENTITY_TYPES:
            base_score += 25.0
        elif node.asset.resource_type in self.COMPUTE_TYPES:
            base_score += 20.0

        # Increase for internet-facing resources
        if node.is_internet_facing:
            base_score += 15.0

        # Increase for production resources
        tags = node.asset.tags
        if tags.get("Environment", "").lower() in ("production", "prod"):
            base_score += 10.0

        # Relationship type modifiers
        if rel_type == RelationshipType.IAM_ATTACHED:
            base_score *= 1.2
        elif rel_type == RelationshipType.TRUSTS:
            base_score *= 1.3

        return min(100.0, base_score * distance_multiplier)

    def _determine_impact_categories(
        self,
        source_node: AssetNode,
        directly_affected: list[AffectedResource],
        indirectly_affected: list[AffectedResource],
    ) -> list[ImpactCategory]:
        """Determine the categories of impact."""
        categories: set[ImpactCategory] = set()
        all_affected = directly_affected + indirectly_affected

        for resource in all_affected:
            if resource.resource_type in self.DATA_STORE_TYPES:
                categories.add(ImpactCategory.DATA_EXPOSURE)
            if resource.resource_type in self.COMPUTE_TYPES:
                categories.add(ImpactCategory.SERVICE_DISRUPTION)
            if resource.resource_type in self.SECRETS_TYPES:
                categories.add(ImpactCategory.CREDENTIAL_COMPROMISE)
            if resource.resource_type in self.IDENTITY_TYPES:
                categories.add(ImpactCategory.PRIVILEGE_ESCALATION)
            if resource.resource_type in self.NETWORK_TYPES:
                categories.add(ImpactCategory.LATERAL_MOVEMENT)

        # Check for compliance implications
        if self._has_compliance_implications(source_node, all_affected):
            categories.add(ImpactCategory.COMPLIANCE_VIOLATION)

        return list(categories)

    def _has_compliance_implications(
        self, source_node: AssetNode, affected: list[AffectedResource]
    ) -> bool:
        """Check if there are compliance implications."""
        all_types = [source_node.asset.resource_type] + [
            r.resource_type for r in affected
        ]
        for resource_type in all_types:
            if resource_type in self.COMPLIANCE_MAPPING:
                return True
        return False

    def _assess_data_exposure_risk(
        self,
        source_node: AssetNode,
        directly_affected: list[AffectedResource],
        indirectly_affected: list[AffectedResource],
    ) -> str:
        """Assess the data exposure risk level."""
        all_affected = directly_affected + indirectly_affected

        # Count data stores in blast radius
        data_store_count = sum(
            1 for r in all_affected if r.resource_type in self.DATA_STORE_TYPES
        )

        # Check if source itself is a data store
        if source_node.asset.resource_type in self.DATA_STORE_TYPES:
            data_store_count += 1

        if data_store_count == 0:
            return "none"
        if data_store_count == 1:
            return "low"
        if data_store_count <= 3:
            return "medium"
        if data_store_count <= 5:
            return "high"
        return "critical"

    def _assess_service_disruption_risk(
        self,
        source_node: AssetNode,
        directly_affected: list[AffectedResource],
        indirectly_affected: list[AffectedResource],
    ) -> str:
        """Assess the service disruption risk level."""
        all_affected = directly_affected + indirectly_affected

        # Count compute resources in blast radius
        compute_count = sum(
            1 for r in all_affected if r.resource_type in self.COMPUTE_TYPES
        )

        # Check if source itself is compute
        if source_node.asset.resource_type in self.COMPUTE_TYPES:
            compute_count += 1

        # Check for production resources
        has_production = any(
            "prod" in r.asset_name.lower() for r in all_affected
        )

        if compute_count == 0:
            return "none"
        if compute_count == 1 and not has_production:
            return "low"
        if compute_count <= 3 or (compute_count == 1 and has_production):
            return "medium"
        if compute_count <= 5 or has_production:
            return "high"
        return "critical"

    def _determine_compliance_implications(
        self,
        source_node: AssetNode,
        directly_affected: list[AffectedResource],
        indirectly_affected: list[AffectedResource],
    ) -> list[str]:
        """Determine compliance framework implications."""
        frameworks: set[str] = set()
        all_affected = directly_affected + indirectly_affected

        # Check source node
        source_type = source_node.asset.resource_type
        if source_type in self.COMPLIANCE_MAPPING:
            frameworks.update(self.COMPLIANCE_MAPPING[source_type])

        # Check affected resources
        for resource in all_affected:
            if resource.resource_type in self.COMPLIANCE_MAPPING:
                frameworks.update(self.COMPLIANCE_MAPPING[resource.resource_type])

        return sorted(list(frameworks))

    def _calculate_blast_radius_score(
        self,
        finding: Finding,
        directly_affected: list[AffectedResource],
        indirectly_affected: list[AffectedResource],
        impact_categories: list[ImpactCategory],
        data_exposure_risk: str,
        service_disruption_risk: str,
    ) -> float:
        """Calculate overall blast radius score (0-100)."""
        score = 0.0

        # Base score from finding severity
        severity_scores = {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 30.0,
            Severity.MEDIUM: 20.0,
            Severity.LOW: 10.0,
            Severity.INFO: 5.0,
        }
        score += severity_scores.get(finding.severity, 10.0)

        # Add for affected resource count (diminishing returns)
        direct_count = len(directly_affected)
        indirect_count = len(indirectly_affected)
        score += min(20.0, direct_count * 4.0)
        score += min(15.0, indirect_count * 1.5)

        # Add for impact categories
        score += len(impact_categories) * 3.0

        # Add for data exposure risk
        risk_scores = {"none": 0, "low": 3, "medium": 6, "high": 10, "critical": 15}
        score += risk_scores.get(data_exposure_risk, 0)

        # Add for service disruption risk
        score += risk_scores.get(service_disruption_risk, 0)

        return min(100.0, score)

    def _adjust_severity(
        self, original_severity: Severity, blast_radius_score: float
    ) -> Severity:
        """Adjust severity based on blast radius score."""
        # Define thresholds for upgrading severity
        if blast_radius_score >= 80:
            return Severity.CRITICAL
        if blast_radius_score >= 60:
            if original_severity in (Severity.LOW, Severity.MEDIUM, Severity.INFO):
                return Severity.HIGH
            return original_severity
        if blast_radius_score >= 40:
            if original_severity in (Severity.LOW, Severity.INFO):
                return Severity.MEDIUM
            return original_severity

        return original_severity

    def get_highest_impact_findings(self, limit: int = 10) -> list[BlastRadius]:
        """
        Get the findings with highest blast radius impact.

        Args:
            limit: Maximum number of findings to return

        Returns:
            List of BlastRadius objects with highest impact
        """
        all_radius = self.calculate_all()
        return all_radius[:limit]

    def get_affected_by_category(
        self, category: ImpactCategory
    ) -> list[BlastRadius]:
        """
        Get all blast radius results that have a specific impact category.

        Args:
            category: The impact category to filter by

        Returns:
            List of BlastRadius objects with the specified category
        """
        all_radius = self.calculate_all()
        return [br for br in all_radius if category in br.impact_categories]
