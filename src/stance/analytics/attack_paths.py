"""
Attack Path Analyzer for Mantissa Stance.

Identifies potential attack paths through the cloud environment based on
asset relationships, network exposure, and security findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.analytics.asset_graph import AssetGraph, AssetNode, RelationshipType
from stance.models.finding import Finding, FindingCollection, Severity


class AttackPathType(Enum):
    """Types of attack paths."""

    # Original attack path types
    INTERNET_TO_INTERNAL = "internet_to_internal"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"

    # Phase 4: New attack path types
    CREDENTIAL_EXPOSURE = "credential_exposure"
    DATA_THEFT = "data_theft"
    RANSOMWARE_SPREAD = "ransomware_spread"
    CRYPTO_MINING = "crypto_mining"
    IDENTITY_THEFT = "identity_theft"


@dataclass
class AttackPathStep:
    """
    A single step in an attack path.

    Attributes:
        asset_id: ID of the asset in this step
        asset_name: Human-readable name
        resource_type: Type of resource
        action: Description of the attack action
        findings: Related security findings
        risk_level: Risk level of this step
    """

    asset_id: str
    asset_name: str
    resource_type: str
    action: str
    findings: list[str] = field(default_factory=list)
    risk_level: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "resource_type": self.resource_type,
            "action": self.action,
            "findings": self.findings,
            "risk_level": self.risk_level,
        }


@dataclass
class AttackPath:
    """
    An identified attack path through the environment.

    Attributes:
        id: Unique identifier
        path_type: Type of attack path
        steps: Ordered list of attack steps
        severity: Overall severity of the path
        description: Human-readable description
        mitigation: Suggested mitigation steps
    """

    id: str
    path_type: AttackPathType
    steps: list[AttackPathStep]
    severity: Severity
    description: str
    mitigation: str = ""

    @property
    def length(self) -> int:
        """Get the number of steps in the path."""
        return len(self.steps)

    @property
    def entry_point(self) -> AttackPathStep | None:
        """Get the entry point (first step)."""
        return self.steps[0] if self.steps else None

    @property
    def target(self) -> AttackPathStep | None:
        """Get the target (last step)."""
        return self.steps[-1] if self.steps else None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "path_type": self.path_type.value,
            "steps": [step.to_dict() for step in self.steps],
            "severity": self.severity.value,
            "description": self.description,
            "mitigation": self.mitigation,
            "length": self.length,
        }


class AttackPathAnalyzer:
    """
    Analyzes asset graphs to identify potential attack paths.

    Considers network connectivity, IAM relationships, and security findings
    to identify paths an attacker could exploit.
    """

    # Sensitive resource types that are high-value targets
    SENSITIVE_TYPES = {
        "aws_rds_instance",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_secretsmanager_secret",
        "aws_kms_key",
        "gcp_sql_instance",
        "gcp_storage_bucket",
        "gcp_secret",
        "azure_sql_database",
        "azure_storage_account",
        "azure_key_vault",
    }

    # Resource types that can serve as entry points
    ENTRY_POINT_TYPES = {
        "aws_ec2_instance",
        "aws_lambda_function",
        "aws_api_gateway",
        "aws_elb",
        "aws_alb",
        "gcp_compute_instance",
        "gcp_cloud_function",
        "gcp_cloud_run",
        "azure_virtual_machine",
        "azure_function_app",
        "azure_app_service",
    }

    # Credential and secrets storage types
    CREDENTIAL_TYPES = {
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_iam_access_key",
        "aws_iam_user",
        "gcp_secret",
        "gcp_service_account_key",
        "azure_key_vault",
        "azure_key_vault_secret",
    }

    # High-privilege identity types
    IDENTITY_TYPES = {
        "aws_iam_role",
        "aws_iam_user",
        "aws_iam_group",
        "gcp_service_account",
        "gcp_iam_policy",
        "azure_service_principal",
        "azure_managed_identity",
        "azure_role_assignment",
    }

    # Compute resources that can be abused for crypto mining
    COMPUTE_TYPES = {
        "aws_ec2_instance",
        "aws_ecs_task",
        "aws_lambda_function",
        "aws_batch_compute_environment",
        "gcp_compute_instance",
        "gcp_cloud_function",
        "gcp_cloud_run",
        "gcp_dataproc_cluster",
        "azure_virtual_machine",
        "azure_container_instance",
        "azure_function_app",
    }

    # Storage types that can be targeted by ransomware
    STORAGE_TYPES = {
        "aws_s3_bucket",
        "aws_ebs_volume",
        "aws_efs_file_system",
        "aws_rds_instance",
        "aws_dynamodb_table",
        "gcp_storage_bucket",
        "gcp_persistent_disk",
        "gcp_sql_instance",
        "azure_storage_account",
        "azure_managed_disk",
        "azure_sql_database",
    }

    def __init__(
        self,
        graph: AssetGraph,
        findings: FindingCollection | None = None,
    ) -> None:
        """
        Initialize the attack path analyzer.

        Args:
            graph: Asset graph to analyze
            findings: Optional findings collection for enrichment
        """
        self._graph = graph
        self._findings = findings
        self._findings_by_asset: dict[str, list[Finding]] = {}

        if findings:
            for finding in findings.findings:
                if finding.asset_id not in self._findings_by_asset:
                    self._findings_by_asset[finding.asset_id] = []
                self._findings_by_asset[finding.asset_id].append(finding)

    def analyze(self) -> list[AttackPath]:
        """
        Analyze the graph and return all identified attack paths.

        Returns:
            List of identified attack paths
        """
        paths: list[AttackPath] = []

        # Original attack path types
        # Find internet-to-internal paths
        paths.extend(self._find_internet_to_internal_paths())

        # Find privilege escalation paths
        paths.extend(self._find_privilege_escalation_paths())

        # Find lateral movement paths
        paths.extend(self._find_lateral_movement_paths())

        # Find data exfiltration paths
        paths.extend(self._find_data_exfiltration_paths())

        # Phase 4: New attack path types
        # Find credential exposure paths
        paths.extend(self._find_credential_exposure_paths())

        # Find data theft paths
        paths.extend(self._find_data_theft_paths())

        # Find ransomware spread paths
        paths.extend(self._find_ransomware_spread_paths())

        # Find crypto mining paths
        paths.extend(self._find_crypto_mining_paths())

        # Find identity theft paths
        paths.extend(self._find_identity_theft_paths())

        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        paths.sort(key=lambda p: severity_order.get(p.severity, 5))

        return paths

    def _find_internet_to_internal_paths(self) -> list[AttackPath]:
        """
        Find paths from internet-facing assets to sensitive internal assets.

        Returns:
            List of internet-to-internal attack paths
        """
        paths: list[AttackPath] = []

        # Get internet-facing entry points
        entry_points = [
            node
            for node in self._graph.get_internet_facing_nodes()
            if node.asset.resource_type in self.ENTRY_POINT_TYPES
        ]

        # Find sensitive targets
        sensitive_targets = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.SENSITIVE_TYPES
            and not node.is_internet_facing
        ]

        path_id = 0
        for entry in entry_points:
            for target in sensitive_targets:
                # Find path between entry and target
                path = self._graph.find_path(entry.id, target.id, max_depth=5)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    severity = self._calculate_path_severity(path)

                    attack_path = AttackPath(
                        id=f"internet-internal-{path_id}",
                        path_type=AttackPathType.INTERNET_TO_INTERNAL,
                        steps=steps,
                        severity=severity,
                        description=(
                            f"Path from internet-facing {entry.asset.resource_type} "
                            f"'{entry.asset.name}' to internal "
                            f"{target.asset.resource_type} '{target.asset.name}'"
                        ),
                        mitigation=self._generate_mitigation(
                            AttackPathType.INTERNET_TO_INTERNAL, steps
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _find_privilege_escalation_paths(self) -> list[AttackPath]:
        """
        Find paths that could allow privilege escalation.

        Returns:
            List of privilege escalation attack paths
        """
        paths: list[AttackPath] = []

        # Look for IAM roles with overly permissive policies
        path_id = 0
        for node in self._graph.get_nodes():
            if node.asset.resource_type != "aws_iam_role":
                continue

            # Check for admin policies attached
            for rel in node.inbound:
                if rel.relationship_type != RelationshipType.IAM_ATTACHED:
                    continue

                policy_node = self._graph.get_node(rel.source_id)
                if not policy_node:
                    continue

                # Check if policy has admin-like permissions
                policy_doc = policy_node.asset.raw_config.get("policy_document", {})
                if self._is_overly_permissive(policy_doc):
                    # Find resources that can assume this role
                    assumable_by = self._find_resources_that_can_assume(node)
                    for resource in assumable_by:
                        steps = [
                            self._create_step(
                                resource,
                                "Initial access to resource with assume-role capability",
                            ),
                            self._create_step(
                                node,
                                "Assume role to gain elevated permissions",
                            ),
                        ]
                        attack_path = AttackPath(
                            id=f"priv-esc-{path_id}",
                            path_type=AttackPathType.PRIVILEGE_ESCALATION,
                            steps=steps,
                            severity=Severity.HIGH,
                            description=(
                                f"Privilege escalation via assuming role "
                                f"'{node.asset.name}' with admin-like permissions"
                            ),
                            mitigation=(
                                "Review and restrict IAM role permissions. "
                                "Limit which resources can assume the role."
                            ),
                        )
                        paths.append(attack_path)
                        path_id += 1

        return paths

    def _find_lateral_movement_paths(self) -> list[AttackPath]:
        """
        Find paths that could enable lateral movement.

        Returns:
            List of lateral movement attack paths
        """
        paths: list[AttackPath] = []

        # Find compute instances that are network-connected to each other
        compute_nodes = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type
            in ("aws_ec2_instance", "gcp_compute_instance", "azure_virtual_machine")
        ]

        path_id = 0
        for source in compute_nodes:
            reachable = self._graph.get_reachable_from(
                source.id, max_depth=3, direction="both"
            )

            for target_id in reachable:
                target = self._graph.get_node(target_id)
                if not target:
                    continue

                if target.asset.resource_type not in (
                    "aws_ec2_instance",
                    "gcp_compute_instance",
                    "azure_virtual_machine",
                ):
                    continue

                if source.id == target_id:
                    continue

                path = self._graph.find_path(source.id, target_id, max_depth=3)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    attack_path = AttackPath(
                        id=f"lateral-{path_id}",
                        path_type=AttackPathType.LATERAL_MOVEMENT,
                        steps=steps,
                        severity=Severity.MEDIUM,
                        description=(
                            f"Lateral movement from '{source.asset.name}' "
                            f"to '{target.asset.name}' via network connectivity"
                        ),
                        mitigation=(
                            "Implement network segmentation. "
                            "Restrict security group rules between instances."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _find_data_exfiltration_paths(self) -> list[AttackPath]:
        """
        Find paths that could enable data exfiltration.

        Returns:
            List of data exfiltration attack paths
        """
        paths: list[AttackPath] = []

        # Find paths from sensitive data stores to internet-facing resources
        data_stores = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.SENSITIVE_TYPES
        ]

        internet_facing = self._graph.get_internet_facing_nodes()

        path_id = 0
        for store in data_stores:
            for exit_point in internet_facing:
                if store.id == exit_point.id:
                    continue

                path = self._graph.find_path(store.id, exit_point.id, max_depth=5)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    steps[0].action = "Access sensitive data"
                    steps[-1].action = "Exfiltrate data via internet-facing resource"

                    attack_path = AttackPath(
                        id=f"exfil-{path_id}",
                        path_type=AttackPathType.DATA_EXFILTRATION,
                        steps=steps,
                        severity=Severity.HIGH,
                        description=(
                            f"Data exfiltration path from "
                            f"'{store.asset.name}' to internet via "
                            f"'{exit_point.asset.name}'"
                        ),
                        mitigation=(
                            "Implement data loss prevention controls. "
                            "Monitor and restrict egress traffic. "
                            "Enable VPC flow logs."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _build_steps(self, path: list[str]) -> list[AttackPathStep]:
        """Build attack path steps from a list of asset IDs."""
        steps: list[AttackPathStep] = []
        for i, asset_id in enumerate(path):
            node = self._graph.get_node(asset_id)
            if not node:
                continue

            if i == 0:
                action = "Initial access"
            elif i == len(path) - 1:
                action = "Target reached"
            else:
                action = "Lateral movement/pivot"

            steps.append(self._create_step(node, action))

        return steps

    def _create_step(self, node: AssetNode, action: str) -> AttackPathStep:
        """Create an attack path step from an asset node."""
        findings = self._findings_by_asset.get(node.id, [])
        finding_ids = [f.id for f in findings]

        # Determine risk level based on findings
        if any(f.severity == Severity.CRITICAL for f in findings):
            risk_level = "critical"
        elif any(f.severity == Severity.HIGH for f in findings):
            risk_level = "high"
        elif any(f.severity == Severity.MEDIUM for f in findings):
            risk_level = "medium"
        else:
            risk_level = "low"

        return AttackPathStep(
            asset_id=node.id,
            asset_name=node.asset.name,
            resource_type=node.asset.resource_type,
            action=action,
            findings=finding_ids,
            risk_level=risk_level,
        )

    def _calculate_path_severity(self, path: list[str]) -> Severity:
        """Calculate overall severity of an attack path."""
        max_severity = Severity.INFO

        for asset_id in path:
            findings = self._findings_by_asset.get(asset_id, [])
            for finding in findings:
                if finding.severity.value < max_severity.value:
                    max_severity = finding.severity

        # Internet-to-internal paths are at least HIGH severity
        return max_severity if max_severity != Severity.INFO else Severity.MEDIUM

    def _generate_mitigation(
        self, path_type: AttackPathType, steps: list[AttackPathStep]
    ) -> str:
        """Generate mitigation suggestions for an attack path."""
        mitigations = []

        if path_type == AttackPathType.INTERNET_TO_INTERNAL:
            mitigations.append("Restrict inbound access to entry points")
            mitigations.append("Implement network segmentation")
            mitigations.append("Review security group rules")

        if any(step.risk_level in ("critical", "high") for step in steps):
            mitigations.append("Address critical and high severity findings")

        return ". ".join(mitigations) + "." if mitigations else ""

    def _is_overly_permissive(self, policy_doc: dict[str, Any]) -> bool:
        """Check if an IAM policy is overly permissive."""
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for admin-like permissions
            if "*" in actions and "*" in resources:
                return True
            if any(a.endswith(":*") for a in actions) and "*" in resources:
                return True

        return False

    def _find_resources_that_can_assume(self, role_node: AssetNode) -> list[AssetNode]:
        """Find resources that can assume a given IAM role."""
        resources: list[AssetNode] = []

        trust_policy = role_node.asset.raw_config.get("assume_role_policy", {})
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        principals: set[str] = set()
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})
            if isinstance(principal, str):
                principals.add(principal)
            elif isinstance(principal, dict):
                for p_type, p_values in principal.items():
                    if isinstance(p_values, str):
                        principals.add(p_values)
                    elif isinstance(p_values, list):
                        principals.update(p_values)

        # Find matching resources
        for node in self._graph.get_nodes():
            if node.asset.id in principals:
                resources.append(node)
            # Check for wildcard principals
            if "*" in principals:
                resources.append(node)

        return resources

    # =========================================================================
    # Phase 4: New Attack Path Types
    # =========================================================================

    def _find_credential_exposure_paths(self) -> list[AttackPath]:
        """
        Find paths where credentials might be exposed and lead to compromise.

        Identifies paths from publicly accessible resources to credential stores,
        or resources with exposed credentials that can access other systems.

        Returns:
            List of credential exposure attack paths
        """
        paths: list[AttackPath] = []

        # Get internet-facing entry points
        entry_points = self._graph.get_internet_facing_nodes()

        # Find credential stores
        credential_stores = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.CREDENTIAL_TYPES
        ]

        path_id = 0
        for entry in entry_points:
            for cred_store in credential_stores:
                if entry.id == cred_store.id:
                    continue

                path = self._graph.find_path(entry.id, cred_store.id, max_depth=5)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    steps[0].action = "Initial access via internet-facing resource"
                    steps[-1].action = "Access credentials/secrets"

                    # Check for related findings
                    entry_findings = self._findings_by_asset.get(entry.id, [])
                    cred_findings = self._findings_by_asset.get(cred_store.id, [])

                    # Higher severity if there are vulnerabilities
                    has_vulns = any(
                        "vuln" in f.rule_id.lower() or f.severity == Severity.CRITICAL
                        for f in entry_findings + cred_findings
                    )

                    attack_path = AttackPath(
                        id=f"cred-exposure-{path_id}",
                        path_type=AttackPathType.CREDENTIAL_EXPOSURE,
                        steps=steps,
                        severity=Severity.CRITICAL if has_vulns else Severity.HIGH,
                        description=(
                            f"Credential exposure path from internet-facing "
                            f"'{entry.asset.name}' to credential store "
                            f"'{cred_store.asset.name}'"
                        ),
                        mitigation=(
                            "Restrict network access to credential stores. "
                            "Use VPC endpoints for secrets access. "
                            "Enable encryption at rest and in transit. "
                            "Implement least-privilege access to secrets."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _find_data_theft_paths(self) -> list[AttackPath]:
        """
        Find paths that could lead to sensitive data theft.

        Identifies paths from entry points to data stores that could enable
        an attacker to steal sensitive data.

        Returns:
            List of data theft attack paths
        """
        paths: list[AttackPath] = []

        # Get entry points (any resource with network access from outside)
        entry_points = [
            node
            for node in self._graph.get_internet_facing_nodes()
            if node.asset.resource_type in self.ENTRY_POINT_TYPES
        ]

        # Find sensitive data stores
        data_stores = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.SENSITIVE_TYPES
        ]

        path_id = 0
        for entry in entry_points:
            for data_store in data_stores:
                if entry.id == data_store.id:
                    continue

                path = self._graph.find_path(entry.id, data_store.id, max_depth=6)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    steps[0].action = "Compromise entry point"
                    steps[-1].action = "Access and exfiltrate sensitive data"

                    # Check for data classification or sensitivity indicators
                    data_config = data_store.asset.raw_config
                    is_encrypted = data_config.get("encrypted", False) or \
                                   data_config.get("encryption", {})

                    severity = Severity.HIGH
                    if not is_encrypted:
                        severity = Severity.CRITICAL

                    attack_path = AttackPath(
                        id=f"data-theft-{path_id}",
                        path_type=AttackPathType.DATA_THEFT,
                        steps=steps,
                        severity=severity,
                        description=(
                            f"Data theft path from '{entry.asset.name}' to "
                            f"sensitive data store '{data_store.asset.name}'"
                        ),
                        mitigation=(
                            "Enable encryption at rest for all data stores. "
                            "Implement data loss prevention (DLP) controls. "
                            "Monitor and alert on unusual data access patterns. "
                            "Restrict network access to sensitive data."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _find_ransomware_spread_paths(self) -> list[AttackPath]:
        """
        Find paths that could enable ransomware to spread and encrypt data.

        Identifies paths where an attacker with write access could spread
        ransomware across storage resources.

        Returns:
            List of ransomware spread attack paths
        """
        paths: list[AttackPath] = []

        # Get compute resources that could serve as initial infection point
        compute_nodes = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.COMPUTE_TYPES
        ]

        # Find storage resources that could be targeted
        storage_nodes = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.STORAGE_TYPES
        ]

        path_id = 0
        for compute in compute_nodes:
            reachable_storage: list[AssetNode] = []

            # Find storage accessible from this compute resource
            for storage in storage_nodes:
                path = self._graph.find_path(compute.id, storage.id, max_depth=3)
                if path:
                    reachable_storage.append(storage)

            # If a compute resource can access multiple storage targets, it's higher risk
            if len(reachable_storage) >= 2:
                # Build a path showing spread potential
                steps = [
                    self._create_step(compute, "Initial ransomware infection"),
                ]

                for i, storage in enumerate(reachable_storage[:3]):  # Limit to 3 for readability
                    steps.append(
                        self._create_step(storage, f"Encrypt storage target {i+1}")
                    )

                # Check for backup or versioning
                has_backup = any(
                    s.asset.raw_config.get("versioning", {}).get("enabled", False)
                    or s.asset.raw_config.get("backup_retention_period")
                    for s in reachable_storage
                )

                attack_path = AttackPath(
                    id=f"ransomware-{path_id}",
                    path_type=AttackPathType.RANSOMWARE_SPREAD,
                    steps=steps,
                    severity=Severity.CRITICAL if not has_backup else Severity.HIGH,
                    description=(
                        f"Ransomware spread from '{compute.asset.name}' "
                        f"could affect {len(reachable_storage)} storage resources"
                    ),
                    mitigation=(
                        "Enable versioning and backups on all storage. "
                        "Implement immutable backup solutions. "
                        "Restrict write access to storage resources. "
                        "Deploy endpoint protection on compute resources."
                    ),
                )
                paths.append(attack_path)
                path_id += 1

        return paths

    def _find_crypto_mining_paths(self) -> list[AttackPath]:
        """
        Find paths that could be exploited for cryptomining attacks.

        Identifies paths from internet-facing resources to compute resources
        that could be hijacked for cryptocurrency mining.

        Returns:
            List of crypto mining attack paths
        """
        paths: list[AttackPath] = []

        # Get internet-facing entry points
        entry_points = self._graph.get_internet_facing_nodes()

        # Find high-value compute targets
        compute_targets = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.COMPUTE_TYPES
            and not node.is_internet_facing  # Internal compute is more valuable
        ]

        path_id = 0
        for entry in entry_points:
            for compute in compute_targets:
                if entry.id == compute.id:
                    continue

                path = self._graph.find_path(entry.id, compute.id, max_depth=4)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    steps[0].action = "Exploit internet-facing resource"
                    steps[-1].action = "Deploy cryptominer on compute resource"

                    # Check for high-CPU potential (larger instance types)
                    compute_config = compute.asset.raw_config
                    instance_type = compute_config.get("instance_type", "")
                    is_large_instance = any(
                        size in instance_type.lower()
                        for size in ["xlarge", "2xlarge", "4xlarge", "8xlarge", "metal"]
                    )

                    attack_path = AttackPath(
                        id=f"crypto-mining-{path_id}",
                        path_type=AttackPathType.CRYPTO_MINING,
                        steps=steps,
                        severity=Severity.HIGH if is_large_instance else Severity.MEDIUM,
                        description=(
                            f"Crypto mining path from '{entry.asset.name}' to "
                            f"compute resource '{compute.asset.name}'"
                        ),
                        mitigation=(
                            "Implement network segmentation. "
                            "Monitor for unusual CPU usage patterns. "
                            "Deploy runtime security and anomaly detection. "
                            "Restrict outbound network access from compute."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _find_identity_theft_paths(self) -> list[AttackPath]:
        """
        Find paths that could lead to identity/credential theft.

        Identifies paths from entry points to high-privilege identities
        that could be compromised.

        Returns:
            List of identity theft attack paths
        """
        paths: list[AttackPath] = []

        # Get entry points
        entry_points = self._graph.get_internet_facing_nodes()

        # Find high-privilege identity resources
        identity_targets = [
            node
            for node in self._graph.get_nodes()
            if node.asset.resource_type in self.IDENTITY_TYPES
        ]

        # Filter for high-privilege identities
        high_priv_identities: list[AssetNode] = []
        for identity in identity_targets:
            if self._is_high_privilege_identity(identity):
                high_priv_identities.append(identity)

        path_id = 0
        for entry in entry_points:
            for identity in high_priv_identities:
                if entry.id == identity.id:
                    continue

                path = self._graph.find_path(entry.id, identity.id, max_depth=5)
                if path and len(path) > 1:
                    steps = self._build_steps(path)
                    steps[0].action = "Gain initial foothold"
                    steps[-1].action = "Compromise high-privilege identity"

                    attack_path = AttackPath(
                        id=f"identity-theft-{path_id}",
                        path_type=AttackPathType.IDENTITY_THEFT,
                        steps=steps,
                        severity=Severity.CRITICAL,
                        description=(
                            f"Identity theft path from '{entry.asset.name}' to "
                            f"high-privilege identity '{identity.asset.name}'"
                        ),
                        mitigation=(
                            "Enforce MFA for all privileged identities. "
                            "Implement least-privilege access. "
                            "Monitor identity usage for anomalies. "
                            "Use short-lived credentials and rotate regularly."
                        ),
                    )
                    paths.append(attack_path)
                    path_id += 1

        return paths

    def _is_high_privilege_identity(self, node: AssetNode) -> bool:
        """Check if an identity has high privileges."""
        config = node.asset.raw_config

        # Check for admin-like policy attachments
        attached_policies = config.get("attached_policies", [])
        for policy in attached_policies:
            policy_name = policy if isinstance(policy, str) else policy.get("name", "")
            if any(
                admin_term in policy_name.lower()
                for admin_term in ["admin", "fullaccess", "poweruser"]
            ):
                return True

        # Check for inline policies with admin-like permissions
        inline_policies = config.get("inline_policies", [])
        for policy in inline_policies:
            if isinstance(policy, dict):
                if self._is_overly_permissive(policy.get("policy_document", {})):
                    return True

        # Check assume role policy for AWS roles
        if node.asset.resource_type == "aws_iam_role":
            if self._is_overly_permissive(config.get("assume_role_policy", {})):
                return True

        return False
