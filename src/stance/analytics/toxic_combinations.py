"""
Toxic Combinations Detector for Mantissa Stance.

Identifies dangerous combinations of security conditions that, when present
together, create significantly elevated risk. Individual conditions may be
acceptable in isolation but become critical when combined.

Reference: Wiz "Toxic Combination" Analysis
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.analytics.asset_graph import AssetGraph, AssetNode
from stance.models.finding import Finding, FindingCollection, Severity


class ToxicCombinationType(Enum):
    """Types of toxic combinations."""

    PUBLIC_SENSITIVE_DATA = "public_sensitive_data"
    ADMIN_NO_MFA = "admin_no_mfa"
    INTERNET_FACING_VULNERABLE = "internet_facing_vulnerable"
    WRITE_ACCESS_SECRETS = "write_access_secrets"
    CROSS_ACCOUNT_PRIVILEGED = "cross_account_privileged"


@dataclass
class ToxicCondition:
    """
    A single condition that contributes to a toxic combination.

    Attributes:
        description: Human-readable description of the condition
        asset_id: ID of the asset with this condition
        evidence: Supporting evidence for the condition
        severity_contribution: How much this condition adds to overall severity
    """

    description: str
    asset_id: str
    evidence: dict[str, Any] = field(default_factory=dict)
    severity_contribution: str = "medium"


@dataclass
class ToxicCombination:
    """
    A detected toxic combination of security conditions.

    Attributes:
        id: Unique identifier for this combination
        combination_type: Type of toxic combination
        conditions: List of conditions that form this combination
        severity: Overall severity of the combination
        affected_assets: List of asset IDs affected
        description: Human-readable description
        impact: Potential impact description
        mitigation: Recommended mitigation steps
        score: Numeric risk score (0-100)
    """

    id: str
    combination_type: ToxicCombinationType
    conditions: list[ToxicCondition]
    severity: Severity
    affected_assets: list[str]
    description: str
    impact: str
    mitigation: str
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "combination_type": self.combination_type.value,
            "conditions": [
                {
                    "description": c.description,
                    "asset_id": c.asset_id,
                    "evidence": c.evidence,
                    "severity_contribution": c.severity_contribution,
                }
                for c in self.conditions
            ],
            "severity": self.severity.value,
            "affected_assets": self.affected_assets,
            "description": self.description,
            "impact": self.impact,
            "mitigation": self.mitigation,
            "score": self.score,
        }


class ToxicCombinationDetector:
    """
    Detects toxic combinations of security conditions in cloud environments.

    Analyzes asset graphs and findings to identify dangerous combinations
    that create elevated security risk when present together.
    """

    # Sensitive data resource types
    SENSITIVE_DATA_TYPES = {
        "aws_rds_instance",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_redshift_cluster",
        "aws_elasticache_cluster",
        "gcp_sql_instance",
        "gcp_storage_bucket",
        "gcp_secret",
        "gcp_bigtable_instance",
        "gcp_bigquery_dataset",
        "azure_sql_database",
        "azure_storage_account",
        "azure_key_vault",
        "azure_cosmosdb_account",
    }

    # Admin/privileged identity types
    PRIVILEGED_IDENTITY_TYPES = {
        "aws_iam_role",
        "aws_iam_user",
        "aws_iam_group",
        "gcp_service_account",
        "gcp_iam_policy",
        "azure_service_principal",
        "azure_managed_identity",
        "azure_role_assignment",
    }

    # Compute types that can be internet-facing
    COMPUTE_TYPES = {
        "aws_ec2_instance",
        "aws_lambda_function",
        "aws_ecs_task",
        "aws_eks_node",
        "gcp_compute_instance",
        "gcp_cloud_function",
        "gcp_cloud_run",
        "gcp_gke_node",
        "azure_virtual_machine",
        "azure_function_app",
        "azure_container_instance",
        "azure_aks_node",
    }

    # Secrets storage types
    SECRETS_TYPES = {
        "aws_secretsmanager_secret",
        "aws_ssm_parameter",
        "aws_kms_key",
        "gcp_secret",
        "gcp_kms_key",
        "azure_key_vault",
        "azure_key_vault_secret",
    }

    def __init__(
        self,
        graph: AssetGraph,
        findings: FindingCollection | None = None,
    ) -> None:
        """
        Initialize the toxic combination detector.

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

    def detect(self) -> list[ToxicCombination]:
        """
        Detect all toxic combinations in the environment.

        Returns:
            List of detected toxic combinations, sorted by severity
        """
        combinations: list[ToxicCombination] = []

        # Detect each type of toxic combination
        combinations.extend(self._detect_public_sensitive_data())
        combinations.extend(self._detect_admin_no_mfa())
        combinations.extend(self._detect_internet_facing_vulnerable())
        combinations.extend(self._detect_write_access_secrets())
        combinations.extend(self._detect_cross_account_privileged())

        # Sort by severity and score
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        combinations.sort(key=lambda c: (severity_order.get(c.severity, 5), -c.score))

        return combinations

    def _detect_public_sensitive_data(self) -> list[ToxicCombination]:
        """
        Detect public exposure combined with sensitive data.

        This is one of the most critical toxic combinations - publicly
        accessible resources containing sensitive data like databases,
        storage buckets, or secrets.

        Returns:
            List of public + sensitive data toxic combinations
        """
        combinations: list[ToxicCombination] = []
        combo_id = 0

        # Find sensitive data resources that are internet-facing
        for node in self._graph.get_nodes():
            if node.asset.resource_type not in self.SENSITIVE_DATA_TYPES:
                continue

            is_public = self._is_publicly_accessible(node)
            has_sensitive_data = self._has_sensitive_data_indicators(node)

            if is_public and has_sensitive_data:
                conditions = [
                    ToxicCondition(
                        description="Resource is publicly accessible from the internet",
                        asset_id=node.id,
                        evidence=self._get_public_access_evidence(node),
                        severity_contribution="high",
                    ),
                    ToxicCondition(
                        description="Resource contains or stores sensitive data",
                        asset_id=node.id,
                        evidence=self._get_sensitive_data_evidence(node),
                        severity_contribution="high",
                    ),
                ]

                combination = ToxicCombination(
                    id=f"toxic-public-sensitive-{combo_id}",
                    combination_type=ToxicCombinationType.PUBLIC_SENSITIVE_DATA,
                    conditions=conditions,
                    severity=Severity.CRITICAL,
                    affected_assets=[node.id],
                    description=(
                        f"Publicly accessible {node.asset.resource_type} "
                        f"'{node.asset.name}' contains sensitive data"
                    ),
                    impact=(
                        "Sensitive data may be exposed to unauthorized access. "
                        "This could lead to data breaches, compliance violations, "
                        "and reputational damage."
                    ),
                    mitigation=(
                        "1. Immediately restrict public access to this resource. "
                        "2. Enable encryption at rest and in transit. "
                        "3. Implement proper access controls and authentication. "
                        "4. Review access logs for potential unauthorized access. "
                        "5. Consider data classification and DLP controls."
                    ),
                    score=95.0,
                )
                combinations.append(combination)
                combo_id += 1

        return combinations

    def _detect_admin_no_mfa(self) -> list[ToxicCombination]:
        """
        Detect admin privileges combined with no MFA enabled.

        High-privilege accounts without MFA are prime targets for
        account takeover attacks.

        Returns:
            List of admin + no MFA toxic combinations
        """
        combinations: list[ToxicCombination] = []
        combo_id = 0

        for node in self._graph.get_nodes():
            if node.asset.resource_type not in self.PRIVILEGED_IDENTITY_TYPES:
                continue

            is_admin = self._has_admin_privileges(node)
            has_mfa = self._has_mfa_enabled(node)

            if is_admin and not has_mfa:
                conditions = [
                    ToxicCondition(
                        description="Identity has administrative or high privileges",
                        asset_id=node.id,
                        evidence=self._get_privilege_evidence(node),
                        severity_contribution="high",
                    ),
                    ToxicCondition(
                        description="Multi-factor authentication is not enabled",
                        asset_id=node.id,
                        evidence={"mfa_enabled": False},
                        severity_contribution="high",
                    ),
                ]

                combination = ToxicCombination(
                    id=f"toxic-admin-no-mfa-{combo_id}",
                    combination_type=ToxicCombinationType.ADMIN_NO_MFA,
                    conditions=conditions,
                    severity=Severity.CRITICAL,
                    affected_assets=[node.id],
                    description=(
                        f"Admin identity '{node.asset.name}' does not have MFA enabled"
                    ),
                    impact=(
                        "Privileged account is vulnerable to credential theft attacks. "
                        "Compromised admin credentials without MFA can lead to "
                        "complete environment takeover."
                    ),
                    mitigation=(
                        "1. Enable MFA immediately for this identity. "
                        "2. Review and audit recent activity for this account. "
                        "3. Implement conditional access policies. "
                        "4. Consider using hardware security keys for admin accounts. "
                        "5. Enable session monitoring and anomaly detection."
                    ),
                    score=90.0,
                )
                combinations.append(combination)
                combo_id += 1

        return combinations

    def _detect_internet_facing_vulnerable(self) -> list[ToxicCombination]:
        """
        Detect internet-facing resources with known vulnerabilities.

        Resources exposed to the internet with known CVEs are at immediate
        risk of exploitation.

        Returns:
            List of internet-facing + vulnerable toxic combinations
        """
        combinations: list[ToxicCombination] = []
        combo_id = 0

        # Get internet-facing nodes
        internet_facing = self._graph.get_internet_facing_nodes()

        for node in internet_facing:
            if node.asset.resource_type not in self.COMPUTE_TYPES:
                continue

            # Check for vulnerability findings
            vulns = self._get_vulnerability_findings(node.id)
            if vulns:
                # Get the highest severity vulnerability
                max_severity = max(vulns, key=lambda v: self._severity_rank(v.severity))

                conditions = [
                    ToxicCondition(
                        description="Resource is exposed to the internet",
                        asset_id=node.id,
                        evidence=self._get_internet_exposure_evidence(node),
                        severity_contribution="high",
                    ),
                    ToxicCondition(
                        description=f"Resource has {len(vulns)} known vulnerabilities",
                        asset_id=node.id,
                        evidence={
                            "vulnerability_count": len(vulns),
                            "highest_severity": max_severity.severity.value,
                            "cve_ids": [
                                v.rule_id for v in vulns if v.rule_id.startswith("CVE")
                            ][:5],
                        },
                        severity_contribution="critical" if max_severity.severity == Severity.CRITICAL else "high",
                    ),
                ]

                # Determine overall severity based on vulnerability severity
                overall_severity = Severity.CRITICAL if max_severity.severity in (
                    Severity.CRITICAL, Severity.HIGH
                ) else Severity.HIGH

                combination = ToxicCombination(
                    id=f"toxic-internet-vuln-{combo_id}",
                    combination_type=ToxicCombinationType.INTERNET_FACING_VULNERABLE,
                    conditions=conditions,
                    severity=overall_severity,
                    affected_assets=[node.id],
                    description=(
                        f"Internet-facing {node.asset.resource_type} "
                        f"'{node.asset.name}' has {len(vulns)} known vulnerabilities"
                    ),
                    impact=(
                        "Resource is actively exploitable from the internet. "
                        "Attackers can leverage known vulnerabilities to gain "
                        "unauthorized access, execute code, or steal data."
                    ),
                    mitigation=(
                        "1. Immediately patch or update the vulnerable software. "
                        "2. If patching is not immediately possible, consider "
                        "temporarily restricting internet access. "
                        "3. Implement WAF or IPS rules to block known exploits. "
                        "4. Monitor for exploitation attempts. "
                        "5. Review network segmentation to limit blast radius."
                    ),
                    score=self._calculate_vuln_score(vulns),
                )
                combinations.append(combination)
                combo_id += 1

        return combinations

    def _detect_write_access_secrets(self) -> list[ToxicCombination]:
        """
        Detect entities with write access to secrets storage.

        Entities that can both read and write secrets pose elevated risk
        as they could be used to inject malicious secrets or exfiltrate
        existing ones.

        Returns:
            List of write access + secrets access toxic combinations
        """
        combinations: list[ToxicCombination] = []
        combo_id = 0

        for node in self._graph.get_nodes():
            if node.asset.resource_type not in self.PRIVILEGED_IDENTITY_TYPES:
                continue

            # Check for write access to secrets
            secrets_access = self._get_secrets_access(node)
            if secrets_access.get("has_write", False):
                conditions = [
                    ToxicCondition(
                        description="Identity has write access to secrets",
                        asset_id=node.id,
                        evidence=secrets_access,
                        severity_contribution="high",
                    ),
                    ToxicCondition(
                        description="Identity can access secrets storage",
                        asset_id=node.id,
                        evidence={
                            "secrets_services": secrets_access.get("services", [])
                        },
                        severity_contribution="high",
                    ),
                ]

                combination = ToxicCombination(
                    id=f"toxic-write-secrets-{combo_id}",
                    combination_type=ToxicCombinationType.WRITE_ACCESS_SECRETS,
                    conditions=conditions,
                    severity=Severity.HIGH,
                    affected_assets=[node.id] + secrets_access.get("secret_ids", []),
                    description=(
                        f"Identity '{node.asset.name}' has write access "
                        f"to secrets storage"
                    ),
                    impact=(
                        "Identity can modify secrets, potentially injecting "
                        "malicious values that could lead to credential theft, "
                        "supply chain attacks, or service compromise."
                    ),
                    mitigation=(
                        "1. Review and restrict secrets management permissions. "
                        "2. Implement least-privilege access for secrets. "
                        "3. Enable secrets versioning and audit logging. "
                        "4. Use separate identities for secret reading vs writing. "
                        "5. Implement approval workflows for secret changes."
                    ),
                    score=75.0,
                )
                combinations.append(combination)
                combo_id += 1

        return combinations

    def _detect_cross_account_privileged(self) -> list[ToxicCombination]:
        """
        Detect cross-account access combined with privileged roles.

        Cross-account trust relationships with high privileges create
        lateral movement paths and potential for privilege escalation
        across account boundaries.

        Returns:
            List of cross-account + privileged role toxic combinations
        """
        combinations: list[ToxicCombination] = []
        combo_id = 0

        for node in self._graph.get_nodes():
            if node.asset.resource_type not in self.PRIVILEGED_IDENTITY_TYPES:
                continue

            cross_account = self._has_cross_account_trust(node)
            is_privileged = self._has_admin_privileges(node)

            if cross_account and is_privileged:
                conditions = [
                    ToxicCondition(
                        description="Identity has cross-account trust relationship",
                        asset_id=node.id,
                        evidence=self._get_cross_account_evidence(node),
                        severity_contribution="high",
                    ),
                    ToxicCondition(
                        description="Identity has privileged/admin permissions",
                        asset_id=node.id,
                        evidence=self._get_privilege_evidence(node),
                        severity_contribution="high",
                    ),
                ]

                combination = ToxicCombination(
                    id=f"toxic-cross-account-priv-{combo_id}",
                    combination_type=ToxicCombinationType.CROSS_ACCOUNT_PRIVILEGED,
                    conditions=conditions,
                    severity=Severity.HIGH,
                    affected_assets=[node.id],
                    description=(
                        f"Cross-account role '{node.asset.name}' has "
                        f"elevated privileges"
                    ),
                    impact=(
                        "Compromise of the trusting account could lead to "
                        "lateral movement and privilege escalation across "
                        "account boundaries. This creates a broader blast radius."
                    ),
                    mitigation=(
                        "1. Review and minimize cross-account permissions. "
                        "2. Implement external ID requirements for assume role. "
                        "3. Use more granular permissions instead of admin access. "
                        "4. Enable CloudTrail logging for cross-account activity. "
                        "5. Consider using AWS Organizations SCPs to limit scope."
                    ),
                    score=80.0,
                )
                combinations.append(combination)
                combo_id += 1

        return combinations

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _is_publicly_accessible(self, node: AssetNode) -> bool:
        """Check if a resource is publicly accessible."""
        config = node.asset.raw_config

        # Direct internet-facing check
        if node.is_internet_facing:
            return True

        # S3-specific public access checks
        if node.asset.resource_type == "aws_s3_bucket":
            if config.get("public_access_block_configuration", {}).get(
                "block_public_acls"
            ) is False:
                return True
            acl = config.get("acl", "")
            if acl in ("public-read", "public-read-write"):
                return True
            # Check bucket policy for public access
            policy = config.get("policy", {})
            if self._is_public_bucket_policy(policy):
                return True

        # Database public accessibility
        if node.asset.resource_type in (
            "aws_rds_instance",
            "azure_sql_database",
            "gcp_sql_instance",
        ):
            if config.get("publicly_accessible", False):
                return True

        # Storage account public access
        if node.asset.resource_type == "azure_storage_account":
            if config.get("allow_blob_public_access", False):
                return True

        return False

    def _has_sensitive_data_indicators(self, node: AssetNode) -> bool:
        """Check if a resource has indicators of containing sensitive data."""
        config = node.asset.raw_config
        name_lower = node.asset.name.lower()

        # Sensitive name patterns
        sensitive_patterns = [
            "pii", "personal", "customer", "user",
            "secret", "credential", "password", "key",
            "financial", "payment", "card", "billing",
            "health", "hipaa", "medical", "patient",
            "private", "confidential", "sensitive",
            "prod", "production",
        ]

        for pattern in sensitive_patterns:
            if pattern in name_lower:
                return True

        # Check tags for sensitivity indicators
        tags = config.get("tags", {})
        for key, value in tags.items():
            key_lower = key.lower()
            value_lower = str(value).lower() if value else ""
            if any(p in key_lower or p in value_lower for p in sensitive_patterns):
                return True

        # Encryption enabled often indicates sensitive data
        if config.get("encrypted", False) or config.get("encryption"):
            return True

        # Check for findings related to sensitive data
        findings = self._findings_by_asset.get(node.id, [])
        for finding in findings:
            if any(
                term in finding.title.lower()
                for term in ["sensitive", "data", "pii", "encryption"]
            ):
                return True

        return False

    def _has_admin_privileges(self, node: AssetNode) -> bool:
        """Check if an identity has administrative privileges."""
        config = node.asset.raw_config

        # Check attached policies for admin patterns
        attached_policies = config.get("attached_policies", [])
        for policy in attached_policies:
            policy_name = policy if isinstance(policy, str) else policy.get("name", "")
            policy_lower = policy_name.lower()
            if any(
                term in policy_lower
                for term in ["admin", "fullaccess", "poweruser", "root"]
            ):
                return True

        # Check inline policies
        inline_policies = config.get("inline_policies", [])
        for policy in inline_policies:
            if isinstance(policy, dict):
                policy_doc = policy.get("policy_document", {})
                if self._is_overly_permissive_policy(policy_doc):
                    return True

        # Check for admin role assumption
        assume_role_policy = config.get("assume_role_policy", {})
        if self._is_overly_permissive_policy(assume_role_policy):
            return True

        return False

    def _has_mfa_enabled(self, node: AssetNode) -> bool:
        """Check if an identity has MFA enabled."""
        config = node.asset.raw_config

        # Direct MFA check
        if config.get("mfa_enabled", False):
            return True

        # AWS IAM user MFA devices
        mfa_devices = config.get("mfa_devices", [])
        if mfa_devices:
            return True

        # Virtual MFA
        if config.get("virtual_mfa_devices"):
            return True

        # Azure conditional access / MFA
        if config.get("strong_authentication_detail"):
            return True

        # GCP 2FA
        if config.get("two_factor_enabled", False):
            return True

        return False

    def _has_cross_account_trust(self, node: AssetNode) -> bool:
        """Check if a role has cross-account trust relationships."""
        config = node.asset.raw_config

        # AWS assume role policy
        assume_role_policy = config.get("assume_role_policy", {})
        statements = assume_role_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        current_account = node.asset.account_id

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})
            if isinstance(principals, str):
                if self._is_external_principal(principals, current_account):
                    return True
            elif isinstance(principals, dict):
                for principal_type, values in principals.items():
                    if isinstance(values, str):
                        values = [values]
                    for value in values:
                        if self._is_external_principal(value, current_account):
                            return True

        return False

    def _is_external_principal(self, principal: str, current_account: str) -> bool:
        """Check if a principal is from an external account."""
        if principal == "*":
            return True

        # Check if it's an ARN from a different account
        if principal.startswith("arn:"):
            parts = principal.split(":")
            if len(parts) >= 5:
                account_id = parts[4]
                if account_id and account_id != current_account:
                    return True

        return False

    def _get_vulnerability_findings(self, asset_id: str) -> list[Finding]:
        """Get vulnerability findings for an asset."""
        findings = self._findings_by_asset.get(asset_id, [])
        return [
            f for f in findings
            if f.finding_type.value == "vulnerability"
            or f.rule_id.startswith("CVE")
            or "vuln" in f.rule_id.lower()
        ]

    def _get_secrets_access(self, node: AssetNode) -> dict[str, Any]:
        """Analyze secrets access for an identity."""
        config = node.asset.raw_config
        result: dict[str, Any] = {
            "has_read": False,
            "has_write": False,
            "services": [],
            "secret_ids": [],
        }

        # Check policies for secrets access
        all_policies = config.get("attached_policies", []) + config.get(
            "inline_policies", []
        )

        secrets_actions = {
            "secretsmanager:GetSecretValue": "read",
            "secretsmanager:PutSecretValue": "write",
            "secretsmanager:CreateSecret": "write",
            "secretsmanager:UpdateSecret": "write",
            "ssm:GetParameter": "read",
            "ssm:PutParameter": "write",
            "kms:Decrypt": "read",
            "kms:Encrypt": "write",
        }

        for policy in all_policies:
            if isinstance(policy, dict):
                policy_doc = policy.get("policy_document", {})
                statements = policy_doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]

                for statement in statements:
                    if statement.get("Effect") != "Allow":
                        continue

                    actions = statement.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    for action in actions:
                        for secrets_action, access_type in secrets_actions.items():
                            if action == secrets_action or action == "*":
                                if access_type == "read":
                                    result["has_read"] = True
                                elif access_type == "write":
                                    result["has_write"] = True

                                service = secrets_action.split(":")[0]
                                if service not in result["services"]:
                                    result["services"].append(service)

        return result

    def _is_overly_permissive_policy(self, policy_doc: dict[str, Any]) -> bool:
        """Check if a policy is overly permissive."""
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

    def _is_public_bucket_policy(self, policy: dict[str, Any]) -> bool:
        """Check if a bucket policy allows public access."""
        if not policy:
            return False

        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})
            if principal == "*" or principal == {"AWS": "*"}:
                return True

        return False

    def _get_public_access_evidence(self, node: AssetNode) -> dict[str, Any]:
        """Get evidence of public access configuration."""
        config = node.asset.raw_config
        evidence: dict[str, Any] = {}

        if node.is_internet_facing:
            evidence["internet_facing"] = True

        if node.asset.resource_type == "aws_s3_bucket":
            evidence["public_access_block"] = config.get(
                "public_access_block_configuration"
            )
            evidence["acl"] = config.get("acl")

        if config.get("publicly_accessible"):
            evidence["publicly_accessible"] = True

        return evidence

    def _get_sensitive_data_evidence(self, node: AssetNode) -> dict[str, Any]:
        """Get evidence of sensitive data indicators."""
        evidence: dict[str, Any] = {}
        config = node.asset.raw_config

        # Check name
        name_lower = node.asset.name.lower()
        sensitive_matches = []
        for pattern in ["pii", "personal", "customer", "secret", "credential", "prod"]:
            if pattern in name_lower:
                sensitive_matches.append(pattern)
        if sensitive_matches:
            evidence["name_patterns"] = sensitive_matches

        # Check encryption
        if config.get("encrypted") or config.get("encryption"):
            evidence["encryption_enabled"] = True

        # Check tags
        sensitive_tags = {}
        for key, value in config.get("tags", {}).items():
            if any(
                p in key.lower() or p in str(value).lower()
                for p in ["sensitive", "pii", "confidential"]
            ):
                sensitive_tags[key] = value
        if sensitive_tags:
            evidence["sensitive_tags"] = sensitive_tags

        return evidence

    def _get_privilege_evidence(self, node: AssetNode) -> dict[str, Any]:
        """Get evidence of admin privileges."""
        config = node.asset.raw_config
        evidence: dict[str, Any] = {}

        admin_policies = []
        for policy in config.get("attached_policies", []):
            policy_name = policy if isinstance(policy, str) else policy.get("name", "")
            if any(
                term in policy_name.lower()
                for term in ["admin", "fullaccess", "poweruser"]
            ):
                admin_policies.append(policy_name)

        if admin_policies:
            evidence["admin_policies"] = admin_policies

        return evidence

    def _get_internet_exposure_evidence(self, node: AssetNode) -> dict[str, Any]:
        """Get evidence of internet exposure."""
        config = node.asset.raw_config
        evidence: dict[str, Any] = {}

        if config.get("public_ip_address"):
            evidence["public_ip"] = config["public_ip_address"]

        if config.get("security_groups"):
            evidence["security_groups"] = config["security_groups"]

        if node.is_internet_facing:
            evidence["internet_facing"] = True

        return evidence

    def _get_cross_account_evidence(self, node: AssetNode) -> dict[str, Any]:
        """Get evidence of cross-account trust."""
        config = node.asset.raw_config
        evidence: dict[str, Any] = {}

        assume_role_policy = config.get("assume_role_policy", {})
        external_principals = []

        statements = assume_role_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principals = statement.get("Principal", {})
            if isinstance(principals, dict):
                for principal_type, values in principals.items():
                    if isinstance(values, str):
                        values = [values]
                    for value in values:
                        if self._is_external_principal(value, node.asset.account_id):
                            external_principals.append(value)

        if external_principals:
            evidence["external_principals"] = external_principals

        return evidence

    def _severity_rank(self, severity: Severity) -> int:
        """Get numeric rank for severity (higher = more severe)."""
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(severity, 0)

    def _calculate_vuln_score(self, vulns: list[Finding]) -> float:
        """Calculate a risk score based on vulnerabilities."""
        if not vulns:
            return 0.0

        base_score = 50.0

        for vuln in vulns:
            if vuln.severity == Severity.CRITICAL:
                base_score += 25.0
            elif vuln.severity == Severity.HIGH:
                base_score += 15.0
            elif vuln.severity == Severity.MEDIUM:
                base_score += 5.0

        return min(100.0, base_score)
