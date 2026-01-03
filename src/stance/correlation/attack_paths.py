"""
Attack path analysis for Mantissa Stance.

Identifies potential attack paths through cloud infrastructure
based on findings, asset relationships, and network topology.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from stance.models.finding import Finding, FindingCollection, Severity, FindingType
from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


class AttackPathType(Enum):
    """Types of attack paths."""

    INTERNET_TO_INTERNAL = "internet_to_internal"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"


class ExposureLevel(Enum):
    """Asset exposure levels."""

    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"


@dataclass
class AttackStep:
    """
    A single step in an attack path.

    Attributes:
        order: Step order in the path
        asset_id: Asset involved in this step
        asset_name: Human-readable asset name
        finding_id: Related finding (if any)
        action: Attack action taken
        technique: MITRE ATT&CK technique (if applicable)
        exposure: Exposure level of the asset
        risk_contribution: Risk contribution of this step
    """

    order: int
    asset_id: str
    asset_name: str
    finding_id: str | None = None
    action: str = ""
    technique: str = ""
    exposure: ExposureLevel = ExposureLevel.INTERNAL
    risk_contribution: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "order": self.order,
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "finding_id": self.finding_id,
            "action": self.action,
            "technique": self.technique,
            "exposure": self.exposure.value,
            "risk_contribution": self.risk_contribution,
        }


@dataclass
class AttackPath:
    """
    A potential attack path through cloud infrastructure.

    Attributes:
        id: Unique path identifier
        path_type: Type of attack path
        steps: Ordered list of attack steps
        entry_point: Initial access asset
        target: Final target asset
        total_risk_score: Combined risk score
        likelihood: Estimated likelihood (0-1)
        impact: Estimated impact (0-1)
        findings: Findings that enable this path
        mitigations: Recommended mitigations
    """

    id: str
    path_type: AttackPathType
    steps: list[AttackStep]
    entry_point: str
    target: str
    total_risk_score: float = 0.0
    likelihood: float = 0.0
    impact: float = 0.0
    findings: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        """Get path length."""
        return len(self.steps)

    @property
    def risk_priority(self) -> float:
        """Calculate risk priority (likelihood * impact)."""
        return self.likelihood * self.impact

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "path_type": self.path_type.value,
            "length": self.length,
            "steps": [s.to_dict() for s in self.steps],
            "entry_point": self.entry_point,
            "target": self.target,
            "total_risk_score": self.total_risk_score,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_priority": self.risk_priority,
            "findings": self.findings,
            "mitigations": self.mitigations,
        }


@dataclass
class AttackPathAnalysisResult:
    """
    Result of attack path analysis.

    Attributes:
        paths: Identified attack paths
        high_risk_paths: Paths with high risk priority
        stats: Analysis statistics
    """

    paths: list[AttackPath] = field(default_factory=list)
    high_risk_paths: list[AttackPath] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_paths": len(self.paths),
            "high_risk_count": len(self.high_risk_paths),
            "paths": [p.to_dict() for p in self.paths],
            "stats": self.stats,
        }


class AttackPathAnalyzer:
    """
    Analyzes findings and assets to identify attack paths.

    Identifies potential attack paths including:
    - Internet to internal resource paths
    - Privilege escalation chains
    - Lateral movement opportunities
    - Data exfiltration paths

    Example:
        >>> analyzer = AttackPathAnalyzer()
        >>> result = analyzer.analyze(findings, assets)
        >>> for path in result.high_risk_paths:
        ...     print(f"Path: {path.entry_point} -> {path.target}")
    """

    # Common attack techniques mapped to finding patterns
    TECHNIQUE_MAPPINGS = {
        # Initial access
        "public_bucket": ("T1190", "Exploit Public-Facing Application"),
        "open_ssh": ("T1133", "External Remote Services"),
        "open_rdp": ("T1133", "External Remote Services"),
        "public_database": ("T1190", "Exploit Public-Facing Application"),
        # Credential access
        "weak_password": ("T1110", "Brute Force"),
        "no_mfa": ("T1078", "Valid Accounts"),
        "access_key_exposed": ("T1552", "Unsecured Credentials"),
        "service_account_key": ("T1552", "Unsecured Credentials"),
        # Privilege escalation
        "overly_permissive": ("T1078.004", "Cloud Accounts"),
        "admin_access": ("T1098", "Account Manipulation"),
        "iam_policy": ("T1078", "Valid Accounts"),
        # Lateral movement
        "security_group_open": ("T1021", "Remote Services"),
        "vpc_peering": ("T1021", "Remote Services"),
        # Data access
        "unencrypted_storage": ("T1530", "Data from Cloud Storage Object"),
        "public_access": ("T1530", "Data from Cloud Storage Object"),
    }

    def __init__(
        self,
        max_path_length: int = 5,
        min_risk_threshold: float = 0.3,
    ) -> None:
        """
        Initialize the attack path analyzer.

        Args:
            max_path_length: Maximum steps in an attack path
            min_risk_threshold: Minimum risk to include a path
        """
        self._max_path_length = max_path_length
        self._min_risk_threshold = min_risk_threshold

    def analyze(
        self,
        findings: FindingCollection | list[Finding],
        assets: AssetCollection | list[Asset],
    ) -> AttackPathAnalysisResult:
        """
        Analyze findings and assets to identify attack paths.

        Args:
            findings: Security findings
            assets: Asset inventory

        Returns:
            AttackPathAnalysisResult with identified paths
        """
        if isinstance(findings, FindingCollection):
            finding_list = list(findings)
        else:
            finding_list = findings

        if isinstance(assets, AssetCollection):
            asset_list = list(assets)
        else:
            asset_list = assets

        # Build indexes
        assets_by_id = {a.id: a for a in asset_list}
        findings_by_asset = self._index_findings_by_asset(finding_list)

        # Identify different types of attack paths
        paths: list[AttackPath] = []

        # Internet to internal paths
        internet_paths = self._find_internet_to_internal_paths(
            asset_list, findings_by_asset, assets_by_id
        )
        paths.extend(internet_paths)

        # Privilege escalation paths
        priv_esc_paths = self._find_privilege_escalation_paths(
            finding_list, assets_by_id
        )
        paths.extend(priv_esc_paths)

        # Lateral movement paths
        lateral_paths = self._find_lateral_movement_paths(
            asset_list, findings_by_asset, assets_by_id
        )
        paths.extend(lateral_paths)

        # Data exfiltration paths
        data_paths = self._find_data_exfiltration_paths(
            asset_list, findings_by_asset, assets_by_id
        )
        paths.extend(data_paths)

        # Calculate scores and filter
        for path in paths:
            self._calculate_path_scores(path, findings_by_asset)

        # Filter by risk threshold
        filtered_paths = [
            p for p in paths if p.total_risk_score >= self._min_risk_threshold
        ]

        # Sort by risk
        filtered_paths.sort(key=lambda p: p.total_risk_score, reverse=True)

        # Identify high risk paths
        high_risk = [p for p in filtered_paths if p.risk_priority >= 0.7]

        # Calculate statistics
        stats = self._calculate_stats(filtered_paths, finding_list, asset_list)

        return AttackPathAnalysisResult(
            paths=filtered_paths,
            high_risk_paths=high_risk,
            stats=stats,
        )

    def _index_findings_by_asset(
        self, findings: list[Finding]
    ) -> dict[str, list[Finding]]:
        """Index findings by asset ID."""
        index: dict[str, list[Finding]] = {}
        for finding in findings:
            if finding.asset_id:
                if finding.asset_id not in index:
                    index[finding.asset_id] = []
                index[finding.asset_id].append(finding)
        return index

    def _find_internet_to_internal_paths(
        self,
        assets: list[Asset],
        findings_by_asset: dict[str, list[Finding]],
        assets_by_id: dict[str, Asset],
    ) -> list[AttackPath]:
        """Find paths from internet-facing assets to internal resources."""
        paths: list[AttackPath] = []

        # Find internet-facing assets with findings
        internet_facing = [
            a for a in assets
            if a.network_exposure == "internet_facing"
            and a.id in findings_by_asset
        ]

        # Find internal assets with sensitive data or high-value
        internal_targets = [
            a for a in assets
            if a.network_exposure in ("internal", "isolated")
            and self._is_high_value_target(a)
        ]

        for entry in internet_facing:
            for target in internal_targets:
                path = self._build_path(
                    entry_asset=entry,
                    target_asset=target,
                    path_type=AttackPathType.INTERNET_TO_INTERNAL,
                    findings_by_asset=findings_by_asset,
                    assets_by_id=assets_by_id,
                )
                if path:
                    paths.append(path)

        return paths

    def _find_privilege_escalation_paths(
        self,
        findings: list[Finding],
        assets_by_id: dict[str, Asset],
    ) -> list[AttackPath]:
        """Find privilege escalation paths."""
        paths: list[AttackPath] = []

        # Find IAM-related findings
        iam_findings = [
            f for f in findings
            if f.rule_id and any(
                keyword in f.rule_id.lower()
                for keyword in ["iam", "role", "permission", "policy", "admin"]
            )
        ]

        if len(iam_findings) < 2:
            return paths

        # Group by severity to find escalation chains
        low_priv = [f for f in iam_findings if f.severity in (Severity.LOW, Severity.MEDIUM)]
        high_priv = [f for f in iam_findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]

        for entry in low_priv:
            for target in high_priv:
                if entry.asset_id != target.asset_id:
                    path_id = f"priv_esc_{entry.id[:8]}_{target.id[:8]}"
                    entry_asset = assets_by_id.get(entry.asset_id)
                    target_asset = assets_by_id.get(target.asset_id)

                    steps = [
                        AttackStep(
                            order=1,
                            asset_id=entry.asset_id,
                            asset_name=entry_asset.name if entry_asset else entry.asset_id,
                            finding_id=entry.id,
                            action="Gain initial access via misconfigured permissions",
                            technique=self._get_technique(entry),
                        ),
                        AttackStep(
                            order=2,
                            asset_id=target.asset_id,
                            asset_name=target_asset.name if target_asset else target.asset_id,
                            finding_id=target.id,
                            action="Escalate privileges to administrative access",
                            technique=self._get_technique(target),
                        ),
                    ]

                    paths.append(
                        AttackPath(
                            id=path_id,
                            path_type=AttackPathType.PRIVILEGE_ESCALATION,
                            steps=steps,
                            entry_point=entry.asset_id,
                            target=target.asset_id,
                            findings=[entry.id, target.id],
                            mitigations=[
                                "Apply least privilege principle",
                                "Review and remediate IAM policies",
                                "Enable MFA for privileged accounts",
                            ],
                        )
                    )

        return paths

    def _find_lateral_movement_paths(
        self,
        assets: list[Asset],
        findings_by_asset: dict[str, list[Finding]],
        assets_by_id: dict[str, Asset],
    ) -> list[AttackPath]:
        """Find lateral movement paths between assets."""
        paths: list[AttackPath] = []

        # Find assets with network security findings
        network_vulnerable = [
            a for a in assets
            if a.id in findings_by_asset
            and any(
                f.rule_id and any(
                    kw in f.rule_id.lower()
                    for kw in ["security-group", "firewall", "nsg", "network"]
                )
                for f in findings_by_asset[a.id]
            )
        ]

        for i, source in enumerate(network_vulnerable):
            for target in network_vulnerable[i + 1:]:
                if self._can_reach(source, target):
                    path_id = f"lateral_{source.id[:8]}_{target.id[:8]}"
                    source_findings = [
                        f.id for f in findings_by_asset.get(source.id, [])
                    ]
                    target_findings = [
                        f.id for f in findings_by_asset.get(target.id, [])
                    ]

                    steps = [
                        AttackStep(
                            order=1,
                            asset_id=source.id,
                            asset_name=source.name,
                            action="Compromise source system",
                        ),
                        AttackStep(
                            order=2,
                            asset_id=target.id,
                            asset_name=target.name,
                            action="Move laterally via permissive network controls",
                            technique="T1021",
                        ),
                    ]

                    paths.append(
                        AttackPath(
                            id=path_id,
                            path_type=AttackPathType.LATERAL_MOVEMENT,
                            steps=steps,
                            entry_point=source.id,
                            target=target.id,
                            findings=source_findings + target_findings,
                            mitigations=[
                                "Implement network segmentation",
                                "Restrict security group rules",
                                "Enable VPC flow logs",
                            ],
                        )
                    )

        return paths

    def _find_data_exfiltration_paths(
        self,
        assets: list[Asset],
        findings_by_asset: dict[str, list[Finding]],
        assets_by_id: dict[str, Asset],
    ) -> list[AttackPath]:
        """Find paths to data exfiltration."""
        paths: list[AttackPath] = []

        # Find storage assets with public access or encryption issues
        vulnerable_storage = [
            a for a in assets
            if a.resource_type and any(
                storage_type in a.resource_type.lower()
                for storage_type in ["s3", "storage", "bucket", "blob"]
            )
            and a.id in findings_by_asset
        ]

        for storage in vulnerable_storage:
            findings = findings_by_asset.get(storage.id, [])
            public_access = any(
                f.rule_id and "public" in f.rule_id.lower()
                for f in findings
            )
            unencrypted = any(
                f.rule_id and "encrypt" in f.rule_id.lower()
                for f in findings
            )

            if public_access or unencrypted:
                path_id = f"data_exfil_{storage.id[:8]}"

                steps = [
                    AttackStep(
                        order=1,
                        asset_id=storage.id,
                        asset_name=storage.name,
                        action="Access exposed storage" if public_access else "Access unencrypted data",
                        technique="T1530",
                        exposure=ExposureLevel.INTERNET if public_access else ExposureLevel.INTERNAL,
                    ),
                ]

                paths.append(
                    AttackPath(
                        id=path_id,
                        path_type=AttackPathType.DATA_EXFILTRATION,
                        steps=steps,
                        entry_point=storage.id,
                        target=storage.id,
                        findings=[f.id for f in findings],
                        mitigations=[
                            "Enable encryption at rest",
                            "Block public access",
                            "Enable access logging",
                            "Implement data classification",
                        ],
                    )
                )

        return paths

    def _build_path(
        self,
        entry_asset: Asset,
        target_asset: Asset,
        path_type: AttackPathType,
        findings_by_asset: dict[str, list[Finding]],
        assets_by_id: dict[str, Asset],
    ) -> AttackPath | None:
        """Build an attack path between two assets."""
        path_id = f"{path_type.value}_{entry_asset.id[:8]}_{target_asset.id[:8]}"

        entry_findings = findings_by_asset.get(entry_asset.id, [])
        if not entry_findings:
            return None

        steps = [
            AttackStep(
                order=1,
                asset_id=entry_asset.id,
                asset_name=entry_asset.name,
                finding_id=entry_findings[0].id if entry_findings else None,
                action="Initial access via internet-facing vulnerability",
                exposure=ExposureLevel.INTERNET,
            ),
            AttackStep(
                order=2,
                asset_id=target_asset.id,
                asset_name=target_asset.name,
                action="Pivot to internal target",
                exposure=ExposureLevel.INTERNAL,
            ),
        ]

        return AttackPath(
            id=path_id,
            path_type=path_type,
            steps=steps,
            entry_point=entry_asset.id,
            target=target_asset.id,
            findings=[f.id for f in entry_findings],
            mitigations=[
                "Remediate internet-facing vulnerabilities",
                "Implement network segmentation",
                "Enable monitoring and alerting",
            ],
        )

    def _calculate_path_scores(
        self,
        path: AttackPath,
        findings_by_asset: dict[str, list[Finding]],
    ) -> None:
        """Calculate risk scores for a path."""
        severity_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
        }

        # Calculate likelihood based on findings
        total_severity = 0.0
        finding_count = 0
        for step in path.steps:
            if step.finding_id:
                finding_count += 1
            if step.asset_id in findings_by_asset:
                for finding in findings_by_asset[step.asset_id]:
                    total_severity += severity_scores.get(finding.severity, 0.5)

        if finding_count > 0:
            path.likelihood = min(1.0, total_severity / max(finding_count, 1) * 0.8)
        else:
            path.likelihood = 0.3

        # Calculate impact based on path type and target
        impact_by_type = {
            AttackPathType.INTERNET_TO_INTERNAL: 0.9,
            AttackPathType.PRIVILEGE_ESCALATION: 0.85,
            AttackPathType.LATERAL_MOVEMENT: 0.7,
            AttackPathType.DATA_EXFILTRATION: 0.95,
            AttackPathType.CREDENTIAL_THEFT: 0.8,
        }
        path.impact = impact_by_type.get(path.path_type, 0.5)

        # Total risk score
        path.total_risk_score = round(path.likelihood * path.impact, 2)

        # Calculate step contributions
        if path.steps:
            contribution_per_step = path.total_risk_score / len(path.steps)
            for step in path.steps:
                step.risk_contribution = round(contribution_per_step, 2)

    def _is_high_value_target(self, asset: Asset) -> bool:
        """Determine if asset is a high-value target."""
        # Check tags for criticality
        if asset.tags:
            critical_tags = ["production", "prod", "critical", "sensitive", "pii", "pci"]
            for tag_key, tag_value in asset.tags.items():
                if any(
                    critical in tag_key.lower() or critical in str(tag_value).lower()
                    for critical in critical_tags
                ):
                    return True

        # Check resource type
        high_value_types = ["database", "rds", "sql", "secrets", "kms", "key"]
        if asset.resource_type:
            if any(hvt in asset.resource_type.lower() for hvt in high_value_types):
                return True

        return False

    def _can_reach(self, source: Asset, target: Asset) -> bool:
        """Determine if source can potentially reach target."""
        # Simplified reachability - in real implementation would use
        # network topology data (VPCs, subnets, security groups, etc.)
        # For now, assume assets in same region can potentially reach each other
        if source.region and target.region:
            return source.region == target.region
        return True

    def _get_technique(self, finding: Finding) -> str:
        """Get MITRE ATT&CK technique for a finding."""
        if not finding.rule_id:
            return ""

        rule_lower = finding.rule_id.lower()
        for pattern, (technique_id, _) in self.TECHNIQUE_MAPPINGS.items():
            if pattern in rule_lower:
                return technique_id

        return ""

    def _calculate_stats(
        self,
        paths: list[AttackPath],
        findings: list[Finding],
        assets: list[Asset],
    ) -> dict[str, Any]:
        """Calculate analysis statistics."""
        stats = {
            "total_paths": len(paths),
            "paths_by_type": {},
            "average_path_length": 0.0,
            "max_path_length": 0,
            "average_risk_score": 0.0,
            "assets_in_paths": 0,
            "findings_in_paths": 0,
        }

        if not paths:
            return stats

        # Count by type
        for path in paths:
            path_type = path.path_type.value
            stats["paths_by_type"][path_type] = (
                stats["paths_by_type"].get(path_type, 0) + 1
            )

        # Calculate averages
        stats["average_path_length"] = round(
            sum(len(p.steps) for p in paths) / len(paths), 2
        )
        stats["max_path_length"] = max(len(p.steps) for p in paths)
        stats["average_risk_score"] = round(
            sum(p.total_risk_score for p in paths) / len(paths), 2
        )

        # Count unique assets and findings in paths
        all_assets = set()
        all_findings = set()
        for path in paths:
            for step in path.steps:
                all_assets.add(step.asset_id)
            all_findings.update(path.findings)

        stats["assets_in_paths"] = len(all_assets)
        stats["findings_in_paths"] = len(all_findings)

        return stats
