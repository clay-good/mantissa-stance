"""
Finding correlator for Mantissa Stance.

Correlates security findings by asset, network path, and other
relationships to identify attack chains and aggregate risk.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from stance.models.finding import Finding, FindingCollection, Severity, FindingType
from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFinding:
    """
    A finding with its correlation context.

    Attributes:
        finding: The original finding
        related_findings: List of related finding IDs
        correlation_type: Type of correlation (asset, network, rule, cve)
        correlation_score: Strength of correlation (0-1)
        correlation_reason: Human-readable correlation reason
    """

    finding: Finding
    related_findings: list[str] = field(default_factory=list)
    correlation_type: str = ""
    correlation_score: float = 0.0
    correlation_reason: str = ""


@dataclass
class CorrelationGroup:
    """
    A group of correlated findings.

    Attributes:
        id: Unique group identifier
        findings: Findings in this group
        group_type: Type of correlation grouping
        root_cause: Identified root cause (if any)
        aggregate_severity: Combined severity
        aggregate_risk_score: Combined risk score
        affected_assets: List of affected asset IDs
        metadata: Additional group metadata
    """

    id: str
    findings: list[Finding]
    group_type: str
    root_cause: str = ""
    aggregate_severity: Severity = Severity.INFO
    aggregate_risk_score: float = 0.0
    affected_assets: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        """Get number of findings in group."""
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "group_type": self.group_type,
            "finding_count": self.finding_count,
            "findings": [f.id for f in self.findings],
            "root_cause": self.root_cause,
            "aggregate_severity": self.aggregate_severity.value,
            "aggregate_risk_score": self.aggregate_risk_score,
            "affected_assets": self.affected_assets,
            "metadata": self.metadata,
        }


@dataclass
class CorrelationResult:
    """
    Result of correlation analysis.

    Attributes:
        groups: Identified correlation groups
        uncorrelated_findings: Findings not in any group
        correlation_stats: Statistics about correlations
        analysis_time_ms: Time taken for analysis
    """

    groups: list[CorrelationGroup] = field(default_factory=list)
    uncorrelated_findings: list[Finding] = field(default_factory=list)
    correlation_stats: dict[str, Any] = field(default_factory=dict)
    analysis_time_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "groups": [g.to_dict() for g in self.groups],
            "uncorrelated_count": len(self.uncorrelated_findings),
            "correlation_stats": self.correlation_stats,
            "analysis_time_ms": self.analysis_time_ms,
        }


class FindingCorrelator:
    """
    Correlates findings to identify patterns and relationships.

    Analyzes findings to identify:
    - Findings affecting the same asset
    - Findings in the same network path
    - Findings with common root causes
    - Attack chains spanning multiple resources

    Example:
        >>> correlator = FindingCorrelator()
        >>> result = correlator.correlate(findings, assets)
        >>> for group in result.groups:
        ...     print(f"Group {group.id}: {group.finding_count} findings")
    """

    def __init__(
        self,
        time_window_hours: int = 24,
        min_group_size: int = 2,
        correlation_threshold: float = 0.5,
    ) -> None:
        """
        Initialize the correlator.

        Args:
            time_window_hours: Time window for temporal correlation
            min_group_size: Minimum findings to form a group
            correlation_threshold: Minimum score for correlation
        """
        self._time_window = timedelta(hours=time_window_hours)
        self._min_group_size = min_group_size
        self._correlation_threshold = correlation_threshold

    def correlate(
        self,
        findings: FindingCollection | list[Finding],
        assets: AssetCollection | list[Asset] | None = None,
    ) -> CorrelationResult:
        """
        Correlate findings and identify groups.

        Args:
            findings: Findings to correlate
            assets: Optional assets for enriched correlation

        Returns:
            CorrelationResult with groups and statistics
        """
        start_time = datetime.utcnow()

        if isinstance(findings, FindingCollection):
            finding_list = list(findings)
        else:
            finding_list = findings

        if not finding_list:
            return CorrelationResult()

        # Build asset lookup if provided
        asset_lookup: dict[str, Asset] = {}
        if assets:
            if isinstance(assets, AssetCollection):
                asset_list = list(assets)
            else:
                asset_list = assets
            asset_lookup = {a.id: a for a in asset_list}

        # Perform different types of correlation
        asset_groups = self._correlate_by_asset(finding_list)
        rule_groups = self._correlate_by_rule(finding_list)
        cve_groups = self._correlate_by_cve(finding_list)
        network_groups = self._correlate_by_network(finding_list, asset_lookup)
        temporal_groups = self._correlate_by_time(finding_list)

        # Merge overlapping groups
        all_groups = asset_groups + rule_groups + cve_groups + network_groups + temporal_groups
        merged_groups = self._merge_groups(all_groups)

        # Calculate aggregate scores
        for group in merged_groups:
            group.aggregate_severity = self._calculate_aggregate_severity(group.findings)
            group.aggregate_risk_score = self._calculate_aggregate_risk(group.findings)
            group.affected_assets = list(set(f.asset_id for f in group.findings if f.asset_id))

        # Identify uncorrelated findings
        correlated_ids = set()
        for group in merged_groups:
            for finding in group.findings:
                correlated_ids.add(finding.id)

        uncorrelated = [f for f in finding_list if f.id not in correlated_ids]

        # Calculate statistics
        stats = self._calculate_stats(merged_groups, uncorrelated, finding_list)

        execution_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        return CorrelationResult(
            groups=merged_groups,
            uncorrelated_findings=uncorrelated,
            correlation_stats=stats,
            analysis_time_ms=execution_time,
        )

    def _correlate_by_asset(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group findings by affected asset."""
        groups: list[CorrelationGroup] = []
        by_asset: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.asset_id:
                by_asset[finding.asset_id].append(finding)

        for asset_id, asset_findings in by_asset.items():
            if len(asset_findings) >= self._min_group_size:
                groups.append(
                    CorrelationGroup(
                        id=f"asset_{asset_id[:16]}",
                        findings=asset_findings,
                        group_type="asset",
                        root_cause=f"Multiple findings on asset {asset_id}",
                        metadata={"asset_id": asset_id},
                    )
                )

        return groups

    def _correlate_by_rule(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group findings by policy rule."""
        groups: list[CorrelationGroup] = []
        by_rule: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.rule_id:
                by_rule[finding.rule_id].append(finding)

        for rule_id, rule_findings in by_rule.items():
            if len(rule_findings) >= self._min_group_size:
                # Only group if affecting multiple assets
                unique_assets = set(f.asset_id for f in rule_findings if f.asset_id)
                if len(unique_assets) > 1:
                    groups.append(
                        CorrelationGroup(
                            id=f"rule_{rule_id}",
                            findings=rule_findings,
                            group_type="rule",
                            root_cause=f"Systemic issue: {rule_id} failing across {len(unique_assets)} assets",
                            metadata={
                                "rule_id": rule_id,
                                "asset_count": len(unique_assets),
                            },
                        )
                    )

        return groups

    def _correlate_by_cve(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group vulnerability findings by CVE."""
        groups: list[CorrelationGroup] = []
        by_cve: dict[str, list[Finding]] = defaultdict(list)

        for finding in findings:
            if finding.cve_id:
                by_cve[finding.cve_id].append(finding)

        for cve_id, cve_findings in by_cve.items():
            if len(cve_findings) >= self._min_group_size:
                unique_assets = set(f.asset_id for f in cve_findings if f.asset_id)
                groups.append(
                    CorrelationGroup(
                        id=f"cve_{cve_id}",
                        findings=cve_findings,
                        group_type="cve",
                        root_cause=f"Vulnerability {cve_id} present on {len(unique_assets)} assets",
                        metadata={
                            "cve_id": cve_id,
                            "asset_count": len(unique_assets),
                            "cvss_score": cve_findings[0].cvss_score,
                        },
                    )
                )

        return groups

    def _correlate_by_network(
        self,
        findings: list[Finding],
        assets: dict[str, Asset],
    ) -> list[CorrelationGroup]:
        """Group findings by network exposure."""
        groups: list[CorrelationGroup] = []

        # Group by network exposure level
        by_exposure: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            asset = assets.get(finding.asset_id) if finding.asset_id else None
            if asset:
                exposure = asset.network_exposure
                by_exposure[exposure].append(finding)

        # Create groups for internet-facing assets with multiple findings
        internet_facing = by_exposure.get("internet_facing", [])
        if len(internet_facing) >= self._min_group_size:
            groups.append(
                CorrelationGroup(
                    id="network_internet_facing",
                    findings=internet_facing,
                    group_type="network",
                    root_cause="Multiple findings on internet-facing resources",
                    metadata={
                        "exposure": "internet_facing",
                        "high_priority": True,
                    },
                )
            )

        return groups

    def _correlate_by_time(self, findings: list[Finding]) -> list[CorrelationGroup]:
        """Group findings that appeared around the same time."""
        groups: list[CorrelationGroup] = []

        # Sort findings by first_seen
        findings_with_time = [
            f for f in findings if f.first_seen is not None
        ]
        findings_with_time.sort(key=lambda f: f.first_seen)  # type: ignore

        if len(findings_with_time) < self._min_group_size:
            return groups

        # Find clusters of findings within time window
        current_cluster: list[Finding] = []
        cluster_start: datetime | None = None

        for finding in findings_with_time:
            if not current_cluster:
                current_cluster = [finding]
                cluster_start = finding.first_seen
            else:
                if finding.first_seen and cluster_start:
                    if finding.first_seen - cluster_start <= self._time_window:
                        current_cluster.append(finding)
                    else:
                        # Check if cluster is large enough
                        if len(current_cluster) >= self._min_group_size:
                            groups.append(
                                CorrelationGroup(
                                    id=f"temporal_{cluster_start.strftime('%Y%m%d%H%M')}",
                                    findings=current_cluster.copy(),
                                    group_type="temporal",
                                    root_cause=f"Burst of {len(current_cluster)} findings within {self._time_window}",
                                    metadata={
                                        "start_time": cluster_start.isoformat(),
                                        "end_time": current_cluster[-1].first_seen.isoformat() if current_cluster[-1].first_seen else None,
                                    },
                                )
                            )
                        # Start new cluster
                        current_cluster = [finding]
                        cluster_start = finding.first_seen

        # Check final cluster
        if len(current_cluster) >= self._min_group_size and cluster_start:
            groups.append(
                CorrelationGroup(
                    id=f"temporal_{cluster_start.strftime('%Y%m%d%H%M')}",
                    findings=current_cluster,
                    group_type="temporal",
                    root_cause=f"Burst of {len(current_cluster)} findings within {self._time_window}",
                    metadata={
                        "start_time": cluster_start.isoformat(),
                    },
                )
            )

        return groups

    def _merge_groups(
        self, groups: list[CorrelationGroup]
    ) -> list[CorrelationGroup]:
        """Merge overlapping groups."""
        if not groups:
            return []

        # Sort by size (larger groups first)
        groups.sort(key=lambda g: len(g.findings), reverse=True)

        merged: list[CorrelationGroup] = []
        used_findings: set[str] = set()

        for group in groups:
            # Check overlap with already merged groups
            group_finding_ids = {f.id for f in group.findings}
            overlap = group_finding_ids & used_findings

            if len(overlap) < len(group_finding_ids) * 0.5:
                # Less than 50% overlap, keep as separate group
                # But remove overlapping findings
                non_overlapping = [f for f in group.findings if f.id not in used_findings]
                if len(non_overlapping) >= self._min_group_size:
                    merged.append(
                        CorrelationGroup(
                            id=group.id,
                            findings=non_overlapping,
                            group_type=group.group_type,
                            root_cause=group.root_cause,
                            metadata=group.metadata,
                        )
                    )
                    used_findings.update(f.id for f in non_overlapping)

        return merged

    def _calculate_aggregate_severity(self, findings: list[Finding]) -> Severity:
        """Calculate aggregate severity for a group."""
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

        if not findings:
            return Severity.INFO

        max_severity = Severity.INFO
        for finding in findings:
            if severity_order.index(finding.severity) > severity_order.index(max_severity):
                max_severity = finding.severity

        return max_severity

    def _calculate_aggregate_risk(self, findings: list[Finding]) -> float:
        """Calculate aggregate risk score for a group."""
        if not findings:
            return 0.0

        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.5,
        }

        total_score = sum(severity_weights.get(f.severity, 1.0) for f in findings)

        # Factor in CVSS scores for vulnerabilities
        cvss_bonus = sum(
            (f.cvss_score or 0) * 0.5
            for f in findings
            if f.finding_type == FindingType.VULNERABILITY and f.cvss_score
        )

        # Normalize to 0-100 scale
        raw_score = total_score + cvss_bonus
        normalized = min(100.0, raw_score * 2)

        return round(normalized, 2)

    def _calculate_stats(
        self,
        groups: list[CorrelationGroup],
        uncorrelated: list[Finding],
        all_findings: list[Finding],
    ) -> dict[str, Any]:
        """Calculate correlation statistics."""
        total = len(all_findings)
        correlated = total - len(uncorrelated)

        stats = {
            "total_findings": total,
            "correlated_findings": correlated,
            "uncorrelated_findings": len(uncorrelated),
            "correlation_rate": round(correlated / total, 2) if total > 0 else 0,
            "total_groups": len(groups),
            "groups_by_type": {},
            "largest_group_size": max((len(g.findings) for g in groups), default=0),
            "average_group_size": round(
                sum(len(g.findings) for g in groups) / len(groups), 2
            ) if groups else 0,
        }

        # Count groups by type
        for group in groups:
            if group.group_type not in stats["groups_by_type"]:
                stats["groups_by_type"][group.group_type] = 0
            stats["groups_by_type"][group.group_type] += 1

        return stats

    def find_related(
        self,
        finding: Finding,
        all_findings: list[Finding],
    ) -> list[CorrelatedFinding]:
        """
        Find findings related to a specific finding.

        Args:
            finding: Finding to find relations for
            all_findings: Pool of findings to search

        Returns:
            List of correlated findings with scores
        """
        related: list[CorrelatedFinding] = []

        for other in all_findings:
            if other.id == finding.id:
                continue

            score = 0.0
            reasons: list[str] = []

            # Same asset
            if finding.asset_id and finding.asset_id == other.asset_id:
                score += 0.4
                reasons.append("same asset")

            # Same rule
            if finding.rule_id and finding.rule_id == other.rule_id:
                score += 0.3
                reasons.append("same rule")

            # Same CVE
            if finding.cve_id and finding.cve_id == other.cve_id:
                score += 0.5
                reasons.append("same CVE")

            # Same severity
            if finding.severity == other.severity:
                score += 0.1
                reasons.append("same severity")

            # Close in time
            if finding.first_seen and other.first_seen:
                time_diff = abs((finding.first_seen - other.first_seen).total_seconds())
                if time_diff < 3600:  # Within 1 hour
                    score += 0.2
                    reasons.append("close in time")

            if score >= self._correlation_threshold:
                related.append(
                    CorrelatedFinding(
                        finding=other,
                        related_findings=[finding.id],
                        correlation_type="multi-factor",
                        correlation_score=min(1.0, score),
                        correlation_reason=", ".join(reasons),
                    )
                )

        # Sort by score
        related.sort(key=lambda x: x.correlation_score, reverse=True)
        return related
