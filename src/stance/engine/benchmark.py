"""
CIS Benchmark calculator for Mantissa Stance.

Calculates benchmark scores for CIS controls based on
policy evaluations and findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ControlStatus:
    """Status of a single CIS benchmark control."""

    control_id: str
    control_name: str
    status: str  # "pass", "fail", "not_applicable"
    resources_evaluated: int
    resources_compliant: int
    resources_non_compliant: int
    findings: list[str] = field(default_factory=list)  # Finding IDs


@dataclass
class BenchmarkScore:
    """Score for a single CIS benchmark."""

    benchmark_id: str
    benchmark_name: str
    version: str
    score_percentage: float  # 0-100
    controls_passed: int
    controls_failed: int
    controls_total: int
    control_statuses: list[ControlStatus] = field(default_factory=list)


@dataclass
class BenchmarkReport:
    """Complete CIS benchmark report across all benchmarks."""

    generated_at: datetime
    snapshot_id: str
    overall_score: float
    benchmarks: list[BenchmarkScore] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "snapshot_id": self.snapshot_id,
            "overall_score": self.overall_score,
            "benchmarks": [
                {
                    "benchmark_id": b.benchmark_id,
                    "benchmark_name": b.benchmark_name,
                    "version": b.version,
                    "score_percentage": b.score_percentage,
                    "controls_passed": b.controls_passed,
                    "controls_failed": b.controls_failed,
                    "controls_total": b.controls_total,
                    "control_statuses": [
                        {
                            "control_id": cs.control_id,
                            "control_name": cs.control_name,
                            "status": cs.status,
                            "resources_evaluated": cs.resources_evaluated,
                            "resources_compliant": cs.resources_compliant,
                            "resources_non_compliant": cs.resources_non_compliant,
                            "findings": cs.findings,
                        }
                        for cs in b.control_statuses
                    ],
                }
                for b in self.benchmarks
            ],
        }

    def to_json(self) -> str:
        """Convert report to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class BenchmarkCalculator:
    """
    Calculates CIS benchmark scores.

    Analyzes policies and findings to determine benchmark
    status for each control.
    """

    # Supported CIS benchmarks
    BENCHMARK_NAMES = {
        "cis-aws": "CIS AWS Foundations Benchmark",
        "cis-aws-foundations": "CIS AWS Foundations Benchmark",
        "cis-gcp": "CIS GCP Foundations Benchmark",
        "cis-gcp-foundations": "CIS GCP Foundations Benchmark",
        "cis-azure": "CIS Azure Foundations Benchmark",
        "cis-azure-foundations": "CIS Azure Foundations Benchmark",
    }

    def calculate_scores(
        self,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
        assets: Any,  # AssetCollection
        snapshot_id: str = "",
    ) -> BenchmarkReport:
        """
        Calculate CIS benchmark scores.

        Args:
            policies: Collection of policies with benchmark mappings
            findings: Collection of findings from evaluation
            assets: Collection of assets evaluated
            snapshot_id: Snapshot ID for the report

        Returns:
            BenchmarkReport with per-benchmark scores
        """
        now = datetime.now(timezone.utc)

        # Discover all CIS benchmarks from policies
        benchmarks = self._discover_benchmarks(policies)

        # Calculate scores for each benchmark
        benchmark_scores: list[BenchmarkScore] = []
        for benchmark_id in benchmarks:
            score = self.get_benchmark_score(
                benchmark_id, policies, findings, assets
            )
            benchmark_scores.append(score)

        # Calculate overall score (weighted average)
        overall_score = self._calculate_overall_score(benchmark_scores)

        return BenchmarkReport(
            generated_at=now,
            snapshot_id=snapshot_id,
            overall_score=overall_score,
            benchmarks=benchmark_scores,
        )

    def get_benchmark_score(
        self,
        benchmark_id: str,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
        assets: Any,  # AssetCollection
    ) -> BenchmarkScore:
        """
        Calculate score for a specific CIS benchmark.

        Args:
            benchmark_id: Benchmark identifier (e.g., "cis-aws")
            policies: Collection of policies
            findings: Collection of findings
            assets: Collection of assets

        Returns:
            BenchmarkScore for the benchmark
        """
        # Get policies mapped to this benchmark
        benchmark_policies = policies.filter_by_benchmark(benchmark_id)

        # Build control status map
        control_statuses: dict[str, ControlStatus] = {}

        for policy in benchmark_policies:
            for mapping in policy.benchmark:
                if not self._benchmark_matches(mapping.benchmark, benchmark_id):
                    continue

                control_id = mapping.control
                if control_id not in control_statuses:
                    control_statuses[control_id] = ControlStatus(
                        control_id=control_id,
                        control_name=policy.name,
                        status="pass",
                        resources_evaluated=0,
                        resources_compliant=0,
                        resources_non_compliant=0,
                        findings=[],
                    )

                # Check for findings related to this policy
                policy_findings = [
                    f for f in findings if f.rule_id == policy.id
                ]

                # Count matching assets
                matching_assets = [
                    a for a in assets
                    if self._asset_matches_policy(a, policy)
                ]

                cs = control_statuses[control_id]
                cs.resources_evaluated += len(matching_assets)
                cs.resources_non_compliant += len(policy_findings)
                cs.resources_compliant += len(matching_assets) - len(policy_findings)

                for f in policy_findings:
                    if f.id not in cs.findings:
                        cs.findings.append(f.id)

                # Update status
                if policy_findings:
                    cs.status = "fail"

        # Calculate totals
        controls_list = list(control_statuses.values())
        controls_passed = sum(1 for c in controls_list if c.status == "pass")
        controls_failed = sum(1 for c in controls_list if c.status == "fail")
        controls_total = len(controls_list)

        # Calculate score
        if controls_total > 0:
            score_percentage = (controls_passed / controls_total) * 100
        else:
            score_percentage = 100.0

        # Get benchmark display name
        benchmark_name = self.BENCHMARK_NAMES.get(
            benchmark_id.lower(), benchmark_id
        )

        # Extract version if present
        version = ""
        for policy in benchmark_policies:
            for mapping in policy.benchmark:
                if self._benchmark_matches(mapping.benchmark, benchmark_id):
                    if mapping.version:
                        version = mapping.version
                        break
            if version:
                break

        return BenchmarkScore(
            benchmark_id=benchmark_id,
            benchmark_name=benchmark_name,
            version=version,
            score_percentage=round(score_percentage, 2),
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_total=controls_total,
            control_statuses=controls_list,
        )

    def get_control_status(
        self,
        benchmark_id: str,
        control_id: str,
        policies: Any,  # PolicyCollection
        findings: Any,  # FindingCollection
    ) -> ControlStatus:
        """
        Get status for a specific CIS control.

        Args:
            benchmark_id: Benchmark identifier
            control_id: Control identifier
            policies: Collection of policies
            findings: Collection of findings

        Returns:
            ControlStatus for the control
        """
        # Find policies for this control
        control_policies = []
        control_name = control_id

        for policy in policies:
            for mapping in policy.benchmark:
                if (
                    self._benchmark_matches(mapping.benchmark, benchmark_id)
                    and mapping.control == control_id
                ):
                    control_policies.append(policy)
                    control_name = policy.name
                    break

        if not control_policies:
            return ControlStatus(
                control_id=control_id,
                control_name=control_name,
                status="not_applicable",
                resources_evaluated=0,
                resources_compliant=0,
                resources_non_compliant=0,
                findings=[],
            )

        # Check for related findings
        related_findings: list[str] = []
        for policy in control_policies:
            for finding in findings:
                if finding.rule_id == policy.id:
                    related_findings.append(finding.id)

        status = "fail" if related_findings else "pass"

        return ControlStatus(
            control_id=control_id,
            control_name=control_name,
            status=status,
            resources_evaluated=0,  # Would need assets to calculate
            resources_compliant=0,
            resources_non_compliant=len(related_findings),
            findings=related_findings,
        )

    def _discover_benchmarks(self, policies: Any) -> set[str]:
        """
        Discover all CIS benchmarks from policy mappings.

        Args:
            policies: Collection of policies

        Returns:
            Set of benchmark identifiers
        """
        benchmarks: set[str] = set()

        for policy in policies:
            for mapping in policy.benchmark:
                if mapping.benchmark:
                    # Normalize benchmark ID
                    benchmark_id = mapping.benchmark.lower().replace(" ", "-")
                    # Only include CIS benchmarks
                    if benchmark_id.startswith("cis-"):
                        benchmarks.add(benchmark_id)

        return benchmarks

    def _benchmark_matches(self, mapping_benchmark: str, target_benchmark: str) -> bool:
        """
        Check if benchmark mapping matches target.

        Args:
            mapping_benchmark: Benchmark from policy mapping
            target_benchmark: Target benchmark to match

        Returns:
            True if benchmarks match
        """
        normalized_mapping = mapping_benchmark.lower().replace(" ", "-")
        normalized_target = target_benchmark.lower().replace(" ", "-")

        return normalized_mapping == normalized_target

    def _asset_matches_policy(self, asset: Any, policy: Any) -> bool:
        """
        Check if asset matches policy resource type.

        Args:
            asset: Asset to check
            policy: Policy to match against

        Returns:
            True if asset matches policy
        """
        if not policy.resource_type:
            return False

        if policy.resource_type == "*":
            return True

        if policy.resource_type.endswith("*"):
            prefix = policy.resource_type[:-1]
            return asset.resource_type.startswith(prefix)

        return asset.resource_type == policy.resource_type

    def _calculate_overall_score(
        self, benchmark_scores: list[BenchmarkScore]
    ) -> float:
        """
        Calculate weighted overall benchmark score.

        Args:
            benchmark_scores: List of benchmark scores

        Returns:
            Overall score (0-100)
        """
        if not benchmark_scores:
            return 100.0

        # Weight by number of controls
        total_weight = sum(b.controls_total for b in benchmark_scores)

        if total_weight == 0:
            return 100.0

        weighted_sum = sum(
            b.score_percentage * b.controls_total for b in benchmark_scores
        )

        return round(weighted_sum / total_weight, 2)
