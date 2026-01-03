"""
Metrics aggregation for Mantissa Stance dashboards.

Provides security, compliance, and operational metrics calculation.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Metric Data Structures
# =============================================================================

class TrendDirection(Enum):
    """Direction of a metric trend."""
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    UNKNOWN = "unknown"


@dataclass
class MetricValue:
    """
    A metric value at a point in time.

    Attributes:
        value: The metric value
        timestamp: When the value was recorded
        unit: Unit of measurement
        metadata: Additional context
    """
    value: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    unit: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "unit": self.unit,
        }


@dataclass
class MetricTrend:
    """
    Trend information for a metric.

    Attributes:
        current: Current value
        previous: Previous value (for comparison)
        change: Absolute change
        change_percent: Percentage change
        direction: Trend direction
        history: Historical values
    """
    current: float
    previous: float
    change: float
    change_percent: float
    direction: TrendDirection
    history: List[MetricValue] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "current": self.current,
            "previous": self.previous,
            "change": self.change,
            "change_percent": self.change_percent,
            "direction": self.direction.value,
            "history_length": len(self.history),
        }


@dataclass
class DashboardMetric:
    """
    A dashboard metric with current value and trend.

    Attributes:
        id: Metric identifier
        name: Display name
        description: Metric description
        value: Current value
        trend: Trend information
        target: Target value (optional)
        threshold_warning: Warning threshold
        threshold_critical: Critical threshold
        format: Display format pattern
    """
    id: str
    name: str
    description: str = ""
    value: MetricValue = field(default_factory=lambda: MetricValue(0.0))
    trend: Optional[MetricTrend] = None
    target: Optional[float] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    format: str = "{value:.0f}"
    category: str = "general"

    def get_status(self) -> str:
        """Get metric status based on thresholds."""
        if self.threshold_critical is not None:
            if self.value.value >= self.threshold_critical:
                return "critical"
        if self.threshold_warning is not None:
            if self.value.value >= self.threshold_warning:
                return "warning"
        return "ok"

    def get_target_progress(self) -> Optional[float]:
        """Get progress toward target as percentage."""
        if self.target is None or self.target == 0:
            return None
        return min(100, (self.value.value / self.target) * 100)

    def format_value(self) -> str:
        """Format the value for display."""
        try:
            return self.format.format(value=self.value.value)
        except (ValueError, KeyError):
            return str(self.value.value)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "value": self.value.to_dict(),
            "formatted_value": self.format_value(),
            "trend": self.trend.to_dict() if self.trend else None,
            "target": self.target,
            "status": self.get_status(),
            "category": self.category,
        }


# =============================================================================
# Metric Calculators
# =============================================================================

def calculate_security_score(
    findings: Dict[str, int],
    assets: Dict[str, Any],
    weights: Optional[Dict[str, float]] = None
) -> float:
    """
    Calculate an overall security score (0-100).

    Args:
        findings: Finding counts by severity
        assets: Asset information
        weights: Optional custom weights for severities

    Returns:
        Security score from 0 (worst) to 100 (best)
    """
    default_weights = {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 0.5,
        "info": 0.1,
    }
    weights = weights or default_weights

    total_assets = assets.get("total", 1)
    if total_assets == 0:
        total_assets = 1

    # Calculate weighted finding score
    weighted_sum = 0.0
    for severity, count in findings.items():
        weight = weights.get(severity.lower(), 1.0)
        weighted_sum += count * weight

    # Normalize by assets
    findings_per_asset = weighted_sum / total_assets

    # Convert to score (higher findings = lower score)
    # Use exponential decay: score = 100 * e^(-k * findings_per_asset)
    k = 0.1  # Decay rate
    score = 100 * math.exp(-k * findings_per_asset)

    return max(0, min(100, score))


def calculate_risk_trend(
    current_score: float,
    previous_score: float,
    threshold: float = 5.0
) -> MetricTrend:
    """
    Calculate risk trend from scores.

    Args:
        current_score: Current risk score
        previous_score: Previous risk score
        threshold: Change threshold for trend detection

    Returns:
        Metric trend information
    """
    change = current_score - previous_score
    if previous_score != 0:
        change_percent = (change / previous_score) * 100
    else:
        change_percent = 0 if change == 0 else 100

    if change > threshold:
        direction = TrendDirection.DECLINING  # Higher risk score is worse
    elif change < -threshold:
        direction = TrendDirection.IMPROVING
    else:
        direction = TrendDirection.STABLE

    return MetricTrend(
        current=current_score,
        previous=previous_score,
        change=change,
        change_percent=change_percent,
        direction=direction,
    )


def calculate_compliance_gap(
    framework_scores: Dict[str, float],
    target_score: float = 90.0
) -> Dict[str, Any]:
    """
    Calculate compliance gaps from target.

    Args:
        framework_scores: Compliance scores by framework
        target_score: Target compliance percentage

    Returns:
        Compliance gap analysis
    """
    gaps = {}
    total_gap = 0.0

    for framework, score in framework_scores.items():
        gap = max(0, target_score - score)
        gaps[framework] = {
            "current_score": score,
            "target": target_score,
            "gap": gap,
            "gap_percent": (gap / target_score) * 100 if target_score > 0 else 0,
            "status": "compliant" if score >= target_score else "non_compliant",
        }
        total_gap += gap

    average_gap = total_gap / len(framework_scores) if framework_scores else 0

    return {
        "frameworks": gaps,
        "average_gap": average_gap,
        "frameworks_compliant": sum(1 for g in gaps.values() if g["status"] == "compliant"),
        "frameworks_total": len(gaps),
    }


# =============================================================================
# Metrics Aggregators
# =============================================================================

class MetricsAggregator:
    """
    Base class for metrics aggregation.

    Provides common aggregation patterns and calculations.
    """

    def __init__(self):
        self.metrics: Dict[str, DashboardMetric] = {}
        self.history: Dict[str, List[MetricValue]] = {}
        self._max_history = 1000

    def add_value(self, metric_id: str, value: float,
                 timestamp: Optional[datetime] = None) -> None:
        """Add a value to a metric's history."""
        if metric_id not in self.history:
            self.history[metric_id] = []

        metric_value = MetricValue(
            value=value,
            timestamp=timestamp or datetime.utcnow()
        )
        self.history[metric_id].append(metric_value)

        # Trim history
        if len(self.history[metric_id]) > self._max_history:
            self.history[metric_id] = self.history[metric_id][-self._max_history:]

    def get_trend(self, metric_id: str,
                 current_value: float,
                 lookback_hours: int = 24) -> MetricTrend:
        """Calculate trend for a metric."""
        history = self.history.get(metric_id, [])

        cutoff = datetime.utcnow() - timedelta(hours=lookback_hours)
        relevant = [v for v in history if v.timestamp >= cutoff]

        if not relevant:
            return MetricTrend(
                current=current_value,
                previous=current_value,
                change=0,
                change_percent=0,
                direction=TrendDirection.UNKNOWN,
            )

        # Get first value in period as "previous"
        previous_value = relevant[0].value

        change = current_value - previous_value
        if previous_value != 0:
            change_percent = (change / previous_value) * 100
        else:
            change_percent = 0 if change == 0 else 100

        if abs(change_percent) < 5:
            direction = TrendDirection.STABLE
        elif change > 0:
            direction = TrendDirection.DECLINING
        else:
            direction = TrendDirection.IMPROVING

        return MetricTrend(
            current=current_value,
            previous=previous_value,
            change=change,
            change_percent=change_percent,
            direction=direction,
            history=relevant,
        )

    def get_metric(self, metric_id: str) -> Optional[DashboardMetric]:
        """Get a metric by ID."""
        return self.metrics.get(metric_id)

    def list_metrics(self) -> List[DashboardMetric]:
        """List all metrics."""
        return list(self.metrics.values())

    def to_dict(self) -> Dict[str, Any]:
        """Convert all metrics to dictionary."""
        return {
            m.id: m.to_dict() for m in self.metrics.values()
        }


class SecurityMetrics(MetricsAggregator):
    """
    Security-focused metrics aggregation.

    Calculates:
    - Total findings by severity
    - Security score
    - MTTR (Mean Time to Remediate)
    - Finding velocity
    - Attack surface metrics
    """

    def __init__(self):
        super().__init__()
        self._initialize_metrics()

    def _initialize_metrics(self) -> None:
        """Initialize security metrics."""
        self.metrics = {
            "total_findings": DashboardMetric(
                id="total_findings",
                name="Total Findings",
                description="Total number of security findings",
                category="findings",
                threshold_warning=100,
                threshold_critical=500,
            ),
            "critical_findings": DashboardMetric(
                id="critical_findings",
                name="Critical Findings",
                description="Number of critical severity findings",
                category="findings",
                threshold_warning=1,
                threshold_critical=5,
            ),
            "high_findings": DashboardMetric(
                id="high_findings",
                name="High Findings",
                description="Number of high severity findings",
                category="findings",
                threshold_warning=10,
                threshold_critical=50,
            ),
            "security_score": DashboardMetric(
                id="security_score",
                name="Security Score",
                description="Overall security posture score (0-100)",
                category="score",
                format="{value:.1f}",
                target=90.0,
            ),
            "mttr_hours": DashboardMetric(
                id="mttr_hours",
                name="MTTR",
                description="Mean Time to Remediate (hours)",
                category="operational",
                format="{value:.1f}h",
                threshold_warning=72,
                threshold_critical=168,
            ),
            "findings_velocity": DashboardMetric(
                id="findings_velocity",
                name="Finding Velocity",
                description="New findings per day",
                category="trend",
                format="{value:.1f}/day",
            ),
            "assets_at_risk": DashboardMetric(
                id="assets_at_risk",
                name="Assets at Risk",
                description="Assets with critical/high findings",
                category="assets",
                threshold_warning=10,
                threshold_critical=50,
            ),
        }

    def calculate(self, data: Dict[str, Any]) -> Dict[str, DashboardMetric]:
        """
        Calculate all security metrics from data.

        Args:
            data: Security data with findings, assets, history

        Returns:
            Dictionary of calculated metrics
        """
        findings = data.get("findings", {})
        assets = data.get("assets", {})
        history = data.get("history", [])

        # Total findings
        total = findings.get("total", sum(findings.values()))
        self.metrics["total_findings"].value = MetricValue(float(total))
        self.add_value("total_findings", float(total))
        self.metrics["total_findings"].trend = self.get_trend("total_findings", float(total))

        # Critical findings
        critical = findings.get("critical", 0)
        self.metrics["critical_findings"].value = MetricValue(float(critical))
        self.add_value("critical_findings", float(critical))
        self.metrics["critical_findings"].trend = self.get_trend("critical_findings", float(critical))

        # High findings
        high = findings.get("high", 0)
        self.metrics["high_findings"].value = MetricValue(float(high))

        # Security score
        score = calculate_security_score(findings, assets)
        self.metrics["security_score"].value = MetricValue(score)
        self.add_value("security_score", score)
        self.metrics["security_score"].trend = self.get_trend("security_score", score)

        # MTTR
        mttr = self._calculate_mttr(history)
        self.metrics["mttr_hours"].value = MetricValue(mttr)

        # Finding velocity
        velocity = self._calculate_velocity(history)
        self.metrics["findings_velocity"].value = MetricValue(velocity)

        # Assets at risk
        at_risk = assets.get("with_critical_high", assets.get("with_findings", 0))
        self.metrics["assets_at_risk"].value = MetricValue(float(at_risk))

        return self.metrics

    def _calculate_mttr(self, history: List[Dict]) -> float:
        """Calculate mean time to remediate from history."""
        remediation_times = []

        for entry in history:
            resolved = entry.get("resolved_findings", [])
            for finding in resolved:
                first_seen = finding.get("first_seen")
                resolved_at = finding.get("resolved_at")

                if first_seen and resolved_at:
                    if isinstance(first_seen, str):
                        first_seen = datetime.fromisoformat(first_seen)
                    if isinstance(resolved_at, str):
                        resolved_at = datetime.fromisoformat(resolved_at)

                    hours = (resolved_at - first_seen).total_seconds() / 3600
                    remediation_times.append(hours)

        if remediation_times:
            return sum(remediation_times) / len(remediation_times)
        return 0.0

    def _calculate_velocity(self, history: List[Dict]) -> float:
        """Calculate new findings per day."""
        if not history or len(history) < 2:
            return 0.0

        # Get date range
        dates = []
        totals = []

        for entry in history:
            ts = entry.get("timestamp")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts:
                dates.append(ts)
                totals.append(entry.get("findings_total", 0))

        if len(dates) < 2:
            return 0.0

        days = (max(dates) - min(dates)).days
        if days == 0:
            return 0.0

        # Simple: total change / days
        change = totals[-1] - totals[0]
        return change / days


class ComplianceMetrics(MetricsAggregator):
    """
    Compliance-focused metrics aggregation.

    Calculates:
    - Average compliance score
    - Per-framework scores
    - Controls passed/failed
    - Compliance gaps
    """

    def __init__(self):
        super().__init__()
        self._initialize_metrics()

    def _initialize_metrics(self) -> None:
        """Initialize compliance metrics."""
        self.metrics = {
            "average_compliance": DashboardMetric(
                id="average_compliance",
                name="Average Compliance",
                description="Average compliance score across frameworks",
                category="compliance",
                format="{value:.1f}%",
                target=90.0,
                threshold_warning=70,
                threshold_critical=50,
            ),
            "controls_passed": DashboardMetric(
                id="controls_passed",
                name="Controls Passed",
                description="Total controls passing compliance",
                category="compliance",
            ),
            "controls_failed": DashboardMetric(
                id="controls_failed",
                name="Controls Failed",
                description="Total controls failing compliance",
                category="compliance",
                threshold_warning=10,
                threshold_critical=50,
            ),
            "frameworks_compliant": DashboardMetric(
                id="frameworks_compliant",
                name="Compliant Frameworks",
                description="Frameworks meeting target score",
                category="compliance",
            ),
        }

    def calculate(self, data: Dict[str, Any]) -> Dict[str, DashboardMetric]:
        """
        Calculate all compliance metrics from data.

        Args:
            data: Compliance data with framework scores, controls

        Returns:
            Dictionary of calculated metrics
        """
        frameworks = data.get("frameworks", {})
        controls = data.get("controls", {})
        target = data.get("target_score", 90.0)

        # Average compliance
        if frameworks:
            avg = sum(frameworks.values()) / len(frameworks)
        else:
            avg = 0.0

        self.metrics["average_compliance"].value = MetricValue(avg)
        self.metrics["average_compliance"].target = target
        self.add_value("average_compliance", avg)
        self.metrics["average_compliance"].trend = self.get_trend("average_compliance", avg)

        # Controls
        passed = controls.get("passed", 0)
        failed = controls.get("failed", 0)

        self.metrics["controls_passed"].value = MetricValue(float(passed))
        self.metrics["controls_failed"].value = MetricValue(float(failed))

        # Frameworks compliant
        compliant = sum(1 for score in frameworks.values() if score >= target)
        self.metrics["frameworks_compliant"].value = MetricValue(float(compliant))

        # Add framework-specific metrics
        for fw_name, score in frameworks.items():
            metric_id = f"framework_{fw_name.lower().replace(' ', '_')}"
            if metric_id not in self.metrics:
                self.metrics[metric_id] = DashboardMetric(
                    id=metric_id,
                    name=fw_name,
                    description=f"Compliance score for {fw_name}",
                    category="framework",
                    format="{value:.1f}%",
                    target=target,
                )
            self.metrics[metric_id].value = MetricValue(score)

        return self.metrics

    def get_gap_analysis(self, target: float = 90.0) -> Dict[str, Any]:
        """Get compliance gap analysis."""
        framework_scores = {}

        for metric in self.metrics.values():
            if metric.category == "framework":
                # Extract framework name from metric
                fw_name = metric.name
                framework_scores[fw_name] = metric.value.value

        return calculate_compliance_gap(framework_scores, target)


class OperationalMetrics(MetricsAggregator):
    """
    Operational metrics aggregation.

    Calculates:
    - Scan frequency and duration
    - Asset coverage
    - Collection success rates
    - API latency
    """

    def __init__(self):
        super().__init__()
        self._initialize_metrics()

    def _initialize_metrics(self) -> None:
        """Initialize operational metrics."""
        self.metrics = {
            "scans_per_day": DashboardMetric(
                id="scans_per_day",
                name="Scans/Day",
                description="Average scans per day",
                category="operational",
                format="{value:.1f}",
            ),
            "avg_scan_duration": DashboardMetric(
                id="avg_scan_duration",
                name="Avg Scan Duration",
                description="Average scan duration in minutes",
                category="operational",
                format="{value:.1f}m",
                threshold_warning=30,
                threshold_critical=60,
            ),
            "asset_coverage": DashboardMetric(
                id="asset_coverage",
                name="Asset Coverage",
                description="Percentage of assets scanned",
                category="operational",
                format="{value:.1f}%",
                target=100.0,
            ),
            "collection_success_rate": DashboardMetric(
                id="collection_success_rate",
                name="Collection Success",
                description="Percentage of successful collections",
                category="operational",
                format="{value:.1f}%",
                target=99.0,
                threshold_warning=95,
                threshold_critical=90,
            ),
            "total_assets": DashboardMetric(
                id="total_assets",
                name="Total Assets",
                description="Total assets under management",
                category="inventory",
            ),
            "cloud_accounts": DashboardMetric(
                id="cloud_accounts",
                name="Cloud Accounts",
                description="Number of connected cloud accounts",
                category="inventory",
            ),
        }

    def calculate(self, data: Dict[str, Any]) -> Dict[str, DashboardMetric]:
        """
        Calculate all operational metrics from data.

        Args:
            data: Operational data with scans, assets, collection stats

        Returns:
            Dictionary of calculated metrics
        """
        scans = data.get("scans", {})
        assets = data.get("assets", {})
        collections = data.get("collections", {})

        # Scans per day
        scans_per_day = scans.get("per_day", 0)
        self.metrics["scans_per_day"].value = MetricValue(float(scans_per_day))

        # Average scan duration
        avg_duration = scans.get("avg_duration_minutes", 0)
        self.metrics["avg_scan_duration"].value = MetricValue(float(avg_duration))

        # Asset coverage
        total = assets.get("total", 0)
        scanned = assets.get("scanned", 0)
        coverage = (scanned / total * 100) if total > 0 else 0
        self.metrics["asset_coverage"].value = MetricValue(coverage)

        # Collection success rate
        total_collections = collections.get("total", 0)
        successful = collections.get("successful", 0)
        success_rate = (successful / total_collections * 100) if total_collections > 0 else 100
        self.metrics["collection_success_rate"].value = MetricValue(success_rate)

        # Inventory counts
        self.metrics["total_assets"].value = MetricValue(float(total))
        self.metrics["cloud_accounts"].value = MetricValue(float(assets.get("accounts", 0)))

        return self.metrics
