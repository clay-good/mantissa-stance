"""
Continuous Compliance Monitoring for Mantissa Stance.

Provides real-time compliance state tracking, drift detection,
and automated alerting for compliance deviations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable


class ComplianceState(Enum):
    """Overall compliance state."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    AT_RISK = "at_risk"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    """Compliance alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DriftType(Enum):
    """Types of compliance drift."""

    SCORE_DECREASE = "score_decrease"
    CONTROL_FAILURE = "control_failure"
    NEW_FINDING = "new_finding"
    EVIDENCE_EXPIRING = "evidence_expiring"
    CONFIGURATION_CHANGE = "configuration_change"
    POLICY_VIOLATION = "policy_violation"
    ATTESTATION_EXPIRING = "attestation_expiring"


@dataclass
class ComplianceAlert:
    """Compliance-related alert."""

    id: str
    alert_type: DriftType
    severity: AlertSeverity
    title: str
    description: str
    framework: str
    control_id: str | None = None
    resource_id: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: datetime | None = None
    acknowledged: bool = False
    acknowledged_by: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """Check if alert is still active."""
        return self.resolved_at is None

    @property
    def age_hours(self) -> float:
        """Get alert age in hours."""
        now = datetime.now(timezone.utc)
        delta = now - self.detected_at
        return delta.total_seconds() / 3600

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "framework": self.framework,
            "control_id": self.control_id,
            "resource_id": self.resource_id,
            "detected_at": self.detected_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "is_active": self.is_active,
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
            "age_hours": round(self.age_hours, 2),
            "metadata": self.metadata,
        }


@dataclass
class ComplianceDrift:
    """Represents compliance drift from baseline."""

    framework: str
    control_id: str
    drift_type: DriftType
    baseline_value: Any
    current_value: Any
    delta: float
    detected_at: datetime
    description: str
    severity: AlertSeverity = AlertSeverity.MEDIUM
    remediation_steps: list[str] = field(default_factory=list)

    @property
    def is_significant(self) -> bool:
        """Check if drift is significant (>5% change)."""
        if isinstance(self.delta, (int, float)):
            return abs(self.delta) > 5.0
        return True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "drift_type": self.drift_type.value,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "delta": self.delta,
            "detected_at": self.detected_at.isoformat(),
            "description": self.description,
            "severity": self.severity.value,
            "is_significant": self.is_significant,
            "remediation_steps": self.remediation_steps,
        }


@dataclass
class ComplianceBaseline:
    """Baseline compliance state for drift detection."""

    framework: str
    version: str
    captured_at: datetime
    overall_score: float
    control_scores: dict[str, float] = field(default_factory=dict)  # control_id -> score
    control_statuses: dict[str, str] = field(default_factory=dict)  # control_id -> status
    resource_counts: dict[str, int] = field(default_factory=dict)  # control_id -> count
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "version": self.version,
            "captured_at": self.captured_at.isoformat(),
            "overall_score": self.overall_score,
            "control_scores": self.control_scores,
            "control_statuses": self.control_statuses,
            "resource_counts": self.resource_counts,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceSnapshot:
    """Point-in-time compliance snapshot."""

    id: str
    timestamp: datetime
    framework: str
    overall_score: float
    state: ComplianceState
    controls_passing: int
    controls_failing: int
    controls_total: int
    findings_count: int
    high_severity_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "framework": self.framework,
            "overall_score": round(self.overall_score, 2),
            "state": self.state.value,
            "controls_passing": self.controls_passing,
            "controls_failing": self.controls_failing,
            "controls_total": self.controls_total,
            "findings_count": self.findings_count,
            "high_severity_count": self.high_severity_count,
            "metadata": self.metadata,
        }


@dataclass
class MonitoringThreshold:
    """Threshold for compliance monitoring alerts."""

    name: str
    metric: str  # score, control_pass_rate, findings_count, etc.
    framework: str | None = None  # None means all frameworks
    warning_threshold: float = 90.0
    critical_threshold: float = 80.0
    comparison: str = "below"  # below, above, change
    enabled: bool = True

    def evaluate(self, current_value: float, baseline_value: float | None = None) -> AlertSeverity | None:
        """Evaluate threshold and return alert severity if triggered."""
        if not self.enabled:
            return None

        if self.comparison == "below":
            if current_value < self.critical_threshold:
                return AlertSeverity.CRITICAL
            elif current_value < self.warning_threshold:
                return AlertSeverity.HIGH
        elif self.comparison == "above":
            if current_value > self.critical_threshold:
                return AlertSeverity.CRITICAL
            elif current_value > self.warning_threshold:
                return AlertSeverity.HIGH
        elif self.comparison == "change" and baseline_value is not None:
            change = abs(current_value - baseline_value)
            if change > self.critical_threshold:
                return AlertSeverity.CRITICAL
            elif change > self.warning_threshold:
                return AlertSeverity.HIGH

        return None


class ContinuousComplianceMonitor:
    """
    Continuous compliance monitoring engine.

    Tracks compliance state over time, detects drift from
    baselines, and generates alerts for compliance issues.
    """

    def __init__(self) -> None:
        """Initialize the continuous monitoring engine."""
        self._baselines: dict[str, ComplianceBaseline] = {}  # framework -> baseline
        self._snapshots: list[ComplianceSnapshot] = []
        self._alerts: dict[str, ComplianceAlert] = {}
        self._thresholds: list[MonitoringThreshold] = []
        self._alert_handlers: list[Callable[[ComplianceAlert], None]] = []
        self._alert_counter = 0
        self._snapshot_counter = 0

        self._initialize_default_thresholds()

    def _initialize_default_thresholds(self) -> None:
        """Initialize default monitoring thresholds."""
        self._thresholds = [
            MonitoringThreshold(
                name="Overall Compliance Score",
                metric="overall_score",
                warning_threshold=90.0,
                critical_threshold=80.0,
                comparison="below",
            ),
            MonitoringThreshold(
                name="Control Pass Rate",
                metric="control_pass_rate",
                warning_threshold=95.0,
                critical_threshold=90.0,
                comparison="below",
            ),
            MonitoringThreshold(
                name="High Severity Findings",
                metric="high_severity_count",
                warning_threshold=5,
                critical_threshold=10,
                comparison="above",
            ),
            MonitoringThreshold(
                name="Score Change Detection",
                metric="score_change",
                warning_threshold=5.0,
                critical_threshold=10.0,
                comparison="change",
            ),
        ]

    def set_baseline(
        self,
        framework: str,
        assessment_result: Any,
        version: str = "1.0",
    ) -> ComplianceBaseline:
        """
        Set compliance baseline for a framework.

        Args:
            framework: Framework identifier
            assessment_result: Assessment result to use as baseline
            version: Baseline version

        Returns:
            ComplianceBaseline that was set
        """
        now = datetime.now(timezone.utc)

        control_scores: dict[str, float] = {}
        control_statuses: dict[str, str] = {}
        resource_counts: dict[str, int] = {}
        overall_score = 0.0

        # Extract data from different assessment types
        if hasattr(assessment_result, "overall_score"):
            overall_score = assessment_result.overall_score
        elif hasattr(assessment_result, "overall_compliance"):
            overall_score = assessment_result.overall_compliance

        # Extract section/requirement assessments
        assessments = []
        if hasattr(assessment_result, "section_assessments"):
            assessments = assessment_result.section_assessments
        elif hasattr(assessment_result, "safeguard_assessments"):
            assessments = assessment_result.safeguard_assessments
        elif hasattr(assessment_result, "requirement_assessments"):
            assessments = assessment_result.requirement_assessments
        elif hasattr(assessment_result, "principle_assessments"):
            assessments = assessment_result.principle_assessments

        for assessment in assessments:
            control_validations = []
            if hasattr(assessment, "control_assessments"):
                control_validations = assessment.control_assessments
            elif hasattr(assessment, "control_validations"):
                control_validations = assessment.control_validations
            elif hasattr(assessment, "criteria_assessments"):
                control_validations = assessment.criteria_assessments

            for cv in control_validations:
                control_id = getattr(cv, "control_id", getattr(cv, "criteria_id", ""))
                if control_id:
                    control_scores[control_id] = getattr(cv, "compliance_percentage", 100.0)
                    control_statuses[control_id] = getattr(cv, "status", "unknown")
                    if hasattr(cv, "status"):
                        status_val = cv.status
                        if hasattr(status_val, "value"):
                            control_statuses[control_id] = status_val.value
                        else:
                            control_statuses[control_id] = str(status_val)
                    resource_counts[control_id] = getattr(cv, "resources_evaluated", 0)

        baseline = ComplianceBaseline(
            framework=framework,
            version=version,
            captured_at=now,
            overall_score=overall_score,
            control_scores=control_scores,
            control_statuses=control_statuses,
            resource_counts=resource_counts,
        )

        self._baselines[framework] = baseline
        return baseline

    def get_baseline(self, framework: str) -> ComplianceBaseline | None:
        """Get baseline for a framework."""
        return self._baselines.get(framework)

    def capture_snapshot(
        self,
        framework: str,
        assessment_result: Any,
    ) -> ComplianceSnapshot:
        """
        Capture a compliance snapshot.

        Args:
            framework: Framework identifier
            assessment_result: Current assessment result

        Returns:
            ComplianceSnapshot
        """
        self._snapshot_counter += 1
        snapshot_id = f"SNAP-{self._snapshot_counter:06d}"
        now = datetime.now(timezone.utc)

        # Extract metrics from assessment
        overall_score = 0.0
        controls_passing = 0
        controls_failing = 0
        controls_total = 0
        findings_count = 0
        high_severity_count = 0

        if hasattr(assessment_result, "overall_score"):
            overall_score = assessment_result.overall_score
        elif hasattr(assessment_result, "overall_compliance"):
            overall_score = assessment_result.overall_compliance

        if hasattr(assessment_result, "controls_passed"):
            controls_passing = assessment_result.controls_passed
        if hasattr(assessment_result, "controls_failed"):
            controls_failing = assessment_result.controls_failed
        if hasattr(assessment_result, "total_controls"):
            controls_total = assessment_result.total_controls

        # Determine state
        if overall_score >= 95:
            state = ComplianceState.COMPLIANT
        elif overall_score >= 80:
            state = ComplianceState.AT_RISK
        elif overall_score > 0:
            state = ComplianceState.NON_COMPLIANT
        else:
            state = ComplianceState.UNKNOWN

        snapshot = ComplianceSnapshot(
            id=snapshot_id,
            timestamp=now,
            framework=framework,
            overall_score=overall_score,
            state=state,
            controls_passing=controls_passing,
            controls_failing=controls_failing,
            controls_total=controls_total,
            findings_count=findings_count,
            high_severity_count=high_severity_count,
        )

        self._snapshots.append(snapshot)

        # Check for drift and generate alerts
        self._check_thresholds(snapshot)
        self._detect_drift(framework, assessment_result)

        return snapshot

    def _check_thresholds(self, snapshot: ComplianceSnapshot) -> None:
        """Check monitoring thresholds and generate alerts."""
        for threshold in self._thresholds:
            if threshold.framework and threshold.framework != snapshot.framework:
                continue

            current_value = 0.0
            baseline_value = None

            if threshold.metric == "overall_score":
                current_value = snapshot.overall_score
            elif threshold.metric == "control_pass_rate":
                if snapshot.controls_total > 0:
                    current_value = (snapshot.controls_passing / snapshot.controls_total) * 100
            elif threshold.metric == "high_severity_count":
                current_value = snapshot.high_severity_count
            elif threshold.metric == "score_change":
                current_value = snapshot.overall_score
                baseline = self.get_baseline(snapshot.framework)
                if baseline:
                    baseline_value = baseline.overall_score

            severity = threshold.evaluate(current_value, baseline_value)
            if severity:
                self._create_alert(
                    alert_type=DriftType.SCORE_DECREASE if threshold.comparison == "below" else DriftType.CONTROL_FAILURE,
                    severity=severity,
                    title=f"{threshold.name} threshold exceeded",
                    description=f"{threshold.metric} is {current_value:.1f} (threshold: {threshold.critical_threshold})",
                    framework=snapshot.framework,
                )

    def _detect_drift(self, framework: str, assessment_result: Any) -> list[ComplianceDrift]:
        """Detect drift from baseline."""
        drifts: list[ComplianceDrift] = []
        baseline = self.get_baseline(framework)

        if not baseline:
            return drifts

        now = datetime.now(timezone.utc)

        # Check overall score drift
        current_score = 0.0
        if hasattr(assessment_result, "overall_score"):
            current_score = assessment_result.overall_score
        elif hasattr(assessment_result, "overall_compliance"):
            current_score = assessment_result.overall_compliance

        score_delta = current_score - baseline.overall_score
        if abs(score_delta) > 5.0:
            drift = ComplianceDrift(
                framework=framework,
                control_id="overall",
                drift_type=DriftType.SCORE_DECREASE if score_delta < 0 else DriftType.CONFIGURATION_CHANGE,
                baseline_value=baseline.overall_score,
                current_value=current_score,
                delta=score_delta,
                detected_at=now,
                description=f"Compliance score changed by {score_delta:.1f}%",
                severity=AlertSeverity.HIGH if score_delta < -10 else AlertSeverity.MEDIUM,
            )
            drifts.append(drift)

            if score_delta < 0:
                self._create_alert(
                    alert_type=DriftType.SCORE_DECREASE,
                    severity=drift.severity,
                    title=f"Compliance score decreased for {framework}",
                    description=f"Score dropped from {baseline.overall_score:.1f}% to {current_score:.1f}%",
                    framework=framework,
                )

        # Check individual control drift
        current_statuses = self._extract_control_statuses(assessment_result)
        for control_id, baseline_status in baseline.control_statuses.items():
            current_status = current_statuses.get(control_id, "unknown")
            if baseline_status != current_status:
                # Status changed
                if current_status in ("fail", "failed", "non_compliant"):
                    drift = ComplianceDrift(
                        framework=framework,
                        control_id=control_id,
                        drift_type=DriftType.CONTROL_FAILURE,
                        baseline_value=baseline_status,
                        current_value=current_status,
                        delta=0,
                        detected_at=now,
                        description=f"Control {control_id} changed from {baseline_status} to {current_status}",
                        severity=AlertSeverity.HIGH,
                    )
                    drifts.append(drift)

                    self._create_alert(
                        alert_type=DriftType.CONTROL_FAILURE,
                        severity=AlertSeverity.HIGH,
                        title=f"Control failure detected: {control_id}",
                        description=f"Control status changed to {current_status}",
                        framework=framework,
                        control_id=control_id,
                    )

        return drifts

    def _extract_control_statuses(self, assessment_result: Any) -> dict[str, str]:
        """Extract control statuses from assessment result."""
        statuses: dict[str, str] = {}

        assessments = []
        if hasattr(assessment_result, "section_assessments"):
            assessments = assessment_result.section_assessments
        elif hasattr(assessment_result, "safeguard_assessments"):
            assessments = assessment_result.safeguard_assessments
        elif hasattr(assessment_result, "requirement_assessments"):
            assessments = assessment_result.requirement_assessments
        elif hasattr(assessment_result, "principle_assessments"):
            assessments = assessment_result.principle_assessments

        for assessment in assessments:
            control_validations = []
            if hasattr(assessment, "control_assessments"):
                control_validations = assessment.control_assessments
            elif hasattr(assessment, "control_validations"):
                control_validations = assessment.control_validations
            elif hasattr(assessment, "criteria_assessments"):
                control_validations = assessment.criteria_assessments

            for cv in control_validations:
                control_id = getattr(cv, "control_id", getattr(cv, "criteria_id", ""))
                if control_id and hasattr(cv, "status"):
                    status_val = cv.status
                    if hasattr(status_val, "value"):
                        statuses[control_id] = status_val.value
                    else:
                        statuses[control_id] = str(status_val)

        return statuses

    def _create_alert(
        self,
        alert_type: DriftType,
        severity: AlertSeverity,
        title: str,
        description: str,
        framework: str,
        control_id: str | None = None,
        resource_id: str | None = None,
    ) -> ComplianceAlert:
        """Create and store a compliance alert."""
        self._alert_counter += 1
        alert_id = f"ALERT-{self._alert_counter:06d}"

        alert = ComplianceAlert(
            id=alert_id,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            framework=framework,
            control_id=control_id,
            resource_id=resource_id,
        )

        self._alerts[alert_id] = alert

        # Notify handlers
        for handler in self._alert_handlers:
            try:
                handler(alert)
            except Exception:
                pass  # Don't let handler errors affect alerting

        return alert

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> ComplianceAlert | None:
        """Acknowledge an alert."""
        if alert_id not in self._alerts:
            return None

        alert = self._alerts[alert_id]
        alert.acknowledged = True
        alert.acknowledged_by = acknowledged_by
        return alert

    def resolve_alert(
        self,
        alert_id: str,
        resolution_notes: str = "",
    ) -> ComplianceAlert | None:
        """Resolve an alert."""
        if alert_id not in self._alerts:
            return None

        alert = self._alerts[alert_id]
        alert.resolved_at = datetime.now(timezone.utc)
        if resolution_notes:
            alert.metadata["resolution_notes"] = resolution_notes
        return alert

    def get_active_alerts(
        self,
        framework: str | None = None,
        severity: AlertSeverity | None = None,
    ) -> list[ComplianceAlert]:
        """Get active (unresolved) alerts."""
        alerts = [a for a in self._alerts.values() if a.is_active]

        if framework:
            alerts = [a for a in alerts if a.framework == framework]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return sorted(alerts, key=lambda x: (
            0 if x.severity == AlertSeverity.CRITICAL else
            1 if x.severity == AlertSeverity.HIGH else
            2 if x.severity == AlertSeverity.MEDIUM else 3,
            x.detected_at,
        ))

    def get_alert_summary(self) -> dict[str, Any]:
        """Get summary of all alerts."""
        active = [a for a in self._alerts.values() if a.is_active]
        resolved = [a for a in self._alerts.values() if not a.is_active]

        severity_counts = {}
        for severity in AlertSeverity:
            severity_counts[severity.value] = sum(
                1 for a in active if a.severity == severity
            )

        return {
            "total_active": len(active),
            "total_resolved": len(resolved),
            "by_severity": severity_counts,
            "oldest_active": min(
                (a.detected_at for a in active), default=None
            ),
            "unacknowledged": sum(1 for a in active if not a.acknowledged),
        }

    def register_alert_handler(
        self,
        handler: Callable[[ComplianceAlert], None],
    ) -> None:
        """Register a handler for new alerts."""
        self._alert_handlers.append(handler)

    def add_threshold(self, threshold: MonitoringThreshold) -> None:
        """Add a monitoring threshold."""
        self._thresholds.append(threshold)

    def get_compliance_trend(
        self,
        framework: str,
        days: int = 30,
    ) -> list[dict[str, Any]]:
        """Get compliance trend over time."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        snapshots = [
            s for s in self._snapshots
            if s.framework == framework and s.timestamp >= cutoff
        ]

        return [
            {
                "timestamp": s.timestamp.isoformat(),
                "score": round(s.overall_score, 2),
                "state": s.state.value,
                "controls_passing": s.controls_passing,
                "controls_failing": s.controls_failing,
            }
            for s in sorted(snapshots, key=lambda x: x.timestamp)
        ]

    def get_framework_status(self, framework: str) -> dict[str, Any]:
        """Get current status for a framework."""
        # Get most recent snapshot
        framework_snapshots = [
            s for s in self._snapshots
            if s.framework == framework
        ]

        if not framework_snapshots:
            return {
                "framework": framework,
                "status": "no_data",
                "message": "No compliance data available",
            }

        latest = max(framework_snapshots, key=lambda x: x.timestamp)
        baseline = self.get_baseline(framework)
        active_alerts = self.get_active_alerts(framework=framework)

        return {
            "framework": framework,
            "current_score": round(latest.overall_score, 2),
            "state": latest.state.value,
            "baseline_score": round(baseline.overall_score, 2) if baseline else None,
            "score_trend": round(
                latest.overall_score - baseline.overall_score, 2
            ) if baseline else None,
            "controls_passing": latest.controls_passing,
            "controls_failing": latest.controls_failing,
            "active_alerts": len(active_alerts),
            "critical_alerts": sum(
                1 for a in active_alerts if a.severity == AlertSeverity.CRITICAL
            ),
            "last_assessed": latest.timestamp.isoformat(),
        }

    def get_dashboard_data(self) -> dict[str, Any]:
        """Get data for compliance monitoring dashboard."""
        frameworks = set(s.framework for s in self._snapshots)

        framework_status = {}
        for framework in frameworks:
            framework_status[framework] = self.get_framework_status(framework)

        alert_summary = self.get_alert_summary()

        # Calculate overall compliance
        overall_score = 0.0
        if framework_status:
            scores = [
                fs["current_score"]
                for fs in framework_status.values()
                if fs.get("current_score") is not None
            ]
            if scores:
                overall_score = sum(scores) / len(scores)

        return {
            "overall_compliance_score": round(overall_score, 2),
            "frameworks_monitored": len(frameworks),
            "frameworks": framework_status,
            "alerts": alert_summary,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
