"""
Drift detection for Mantissa Stance.

Provides configuration drift detection, severity scoring,
and drift finding generation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from stance.drift.baseline import (
    AssetBaseline,
    Baseline,
    BaselineConfig,
    BaselineManager,
)
from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingStatus, FindingType, Severity


class DriftType(Enum):
    """Types of configuration drift."""

    NEW_ASSET = "new_asset"
    REMOVED_ASSET = "removed_asset"
    CONFIG_CHANGED = "config_changed"
    SECURITY_DEGRADED = "security_degraded"
    COMPLIANCE_VIOLATED = "compliance_violated"


class DriftSeverity(Enum):
    """Severity levels for drift."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ConfigDifference:
    """
    Single configuration difference.

    Attributes:
        path: Configuration path (dot-separated)
        change_type: Type of change (added, removed, changed)
        baseline_value: Value in baseline
        current_value: Current value
        is_security_relevant: Whether change affects security
        severity: Severity of the change
    """

    path: str
    change_type: str
    baseline_value: Any
    current_value: Any
    is_security_relevant: bool = False
    severity: DriftSeverity = DriftSeverity.INFO

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "change_type": self.change_type,
            "baseline_value": self.baseline_value,
            "current_value": self.current_value,
            "is_security_relevant": self.is_security_relevant,
            "severity": self.severity.value,
        }


@dataclass
class DriftEvent:
    """
    Configuration drift event.

    Attributes:
        asset_id: Affected asset ID
        asset_type: Resource type
        cloud_provider: Cloud provider
        region: Asset region
        drift_type: Type of drift
        severity: Drift severity
        differences: List of configuration differences
        detected_at: When drift was detected
        baseline_id: Reference baseline ID
        description: Human-readable description
    """

    asset_id: str
    asset_type: str
    cloud_provider: str
    region: str
    drift_type: DriftType
    severity: DriftSeverity
    differences: list[ConfigDifference]
    detected_at: datetime = field(default_factory=datetime.utcnow)
    baseline_id: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "cloud_provider": self.cloud_provider,
            "region": self.region,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "differences": [d.to_dict() for d in self.differences],
            "detected_at": self.detected_at.isoformat(),
            "baseline_id": self.baseline_id,
            "description": self.description,
        }

    def to_finding(self) -> Finding:
        """Convert drift event to a finding."""
        # Map drift severity to finding severity
        severity_map = {
            DriftSeverity.CRITICAL: Severity.CRITICAL,
            DriftSeverity.HIGH: Severity.HIGH,
            DriftSeverity.MEDIUM: Severity.MEDIUM,
            DriftSeverity.LOW: Severity.LOW,
            DriftSeverity.INFO: Severity.INFO,
        }

        # Build description with differences
        diff_text = "\n".join(
            f"- {d.path}: {d.change_type} "
            f"(was: {d.baseline_value}, now: {d.current_value})"
            for d in self.differences[:5]  # Limit to first 5
        )
        if len(self.differences) > 5:
            diff_text += f"\n... and {len(self.differences) - 5} more changes"

        return Finding(
            id=f"drift-{self.asset_id}-{self.detected_at.strftime('%Y%m%d%H%M%S')}",
            asset_id=self.asset_id,
            finding_type=FindingType.MISCONFIGURATION,
            severity=severity_map.get(self.severity, Severity.INFO),
            status=FindingStatus.OPEN,
            title=f"Configuration drift detected: {self.drift_type.value}",
            description=f"{self.description}\n\nChanges detected:\n{diff_text}",
            rule_id="drift-detection",
            first_seen=self.detected_at,
            last_seen=self.detected_at,
            remediation_guidance="Review the configuration changes and either update the baseline or revert the changes.",
        )


@dataclass
class DriftDetectionResult:
    """
    Result of drift detection.

    Attributes:
        baseline_id: Baseline used for comparison
        detected_at: When detection was performed
        drift_events: List of drift events
        assets_checked: Number of assets checked
        assets_with_drift: Number of assets with drift
        summary: Summary statistics
    """

    baseline_id: str
    detected_at: datetime
    drift_events: list[DriftEvent]
    assets_checked: int
    assets_with_drift: int
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "baseline_id": self.baseline_id,
            "detected_at": self.detected_at.isoformat(),
            "drift_events": [e.to_dict() for e in self.drift_events],
            "assets_checked": self.assets_checked,
            "assets_with_drift": self.assets_with_drift,
            "summary": self.summary,
        }

    def get_findings(self) -> list[Finding]:
        """Convert all drift events to findings."""
        return [event.to_finding() for event in self.drift_events]


class DriftDetector:
    """
    Detects configuration drift from baselines.

    Compares current asset configurations against baselines
    and generates drift events with severity scoring.
    """

    # Security-sensitive configuration paths
    SECURITY_PATHS = {
        # AWS S3
        "PublicAccessBlockConfiguration",
        "BucketPolicy",
        "ServerSideEncryptionConfiguration",
        "Encryption",
        "Versioning",
        # AWS IAM
        "MFAEnabled",
        "PasswordPolicy",
        "AccessKeys",
        "TrustPolicy",
        "AssumeRolePolicyDocument",
        # AWS EC2
        "SecurityGroups",
        "IamInstanceProfile",
        "MetadataOptions",
        "BlockDeviceMappings",
        # AWS RDS
        "PubliclyAccessible",
        "StorageEncrypted",
        "DeletionProtection",
        # GCP
        "iamPolicy",
        "encryption",
        "accessConfigs",
        "networkInterfaces",
        # Azure
        "networkSecurityGroup",
        "encryption",
        "accessPolicies",
        "keyVault",
    }

    # High-severity configuration patterns
    HIGH_SEVERITY_PATTERNS = {
        "publicAccess": True,
        "PubliclyAccessible": True,
        "public": True,
        "0.0.0.0/0": True,
        "::/0": True,
        "MFAEnabled": False,
        "encrypted": False,
        "Encrypted": False,
        "StorageEncrypted": False,
    }

    def __init__(
        self,
        baseline_manager: BaselineManager | None = None,
        security_paths: set[str] | None = None,
    ):
        """
        Initialize drift detector.

        Args:
            baseline_manager: Baseline manager instance
            security_paths: Custom security-sensitive paths
        """
        self.baseline_manager = baseline_manager or BaselineManager()
        self.security_paths = security_paths or self.SECURITY_PATHS

    def detect_drift(
        self,
        assets: AssetCollection | list[Asset],
        baseline_id: str | None = None,
    ) -> DriftDetectionResult:
        """
        Detect configuration drift.

        Args:
            assets: Current assets to check
            baseline_id: Baseline to compare against (None = active baseline)

        Returns:
            Drift detection result
        """
        # Get baseline
        if baseline_id:
            baseline = self.baseline_manager.get_baseline(baseline_id)
        else:
            baseline = self.baseline_manager.get_active_baseline()

        if not baseline:
            return DriftDetectionResult(
                baseline_id=baseline_id or "none",
                detected_at=datetime.utcnow(),
                drift_events=[],
                assets_checked=0,
                assets_with_drift=0,
                summary={"error": "No baseline found"},
            )

        if isinstance(assets, AssetCollection):
            assets_list = list(assets.assets)
        else:
            assets_list = assets

        # Build asset lookup
        current_assets = {a.id: a for a in assets_list}
        baseline_asset_ids = set(baseline.asset_baselines.keys())
        current_asset_ids = set(current_assets.keys())

        drift_events: list[DriftEvent] = []

        # Detect new assets
        new_asset_ids = current_asset_ids - baseline_asset_ids
        for asset_id in new_asset_ids:
            asset = current_assets[asset_id]
            drift_events.append(DriftEvent(
                asset_id=asset_id,
                asset_type=asset.resource_type,
                cloud_provider=asset.cloud_provider,
                region=asset.region,
                drift_type=DriftType.NEW_ASSET,
                severity=DriftSeverity.LOW,
                differences=[],
                baseline_id=baseline.id,
                description=f"New asset detected: {asset.name}",
            ))

        # Detect removed assets
        removed_asset_ids = baseline_asset_ids - current_asset_ids
        for asset_id in removed_asset_ids:
            asset_baseline = baseline.asset_baselines[asset_id]
            drift_events.append(DriftEvent(
                asset_id=asset_id,
                asset_type=asset_baseline.asset_type,
                cloud_provider=asset_baseline.cloud_provider,
                region=asset_baseline.region,
                drift_type=DriftType.REMOVED_ASSET,
                severity=DriftSeverity.MEDIUM,
                differences=[],
                baseline_id=baseline.id,
                description=f"Asset removed from environment",
            ))

        # Detect configuration changes
        common_asset_ids = baseline_asset_ids & current_asset_ids
        for asset_id in common_asset_ids:
            asset_baseline = baseline.asset_baselines[asset_id]
            current_asset = current_assets[asset_id]

            event = self._detect_asset_drift(
                asset_baseline,
                current_asset,
                baseline.id,
            )
            if event:
                drift_events.append(event)

        # Build summary
        drift_by_severity: dict[str, int] = {}
        drift_by_type: dict[str, int] = {}

        for event in drift_events:
            sev = event.severity.value
            drift_by_severity[sev] = drift_by_severity.get(sev, 0) + 1

            dt = event.drift_type.value
            drift_by_type[dt] = drift_by_type.get(dt, 0) + 1

        return DriftDetectionResult(
            baseline_id=baseline.id,
            detected_at=datetime.utcnow(),
            drift_events=drift_events,
            assets_checked=len(assets_list),
            assets_with_drift=len(drift_events),
            summary={
                "has_drift": len(drift_events) > 0,
                "drift_by_severity": drift_by_severity,
                "drift_by_type": drift_by_type,
                "security_drift_count": sum(
                    1 for e in drift_events
                    if any(d.is_security_relevant for d in e.differences)
                ),
            },
        )

    def _detect_asset_drift(
        self,
        asset_baseline: AssetBaseline,
        current_asset: Asset,
        baseline_id: str,
    ) -> DriftEvent | None:
        """Detect drift for a single asset."""
        current_config = BaselineConfig.from_asset(current_asset)

        # Quick hash comparison
        if current_config.config_hash == asset_baseline.baseline_config.config_hash:
            return None

        # Detailed comparison
        differences = self._find_differences(
            asset_baseline.baseline_config.normalized_data,
            current_config.normalized_data,
        )

        if not differences:
            return None

        # Score differences
        scored_differences = [
            self._score_difference(d) for d in differences
        ]

        # Determine overall severity
        max_severity = max(
            (d.severity for d in scored_differences),
            key=lambda s: self._severity_order(s),
        )

        # Determine drift type
        has_security_drift = any(d.is_security_relevant for d in scored_differences)
        if has_security_drift:
            drift_type = DriftType.SECURITY_DEGRADED
        else:
            drift_type = DriftType.CONFIG_CHANGED

        # Build description
        security_changes = [d for d in scored_differences if d.is_security_relevant]
        if security_changes:
            description = f"Security-relevant configuration changes detected ({len(security_changes)} changes)"
        else:
            description = f"Configuration drift detected ({len(scored_differences)} changes)"

        return DriftEvent(
            asset_id=current_asset.id,
            asset_type=current_asset.resource_type,
            cloud_provider=current_asset.cloud_provider,
            region=current_asset.region,
            drift_type=drift_type,
            severity=max_severity,
            differences=scored_differences,
            baseline_id=baseline_id,
            description=description,
        )

    def _find_differences(
        self,
        baseline: dict,
        current: dict,
        path: str = "",
    ) -> list[ConfigDifference]:
        """Find configuration differences."""
        differences = []

        all_keys = set(baseline.keys()) | set(current.keys())

        for key in all_keys:
            current_path = f"{path}.{key}" if path else key

            if key not in baseline:
                differences.append(ConfigDifference(
                    path=current_path,
                    change_type="added",
                    baseline_value=None,
                    current_value=current.get(key),
                ))
            elif key not in current:
                differences.append(ConfigDifference(
                    path=current_path,
                    change_type="removed",
                    baseline_value=baseline.get(key),
                    current_value=None,
                ))
            elif baseline[key] != current[key]:
                if isinstance(baseline[key], dict) and isinstance(current[key], dict):
                    differences.extend(
                        self._find_differences(baseline[key], current[key], current_path)
                    )
                else:
                    differences.append(ConfigDifference(
                        path=current_path,
                        change_type="changed",
                        baseline_value=baseline.get(key),
                        current_value=current.get(key),
                    ))

        return differences

    def _score_difference(self, diff: ConfigDifference) -> ConfigDifference:
        """Score a configuration difference."""
        # Check if path is security-sensitive
        path_parts = diff.path.split(".")
        is_security_relevant = any(
            part in self.security_paths for part in path_parts
        )

        # Check for high-severity patterns
        is_high_severity = False

        # Check if change introduces a risky value
        for pattern, risky_value in self.HIGH_SEVERITY_PATTERNS.items():
            if pattern in diff.path:
                if diff.current_value == risky_value:
                    is_high_severity = True
                    is_security_relevant = True
                    break

        # Determine severity
        if is_high_severity:
            severity = DriftSeverity.HIGH
        elif is_security_relevant:
            severity = DriftSeverity.MEDIUM
        else:
            severity = DriftSeverity.LOW

        return ConfigDifference(
            path=diff.path,
            change_type=diff.change_type,
            baseline_value=diff.baseline_value,
            current_value=diff.current_value,
            is_security_relevant=is_security_relevant,
            severity=severity,
        )

    def _severity_order(self, severity: DriftSeverity) -> int:
        """Get severity order for comparison."""
        order = {
            DriftSeverity.CRITICAL: 0,
            DriftSeverity.HIGH: 1,
            DriftSeverity.MEDIUM: 2,
            DriftSeverity.LOW: 3,
            DriftSeverity.INFO: 4,
        }
        return order.get(severity, 5)

    def add_security_path(self, path: str) -> None:
        """Add a security-sensitive path."""
        self.security_paths.add(path)

    def get_drift_summary(
        self,
        result: DriftDetectionResult,
    ) -> dict[str, Any]:
        """
        Generate drift summary for reporting.

        Args:
            result: Drift detection result

        Returns:
            Summary dictionary
        """
        return {
            "baseline_id": result.baseline_id,
            "detected_at": result.detected_at.isoformat(),
            "assets_checked": result.assets_checked,
            "assets_with_drift": result.assets_with_drift,
            "drift_percentage": (
                result.assets_with_drift / result.assets_checked * 100
                if result.assets_checked > 0 else 0
            ),
            "critical_drift": result.summary.get("drift_by_severity", {}).get("critical", 0),
            "high_drift": result.summary.get("drift_by_severity", {}).get("high", 0),
            "security_drift_count": result.summary.get("security_drift_count", 0),
            "has_drift": result.summary.get("has_drift", False),
        }
