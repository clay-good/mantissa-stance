"""
Baseline and drift detection for Mantissa Stance.

Provides configuration baselining, drift detection,
and change tracking capabilities.
"""

from stance.drift.baseline import (
    AssetBaseline,
    Baseline,
    BaselineConfig,
    BaselineManager,
    BaselineStatus,
    BaselineStorage,
    InMemoryBaselineStorage,
)
from stance.drift.drift_detector import (
    ConfigDifference,
    DriftDetectionResult,
    DriftDetector,
    DriftEvent,
    DriftSeverity,
    DriftType,
)
from stance.drift.change_tracker import (
    AssetHistory,
    ChangeEvent,
    ChangeStorage,
    ChangeTracker,
    ChangeType,
    ConfigSnapshot,
    InMemoryChangeStorage,
)

__all__ = [
    # Baseline
    "AssetBaseline",
    "Baseline",
    "BaselineConfig",
    "BaselineManager",
    "BaselineStatus",
    "BaselineStorage",
    "InMemoryBaselineStorage",
    # Drift detection
    "ConfigDifference",
    "DriftDetectionResult",
    "DriftDetector",
    "DriftEvent",
    "DriftSeverity",
    "DriftType",
    # Change tracking
    "AssetHistory",
    "ChangeEvent",
    "ChangeStorage",
    "ChangeTracker",
    "ChangeType",
    "ConfigSnapshot",
    "InMemoryChangeStorage",
]


def detect_drift(
    assets,
    baseline_id: str | None = None,
    baseline_manager: BaselineManager | None = None,
) -> DriftDetectionResult:
    """
    Detect drift in assets compared to baseline.

    Convenience function for drift detection.

    Args:
        assets: Current assets
        baseline_id: Baseline to compare against (None = active)
        baseline_manager: Optional baseline manager

    Returns:
        Drift detection result
    """
    if baseline_manager is None:
        baseline_manager = BaselineManager()

    detector = DriftDetector(baseline_manager=baseline_manager)
    return detector.detect_drift(assets, baseline_id)


def create_baseline(
    name: str,
    assets,
    description: str = "",
    baseline_manager: BaselineManager | None = None,
) -> Baseline:
    """
    Create a new baseline from assets.

    Convenience function for baseline creation.

    Args:
        name: Baseline name
        assets: Assets to baseline
        description: Baseline description
        baseline_manager: Optional baseline manager

    Returns:
        Created baseline
    """
    if baseline_manager is None:
        baseline_manager = BaselineManager()

    return baseline_manager.create_baseline(
        name=name,
        assets=assets,
        description=description,
    )


def track_changes(
    assets,
    change_tracker: ChangeTracker | None = None,
) -> list[ChangeEvent]:
    """
    Track changes in assets.

    Convenience function for change tracking.

    Args:
        assets: Current assets
        change_tracker: Optional change tracker

    Returns:
        List of detected change events
    """
    if change_tracker is None:
        change_tracker = ChangeTracker()

    return change_tracker.track_changes(assets)
