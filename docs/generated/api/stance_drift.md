# stance.drift

Baseline and drift detection for Mantissa Stance.

Provides configuration baselining, drift detection,
and change tracking capabilities.

## Contents

### Functions

- [detect_drift](#detect_drift)
- [create_baseline](#create_baseline)
- [track_changes](#track_changes)

### `detect_drift(assets, baseline_id: str | None, baseline_manager: BaselineManager | None) -> DriftDetectionResult`

Detect drift in assets compared to baseline.  Convenience function for drift detection.

**Parameters:**

- `assets` - Current assets
- `baseline_id` (`str | None`) - Baseline to compare against (None = active)
- `baseline_manager` (`BaselineManager | None`) - Optional baseline manager

**Returns:**

`DriftDetectionResult` - Drift detection result

### `create_baseline(name: str, assets, description: str = , baseline_manager: BaselineManager | None) -> Baseline`

Create a new baseline from assets.  Convenience function for baseline creation.

**Parameters:**

- `name` (`str`) - Baseline name
- `assets` - Assets to baseline
- `description` (`str`) - default: `` - Baseline description
- `baseline_manager` (`BaselineManager | None`) - Optional baseline manager

**Returns:**

`Baseline` - Created baseline

### `track_changes(assets, change_tracker: ChangeTracker | None) -> list[ChangeEvent]`

Track changes in assets.  Convenience function for change tracking.

**Parameters:**

- `assets` - Current assets
- `change_tracker` (`ChangeTracker | None`) - Optional change tracker

**Returns:**

`list[ChangeEvent]` - List of detected change events
