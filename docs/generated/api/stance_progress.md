# stance.progress

Progress tracking for Mantissa Stance.

Provides real-time progress indicators for scans, collections,
and policy evaluations with support for terminal and callback-based output.

## Contents

### Classes

- [ProgressPhase](#progressphase)
- [ProgressStep](#progressstep)
- [ScanProgress](#scanprogress)
- [ProgressRenderer](#progressrenderer)
- [TerminalProgressRenderer](#terminalprogressrenderer)
- [CallbackProgressRenderer](#callbackprogressrenderer)
- [QuietProgressRenderer](#quietprogressrenderer)
- [ProgressTracker](#progresstracker)

### Functions

- [create_progress_tracker](#create_progress_tracker)

## ProgressPhase

**Inherits from:** Enum

Phases of a scan operation.

## ProgressStep

**Tags:** dataclass

Individual step in a progress sequence.

Attributes:
    name: Step name/description
    total: Total items to process (0 if unknown)
    completed: Items completed
    status: Current status message
    started_at: When step started
    completed_at: When step finished

### Attributes

| Name | Type | Default |
|------|------|---------|
| `name` | `str` | - |
| `total` | `int` | `0` |
| `completed` | `int` | `0` |
| `status` | `str` | `` |
| `started_at` | `datetime` | `field(...)` |
| `completed_at` | `datetime | None` | - |

### Properties

#### `percent(self) -> float`

Get completion percentage.

**Returns:**

`float`

#### `is_complete(self) -> bool`

Check if step is complete.

**Returns:**

`bool`

#### `duration_seconds(self) -> float`

Get duration in seconds.

**Returns:**

`float`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ScanProgress

**Tags:** dataclass

Overall scan progress tracking.

Attributes:
    phase: Current phase of the scan
    steps: List of progress steps
    current_step_index: Index of current step
    started_at: When scan started
    completed_at: When scan finished
    error: Error message if failed

### Attributes

| Name | Type | Default |
|------|------|---------|
| `phase` | `ProgressPhase` | `"Attribute(value=Name(id='ProgressPhase', ctx=Load()), attr='INITIALIZING', ctx=Load())"` |
| `steps` | `list[ProgressStep]` | `field(...)` |
| `current_step_index` | `int` | `0` |
| `started_at` | `datetime` | `field(...)` |
| `completed_at` | `datetime | None` | - |
| `error` | `str | None` | - |

### Properties

#### `current_step(self) -> ProgressStep | None`

Get current step.

**Returns:**

`ProgressStep | None`

#### `overall_percent(self) -> float`

Get overall completion percentage.

**Returns:**

`float`

#### `duration_seconds(self) -> float`

Get total duration in seconds.

**Returns:**

`float`

#### `is_complete(self) -> bool`

Check if scan is complete.

**Returns:**

`bool`

### Methods

#### `to_dict(self) -> dict[(str, Any)]`

Convert to dictionary.

**Returns:**

`dict[(str, Any)]`

## ProgressRenderer

**Inherits from:** ABC

Abstract base for progress renderers.

Renderers display progress information to different outputs
(terminal, file, callbacks, etc.).

### Methods

#### `render(self, progress: ScanProgress) -> None`

**Decorators:** @abstractmethod

Render progress update.

**Parameters:**

- `progress` (`ScanProgress`) - Current progress state

**Returns:**

`None`

#### `clear(self) -> None`

**Decorators:** @abstractmethod

Clear/reset the display.

**Returns:**

`None`

#### `finish(self, progress: ScanProgress) -> None`

**Decorators:** @abstractmethod

Render final state.

**Parameters:**

- `progress` (`ScanProgress`) - Final progress state

**Returns:**

`None`

## TerminalProgressRenderer

**Inherits from:** ProgressRenderer

Renders progress to terminal with dynamic updates.

Uses ANSI escape codes for in-place updates when
output is a TTY, falls back to simple output otherwise.

### Methods

#### `__init__(self, output: Any, show_spinner: bool = True, show_bar: bool = True, bar_width: int = 40)`

Initialize terminal renderer.

**Parameters:**

- `output` (`Any`) - Output stream (default: sys.stderr)
- `show_spinner` (`bool`) - default: `True` - Show spinning indicator
- `show_bar` (`bool`) - default: `True` - Show progress bar
- `bar_width` (`int`) - default: `40` - Width of progress bar

#### `render(self, progress: ScanProgress) -> None`

Render progress to terminal.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

#### `clear(self) -> None`

Clear the display.

**Returns:**

`None`

#### `finish(self, progress: ScanProgress) -> None`

Render final state.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

## CallbackProgressRenderer

**Inherits from:** ProgressRenderer

Renders progress via callbacks.

Useful for integration with UI frameworks or logging systems.

### Methods

#### `__init__(self, on_update: Callable[([ScanProgress], None)] | None, on_complete: Callable[([ScanProgress], None)] | None)`

Initialize callback renderer.

**Parameters:**

- `on_update` (`Callable[([ScanProgress], None)] | None`) - Callback for progress updates
- `on_complete` (`Callable[([ScanProgress], None)] | None`) - Callback for completion

#### `render(self, progress: ScanProgress) -> None`

Call update callback.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

#### `clear(self) -> None`

No-op for callback renderer.

**Returns:**

`None`

#### `finish(self, progress: ScanProgress) -> None`

Call completion callback.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

## QuietProgressRenderer

**Inherits from:** ProgressRenderer

Silent progress renderer that does nothing.

### Methods

#### `render(self, progress: ScanProgress) -> None`

No-op.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

#### `clear(self) -> None`

No-op.

**Returns:**

`None`

#### `finish(self, progress: ScanProgress) -> None`

No-op.

**Parameters:**

- `progress` (`ScanProgress`)

**Returns:**

`None`

## ProgressTracker

Tracks and reports progress for scan operations.

Coordinates progress state with one or more renderers
to provide real-time feedback during scans.

### Properties

#### `progress(self) -> ScanProgress`

Get current progress state.

**Returns:**

`ScanProgress`

### Methods

#### `__init__(self, renderers: list[ProgressRenderer] | None, update_interval: float = 0.1)`

Initialize progress tracker.

**Parameters:**

- `renderers` (`list[ProgressRenderer] | None`) - List of progress renderers
- `update_interval` (`float`) - default: `0.1` - Minimum time between updates (seconds)

#### `add_renderer(self, renderer: ProgressRenderer) -> None`

Add a progress renderer.

**Parameters:**

- `renderer` (`ProgressRenderer`)

**Returns:**

`None`

#### `start(self, steps: list[str]) -> None`

Start progress tracking.

**Parameters:**

- `steps` (`list[str]`) - List of step names

**Returns:**

`None`

#### `set_phase(self, phase: ProgressPhase) -> None`

Set current phase.

**Parameters:**

- `phase` (`ProgressPhase`) - New phase

**Returns:**

`None`

#### `start_step(self, index: int, total: int = 0, status: str = ) -> None`

Start a progress step.

**Parameters:**

- `index` (`int`) - Step index
- `total` (`int`) - default: `0` - Total items in step (0 if unknown)
- `status` (`str`) - default: `` - Initial status message

**Returns:**

`None`

#### `update_step(self, completed: int | None, status: str | None, increment: int = 0) -> None`

Update current step progress.

**Parameters:**

- `completed` (`int | None`) - Absolute completed count
- `status` (`str | None`) - New status message
- `increment` (`int`) - default: `0` - Increment completed by this amount

**Returns:**

`None`

#### `complete_step(self, index: int | None) -> None`

Mark a step as complete.

**Parameters:**

- `index` (`int | None`) - Step index (default: current step)

**Returns:**

`None`

#### `complete(self) -> None`

Mark scan as complete.

**Returns:**

`None`

#### `fail(self, error: str) -> None`

Mark scan as failed.

**Parameters:**

- `error` (`str`) - Error message

**Returns:**

`None`

### `create_progress_tracker(quiet: bool = False, callback: Callable[([ScanProgress], None)] | None) -> ProgressTracker`

Create a progress tracker with appropriate renderers.

**Parameters:**

- `quiet` (`bool`) - default: `False` - Suppress terminal output
- `callback` (`Callable[([ScanProgress], None)] | None`) - Optional callback for progress updates

**Returns:**

`ProgressTracker` - Configured ProgressTracker
