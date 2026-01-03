"""
Progress tracking for Mantissa Stance.

Provides real-time progress indicators for scans, collections,
and policy evaluations with support for terminal and callback-based output.
"""

from __future__ import annotations

import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable


class ProgressPhase(Enum):
    """Phases of a scan operation."""

    INITIALIZING = "initializing"
    COLLECTING = "collecting"
    EVALUATING = "evaluating"
    STORING = "storing"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class ProgressStep:
    """
    Individual step in a progress sequence.

    Attributes:
        name: Step name/description
        total: Total items to process (0 if unknown)
        completed: Items completed
        status: Current status message
        started_at: When step started
        completed_at: When step finished
    """

    name: str
    total: int = 0
    completed: int = 0
    status: str = ""
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    @property
    def percent(self) -> float:
        """Get completion percentage."""
        if self.total == 0:
            return 0.0
        return min(100.0, (self.completed / self.total) * 100)

    @property
    def is_complete(self) -> bool:
        """Check if step is complete."""
        return self.completed_at is not None

    @property
    def duration_seconds(self) -> float:
        """Get duration in seconds."""
        end = self.completed_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "total": self.total,
            "completed": self.completed,
            "percent": round(self.percent, 1),
            "status": self.status,
            "is_complete": self.is_complete,
            "duration_seconds": round(self.duration_seconds, 2),
        }


@dataclass
class ScanProgress:
    """
    Overall scan progress tracking.

    Attributes:
        phase: Current phase of the scan
        steps: List of progress steps
        current_step_index: Index of current step
        started_at: When scan started
        completed_at: When scan finished
        error: Error message if failed
    """

    phase: ProgressPhase = ProgressPhase.INITIALIZING
    steps: list[ProgressStep] = field(default_factory=list)
    current_step_index: int = 0
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    error: str | None = None

    @property
    def current_step(self) -> ProgressStep | None:
        """Get current step."""
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    @property
    def overall_percent(self) -> float:
        """Get overall completion percentage."""
        if not self.steps:
            return 0.0
        completed_steps = sum(1 for s in self.steps if s.is_complete)
        current_contrib = 0.0
        if self.current_step and not self.current_step.is_complete:
            current_contrib = self.current_step.percent / 100 / len(self.steps)
        return (completed_steps / len(self.steps) * 100) + (current_contrib * 100)

    @property
    def duration_seconds(self) -> float:
        """Get total duration in seconds."""
        end = self.completed_at or datetime.utcnow()
        return (end - self.started_at).total_seconds()

    @property
    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.phase in (ProgressPhase.COMPLETE, ProgressPhase.FAILED)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "phase": self.phase.value,
            "overall_percent": round(self.overall_percent, 1),
            "duration_seconds": round(self.duration_seconds, 2),
            "is_complete": self.is_complete,
            "error": self.error,
            "steps": [s.to_dict() for s in self.steps],
            "current_step": self.current_step.to_dict() if self.current_step else None,
        }


class ProgressRenderer(ABC):
    """
    Abstract base for progress renderers.

    Renderers display progress information to different outputs
    (terminal, file, callbacks, etc.).
    """

    @abstractmethod
    def render(self, progress: ScanProgress) -> None:
        """
        Render progress update.

        Args:
            progress: Current progress state
        """
        pass

    @abstractmethod
    def clear(self) -> None:
        """Clear/reset the display."""
        pass

    @abstractmethod
    def finish(self, progress: ScanProgress) -> None:
        """
        Render final state.

        Args:
            progress: Final progress state
        """
        pass


class TerminalProgressRenderer(ProgressRenderer):
    """
    Renders progress to terminal with dynamic updates.

    Uses ANSI escape codes for in-place updates when
    output is a TTY, falls back to simple output otherwise.
    """

    def __init__(
        self,
        output: Any = None,
        show_spinner: bool = True,
        show_bar: bool = True,
        bar_width: int = 40,
    ):
        """
        Initialize terminal renderer.

        Args:
            output: Output stream (default: sys.stderr)
            show_spinner: Show spinning indicator
            show_bar: Show progress bar
            bar_width: Width of progress bar
        """
        self._output = output or sys.stderr
        self._show_spinner = show_spinner
        self._show_bar = show_bar
        self._bar_width = bar_width
        self._is_tty = hasattr(self._output, "isatty") and self._output.isatty()
        self._spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._spinner_index = 0
        self._last_lines = 0

    def render(self, progress: ScanProgress) -> None:
        """Render progress to terminal."""
        if self._is_tty:
            self._render_dynamic(progress)
        else:
            self._render_simple(progress)

    def _render_dynamic(self, progress: ScanProgress) -> None:
        """Render with ANSI escape codes for dynamic updates."""
        # Clear previous output
        if self._last_lines > 0:
            self._output.write(f"\033[{self._last_lines}A\033[J")

        lines = self._build_display(progress)
        self._output.write(lines)
        self._output.flush()
        self._last_lines = lines.count("\n")

    def _render_simple(self, progress: ScanProgress) -> None:
        """Render simple line-by-line output."""
        step = progress.current_step
        if step:
            status = step.status or step.name
            self._output.write(f"  {status}... {step.percent:.0f}%\n")
            self._output.flush()

    def _build_display(self, progress: ScanProgress) -> str:
        """Build display string."""
        lines = []

        # Header
        phase = progress.phase.value.upper()
        duration = f"{progress.duration_seconds:.1f}s"
        lines.append(f"[{phase}] {progress.overall_percent:.1f}% complete ({duration})")

        # Current step
        step = progress.current_step
        if step:
            spinner = ""
            if self._show_spinner and not step.is_complete:
                spinner = self._spinner_chars[self._spinner_index] + " "
                self._spinner_index = (self._spinner_index + 1) % len(self._spinner_chars)

            status = step.status or step.name
            lines.append(f"  {spinner}{status}")

            # Progress bar
            if self._show_bar and step.total > 0:
                bar = self._build_bar(step.percent)
                lines.append(f"  {bar} {step.completed}/{step.total}")

        # Error if any
        if progress.error:
            lines.append(f"  ERROR: {progress.error}")

        lines.append("")  # Trailing newline
        return "\n".join(lines)

    def _build_bar(self, percent: float) -> str:
        """Build progress bar string."""
        filled = int(self._bar_width * percent / 100)
        empty = self._bar_width - filled
        return f"[{'█' * filled}{'░' * empty}] {percent:.0f}%"

    def clear(self) -> None:
        """Clear the display."""
        if self._is_tty and self._last_lines > 0:
            self._output.write(f"\033[{self._last_lines}A\033[J")
            self._output.flush()
            self._last_lines = 0

    def finish(self, progress: ScanProgress) -> None:
        """Render final state."""
        self.clear()

        if progress.phase == ProgressPhase.COMPLETE:
            symbol = "✓"
            status = "complete"
        elif progress.phase == ProgressPhase.FAILED:
            symbol = "✗"
            status = f"failed: {progress.error or 'unknown error'}"
        else:
            symbol = "="
            status = "stopped"

        duration = f"{progress.duration_seconds:.1f}s"
        self._output.write(f"{symbol} Scan {status} ({duration})\n")
        self._output.flush()


class CallbackProgressRenderer(ProgressRenderer):
    """
    Renders progress via callbacks.

    Useful for integration with UI frameworks or logging systems.
    """

    def __init__(
        self,
        on_update: Callable[[ScanProgress], None] | None = None,
        on_complete: Callable[[ScanProgress], None] | None = None,
    ):
        """
        Initialize callback renderer.

        Args:
            on_update: Callback for progress updates
            on_complete: Callback for completion
        """
        self._on_update = on_update
        self._on_complete = on_complete

    def render(self, progress: ScanProgress) -> None:
        """Call update callback."""
        if self._on_update:
            self._on_update(progress)

    def clear(self) -> None:
        """No-op for callback renderer."""
        pass

    def finish(self, progress: ScanProgress) -> None:
        """Call completion callback."""
        if self._on_complete:
            self._on_complete(progress)


class QuietProgressRenderer(ProgressRenderer):
    """Silent progress renderer that does nothing."""

    def render(self, progress: ScanProgress) -> None:
        """No-op."""
        pass

    def clear(self) -> None:
        """No-op."""
        pass

    def finish(self, progress: ScanProgress) -> None:
        """No-op."""
        pass


class ProgressTracker:
    """
    Tracks and reports progress for scan operations.

    Coordinates progress state with one or more renderers
    to provide real-time feedback during scans.
    """

    def __init__(
        self,
        renderers: list[ProgressRenderer] | None = None,
        update_interval: float = 0.1,
    ):
        """
        Initialize progress tracker.

        Args:
            renderers: List of progress renderers
            update_interval: Minimum time between updates (seconds)
        """
        self._renderers = renderers or []
        self._update_interval = update_interval
        self._progress = ScanProgress()
        self._last_update = 0.0
        self._lock = threading.Lock()

    @property
    def progress(self) -> ScanProgress:
        """Get current progress state."""
        return self._progress

    def add_renderer(self, renderer: ProgressRenderer) -> None:
        """Add a progress renderer."""
        self._renderers.append(renderer)

    def start(self, steps: list[str]) -> None:
        """
        Start progress tracking.

        Args:
            steps: List of step names
        """
        with self._lock:
            self._progress = ScanProgress(
                phase=ProgressPhase.INITIALIZING,
                steps=[ProgressStep(name=s) for s in steps],
                started_at=datetime.utcnow(),
            )
            self._render()

    def set_phase(self, phase: ProgressPhase) -> None:
        """
        Set current phase.

        Args:
            phase: New phase
        """
        with self._lock:
            self._progress.phase = phase
            self._render()

    def start_step(self, index: int, total: int = 0, status: str = "") -> None:
        """
        Start a progress step.

        Args:
            index: Step index
            total: Total items in step (0 if unknown)
            status: Initial status message
        """
        with self._lock:
            if 0 <= index < len(self._progress.steps):
                step = self._progress.steps[index]
                step.total = total
                step.completed = 0
                step.status = status
                step.started_at = datetime.utcnow()
                step.completed_at = None
                self._progress.current_step_index = index
                self._render()

    def update_step(
        self,
        completed: int | None = None,
        status: str | None = None,
        increment: int = 0,
    ) -> None:
        """
        Update current step progress.

        Args:
            completed: Absolute completed count
            status: New status message
            increment: Increment completed by this amount
        """
        with self._lock:
            step = self._progress.current_step
            if step:
                if completed is not None:
                    step.completed = completed
                elif increment:
                    step.completed += increment
                if status is not None:
                    step.status = status
                self._render_throttled()

    def complete_step(self, index: int | None = None) -> None:
        """
        Mark a step as complete.

        Args:
            index: Step index (default: current step)
        """
        with self._lock:
            idx = index if index is not None else self._progress.current_step_index
            if 0 <= idx < len(self._progress.steps):
                step = self._progress.steps[idx]
                step.completed = step.total or step.completed
                step.completed_at = datetime.utcnow()
                self._render()

    def complete(self) -> None:
        """Mark scan as complete."""
        with self._lock:
            self._progress.phase = ProgressPhase.COMPLETE
            self._progress.completed_at = datetime.utcnow()
            self._finish()

    def fail(self, error: str) -> None:
        """
        Mark scan as failed.

        Args:
            error: Error message
        """
        with self._lock:
            self._progress.phase = ProgressPhase.FAILED
            self._progress.error = error
            self._progress.completed_at = datetime.utcnow()
            self._finish()

    def _render(self) -> None:
        """Render to all renderers."""
        for renderer in self._renderers:
            try:
                renderer.render(self._progress)
            except Exception:
                pass  # Don't let rendering errors affect scan

    def _render_throttled(self) -> None:
        """Render with throttling."""
        now = time.time()
        if now - self._last_update >= self._update_interval:
            self._last_update = now
            self._render()

    def _finish(self) -> None:
        """Call finish on all renderers."""
        for renderer in self._renderers:
            try:
                renderer.finish(self._progress)
            except Exception:
                pass


def create_progress_tracker(
    quiet: bool = False,
    callback: Callable[[ScanProgress], None] | None = None,
) -> ProgressTracker:
    """
    Create a progress tracker with appropriate renderers.

    Args:
        quiet: Suppress terminal output
        callback: Optional callback for progress updates

    Returns:
        Configured ProgressTracker
    """
    renderers: list[ProgressRenderer] = []

    if not quiet:
        renderers.append(TerminalProgressRenderer())

    if callback:
        renderers.append(CallbackProgressRenderer(on_update=callback))

    if not renderers:
        renderers.append(QuietProgressRenderer())

    return ProgressTracker(renderers=renderers)
