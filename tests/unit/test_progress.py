"""
Tests for Progress tracking module.

Tests real-time progress indicators for scans, collections,
and policy evaluations.
"""

from __future__ import annotations

import io
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.progress import (
    ProgressPhase,
    ProgressStep,
    ScanProgress,
    ProgressRenderer,
    TerminalProgressRenderer,
    CallbackProgressRenderer,
    QuietProgressRenderer,
    ProgressTracker,
    create_progress_tracker,
)


# =============================================================================
# ProgressPhase Tests
# =============================================================================


class TestProgressPhase:
    """Tests for ProgressPhase enum."""

    def test_phase_values(self):
        """Test all phase values exist."""
        assert ProgressPhase.INITIALIZING.value == "initializing"
        assert ProgressPhase.COLLECTING.value == "collecting"
        assert ProgressPhase.EVALUATING.value == "evaluating"
        assert ProgressPhase.STORING.value == "storing"
        assert ProgressPhase.COMPLETE.value == "complete"
        assert ProgressPhase.FAILED.value == "failed"

    def test_phase_count(self):
        """Test expected number of phases."""
        assert len(ProgressPhase) == 6


# =============================================================================
# ProgressStep Tests
# =============================================================================


class TestProgressStep:
    """Tests for ProgressStep dataclass."""

    def test_default_values(self):
        """Test default step values."""
        step = ProgressStep(name="Test Step")
        assert step.name == "Test Step"
        assert step.total == 0
        assert step.completed == 0
        assert step.status == ""
        assert step.completed_at is None
        assert isinstance(step.started_at, datetime)

    def test_percent_zero_total(self):
        """Test percent with zero total."""
        step = ProgressStep(name="Test", total=0)
        assert step.percent == 0.0

    def test_percent_calculation(self):
        """Test percent calculation."""
        step = ProgressStep(name="Test", total=100, completed=50)
        assert step.percent == 50.0

    def test_percent_max_100(self):
        """Test percent doesn't exceed 100."""
        step = ProgressStep(name="Test", total=100, completed=150)
        assert step.percent == 100.0

    def test_is_complete_false(self):
        """Test is_complete when not complete."""
        step = ProgressStep(name="Test")
        assert step.is_complete is False

    def test_is_complete_true(self):
        """Test is_complete when complete."""
        step = ProgressStep(name="Test", completed_at=datetime.utcnow())
        assert step.is_complete is True

    def test_duration_seconds_ongoing(self):
        """Test duration for ongoing step."""
        past = datetime.utcnow() - timedelta(seconds=5)
        step = ProgressStep(name="Test", started_at=past)
        assert step.duration_seconds >= 5.0

    def test_duration_seconds_completed(self):
        """Test duration for completed step."""
        start = datetime.utcnow() - timedelta(seconds=10)
        end = datetime.utcnow() - timedelta(seconds=5)
        step = ProgressStep(name="Test", started_at=start, completed_at=end)
        assert abs(step.duration_seconds - 5.0) < 0.1

    def test_to_dict(self):
        """Test dictionary conversion."""
        step = ProgressStep(
            name="Collection",
            total=100,
            completed=50,
            status="Collecting assets",
        )
        d = step.to_dict()
        assert d["name"] == "Collection"
        assert d["total"] == 100
        assert d["completed"] == 50
        assert d["percent"] == 50.0
        assert d["status"] == "Collecting assets"
        assert d["is_complete"] is False
        assert "duration_seconds" in d


# =============================================================================
# ScanProgress Tests
# =============================================================================


class TestScanProgress:
    """Tests for ScanProgress dataclass."""

    def test_default_values(self):
        """Test default progress values."""
        progress = ScanProgress()
        assert progress.phase == ProgressPhase.INITIALIZING
        assert progress.steps == []
        assert progress.current_step_index == 0
        assert progress.completed_at is None
        assert progress.error is None

    def test_current_step_empty(self):
        """Test current_step with no steps."""
        progress = ScanProgress()
        assert progress.current_step is None

    def test_current_step_valid_index(self):
        """Test current_step with valid index."""
        steps = [ProgressStep(name="Step 1"), ProgressStep(name="Step 2")]
        progress = ScanProgress(steps=steps, current_step_index=1)
        assert progress.current_step.name == "Step 2"

    def test_current_step_invalid_index(self):
        """Test current_step with invalid index."""
        steps = [ProgressStep(name="Step 1")]
        progress = ScanProgress(steps=steps, current_step_index=5)
        assert progress.current_step is None

    def test_overall_percent_no_steps(self):
        """Test overall_percent with no steps."""
        progress = ScanProgress()
        assert progress.overall_percent == 0.0

    def test_overall_percent_all_complete(self):
        """Test overall_percent with all steps complete."""
        steps = [
            ProgressStep(name="Step 1", completed_at=datetime.utcnow()),
            ProgressStep(name="Step 2", completed_at=datetime.utcnow()),
        ]
        progress = ScanProgress(steps=steps)
        assert progress.overall_percent == 100.0

    def test_overall_percent_partial(self):
        """Test overall_percent with partial progress."""
        steps = [
            ProgressStep(name="Step 1", completed_at=datetime.utcnow()),
            ProgressStep(name="Step 2", total=100, completed=50),
        ]
        progress = ScanProgress(steps=steps, current_step_index=1)
        # 1 complete + 50% of current = 50% + 25% = 75%
        assert progress.overall_percent == 75.0

    def test_duration_seconds(self):
        """Test duration calculation."""
        past = datetime.utcnow() - timedelta(seconds=10)
        progress = ScanProgress(started_at=past)
        assert progress.duration_seconds >= 10.0

    def test_is_complete_false(self):
        """Test is_complete when not complete."""
        progress = ScanProgress(phase=ProgressPhase.COLLECTING)
        assert progress.is_complete is False

    def test_is_complete_true_complete(self):
        """Test is_complete when phase is COMPLETE."""
        progress = ScanProgress(phase=ProgressPhase.COMPLETE)
        assert progress.is_complete is True

    def test_is_complete_true_failed(self):
        """Test is_complete when phase is FAILED."""
        progress = ScanProgress(phase=ProgressPhase.FAILED)
        assert progress.is_complete is True

    def test_to_dict(self):
        """Test dictionary conversion."""
        steps = [ProgressStep(name="Step 1")]
        progress = ScanProgress(
            phase=ProgressPhase.COLLECTING,
            steps=steps,
            current_step_index=0,
        )
        d = progress.to_dict()
        assert d["phase"] == "collecting"
        assert "overall_percent" in d
        assert "duration_seconds" in d
        assert d["is_complete"] is False
        assert d["error"] is None
        assert len(d["steps"]) == 1
        assert d["current_step"] is not None


# =============================================================================
# TerminalProgressRenderer Tests
# =============================================================================


class TestTerminalProgressRenderer:
    """Tests for TerminalProgressRenderer."""

    def test_init_defaults(self):
        """Test default initialization."""
        renderer = TerminalProgressRenderer()
        assert renderer._show_spinner is True
        assert renderer._show_bar is True
        assert renderer._bar_width == 40

    def test_init_custom_output(self):
        """Test custom output stream."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        assert renderer._output is output

    def test_init_options(self):
        """Test initialization options."""
        renderer = TerminalProgressRenderer(
            show_spinner=False,
            show_bar=False,
            bar_width=20,
        )
        assert renderer._show_spinner is False
        assert renderer._show_bar is False
        assert renderer._bar_width == 20

    def test_render_simple_non_tty(self):
        """Test simple render for non-TTY output."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        renderer._is_tty = False  # Force non-TTY mode

        step = ProgressStep(name="Collection", total=100, completed=50, status="Collecting")
        progress = ScanProgress(
            phase=ProgressPhase.COLLECTING,
            steps=[step],
            current_step_index=0,
        )

        renderer.render(progress)
        result = output.getvalue()
        assert "Collecting" in result
        assert "50%" in result

    def test_build_bar(self):
        """Test progress bar building."""
        renderer = TerminalProgressRenderer(bar_width=10)
        bar = renderer._build_bar(50.0)
        assert "█" in bar
        assert "░" in bar
        assert "50%" in bar

    def test_build_bar_zero(self):
        """Test progress bar at 0%."""
        renderer = TerminalProgressRenderer(bar_width=10)
        bar = renderer._build_bar(0.0)
        assert "░" * 10 in bar

    def test_build_bar_full(self):
        """Test progress bar at 100%."""
        renderer = TerminalProgressRenderer(bar_width=10)
        bar = renderer._build_bar(100.0)
        assert "█" * 10 in bar

    def test_build_display(self):
        """Test display building."""
        renderer = TerminalProgressRenderer()
        step = ProgressStep(name="Test", total=100, completed=50, status="Working")
        progress = ScanProgress(
            phase=ProgressPhase.COLLECTING,
            steps=[step],
            current_step_index=0,
        )

        display = renderer._build_display(progress)
        assert "COLLECTING" in display
        assert "Working" in display

    def test_build_display_with_error(self):
        """Test display building with error."""
        renderer = TerminalProgressRenderer()
        progress = ScanProgress(
            phase=ProgressPhase.FAILED,
            error="Connection failed",
        )

        display = renderer._build_display(progress)
        assert "ERROR:" in display
        assert "Connection failed" in display

    def test_clear_non_tty(self):
        """Test clear for non-TTY does nothing."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        renderer._is_tty = False
        renderer.clear()
        assert output.getvalue() == ""

    def test_finish_complete(self):
        """Test finish with complete status."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        renderer._is_tty = False

        progress = ScanProgress(phase=ProgressPhase.COMPLETE)
        renderer.finish(progress)

        result = output.getvalue()
        assert "✓" in result
        assert "complete" in result

    def test_finish_failed(self):
        """Test finish with failed status."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        renderer._is_tty = False

        progress = ScanProgress(
            phase=ProgressPhase.FAILED,
            error="Test error",
        )
        renderer.finish(progress)

        result = output.getvalue()
        assert "✗" in result
        assert "failed" in result
        assert "Test error" in result

    def test_finish_stopped(self):
        """Test finish with stopped status."""
        output = io.StringIO()
        renderer = TerminalProgressRenderer(output=output)
        renderer._is_tty = False

        progress = ScanProgress(phase=ProgressPhase.COLLECTING)
        renderer.finish(progress)

        result = output.getvalue()
        assert "=" in result
        assert "stopped" in result

    def test_spinner_cycles(self):
        """Test spinner character cycling."""
        renderer = TerminalProgressRenderer()
        step = ProgressStep(name="Test")
        progress = ScanProgress(steps=[step], current_step_index=0)

        initial_index = renderer._spinner_index
        renderer._build_display(progress)
        assert renderer._spinner_index == (initial_index + 1) % len(renderer._spinner_chars)


# =============================================================================
# CallbackProgressRenderer Tests
# =============================================================================


class TestCallbackProgressRenderer:
    """Tests for CallbackProgressRenderer."""

    def test_init_no_callbacks(self):
        """Test initialization without callbacks."""
        renderer = CallbackProgressRenderer()
        assert renderer._on_update is None
        assert renderer._on_complete is None

    def test_init_with_callbacks(self):
        """Test initialization with callbacks."""
        on_update = MagicMock()
        on_complete = MagicMock()
        renderer = CallbackProgressRenderer(
            on_update=on_update,
            on_complete=on_complete,
        )
        assert renderer._on_update is on_update
        assert renderer._on_complete is on_complete

    def test_render_calls_on_update(self):
        """Test render calls on_update callback."""
        on_update = MagicMock()
        renderer = CallbackProgressRenderer(on_update=on_update)

        progress = ScanProgress()
        renderer.render(progress)

        on_update.assert_called_once_with(progress)

    def test_render_no_callback(self):
        """Test render without callback does nothing."""
        renderer = CallbackProgressRenderer()
        progress = ScanProgress()
        renderer.render(progress)  # Should not raise

    def test_clear_does_nothing(self):
        """Test clear is a no-op."""
        renderer = CallbackProgressRenderer()
        renderer.clear()  # Should not raise

    def test_finish_calls_on_complete(self):
        """Test finish calls on_complete callback."""
        on_complete = MagicMock()
        renderer = CallbackProgressRenderer(on_complete=on_complete)

        progress = ScanProgress(phase=ProgressPhase.COMPLETE)
        renderer.finish(progress)

        on_complete.assert_called_once_with(progress)

    def test_finish_no_callback(self):
        """Test finish without callback does nothing."""
        renderer = CallbackProgressRenderer()
        progress = ScanProgress()
        renderer.finish(progress)  # Should not raise


# =============================================================================
# QuietProgressRenderer Tests
# =============================================================================


class TestQuietProgressRenderer:
    """Tests for QuietProgressRenderer."""

    def test_render_does_nothing(self):
        """Test render is a no-op."""
        renderer = QuietProgressRenderer()
        progress = ScanProgress()
        renderer.render(progress)  # Should not raise

    def test_clear_does_nothing(self):
        """Test clear is a no-op."""
        renderer = QuietProgressRenderer()
        renderer.clear()  # Should not raise

    def test_finish_does_nothing(self):
        """Test finish is a no-op."""
        renderer = QuietProgressRenderer()
        progress = ScanProgress()
        renderer.finish(progress)  # Should not raise


# =============================================================================
# ProgressTracker Tests
# =============================================================================


class TestProgressTracker:
    """Tests for ProgressTracker."""

    def test_init_defaults(self):
        """Test default initialization."""
        tracker = ProgressTracker()
        assert tracker._renderers == []
        assert tracker._update_interval == 0.1
        assert tracker.progress is not None

    def test_init_with_renderers(self):
        """Test initialization with renderers."""
        renderer = QuietProgressRenderer()
        tracker = ProgressTracker(renderers=[renderer])
        assert renderer in tracker._renderers

    def test_add_renderer(self):
        """Test adding a renderer."""
        tracker = ProgressTracker()
        renderer = QuietProgressRenderer()
        tracker.add_renderer(renderer)
        assert renderer in tracker._renderers

    def test_start_initializes_progress(self):
        """Test start initializes progress."""
        tracker = ProgressTracker()
        tracker.start(["Step 1", "Step 2", "Step 3"])

        assert tracker.progress.phase == ProgressPhase.INITIALIZING
        assert len(tracker.progress.steps) == 3
        assert tracker.progress.steps[0].name == "Step 1"
        assert tracker.progress.steps[1].name == "Step 2"
        assert tracker.progress.steps[2].name == "Step 3"

    def test_start_calls_render(self):
        """Test start calls render on all renderers."""
        renderer = MagicMock(spec=ProgressRenderer)
        tracker = ProgressTracker(renderers=[renderer])
        tracker.start(["Step 1"])

        renderer.render.assert_called()

    def test_set_phase(self):
        """Test setting phase."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.set_phase(ProgressPhase.COLLECTING)

        assert tracker.progress.phase == ProgressPhase.COLLECTING

    def test_start_step(self):
        """Test starting a step."""
        tracker = ProgressTracker()
        tracker.start(["Step 1", "Step 2"])
        tracker.start_step(1, total=100, status="Processing")

        assert tracker.progress.current_step_index == 1
        step = tracker.progress.steps[1]
        assert step.total == 100
        assert step.status == "Processing"
        assert step.completed == 0

    def test_start_step_invalid_index(self):
        """Test starting step with invalid index."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.start_step(5, total=100)  # Should not raise

    def test_update_step_completed(self):
        """Test updating step with completed count."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.start_step(0, total=100)
        tracker.update_step(completed=50)

        assert tracker.progress.steps[0].completed == 50

    def test_update_step_increment(self):
        """Test updating step with increment."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.start_step(0, total=100)
        tracker.update_step(completed=10)
        tracker.update_step(increment=5)

        assert tracker.progress.steps[0].completed == 15

    def test_update_step_status(self):
        """Test updating step status."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.start_step(0, total=100)
        tracker.update_step(status="New status")

        assert tracker.progress.steps[0].status == "New status"

    def test_complete_step(self):
        """Test completing a step."""
        tracker = ProgressTracker()
        tracker.start(["Step 1", "Step 2"])
        tracker.start_step(0, total=100)
        tracker.complete_step()

        step = tracker.progress.steps[0]
        assert step.is_complete
        assert step.completed == 100

    def test_complete_step_by_index(self):
        """Test completing step by index."""
        tracker = ProgressTracker()
        tracker.start(["Step 1", "Step 2"])
        tracker.complete_step(1)

        assert tracker.progress.steps[1].is_complete

    def test_complete(self):
        """Test completing the scan."""
        renderer = MagicMock(spec=ProgressRenderer)
        tracker = ProgressTracker(renderers=[renderer])
        tracker.start(["Step 1"])
        tracker.complete()

        assert tracker.progress.phase == ProgressPhase.COMPLETE
        assert tracker.progress.completed_at is not None
        renderer.finish.assert_called_once()

    def test_fail(self):
        """Test failing the scan."""
        renderer = MagicMock(spec=ProgressRenderer)
        tracker = ProgressTracker(renderers=[renderer])
        tracker.start(["Step 1"])
        tracker.fail("Test error")

        assert tracker.progress.phase == ProgressPhase.FAILED
        assert tracker.progress.error == "Test error"
        assert tracker.progress.completed_at is not None
        renderer.finish.assert_called_once()

    def test_render_throttled(self):
        """Test render throttling."""
        renderer = MagicMock(spec=ProgressRenderer)
        tracker = ProgressTracker(renderers=[renderer], update_interval=1.0)
        tracker.start(["Step 1"])
        tracker.start_step(0, total=100)

        # Reset mock after start
        renderer.render.reset_mock()

        # Rapid updates should be throttled
        for i in range(10):
            tracker.update_step(increment=1)

        # Should have been throttled (fewer than 10 calls)
        assert renderer.render.call_count < 10

    def test_render_error_handling(self):
        """Test render error handling."""
        renderer = MagicMock(spec=ProgressRenderer)
        renderer.render.side_effect = Exception("Render error")
        tracker = ProgressTracker(renderers=[renderer])

        # Should not raise even though renderer throws
        tracker.start(["Step 1"])

    def test_finish_error_handling(self):
        """Test finish error handling."""
        renderer = MagicMock(spec=ProgressRenderer)
        renderer.finish.side_effect = Exception("Finish error")
        tracker = ProgressTracker(renderers=[renderer])
        tracker.start(["Step 1"])

        # Should not raise even though renderer throws
        tracker.complete()

    def test_thread_safety(self):
        """Test thread-safe updates."""
        tracker = ProgressTracker()
        tracker.start(["Step 1"])
        tracker.start_step(0, total=1000)

        errors = []

        def update_thread():
            try:
                for _ in range(100):
                    tracker.update_step(increment=1)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=update_thread) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        # All increments should have been applied
        assert tracker.progress.steps[0].completed == 500


# =============================================================================
# create_progress_tracker Tests
# =============================================================================


class TestCreateProgressTracker:
    """Tests for create_progress_tracker factory function."""

    def test_default_creates_terminal_renderer(self):
        """Test default creates terminal renderer."""
        tracker = create_progress_tracker()
        assert len(tracker._renderers) == 1
        assert isinstance(tracker._renderers[0], TerminalProgressRenderer)

    def test_quiet_creates_quiet_renderer(self):
        """Test quiet mode creates quiet renderer."""
        tracker = create_progress_tracker(quiet=True)
        assert len(tracker._renderers) == 1
        assert isinstance(tracker._renderers[0], QuietProgressRenderer)

    def test_callback_creates_callback_renderer(self):
        """Test callback creates callback renderer."""
        callback = MagicMock()
        tracker = create_progress_tracker(callback=callback)

        # Should have terminal + callback
        assert len(tracker._renderers) == 2
        assert isinstance(tracker._renderers[0], TerminalProgressRenderer)
        assert isinstance(tracker._renderers[1], CallbackProgressRenderer)

    def test_quiet_with_callback(self):
        """Test quiet mode with callback."""
        callback = MagicMock()
        tracker = create_progress_tracker(quiet=True, callback=callback)

        # Should only have callback (no terminal, no quiet)
        assert len(tracker._renderers) == 1
        assert isinstance(tracker._renderers[0], CallbackProgressRenderer)


# =============================================================================
# Integration Tests
# =============================================================================


class TestProgressIntegration:
    """Integration tests for progress tracking."""

    def test_full_scan_progress_flow(self):
        """Test full scan progress flow."""
        updates = []

        def on_update(progress: ScanProgress):
            updates.append(progress.to_dict())

        tracker = create_progress_tracker(quiet=True, callback=on_update)

        # Simulate a scan
        tracker.start(["Collection", "Evaluation", "Storage"])

        # Collection phase
        tracker.set_phase(ProgressPhase.COLLECTING)
        tracker.start_step(0, total=10, status="Collecting assets")
        for i in range(10):
            tracker.update_step(increment=1, status=f"Collected {i+1}/10")
        tracker.complete_step()

        # Evaluation phase
        tracker.set_phase(ProgressPhase.EVALUATING)
        tracker.start_step(1, total=5, status="Evaluating policies")
        for i in range(5):
            tracker.update_step(increment=1)
        tracker.complete_step()

        # Storage phase
        tracker.set_phase(ProgressPhase.STORING)
        tracker.start_step(2, status="Storing results")
        tracker.complete_step()

        # Complete
        tracker.complete()

        # Verify final state
        assert tracker.progress.phase == ProgressPhase.COMPLETE
        assert tracker.progress.is_complete
        assert len(updates) > 0

    def test_failed_scan_flow(self):
        """Test failed scan flow."""
        tracker = create_progress_tracker(quiet=True)

        tracker.start(["Collection", "Evaluation"])
        tracker.set_phase(ProgressPhase.COLLECTING)
        tracker.start_step(0, total=10)
        tracker.update_step(completed=5)

        # Simulate failure
        tracker.fail("Connection timeout")

        assert tracker.progress.phase == ProgressPhase.FAILED
        assert tracker.progress.error == "Connection timeout"
        assert tracker.progress.is_complete

    def test_progress_percentage_accuracy(self):
        """Test progress percentage accuracy."""
        tracker = ProgressTracker()
        tracker.start(["Step 1", "Step 2", "Step 3", "Step 4"])

        # Complete first step
        tracker.start_step(0, total=100)
        tracker.update_step(completed=100)
        tracker.complete_step()

        # 25% complete
        assert tracker.progress.overall_percent == 25.0

        # Complete second step
        tracker.start_step(1, total=100)
        tracker.update_step(completed=100)
        tracker.complete_step()

        # 50% complete
        assert tracker.progress.overall_percent == 50.0

        # Third step at 50%
        tracker.start_step(2, total=100)
        tracker.update_step(completed=50)

        # 50% + (50% of 25%) = 62.5%
        assert tracker.progress.overall_percent == 62.5

    def test_multiple_renderers(self):
        """Test multiple renderers receive updates."""
        output1 = io.StringIO()
        output2 = io.StringIO()
        callback_updates = []

        renderer1 = TerminalProgressRenderer(output=output1)
        renderer1._is_tty = False
        renderer2 = TerminalProgressRenderer(output=output2)
        renderer2._is_tty = False
        renderer3 = CallbackProgressRenderer(
            on_update=lambda p: callback_updates.append(p)
        )

        tracker = ProgressTracker(renderers=[renderer1, renderer2, renderer3])
        tracker.start(["Test Step"])
        tracker.start_step(0, total=100, status="Working")
        tracker.update_step(completed=50)

        # All renderers should have received updates
        assert len(output1.getvalue()) > 0
        assert len(output2.getvalue()) > 0
        assert len(callback_updates) > 0
