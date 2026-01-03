"""
Unit tests for the Mantissa Stance web aggregation module.

Tests dashboard data aggregation from scheduling, scanning, and reporting.
"""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.web.aggregation import (
    DashboardAggregation,
    DashboardAggregator,
    MultiAccountSummary,
    SchedulerStatus,
    ScanHistorySummary,
    TrendSummary,
    create_aggregator,
)
from stance.scheduling import (
    ScanScheduler,
    ScanHistoryManager,
    ScanHistoryEntry,
    ScanJob,
    ScanResult,
    CronExpression,
)
from stance.reporting import TrendAnalyzer, TrendReport, TrendDirection, TrendMetrics


class TestSchedulerStatus:
    """Tests for SchedulerStatus dataclass."""

    def test_default_status(self):
        """Test default scheduler status."""
        status = SchedulerStatus()

        assert status.is_running is False
        assert status.total_jobs == 0
        assert status.enabled_jobs == 0

    def test_status_with_values(self):
        """Test scheduler status with values."""
        status = SchedulerStatus(
            is_running=True,
            total_jobs=5,
            enabled_jobs=3,
            pending_jobs=1,
            last_run=datetime(2025, 1, 1, 12, 0, 0),
            next_run=datetime(2025, 1, 1, 13, 0, 0),
        )

        assert status.is_running is True
        assert status.total_jobs == 5
        assert status.pending_jobs == 1

    def test_status_to_dict(self):
        """Test converting status to dictionary."""
        status = SchedulerStatus(
            is_running=True,
            total_jobs=3,
            last_run=datetime(2025, 1, 1, 12, 0, 0),
        )

        result = status.to_dict()

        assert result["is_running"] is True
        assert result["total_jobs"] == 3
        assert result["last_run"] is not None


class TestScanHistorySummary:
    """Tests for ScanHistorySummary dataclass."""

    def test_default_summary(self):
        """Test default history summary."""
        summary = ScanHistorySummary()

        assert summary.total_scans == 0
        assert summary.scans_last_24h == 0
        assert summary.average_duration == 0.0

    def test_summary_with_values(self):
        """Test history summary with values."""
        summary = ScanHistorySummary(
            total_scans=100,
            scans_last_24h=5,
            scans_last_7d=35,
            average_duration=120.5,
            average_findings=25.3,
        )

        assert summary.total_scans == 100
        assert summary.average_findings == 25.3

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        summary = ScanHistorySummary(
            total_scans=50,
            average_duration=99.999,
        )

        result = summary.to_dict()

        assert result["total_scans"] == 50
        assert result["average_duration"] == 100.0  # Rounded


class TestTrendSummary:
    """Tests for TrendSummary dataclass."""

    def test_default_summary(self):
        """Test default trend summary."""
        summary = TrendSummary()

        assert summary.direction == "stable"
        assert summary.is_improving is False

    def test_summary_improving(self):
        """Test trend summary when improving."""
        summary = TrendSummary(
            direction="improving",
            findings_change=-10,
            findings_change_percent=-15.5,
            is_improving=True,
        )

        assert summary.direction == "improving"
        assert summary.findings_change == -10
        assert summary.is_improving is True

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        summary = TrendSummary(
            direction="declining",
            findings_change_percent=20.123,
            recommendations=["Fix critical findings"],
        )

        result = summary.to_dict()

        assert result["direction"] == "declining"
        assert result["findings_change_percent"] == 20.12
        assert len(result["recommendations"]) == 1


class TestMultiAccountSummary:
    """Tests for MultiAccountSummary dataclass."""

    def test_default_summary(self):
        """Test default multi-account summary."""
        summary = MultiAccountSummary()

        assert summary.total_accounts == 0
        assert summary.accounts_by_provider == {}

    def test_summary_with_values(self):
        """Test multi-account summary with values."""
        summary = MultiAccountSummary(
            total_accounts=10,
            accounts_by_provider={"aws": 5, "gcp": 3, "azure": 2},
            accounts_with_findings=7,
            total_findings=150,
        )

        assert summary.total_accounts == 10
        assert summary.accounts_by_provider["aws"] == 5

    def test_summary_to_dict(self):
        """Test converting summary to dictionary."""
        summary = MultiAccountSummary(
            total_accounts=5,
            accounts_by_provider={"aws": 5},
        )

        result = summary.to_dict()

        assert result["total_accounts"] == 5
        assert "aws" in result["accounts_by_provider"]


class TestDashboardAggregation:
    """Tests for DashboardAggregation dataclass."""

    def test_default_aggregation(self):
        """Test default dashboard aggregation."""
        agg = DashboardAggregation()

        assert agg.generated_at is not None
        assert isinstance(agg.scheduler, SchedulerStatus)
        assert isinstance(agg.history, ScanHistorySummary)
        assert isinstance(agg.trends, TrendSummary)
        assert isinstance(agg.multi_account, MultiAccountSummary)

    def test_aggregation_to_dict(self):
        """Test converting aggregation to dictionary."""
        agg = DashboardAggregation(
            scheduler=SchedulerStatus(is_running=True),
            history=ScanHistorySummary(total_scans=100),
            trends=TrendSummary(direction="improving"),
        )

        result = agg.to_dict()

        assert "generated_at" in result
        assert result["scheduler"]["is_running"] is True
        assert result["history"]["total_scans"] == 100
        assert result["trends"]["direction"] == "improving"


class TestDashboardAggregator:
    """Tests for DashboardAggregator class."""

    @pytest.fixture
    def aggregator(self):
        """Create a basic aggregator."""
        return DashboardAggregator()

    @pytest.fixture
    def mock_scheduler(self):
        """Create a mock scheduler."""
        scheduler = MagicMock(spec=ScanScheduler)
        scheduler.get_status.return_value = {"running": True}
        scheduler.get_jobs.return_value = []
        scheduler.get_enabled_jobs.return_value = []
        scheduler.get_pending_jobs.return_value = []
        return scheduler

    @pytest.fixture
    def mock_history_manager(self):
        """Create a mock history manager."""
        manager = MagicMock(spec=ScanHistoryManager)
        manager.get_history.return_value = []
        return manager

    @pytest.fixture
    def mock_trend_analyzer(self):
        """Create a mock trend analyzer."""
        analyzer = MagicMock(spec=TrendAnalyzer)
        mock_report = MagicMock(spec=TrendReport)
        mock_report.total_findings = TrendMetrics(
            current_value=50,
            previous_value=60,
            average=55,
            min_value=40,
            max_value=70,
            change=-10,
            change_percent=-16.67,
            direction=TrendDirection.IMPROVING,
            data_points=10,
        )
        mock_report.is_improving = True
        mock_report.severity_trends = {}
        mock_report.recommendations = []
        analyzer.analyze.return_value = mock_report
        return analyzer

    def test_aggregator_initialization(self, aggregator):
        """Test aggregator initialization."""
        assert aggregator._scheduler is None
        assert aggregator._history_manager is None

    def test_set_scheduler(self, aggregator, mock_scheduler):
        """Test setting scheduler."""
        aggregator.set_scheduler(mock_scheduler)
        assert aggregator._scheduler is mock_scheduler

    def test_set_history_manager(self, aggregator, mock_history_manager):
        """Test setting history manager."""
        aggregator.set_history_manager(mock_history_manager)
        assert aggregator._history_manager is mock_history_manager

    def test_set_trend_analyzer(self, aggregator, mock_trend_analyzer):
        """Test setting trend analyzer."""
        aggregator.set_trend_analyzer(mock_trend_analyzer)
        assert aggregator._trend_analyzer is mock_trend_analyzer

    def test_get_scheduler_status_no_scheduler(self, aggregator):
        """Test getting scheduler status without scheduler."""
        status = aggregator.get_scheduler_status()

        assert status.is_running is False
        assert status.total_jobs == 0

    def test_get_scheduler_status_with_scheduler(
        self, aggregator, mock_scheduler
    ):
        """Test getting scheduler status with scheduler."""
        now = datetime.utcnow()
        mock_job = MagicMock(spec=ScanJob)
        mock_job.id = "job-1"
        mock_job.name = "Daily Scan"
        mock_job.schedule = CronExpression("0 0 * * *")
        mock_job.enabled = True
        mock_job.last_run = now - timedelta(hours=1)
        mock_job.next_run = now + timedelta(hours=23)
        mock_job.run_count = 5

        mock_scheduler.get_jobs.return_value = [mock_job]
        mock_scheduler.get_enabled_jobs.return_value = [mock_job]
        mock_scheduler.get_pending_jobs.return_value = []

        aggregator.set_scheduler(mock_scheduler)
        status = aggregator.get_scheduler_status()

        assert status.is_running is True
        assert status.total_jobs == 1
        assert status.enabled_jobs == 1
        assert len(status.jobs) == 1

    def test_get_history_summary_no_manager(self, aggregator):
        """Test getting history summary without manager."""
        summary = aggregator.get_history_summary()

        assert summary.total_scans == 0

    def test_get_history_summary_with_manager(
        self, aggregator, mock_history_manager
    ):
        """Test getting history summary with manager."""
        now = datetime.utcnow()
        entries = [
            ScanHistoryEntry(
                scan_id=f"scan-{i}",
                timestamp=now - timedelta(hours=i),
                duration_seconds=300 + i * 10,
                findings_total=50 + i,
            )
            for i in range(5)
        ]
        mock_history_manager.get_history.return_value = entries

        aggregator.set_history_manager(mock_history_manager)
        summary = aggregator.get_history_summary()

        assert summary.total_scans == 5
        assert summary.scans_last_24h == 5
        assert summary.latest_scan is not None

    def test_get_trend_summary_no_analyzer(self, aggregator):
        """Test getting trend summary without analyzer."""
        summary = aggregator.get_trend_summary()

        assert summary.direction == "stable"

    def test_get_trend_summary_with_analyzer(
        self, aggregator, mock_trend_analyzer
    ):
        """Test getting trend summary with analyzer."""
        aggregator.set_trend_analyzer(mock_trend_analyzer)
        summary = aggregator.get_trend_summary()

        assert summary.direction == "improving"
        assert summary.is_improving is True
        assert summary.findings_change == -10

    def test_get_multi_account_summary_no_scanner(self, aggregator):
        """Test getting multi-account summary without scanner."""
        summary = aggregator.get_multi_account_summary()

        assert summary.total_accounts == 0

    def test_get_aggregation(
        self,
        aggregator,
        mock_scheduler,
        mock_history_manager,
        mock_trend_analyzer,
    ):
        """Test getting complete aggregation."""
        aggregator.set_scheduler(mock_scheduler)
        aggregator.set_history_manager(mock_history_manager)
        aggregator.set_trend_analyzer(mock_trend_analyzer)

        agg = aggregator.get_aggregation()

        assert agg.generated_at is not None
        assert agg.scheduler.is_running is True

    def test_get_forecast_no_analyzer(self, aggregator):
        """Test getting forecast without analyzer."""
        result = aggregator.get_forecast()

        assert "error" in result

    def test_get_forecast_with_analyzer(self, aggregator, mock_trend_analyzer):
        """Test getting forecast with analyzer."""
        mock_trend_analyzer.forecast.return_value = {
            "forecasts": [],
            "trend_slope": -1.5,
        }

        aggregator.set_trend_analyzer(mock_trend_analyzer)
        result = aggregator.get_forecast()

        assert "trend_slope" in result

    def test_get_period_comparison_no_analyzer(self, aggregator):
        """Test getting period comparison without analyzer."""
        result = aggregator.get_period_comparison()

        assert "error" in result

    def test_get_period_comparison_with_analyzer(
        self, aggregator, mock_trend_analyzer
    ):
        """Test getting period comparison with analyzer."""
        mock_trend_analyzer.compare_periods.return_value = {
            "current_period": {},
            "previous_period": {},
            "comparison": {},
        }

        aggregator.set_trend_analyzer(mock_trend_analyzer)
        result = aggregator.get_period_comparison()

        assert "current_period" in result
        assert "comparison" in result

    def test_get_velocity_metrics_no_analyzer(self, aggregator):
        """Test getting velocity metrics without analyzer."""
        result = aggregator.get_velocity_metrics()

        assert "error" in result

    def test_get_velocity_metrics_with_analyzer(
        self, aggregator, mock_trend_analyzer
    ):
        """Test getting velocity metrics with analyzer."""
        mock_trend_analyzer.get_findings_velocity.return_value = {
            "total": -2.5,
            "critical": -0.5,
        }

        aggregator.set_trend_analyzer(mock_trend_analyzer)
        result = aggregator.get_velocity_metrics()

        assert "total" in result


class TestCreateAggregator:
    """Tests for create_aggregator function."""

    def test_create_aggregator(self):
        """Test creating aggregator with defaults."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aggregator = create_aggregator(history_path=tmpdir)

            assert aggregator._history_manager is not None
            assert aggregator._trend_analyzer is not None

    def test_aggregator_components_linked(self):
        """Test that aggregator components are properly linked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            aggregator = create_aggregator(history_path=tmpdir)

            # History manager and trend analyzer should be linked
            assert aggregator._trend_analyzer.history_manager is aggregator._history_manager


class TestAggregatorIntegration:
    """Integration tests for DashboardAggregator."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_full_aggregation_workflow(self, temp_storage):
        """Test complete aggregation workflow."""
        # Create real components
        history_manager = ScanHistoryManager(storage_path=temp_storage)
        trend_analyzer = TrendAnalyzer(history_manager=history_manager)

        # Record some scan history
        from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity

        for i in range(5):
            findings = FindingCollection(
                findings=[
                    Finding(
                        id=f"finding-{i}",
                        asset_id=f"asset-{i}",
                        finding_type=FindingType.MISCONFIGURATION,
                        title=f"Finding {i}",
                        description=f"Description {i}",
                        severity=Severity.HIGH,
                        status=FindingStatus.OPEN,
                    )
                ]
            )

            history_manager.record_scan(
                scan_id=f"scan-{i}",
                findings=findings,
                config_name="default",
                duration_seconds=100 + i * 10,
                assets_scanned=50 + i,
            )

        # Create aggregator
        aggregator = DashboardAggregator(
            history_manager=history_manager,
            trend_analyzer=trend_analyzer,
        )

        # Get aggregation
        agg = aggregator.get_aggregation()

        # Verify results
        assert agg.history.total_scans == 5
        assert agg.history.latest_scan is not None
        assert agg.trends.period_days == 7

    def test_aggregation_with_empty_history(self, temp_storage):
        """Test aggregation with no scan history."""
        history_manager = ScanHistoryManager(storage_path=temp_storage)
        trend_analyzer = TrendAnalyzer(history_manager=history_manager)

        aggregator = DashboardAggregator(
            history_manager=history_manager,
            trend_analyzer=trend_analyzer,
        )

        agg = aggregator.get_aggregation()

        assert agg.history.total_scans == 0
        assert agg.history.latest_scan is None
