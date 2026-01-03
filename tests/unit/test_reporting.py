"""
Unit tests for the Mantissa Stance reporting module.

Tests trend analysis, metrics calculation, and report generation.
"""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.reporting import (
    ComplianceTrend,
    SeverityTrend,
    TrendAnalyzer,
    TrendDirection,
    TrendMetrics,
    TrendPeriod,
    TrendReport,
)
from stance.scheduling.history import ScanHistoryEntry, ScanHistoryManager


class TestTrendMetrics:
    """Tests for TrendMetrics dataclass."""

    def test_create_metrics(self):
        """Test creating trend metrics."""
        metrics = TrendMetrics(
            current_value=100,
            previous_value=120,
            average=110,
            min_value=90,
            max_value=130,
            change=-20,
            change_percent=-16.67,
            direction=TrendDirection.IMPROVING,
            data_points=10,
            velocity=-2.0,
        )

        assert metrics.current_value == 100
        assert metrics.previous_value == 120
        assert metrics.change == -20
        assert metrics.direction == TrendDirection.IMPROVING

    def test_metrics_to_dict(self):
        """Test converting metrics to dictionary."""
        metrics = TrendMetrics(
            current_value=50,
            previous_value=60,
            average=55,
            min_value=40,
            max_value=70,
            change=-10,
            change_percent=-16.67,
            direction=TrendDirection.IMPROVING,
            data_points=5,
            velocity=-1.5,
        )

        result = metrics.to_dict()

        assert result["current_value"] == 50
        assert result["previous_value"] == 60
        assert result["direction"] == "improving"
        assert result["data_points"] == 5

    def test_metrics_rounding(self):
        """Test that metrics are properly rounded."""
        metrics = TrendMetrics(
            current_value=100,
            previous_value=99,
            average=99.12345678,
            min_value=90,
            max_value=110,
            change=1,
            change_percent=1.01010101,
            direction=TrendDirection.STABLE,
            data_points=5,
            velocity=0.123456789,
        )

        result = metrics.to_dict()

        assert result["average"] == 99.12
        assert result["change_percent"] == 1.01
        assert result["velocity"] == 0.1235


class TestSeverityTrend:
    """Tests for SeverityTrend dataclass."""

    def test_create_severity_trend(self):
        """Test creating a severity trend."""
        metrics = TrendMetrics(
            current_value=5,
            previous_value=8,
            average=6.5,
            min_value=4,
            max_value=10,
            change=-3,
            change_percent=-37.5,
            direction=TrendDirection.IMPROVING,
            data_points=10,
        )

        trend = SeverityTrend(
            severity="critical",
            metrics=metrics,
            history=[
                {"timestamp": "2025-01-01T00:00:00", "value": 8},
                {"timestamp": "2025-01-02T00:00:00", "value": 5},
            ],
        )

        assert trend.severity == "critical"
        assert trend.metrics.current_value == 5
        assert len(trend.history) == 2

    def test_severity_trend_to_dict(self):
        """Test converting severity trend to dictionary."""
        metrics = TrendMetrics(
            current_value=10,
            previous_value=12,
            average=11,
            min_value=8,
            max_value=15,
            change=-2,
            change_percent=-16.67,
            direction=TrendDirection.IMPROVING,
            data_points=5,
        )

        trend = SeverityTrend(severity="high", metrics=metrics)
        result = trend.to_dict()

        assert result["severity"] == "high"
        assert "metrics" in result
        assert result["history"] == []


class TestComplianceTrend:
    """Tests for ComplianceTrend dataclass."""

    def test_create_compliance_trend(self):
        """Test creating a compliance trend."""
        metrics = TrendMetrics(
            current_value=85,
            previous_value=80,
            average=82.5,
            min_value=75,
            max_value=85,
            change=5,
            change_percent=6.25,
            direction=TrendDirection.IMPROVING,
            data_points=10,
        )

        trend = ComplianceTrend(
            framework="CIS",
            metrics=metrics,
            current_score=85.0,
            target_score=95.0,
        )

        assert trend.framework == "CIS"
        assert trend.current_score == 85.0
        assert trend.gap == 10.0

    def test_compliance_gap_calculation(self):
        """Test that gap is calculated correctly."""
        metrics = TrendMetrics(
            current_value=70,
            previous_value=65,
            average=67.5,
            min_value=60,
            max_value=70,
            change=5,
            change_percent=7.69,
            direction=TrendDirection.IMPROVING,
            data_points=5,
        )

        trend = ComplianceTrend(
            framework="SOC2",
            metrics=metrics,
            current_score=70.0,
            target_score=100.0,
        )

        assert trend.gap == 30.0

    def test_compliance_trend_to_dict(self):
        """Test converting compliance trend to dictionary."""
        metrics = TrendMetrics(
            current_value=90,
            previous_value=88,
            average=89,
            min_value=85,
            max_value=90,
            change=2,
            change_percent=2.27,
            direction=TrendDirection.IMPROVING,
            data_points=5,
        )

        trend = ComplianceTrend(
            framework="PCI-DSS",
            metrics=metrics,
            current_score=90.0,
        )

        result = trend.to_dict()

        assert result["framework"] == "PCI-DSS"
        assert result["current_score"] == 90.0
        assert result["gap"] == 10.0


class TestTrendReport:
    """Tests for TrendReport dataclass."""

    def test_create_trend_report(self):
        """Test creating a trend report."""
        metrics = TrendMetrics(
            current_value=50,
            previous_value=60,
            average=55,
            min_value=45,
            max_value=65,
            change=-10,
            change_percent=-16.67,
            direction=TrendDirection.IMPROVING,
            data_points=10,
        )

        report = TrendReport(
            report_id="test-123",
            generated_at=datetime.utcnow(),
            period=TrendPeriod.DAILY,
            days_analyzed=30,
            total_findings=metrics,
        )

        assert report.report_id == "test-123"
        assert report.period == TrendPeriod.DAILY
        assert report.days_analyzed == 30

    def test_report_overall_direction(self):
        """Test overall direction property."""
        metrics = TrendMetrics(
            current_value=40,
            previous_value=50,
            average=45,
            min_value=35,
            max_value=55,
            change=-10,
            change_percent=-20,
            direction=TrendDirection.IMPROVING,
            data_points=5,
        )

        report = TrendReport(
            report_id="test-456",
            generated_at=datetime.utcnow(),
            period=TrendPeriod.WEEKLY,
            days_analyzed=7,
            total_findings=metrics,
        )

        assert report.overall_direction == TrendDirection.IMPROVING
        assert report.is_improving is True

    def test_report_critical_severity_change(self):
        """Test critical severity change property."""
        total_metrics = TrendMetrics(
            current_value=100,
            previous_value=100,
            average=100,
            min_value=100,
            max_value=100,
            change=0,
            change_percent=0,
            direction=TrendDirection.STABLE,
            data_points=5,
        )

        critical_metrics = TrendMetrics(
            current_value=5,
            previous_value=10,
            average=7.5,
            min_value=5,
            max_value=10,
            change=-5,
            change_percent=-50,
            direction=TrendDirection.IMPROVING,
            data_points=5,
        )

        report = TrendReport(
            report_id="test-789",
            generated_at=datetime.utcnow(),
            period=TrendPeriod.DAILY,
            days_analyzed=7,
            total_findings=total_metrics,
            severity_trends={
                "critical": SeverityTrend(severity="critical", metrics=critical_metrics)
            },
        )

        assert report.critical_severity_change == -5

    def test_report_to_dict(self):
        """Test converting report to dictionary."""
        metrics = TrendMetrics(
            current_value=100,
            previous_value=110,
            average=105,
            min_value=95,
            max_value=115,
            change=-10,
            change_percent=-9.09,
            direction=TrendDirection.IMPROVING,
            data_points=10,
        )

        report = TrendReport(
            report_id="test-dict",
            generated_at=datetime(2025, 1, 1, 12, 0, 0),
            period=TrendPeriod.MONTHLY,
            days_analyzed=30,
            total_findings=metrics,
            recommendations=["Test recommendation"],
        )

        result = report.to_dict()

        assert result["report_id"] == "test-dict"
        assert result["period"] == "monthly"
        assert result["days_analyzed"] == 30
        assert len(result["recommendations"]) == 1


class TestTrendAnalyzer:
    """Tests for TrendAnalyzer class."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def analyzer(self, temp_storage):
        """Create analyzer with temporary storage."""
        return TrendAnalyzer(storage_path=temp_storage)

    @pytest.fixture
    def sample_entries(self):
        """Create sample history entries."""
        base_time = datetime.utcnow()
        entries = []

        for i in range(10):
            entries.append(
                ScanHistoryEntry(
                    scan_id=f"scan-{i}",
                    timestamp=base_time - timedelta(days=10 - i),
                    config_name="default",
                    duration_seconds=300,
                    assets_scanned=100 + i * 5,
                    findings_total=50 - i * 3,  # Decreasing (improving)
                    findings_by_severity={
                        "critical": max(0, 5 - i),
                        "high": max(0, 10 - i),
                        "medium": 15,
                        "low": 10,
                        "info": 10 - i,
                    },
                )
            )

        return entries

    def test_analyzer_initialization(self, temp_storage):
        """Test analyzer initialization."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        assert analyzer.history_manager is not None

    def test_analyzer_with_history_manager(self, temp_storage):
        """Test analyzer with provided history manager."""
        manager = ScanHistoryManager(storage_path=temp_storage)
        analyzer = TrendAnalyzer(history_manager=manager)
        assert analyzer.history_manager is manager

    def test_analyze_from_entries(self, analyzer, sample_entries):
        """Test analyzing from entry list."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert report.report_id is not None
        assert report.period == TrendPeriod.DAILY
        assert report.days_analyzed >= 9
        assert report.total_findings.direction == TrendDirection.IMPROVING

    def test_analyze_from_entries_empty(self, analyzer):
        """Test analyzing with no entries."""
        report = analyzer.analyze_from_entries([])

        assert report.total_findings.direction == TrendDirection.INSUFFICIENT_DATA
        assert "error" in report.summary

    def test_calculate_findings_trend(self, analyzer, sample_entries):
        """Test findings trend calculation."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert report.total_findings.current_value < report.total_findings.previous_value
        assert report.total_findings.change < 0

    def test_calculate_severity_trends(self, analyzer, sample_entries):
        """Test severity trends calculation."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert "critical" in report.severity_trends
        assert "high" in report.severity_trends
        assert "medium" in report.severity_trends

    def test_calculate_assets_trend(self, analyzer, sample_entries):
        """Test assets trend calculation."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert report.assets_trend is not None
        # Assets are increasing which shows growth, velocity should be positive
        assert report.assets_trend.velocity > 0

    def test_scan_frequency_calculation(self, analyzer, sample_entries):
        """Test scan frequency calculation."""
        report = analyzer.analyze_from_entries(sample_entries)

        # 10 scans over ~10 days = ~1 scan/day
        assert report.scan_frequency > 0

    def test_get_findings_velocity(self, analyzer, temp_storage):
        """Test findings velocity calculation."""
        # Create manager with entries
        manager = ScanHistoryManager(storage_path=temp_storage)

        # Mock the get_history method - entries within the date range
        base_time = datetime.utcnow()
        mock_entries = [
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=6),  # Within 7 day range
                findings_total=100,
                findings_by_severity={"critical": 10, "high": 20},
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time - timedelta(days=1),  # Recent
                findings_total=70,
                findings_by_severity={"critical": 5, "high": 15},
            ),
        ]

        analyzer = TrendAnalyzer(history_manager=manager)
        with patch.object(analyzer, "_get_recent_history", return_value=mock_entries):
            velocities = analyzer.get_findings_velocity(days=7)

            assert "total" in velocities
            assert velocities["total"] < 0  # Decreasing findings

    def test_get_improvement_rate(self, analyzer, temp_storage):
        """Test improvement rate calculation."""
        manager = ScanHistoryManager(storage_path=temp_storage)

        base_time = datetime.utcnow()
        mock_entries = [
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=6),  # Within range
                findings_total=100,
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time - timedelta(days=1),  # Recent
                findings_total=80,
            ),
        ]

        analyzer = TrendAnalyzer(history_manager=manager)
        with patch.object(analyzer, "_get_recent_history", return_value=mock_entries):
            rate = analyzer.get_improvement_rate(days=7)

            assert rate == 20.0  # 20% improvement

    def test_compare_periods(self, analyzer, temp_storage):
        """Test period comparison."""
        manager = ScanHistoryManager(storage_path=temp_storage)

        base_time = datetime.utcnow()
        mock_entries = [
            # Previous period
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=10),
                findings_total=100,
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time - timedelta(days=8),
                findings_total=95,
            ),
            # Current period
            ScanHistoryEntry(
                scan_id="scan-3",
                timestamp=base_time - timedelta(days=3),
                findings_total=80,
            ),
            ScanHistoryEntry(
                scan_id="scan-4",
                timestamp=base_time - timedelta(days=1),
                findings_total=75,
            ),
        ]

        with patch.object(manager, "get_history", return_value=mock_entries):
            analyzer = TrendAnalyzer(history_manager=manager)
            comparison = analyzer.compare_periods(current_days=7, previous_days=7)

            assert "current_period" in comparison
            assert "previous_period" in comparison
            assert "comparison" in comparison

    def test_forecast(self, analyzer, temp_storage):
        """Test forecasting."""
        manager = ScanHistoryManager(storage_path=temp_storage)

        base_time = datetime.utcnow()
        mock_entries = [
            ScanHistoryEntry(
                scan_id=f"scan-{i}",
                timestamp=base_time - timedelta(days=30 - i),
                findings_total=100 - i * 2,  # Linear decrease
            )
            for i in range(30)
        ]

        with patch.object(manager, "get_history", return_value=mock_entries):
            analyzer = TrendAnalyzer(history_manager=manager)
            forecast = analyzer.forecast(days_history=30, days_forecast=7)

            assert "forecasts" in forecast
            assert len(forecast["forecasts"]) == 7
            assert forecast["trend_direction"] == "improving"

    def test_forecast_insufficient_data(self, analyzer, temp_storage):
        """Test forecasting with insufficient data."""
        manager = ScanHistoryManager(storage_path=temp_storage)

        with patch.object(manager, "get_history", return_value=[]):
            analyzer = TrendAnalyzer(history_manager=manager)
            forecast = analyzer.forecast(days_history=30, days_forecast=7)

            assert "error" in forecast

    def test_recommendations_generated(self, analyzer, sample_entries):
        """Test that recommendations are generated."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert len(report.recommendations) > 0

    def test_summary_generated(self, analyzer, sample_entries):
        """Test that summary is generated."""
        report = analyzer.analyze_from_entries(sample_entries)

        assert "overall_direction" in report.summary
        assert "total_scans" in report.summary


class TestTrendAnalyzerEdgeCases:
    """Edge case tests for TrendAnalyzer."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_single_entry(self, temp_storage):
        """Test with single history entry."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        entries = [
            ScanHistoryEntry(
                scan_id="single",
                timestamp=datetime.utcnow(),
                findings_total=50,
            )
        ]

        report = analyzer.analyze_from_entries(entries)

        assert report.total_findings.data_points == 1
        assert report.total_findings.change == 0

    def test_identical_values(self, temp_storage):
        """Test with all identical values."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        base_time = datetime.utcnow()

        entries = [
            ScanHistoryEntry(
                scan_id=f"scan-{i}",
                timestamp=base_time - timedelta(days=5 - i),
                findings_total=100,
                findings_by_severity={"critical": 10, "high": 20},
            )
            for i in range(5)
        ]

        report = analyzer.analyze_from_entries(entries)

        assert report.total_findings.direction == TrendDirection.STABLE
        assert report.total_findings.change == 0

    def test_zero_to_nonzero(self, temp_storage):
        """Test transition from zero to non-zero."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        base_time = datetime.utcnow()

        entries = [
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=1),
                findings_total=0,
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time,
                findings_total=10,
            ),
        ]

        report = analyzer.analyze_from_entries(entries)

        assert report.total_findings.direction == TrendDirection.DECLINING

    def test_nonzero_to_zero(self, temp_storage):
        """Test transition from non-zero to zero."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        base_time = datetime.utcnow()

        entries = [
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=1),
                findings_total=10,
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time,
                findings_total=0,
            ),
        ]

        report = analyzer.analyze_from_entries(entries)

        assert report.total_findings.direction == TrendDirection.IMPROVING

    def test_negative_velocity(self, temp_storage):
        """Test negative velocity (improving)."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)
        base_time = datetime.utcnow()

        entries = [
            ScanHistoryEntry(
                scan_id=f"scan-{i}",
                timestamp=base_time - timedelta(days=10 - i),
                findings_total=100 - i * 10,
            )
            for i in range(10)
        ]

        report = analyzer.analyze_from_entries(entries)

        assert report.total_findings.velocity < 0

    def test_compliance_trends(self, temp_storage):
        """Test compliance trend calculation."""
        analyzer = TrendAnalyzer(storage_path=temp_storage)

        compliance_scores = {
            "CIS": [
                {"timestamp": "2025-01-01", "score": 70},
                {"timestamp": "2025-01-15", "score": 75},
                {"timestamp": "2025-02-01", "score": 80},
            ],
            "SOC2": [
                {"timestamp": "2025-01-01", "score": 60},
                {"timestamp": "2025-02-01", "score": 65},
            ],
        }

        base_time = datetime.utcnow()
        entries = [
            ScanHistoryEntry(
                scan_id="scan-1",
                timestamp=base_time - timedelta(days=30),
                findings_total=100,
            ),
            ScanHistoryEntry(
                scan_id="scan-2",
                timestamp=base_time,
                findings_total=80,
            ),
        ]

        report = analyzer.analyze_from_entries(entries)
        # Manually add compliance trends for testing
        report.compliance_trends = analyzer._calculate_compliance_trends(compliance_scores)

        assert "CIS" in report.compliance_trends
        assert "SOC2" in report.compliance_trends
        assert report.compliance_trends["CIS"].current_score == 80


class TestLinearRegression:
    """Tests for linear regression functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer."""
        with tempfile.TemporaryDirectory() as tmpdir:
            return TrendAnalyzer(storage_path=tmpdir)

    def test_perfect_linear(self, analyzer):
        """Test with perfect linear data."""
        x = [0, 1, 2, 3, 4]
        y = [0, 2, 4, 6, 8]

        slope, intercept = analyzer._linear_regression(x, y)

        assert slope == pytest.approx(2.0)
        assert intercept == pytest.approx(0.0)

    def test_constant_values(self, analyzer):
        """Test with constant values."""
        x = [0, 1, 2, 3, 4]
        y = [5, 5, 5, 5, 5]

        slope, intercept = analyzer._linear_regression(x, y)

        assert slope == pytest.approx(0.0)
        assert intercept == pytest.approx(5.0)

    def test_confidence_perfect_fit(self, analyzer):
        """Test confidence with perfect fit."""
        x = [0, 1, 2, 3, 4]
        y = [0, 2, 4, 6, 8]

        confidence = analyzer._calculate_confidence(x, y, 2.0, 0.0)

        assert confidence == pytest.approx(1.0)

    def test_confidence_poor_fit(self, analyzer):
        """Test confidence with poor fit."""
        x = [0, 1, 2, 3, 4]
        y = [10, 2, 8, 4, 6]  # Scattered data

        slope, intercept = analyzer._linear_regression(x, y)
        confidence = analyzer._calculate_confidence(x, y, slope, intercept)

        assert confidence < 0.5


class TestTrendAnalyzerIntegration:
    """Integration tests for TrendAnalyzer."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_full_analysis_workflow(self, temp_storage):
        """Test complete analysis workflow."""
        # Create history manager and analyzer
        manager = ScanHistoryManager(storage_path=temp_storage)
        analyzer = TrendAnalyzer(history_manager=manager)

        # Record some scans
        from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity

        base_time = datetime.utcnow()

        for i in range(5):
            findings = FindingCollection(
                findings=[
                    Finding(
                        id=f"finding-{i}-{j}",
                        asset_id=f"asset-{j}",
                        finding_type=FindingType.MISCONFIGURATION,
                        title=f"Finding {j}",
                        description=f"Test finding description {j}",
                        severity=Severity.HIGH if j < 5 else Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                    )
                    for j in range(max(1, 10 - i))  # Decreasing findings
                ]
            )

            manager.record_scan(
                scan_id=f"scan-{i}",
                findings=findings,
                config_name="default",
                duration_seconds=300,
                assets_scanned=100,
            )

        # Analyze
        report = analyzer.analyze(config_name="default", days=30)

        # Verify report
        assert report.report_id is not None
        assert report.total_findings.data_points == 5
        assert report.scan_frequency > 0
        assert len(report.recommendations) > 0

    def test_analyze_with_config_filter(self, temp_storage):
        """Test analysis with config name filter."""
        manager = ScanHistoryManager(storage_path=temp_storage)
        analyzer = TrendAnalyzer(history_manager=manager)

        from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity

        # Create scans for different configs
        for config in ["config-a", "config-b"]:
            findings = FindingCollection(
                findings=[
                    Finding(
                        id=f"finding-{config}-1",
                        asset_id="asset-1",
                        finding_type=FindingType.MISCONFIGURATION,
                        title="Test Finding",
                        description="Test finding description",
                        severity=Severity.MEDIUM,
                        status=FindingStatus.OPEN,
                    )
                ]
            )

            manager.record_scan(
                scan_id=f"scan-{config}",
                findings=findings,
                config_name=config,
            )

        # Analyze specific config
        report = analyzer.analyze(config_name="config-a", days=30)

        assert report.total_findings.data_points == 1
