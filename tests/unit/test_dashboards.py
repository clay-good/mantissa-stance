"""
Unit tests for Advanced Reporting & Dashboards module.

Tests dashboard models, visualizations, reports, scheduler, and metrics.

Part of Phase 91: Advanced Reporting & Dashboards
"""

import json
import pytest
from datetime import datetime, timedelta
from typing import Dict, List

from stance.dashboards.models import (
    WidgetType,
    ChartType,
    TimeRange,
    ReportFormat,
    ReportFrequency,
    DashboardTheme,
    MetricAggregation,
    WidgetConfig,
    ChartConfig,
    MetricConfig,
    TableConfig,
    Widget,
    DashboardLayout,
    Dashboard,
    ReportSection,
    ReportConfig,
    ReportDelivery,
    ScheduledReport,
    GeneratedReport,
)

from stance.dashboards.visualizations import (
    DataPoint,
    DataSeries,
    ChartData,
    ChartBuilder,
    LineChartBuilder,
    BarChartBuilder,
    PieChartBuilder,
    AreaChartBuilder,
    SVGRenderer,
    ASCIIRenderer,
    create_chart,
    create_trend_chart,
    create_severity_chart,
    create_compliance_chart,
)

from stance.dashboards.reports import (
    SectionBuilder,
    ExecutiveSummarySection,
    FindingsSection,
    ComplianceSection,
    TrendSection,
    RecommendationsSection,
    ReportTemplate,
    ExecutiveSummaryTemplate,
    TechnicalDetailTemplate,
    ComplianceReportTemplate,
    TrendReportTemplate,
    ReportGenerator,
)

from stance.dashboards.scheduler import (
    ScheduleStatus,
    ScheduleEntry,
    DeliveryChannel,
    EmailDelivery,
    WebhookDelivery,
    StorageDelivery,
    ReportDistributor,
    ReportScheduler,
)

from stance.dashboards.metrics import (
    TrendDirection,
    MetricValue,
    MetricTrend,
    DashboardMetric,
    MetricsAggregator,
    SecurityMetrics,
    ComplianceMetrics,
    OperationalMetrics,
    calculate_security_score,
    calculate_risk_trend,
    calculate_compliance_gap,
)

from stance.dashboards.factory import (
    create_dashboard,
    create_executive_dashboard,
    create_security_ops_dashboard,
    create_compliance_dashboard,
    create_report,
    create_scheduled_report,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def sample_findings_data() -> Dict:
    """Sample findings data for testing."""
    return {
        "total": 150,
        "critical": 5,
        "high": 25,
        "medium": 70,
        "low": 40,
        "info": 10,
        "by_category": {
            "IAM": 40,
            "Storage": 35,
            "Network": 30,
            "Compute": 25,
            "Other": 20,
        },
        "by_provider": {
            "AWS": 80,
            "GCP": 40,
            "Azure": 30,
        },
    }


@pytest.fixture
def sample_compliance_data() -> Dict:
    """Sample compliance data for testing."""
    return {
        "average_score": 72.5,
        "frameworks": {
            "CIS AWS": 85.0,
            "PCI-DSS": 68.0,
            "SOC 2": 75.0,
            "HIPAA": 62.0,
        },
        "total_controls": 200,
        "passed_controls": 145,
        "failed_controls": 55,
    }


@pytest.fixture
def sample_report_data(sample_findings_data, sample_compliance_data) -> Dict:
    """Complete sample data for reports."""
    return {
        "findings": sample_findings_data,
        "findings_list": [
            {"id": "f1", "title": "Open S3 bucket", "severity": "critical", "asset_id": "arn:aws:s3:::bucket1"},
            {"id": "f2", "title": "Weak password policy", "severity": "high", "asset_id": "arn:aws:iam::123:policy/weak"},
        ],
        "assets": {
            "total": 500,
            "with_findings": 120,
            "with_critical_high": 30,
        },
        "compliance": sample_compliance_data,
        "trends": {
            "direction": "improving",
            "findings_change_pct": -5.2,
            "compliance_change_pct": 3.1,
            "findings_velocity": 2.5,
        },
        "scan_history": [
            {"timestamp": (datetime.utcnow() - timedelta(days=i)).isoformat(),
             "findings_total": 150 + i * 2,
             "findings_by_severity": {"critical": 5, "high": 25}}
            for i in range(7)
        ],
        "time_range": "Last 7 days",
    }


# =============================================================================
# Test Models
# =============================================================================

class TestTimeRange:
    """Tests for TimeRange enum."""

    def test_to_timedelta(self):
        """Test time range to timedelta conversion."""
        assert TimeRange.LAST_HOUR.to_timedelta() == timedelta(hours=1)
        assert TimeRange.LAST_24_HOURS.to_timedelta() == timedelta(days=1)
        assert TimeRange.LAST_7_DAYS.to_timedelta() == timedelta(days=7)
        assert TimeRange.LAST_30_DAYS.to_timedelta() == timedelta(days=30)
        assert TimeRange.CUSTOM.to_timedelta() is None


class TestReportFrequency:
    """Tests for ReportFrequency enum."""

    def test_to_timedelta(self):
        """Test frequency to timedelta conversion."""
        assert ReportFrequency.HOURLY.to_timedelta() == timedelta(hours=1)
        assert ReportFrequency.DAILY.to_timedelta() == timedelta(days=1)
        assert ReportFrequency.WEEKLY.to_timedelta() == timedelta(weeks=1)
        assert ReportFrequency.ONCE.to_timedelta() is None


class TestWidget:
    """Tests for Widget class."""

    def test_widget_creation(self):
        """Test basic widget creation."""
        config = MetricConfig(title="Test Metric")
        widget = Widget(
            id="test",
            widget_type=WidgetType.METRIC,
            config=config,
            data_source="test.source",
        )

        assert widget.id == "test"
        assert widget.widget_type == WidgetType.METRIC
        assert widget.visible

    def test_widget_auto_id(self):
        """Test widget auto-generates ID if empty."""
        config = MetricConfig(title="Test")
        widget = Widget(
            id="",
            widget_type=WidgetType.METRIC,
            config=config,
            data_source="test",
        )
        assert widget.id != ""

    def test_widget_needs_refresh(self):
        """Test widget refresh check."""
        config = MetricConfig(title="Test", refresh_interval_seconds=60)
        widget = Widget(
            id="test",
            widget_type=WidgetType.METRIC,
            config=config,
            data_source="test",
        )

        assert widget.needs_refresh()  # Never updated

        widget.last_updated = datetime.utcnow()
        assert not widget.needs_refresh()

        widget.last_updated = datetime.utcnow() - timedelta(seconds=120)
        assert widget.needs_refresh()

    def test_widget_to_dict(self):
        """Test widget serialization."""
        config = MetricConfig(title="Test")
        widget = Widget(
            id="test",
            widget_type=WidgetType.METRIC,
            config=config,
            data_source="test.source",
            position=(1, 2),
            size=(3, 4),
        )

        d = widget.to_dict()
        assert d["id"] == "test"
        assert d["widget_type"] == "metric"
        assert d["position"] == (1, 2)
        assert d["size"] == (3, 4)


class TestDashboard:
    """Tests for Dashboard class."""

    def test_dashboard_creation(self):
        """Test dashboard creation."""
        dashboard = Dashboard(
            id="",
            name="Test Dashboard",
            description="A test dashboard",
        )

        assert dashboard.name == "Test Dashboard"
        assert dashboard.id != ""  # Auto-generated
        assert len(dashboard.widgets) == 0

    def test_add_widget(self):
        """Test adding widgets."""
        dashboard = Dashboard(id="test", name="Test")
        widget = Widget(
            id="w1",
            widget_type=WidgetType.METRIC,
            config=MetricConfig(title="W1"),
            data_source="test",
        )

        dashboard.add_widget(widget)

        assert len(dashboard.widgets) == 1
        assert dashboard.get_widget("w1") is not None

    def test_remove_widget(self):
        """Test removing widgets."""
        dashboard = Dashboard(id="test", name="Test")
        widget = Widget(
            id="w1",
            widget_type=WidgetType.METRIC,
            config=MetricConfig(title="W1"),
            data_source="test",
        )
        dashboard.add_widget(widget)

        assert dashboard.remove_widget("w1")
        assert len(dashboard.widgets) == 0
        assert not dashboard.remove_widget("nonexistent")

    def test_get_widgets_by_type(self):
        """Test filtering widgets by type."""
        dashboard = Dashboard(id="test", name="Test")

        dashboard.add_widget(Widget(
            id="m1", widget_type=WidgetType.METRIC,
            config=MetricConfig(title="M1"), data_source="test"
        ))
        dashboard.add_widget(Widget(
            id="c1", widget_type=WidgetType.CHART,
            config=ChartConfig(title="C1"), data_source="test"
        ))
        dashboard.add_widget(Widget(
            id="m2", widget_type=WidgetType.METRIC,
            config=MetricConfig(title="M2"), data_source="test"
        ))

        metrics = dashboard.get_widgets_by_type(WidgetType.METRIC)
        assert len(metrics) == 2

        charts = dashboard.get_widgets_by_type(WidgetType.CHART)
        assert len(charts) == 1


class TestScheduledReport:
    """Tests for ScheduledReport class."""

    def test_scheduled_report_creation(self):
        """Test scheduled report creation."""
        config = ReportConfig(title="Test Report")
        schedule = ScheduledReport(
            id="",
            name="Weekly Report",
            config=config,
            frequency=ReportFrequency.WEEKLY,
        )

        assert schedule.id != ""
        assert schedule.enabled
        assert schedule.next_run is not None

    def test_is_due(self):
        """Test due check."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(
            id="test",
            name="Test",
            config=config,
            frequency=ReportFrequency.DAILY,
        )

        schedule.next_run = datetime.utcnow() - timedelta(hours=1)
        assert schedule.is_due()

        schedule.next_run = datetime.utcnow() + timedelta(hours=1)
        assert not schedule.is_due()

        schedule.enabled = False
        schedule.next_run = datetime.utcnow() - timedelta(hours=1)
        assert not schedule.is_due()

    def test_update_after_run(self):
        """Test updating schedule after run."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(
            id="test",
            name="Test",
            config=config,
            frequency=ReportFrequency.DAILY,
        )

        schedule.update_after_run(True)
        assert schedule.run_count == 1
        assert schedule.failure_count == 0
        assert schedule.last_status == "success"

        schedule.update_after_run(False)
        assert schedule.run_count == 2
        assert schedule.failure_count == 1
        assert schedule.last_status == "failed"


# =============================================================================
# Test Visualizations
# =============================================================================

class TestDataStructures:
    """Tests for chart data structures."""

    def test_data_point(self):
        """Test DataPoint creation."""
        point = DataPoint(x=1.0, y=10.0, label="Test")
        assert point.x == 1.0
        assert point.y == 10.0

        d = point.to_dict()
        assert d["x"] == 1.0
        assert d["y"] == 10.0

    def test_data_series(self):
        """Test DataSeries operations."""
        series = DataSeries(name="Test", color="#FF0000")
        series.add_point(1, 10)
        series.add_point(2, 20)
        series.add_point(3, 30)

        assert len(series.points) == 3
        assert series.get_min_y() == 10
        assert series.get_max_y() == 30
        assert series.get_sum() == 60
        assert series.get_avg() == 20

    def test_chart_data(self):
        """Test ChartData operations."""
        data = ChartData(title="Test Chart")
        series1 = DataSeries(name="S1")
        series1.add_point("A", 10)
        series1.add_point("B", 20)

        series2 = DataSeries(name="S2")
        series2.add_point("A", 15)
        series2.add_point("B", 25)

        data.add_series(series1)
        data.add_series(series2)

        assert len(data.series) == 2

        y_range = data.get_y_range()
        assert y_range[0] < 10  # With padding
        assert y_range[1] > 25


class TestChartBuilders:
    """Tests for chart builders."""

    def test_line_chart_builder(self):
        """Test line chart builder."""
        builder = LineChartBuilder()
        builder.set_title("Line Chart")
        builder.set_labels("X", "Y")
        builder.add_series("Data", [(1, 10), (2, 20), (3, 15)])

        chart = builder.build()

        assert chart.title == "Line Chart"
        assert chart.chart_type == ChartType.LINE
        assert len(chart.series) == 1
        assert len(chart.series[0].points) == 3

    def test_line_chart_with_trend(self):
        """Test line chart with trend line."""
        builder = LineChartBuilder()
        builder.add_series("Data", [(i, i * 2 + 5) for i in range(10)])
        builder.with_trend_line(0)

        chart = builder.build()

        assert len(chart.series) == 2  # Original + trend

    def test_bar_chart_builder(self):
        """Test bar chart builder."""
        builder = BarChartBuilder()
        builder.from_dict({"A": 10, "B": 20, "C": 15}, name="Values")

        chart = builder.build()

        assert chart.chart_type == ChartType.BAR
        assert len(chart.series[0].points) == 3

    def test_pie_chart_builder(self):
        """Test pie chart builder."""
        builder = PieChartBuilder()
        builder.from_dict({"Critical": 5, "High": 10, "Medium": 20})

        chart = builder.build()

        assert chart.chart_type == ChartType.PIE
        assert len(chart.series[0].points) == 3


class TestChartRenderers:
    """Tests for chart renderers."""

    def test_svg_renderer_line(self):
        """Test SVG rendering for line chart."""
        builder = LineChartBuilder()
        builder.set_title("Test Line")
        builder.add_series("Data", [(1, 10), (2, 20), (3, 15)])
        chart = builder.build()

        renderer = SVGRenderer()
        svg = renderer.render(chart, width=400, height=300)

        assert svg.startswith("<svg")
        assert "</svg>" in svg
        assert "Test Line" in svg

    def test_svg_renderer_bar(self):
        """Test SVG rendering for bar chart."""
        builder = BarChartBuilder()
        builder.from_dict({"A": 10, "B": 20}, name="Values")
        chart = builder.build()

        renderer = SVGRenderer()
        svg = renderer.render(chart, width=400, height=300)

        assert "<rect" in svg

    def test_svg_renderer_pie(self):
        """Test SVG rendering for pie chart."""
        builder = PieChartBuilder()
        builder.from_dict({"X": 30, "Y": 70})
        chart = builder.build()

        renderer = SVGRenderer()
        svg = renderer.render(chart, width=400, height=300)

        assert "<path" in svg

    def test_ascii_renderer(self):
        """Test ASCII rendering."""
        builder = BarChartBuilder()
        builder.set_title("Test Bar")
        builder.from_dict({"A": 10, "B": 20}, name="Values")
        chart = builder.build()

        renderer = ASCIIRenderer()
        ascii_chart = renderer.render(chart)

        assert "Test Bar" in ascii_chart
        assert "█" in ascii_chart


class TestVisualizationFactories:
    """Tests for visualization factory functions."""

    def test_create_chart(self):
        """Test create_chart factory."""
        line = create_chart(ChartType.LINE)
        assert isinstance(line, LineChartBuilder)

        bar = create_chart(ChartType.BAR)
        assert isinstance(bar, BarChartBuilder)

        pie = create_chart(ChartType.PIE)
        assert isinstance(pie, PieChartBuilder)

    def test_create_trend_chart(self):
        """Test create_trend_chart."""
        data = [(datetime.utcnow() - timedelta(days=i), 100 - i * 5) for i in range(7)]
        chart = create_trend_chart(data, title="Trend", series_name="Findings")

        assert chart.title == "Trend"
        assert len(chart.series) >= 1

    def test_create_severity_chart(self):
        """Test create_severity_chart."""
        chart = create_severity_chart(
            critical=5,
            high=10,
            medium=20,
            low=30,
            title="Severity"
        )

        assert chart.title == "Severity"
        assert chart.chart_type == ChartType.PIE

    def test_create_compliance_chart(self):
        """Test create_compliance_chart."""
        scores = {"CIS": 85.0, "PCI": 70.0, "SOC2": 90.0}
        chart = create_compliance_chart(scores, title="Compliance")

        assert chart.title == "Compliance"
        assert len(chart.series[0].points) == 3


# =============================================================================
# Test Reports
# =============================================================================

class TestSectionBuilders:
    """Tests for report section builders."""

    def test_executive_summary_section(self, sample_report_data):
        """Test executive summary section builder."""
        builder = ExecutiveSummarySection()
        section = builder.build(sample_report_data)

        assert section.id == "executive_summary"
        assert section.content_type == "executive_summary"
        assert "key_metrics" in section.content
        assert "risk_summary" in section.content
        assert "recommendations" in section.content

    def test_findings_section(self, sample_report_data):
        """Test findings section builder."""
        builder = FindingsSection()
        section = builder.build(sample_report_data)

        assert section.id == "findings_overview"
        assert "summary" in section.content
        assert "severity_chart" in section.content
        assert section.content["summary"]["total"] == 150

    def test_compliance_section(self, sample_report_data):
        """Test compliance section builder."""
        builder = ComplianceSection()
        section = builder.build(sample_report_data)

        assert section.id == "compliance_status"
        assert "average_score" in section.content
        assert "frameworks" in section.content
        assert len(section.content["frameworks"]) == 4

    def test_trend_section(self, sample_report_data):
        """Test trend section builder."""
        builder = TrendSection()
        section = builder.build(sample_report_data)

        assert section.id == "trends"
        assert "summary" in section.content
        assert "findings_over_time" in section.content

    def test_recommendations_section(self, sample_report_data):
        """Test recommendations section builder."""
        builder = RecommendationsSection()
        section = builder.build(sample_report_data)

        assert section.id == "recommendations"
        assert "priority_actions" in section.content
        assert len(section.content["priority_actions"]) > 0


class TestReportTemplates:
    """Tests for report templates."""

    def test_executive_template_sections(self):
        """Test executive template returns correct sections."""
        template = ExecutiveSummaryTemplate()
        sections = template.get_sections()

        assert len(sections) >= 3
        section_ids = [s.section_id for s in sections]
        assert "executive_summary" in section_ids

    def test_template_render_html(self, sample_report_data):
        """Test HTML rendering."""
        template = ExecutiveSummaryTemplate()
        sections = []

        for builder in template.get_sections():
            sections.append(builder.build(sample_report_data))

        config = ReportConfig(
            title="Test Report",
            format=ReportFormat.HTML,
        )

        html = template.render(sections, config)

        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "</html>" in html

    def test_template_render_markdown(self, sample_report_data):
        """Test Markdown rendering."""
        template = ExecutiveSummaryTemplate()
        sections = []

        for builder in template.get_sections():
            sections.append(builder.build(sample_report_data))

        config = ReportConfig(
            title="Test Report",
            format=ReportFormat.MARKDOWN,
        )

        md = template.render(sections, config)

        assert "# Test Report" in md
        assert "##" in md  # Has sections

    def test_template_render_json(self, sample_report_data):
        """Test JSON rendering."""
        template = ExecutiveSummaryTemplate()
        sections = []

        for builder in template.get_sections():
            sections.append(builder.build(sample_report_data))

        config = ReportConfig(
            title="Test Report",
            format=ReportFormat.JSON,
        )

        json_str = template.render(sections, config)
        data = json.loads(json_str)

        assert data["title"] == "Test Report"
        assert "sections" in data


class TestReportGenerator:
    """Tests for report generator."""

    def test_generator_creation(self):
        """Test generator creation."""
        generator = ReportGenerator()
        templates = generator.list_templates()

        assert len(templates) >= 4
        names = [t["name"] for t in templates]
        assert "executive_summary" in names

    def test_generate_report(self, sample_report_data):
        """Test report generation."""
        generator = ReportGenerator()
        config = ReportConfig(
            title="Generated Report",
            format=ReportFormat.MARKDOWN,
            template="executive_summary",
        )

        report = generator.generate(sample_report_data, config)

        assert report.id != ""
        assert report.format == ReportFormat.MARKDOWN
        assert report.content != ""
        assert report.generation_time_seconds > 0

    def test_generate_multiple_formats(self, sample_report_data):
        """Test generating in multiple formats."""
        generator = ReportGenerator()

        for fmt in [ReportFormat.HTML, ReportFormat.MARKDOWN, ReportFormat.JSON]:
            config = ReportConfig(
                title="Format Test",
                format=fmt,
            )
            report = generator.generate(sample_report_data, config)
            assert report.content != ""


# =============================================================================
# Test Scheduler
# =============================================================================

class TestScheduleEntry:
    """Tests for schedule entries."""

    def test_schedule_entry_creation(self):
        """Test schedule entry creation."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)
        entry = ScheduleEntry(schedule=schedule)

        assert entry.status == ScheduleStatus.PENDING
        assert entry.retry_count == 0

    def test_should_run(self):
        """Test should_run logic."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)
        schedule.next_run = datetime.utcnow() - timedelta(hours=1)

        entry = ScheduleEntry(schedule=schedule)
        assert entry.should_run()

        entry.status = ScheduleStatus.DISABLED
        assert not entry.should_run()

    def test_mark_completed(self):
        """Test marking entry completed."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)
        entry = ScheduleEntry(schedule=schedule)

        entry.mark_running()
        assert entry.status == ScheduleStatus.RUNNING

        entry.mark_completed()
        assert entry.status == ScheduleStatus.COMPLETED
        assert entry.retry_count == 0

    def test_mark_failed_with_retry(self):
        """Test marking entry failed with retry."""
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)
        entry = ScheduleEntry(schedule=schedule, max_retries=3)

        entry.mark_failed("Test error")
        assert entry.status == ScheduleStatus.PENDING  # Retry scheduled
        assert entry.retry_count == 1
        assert entry.last_error == "Test error"

        # Exhaust retries
        entry.mark_failed("Error 2")
        entry.mark_failed("Error 3")
        entry.mark_failed("Error 4")

        assert entry.status == ScheduleStatus.DISABLED


class TestDeliveryChannels:
    """Tests for delivery channels."""

    def test_email_delivery_validation(self):
        """Test email delivery validation."""
        channel = EmailDelivery()

        errors = channel.validate_settings({})
        assert len(errors) > 0  # Missing from_address

        errors = channel.validate_settings({"from_address": "test@example.com"})
        assert len(errors) == 0

        errors = channel.validate_settings({"from_address": "invalid"})
        assert len(errors) > 0

    def test_webhook_delivery_validation(self):
        """Test webhook delivery validation."""
        channel = WebhookDelivery()

        errors = channel.validate_settings({})
        assert len(errors) == 0

        errors = channel.validate_settings({
            "auth": {"type": "bearer"}
        })
        assert len(errors) > 0  # Missing token

        errors = channel.validate_settings({
            "auth": {"type": "bearer", "token": "abc123"}
        })
        assert len(errors) == 0

    def test_storage_delivery_validation(self):
        """Test storage delivery validation."""
        channel = StorageDelivery()
        errors = channel.validate_settings({})
        assert len(errors) == 0


class TestReportDistributor:
    """Tests for report distributor."""

    def test_distributor_creation(self):
        """Test distributor creation."""
        distributor = ReportDistributor()

        assert "email" in distributor.channels
        assert "webhook" in distributor.channels
        assert "storage" in distributor.channels

    def test_register_channel(self):
        """Test registering custom channel."""
        distributor = ReportDistributor()

        class CustomChannel(DeliveryChannel):
            def deliver(self, report, recipients, settings):
                return True

            def validate_settings(self, settings):
                return []

        distributor.register_channel("custom", CustomChannel())
        assert "custom" in distributor.channels


class TestReportScheduler:
    """Tests for report scheduler."""

    def test_scheduler_creation(self):
        """Test scheduler creation."""
        scheduler = ReportScheduler()
        assert len(scheduler.schedules) == 0

    def test_add_remove_schedule(self):
        """Test adding and removing schedules."""
        scheduler = ReportScheduler()
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)

        entry = scheduler.add_schedule(schedule)
        assert entry is not None
        assert len(scheduler.list_schedules()) == 1

        scheduler.remove_schedule("test")
        assert len(scheduler.list_schedules()) == 0

    def test_enable_disable_schedule(self):
        """Test enabling/disabling schedules."""
        scheduler = ReportScheduler()
        config = ReportConfig(title="Test")
        schedule = ScheduledReport(id="test", name="Test", config=config)
        scheduler.add_schedule(schedule)

        scheduler.disable_schedule("test")
        entry = scheduler.get_schedule("test")
        assert not entry.schedule.enabled

        scheduler.enable_schedule("test")
        entry = scheduler.get_schedule("test")
        assert entry.schedule.enabled

    def test_get_status(self):
        """Test scheduler status."""
        scheduler = ReportScheduler()
        config = ReportConfig(title="Test")

        for i in range(3):
            schedule = ScheduledReport(id=f"s{i}", name=f"S{i}", config=config)
            scheduler.add_schedule(schedule)

        status = scheduler.get_status()

        assert status["total_schedules"] == 3
        assert "schedules" in status


# =============================================================================
# Test Metrics
# =============================================================================

class TestMetricValue:
    """Tests for MetricValue class."""

    def test_metric_value_creation(self):
        """Test metric value creation."""
        value = MetricValue(value=42.5, unit="%")

        assert value.value == 42.5
        assert value.unit == "%"

    def test_metric_value_to_dict(self):
        """Test metric value serialization."""
        value = MetricValue(value=100)
        d = value.to_dict()

        assert d["value"] == 100
        assert "timestamp" in d


class TestMetricTrend:
    """Tests for MetricTrend class."""

    def test_metric_trend_creation(self):
        """Test metric trend creation."""
        trend = MetricTrend(
            current=80,
            previous=100,
            change=-20,
            change_percent=-20.0,
            direction=TrendDirection.IMPROVING,
        )

        assert trend.change == -20
        assert trend.direction == TrendDirection.IMPROVING


class TestDashboardMetric:
    """Tests for DashboardMetric class."""

    def test_dashboard_metric_creation(self):
        """Test dashboard metric creation."""
        metric = DashboardMetric(
            id="test",
            name="Test Metric",
            threshold_warning=50,
            threshold_critical=80,
        )
        metric.value = MetricValue(value=30)

        assert metric.get_status() == "ok"

        metric.value = MetricValue(value=60)
        assert metric.get_status() == "warning"

        metric.value = MetricValue(value=90)
        assert metric.get_status() == "critical"

    def test_target_progress(self):
        """Test target progress calculation."""
        metric = DashboardMetric(
            id="test",
            name="Test",
            target=100.0,
        )
        metric.value = MetricValue(value=75)

        progress = metric.get_target_progress()
        assert progress == 75.0

    def test_format_value(self):
        """Test value formatting."""
        metric = DashboardMetric(
            id="test",
            name="Test",
            format="{value:.1f}%",
        )
        metric.value = MetricValue(value=85.5)

        assert metric.format_value() == "85.5%"


class TestMetricCalculators:
    """Tests for metric calculator functions."""

    def test_calculate_security_score(self):
        """Test security score calculation."""
        findings = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assets = {"total": 100}

        score = calculate_security_score(findings, assets)
        assert score == 100.0  # Perfect score

        findings = {"critical": 10, "high": 20, "medium": 50, "low": 100}
        score = calculate_security_score(findings, assets)
        assert score < 100.0
        assert score >= 0

    def test_calculate_risk_trend(self):
        """Test risk trend calculation."""
        trend = calculate_risk_trend(50.0, 80.0)

        assert trend.change == -30
        assert trend.direction == TrendDirection.IMPROVING

        trend = calculate_risk_trend(80.0, 50.0)
        assert trend.direction == TrendDirection.DECLINING

        trend = calculate_risk_trend(50.0, 52.0)
        assert trend.direction == TrendDirection.STABLE

    def test_calculate_compliance_gap(self):
        """Test compliance gap calculation."""
        scores = {"CIS": 90.0, "PCI": 70.0, "SOC2": 85.0}

        gaps = calculate_compliance_gap(scores, target_score=90.0)

        assert "frameworks" in gaps
        assert gaps["frameworks"]["CIS"]["status"] == "compliant"
        assert gaps["frameworks"]["PCI"]["status"] == "non_compliant"
        assert gaps["frameworks_compliant"] == 2


class TestSecurityMetrics:
    """Tests for SecurityMetrics aggregator."""

    def test_security_metrics_creation(self):
        """Test security metrics creation."""
        metrics = SecurityMetrics()

        assert "total_findings" in metrics.metrics
        assert "security_score" in metrics.metrics
        assert "mttr_hours" in metrics.metrics

    def test_security_metrics_calculation(self, sample_findings_data):
        """Test security metrics calculation."""
        metrics = SecurityMetrics()

        data = {
            "findings": sample_findings_data,
            "assets": {"total": 500, "with_critical_high": 30},
            "history": [],
        }

        result = metrics.calculate(data)

        assert result["total_findings"].value.value == 150
        assert result["critical_findings"].value.value == 5
        assert 0 <= result["security_score"].value.value <= 100


class TestComplianceMetrics:
    """Tests for ComplianceMetrics aggregator."""

    def test_compliance_metrics_creation(self):
        """Test compliance metrics creation."""
        metrics = ComplianceMetrics()

        assert "average_compliance" in metrics.metrics
        assert "controls_passed" in metrics.metrics

    def test_compliance_metrics_calculation(self, sample_compliance_data):
        """Test compliance metrics calculation."""
        metrics = ComplianceMetrics()

        data = {
            "frameworks": sample_compliance_data["frameworks"],
            "controls": {
                "passed": 145,
                "failed": 55,
            },
            "target_score": 90.0,
        }

        result = metrics.calculate(data)

        assert result["average_compliance"].value.value == pytest.approx(72.5, 0.1)
        assert result["controls_passed"].value.value == 145

    def test_compliance_gap_analysis(self, sample_compliance_data):
        """Test compliance gap analysis."""
        metrics = ComplianceMetrics()

        data = {
            "frameworks": sample_compliance_data["frameworks"],
            "controls": {"passed": 145, "failed": 55},
        }
        metrics.calculate(data)

        gaps = metrics.get_gap_analysis(target=90.0)

        assert "frameworks" in gaps
        assert "average_gap" in gaps


class TestOperationalMetrics:
    """Tests for OperationalMetrics aggregator."""

    def test_operational_metrics_creation(self):
        """Test operational metrics creation."""
        metrics = OperationalMetrics()

        assert "scans_per_day" in metrics.metrics
        assert "asset_coverage" in metrics.metrics

    def test_operational_metrics_calculation(self):
        """Test operational metrics calculation."""
        metrics = OperationalMetrics()

        data = {
            "scans": {"per_day": 5, "avg_duration_minutes": 15},
            "assets": {"total": 500, "scanned": 450, "accounts": 3},
            "collections": {"total": 100, "successful": 98},
        }

        result = metrics.calculate(data)

        assert result["scans_per_day"].value.value == 5
        assert result["asset_coverage"].value.value == 90.0
        assert result["collection_success_rate"].value.value == 98.0


# =============================================================================
# Test Factory Functions
# =============================================================================

class TestDashboardFactories:
    """Tests for dashboard factory functions."""

    def test_create_dashboard(self):
        """Test create_dashboard factory."""
        dashboard = create_dashboard(
            name="My Dashboard",
            description="Test",
            theme=DashboardTheme.DARK,
        )

        assert dashboard.name == "My Dashboard"
        assert dashboard.theme == DashboardTheme.DARK

    def test_create_executive_dashboard(self):
        """Test executive dashboard creation."""
        dashboard = create_executive_dashboard(owner="test_user")

        assert "Executive" in dashboard.name
        assert len(dashboard.widgets) > 0
        assert dashboard.owner == "test_user"

        # Check for expected widgets
        widget_ids = [w.id for w in dashboard.widgets]
        assert "security_score" in widget_ids
        assert "critical_findings" in widget_ids

    def test_create_security_ops_dashboard(self):
        """Test security ops dashboard creation."""
        dashboard = create_security_ops_dashboard()

        assert "Operations" in dashboard.name
        assert dashboard.theme == DashboardTheme.DARK
        assert dashboard.auto_refresh == 60

    def test_create_compliance_dashboard(self):
        """Test compliance dashboard creation."""
        dashboard = create_compliance_dashboard()

        assert "Compliance" in dashboard.name

        widget_ids = [w.id for w in dashboard.widgets]
        assert "avg_compliance" in widget_ids
        assert "controls_passed" in widget_ids


class TestReportFactories:
    """Tests for report factory functions."""

    def test_create_report(self):
        """Test create_report factory."""
        config = create_report(
            title="Security Report",
            template="executive_summary",
            format=ReportFormat.PDF,
        )

        assert config.title == "Security Report"
        assert config.format == ReportFormat.PDF
        assert "executive_summary" in config.include_sections

    def test_create_scheduled_report(self):
        """Test create_scheduled_report factory."""
        config = create_report(title="Weekly Report")
        schedule = create_scheduled_report(
            name="Weekly Security",
            config=config,
            frequency=ReportFrequency.WEEKLY,
            delivery_email=["security@example.com"],
        )

        assert schedule.name == "Weekly Security"
        assert schedule.frequency == ReportFrequency.WEEKLY
        assert len(schedule.delivery) == 1
        assert schedule.delivery[0].channel == "email"

    def test_create_scheduled_report_multiple_delivery(self):
        """Test scheduled report with multiple delivery channels."""
        config = create_report(title="Report")
        schedule = create_scheduled_report(
            name="Multi-Delivery",
            config=config,
            delivery_email=["a@example.com"],
            delivery_webhook="https://webhook.example.com",
            delivery_storage="/reports",
        )

        assert len(schedule.delivery) == 3


# =============================================================================
# Integration Tests
# =============================================================================

class TestDashboardsIntegration:
    """Integration tests for dashboards module."""

    def test_full_report_generation_flow(self, sample_report_data):
        """Test complete report generation flow."""
        # Create configuration
        config = create_report(
            title="Integration Test Report",
            template="executive_summary",
            format=ReportFormat.HTML,
            time_range=TimeRange.LAST_7_DAYS,
        )

        # Generate report
        generator = ReportGenerator()
        report = generator.generate(sample_report_data, config)

        # Verify
        assert report.content is not None
        assert len(report.sections) > 0
        assert report.generation_time_seconds > 0

    def test_metrics_to_dashboard_flow(self, sample_findings_data, sample_compliance_data):
        """Test metrics calculation to dashboard flow."""
        # Calculate metrics
        security = SecurityMetrics()
        security.calculate({
            "findings": sample_findings_data,
            "assets": {"total": 500},
            "history": [],
        })

        compliance = ComplianceMetrics()
        compliance.calculate({
            "frameworks": sample_compliance_data["frameworks"],
            "controls": {"passed": 145, "failed": 55},
        })

        # Create dashboard
        dashboard = create_executive_dashboard()

        # Metrics should be ready for dashboard consumption
        assert security.metrics["security_score"].value.value > 0
        assert compliance.metrics["average_compliance"].value.value > 0

    def test_scheduler_with_generator(self, sample_report_data):
        """Test scheduler integration with generator."""
        scheduler = ReportScheduler()
        generator = ReportGenerator()

        scheduler.set_report_generator(
            lambda data, config: generator.generate(data, config)
        )
        scheduler.set_data_provider(lambda config: sample_report_data)

        # Add schedule
        config = create_report(title="Scheduled Report")
        schedule = ScheduledReport(
            id="test",
            name="Test Schedule",
            config=config,
        )
        scheduler.add_schedule(schedule)

        # Run immediately
        report = scheduler.run_now("test")

        assert report is not None
        assert report.content is not None
