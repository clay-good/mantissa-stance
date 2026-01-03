"""
Factory functions for Mantissa Stance dashboards.

Provides convenient functions to create dashboards, reports, and schedules.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from stance.dashboards.models import (
    Dashboard,
    DashboardLayout,
    DashboardTheme,
    Widget,
    WidgetType,
    ChartConfig,
    MetricConfig,
    TableConfig,
    TimeRange,
    ReportConfig,
    ReportFormat,
    ReportFrequency,
    ScheduledReport,
    ReportDelivery,
    ChartType,
    MetricAggregation,
)
from stance.dashboards.reports import ReportGenerator
from stance.dashboards.scheduler import ReportScheduler


# =============================================================================
# Dashboard Factory Functions
# =============================================================================

def create_dashboard(
    name: str,
    description: str = "",
    theme: DashboardTheme = DashboardTheme.LIGHT,
    time_range: TimeRange = TimeRange.LAST_7_DAYS,
    owner: str = "",
    tags: Optional[List[str]] = None
) -> Dashboard:
    """
    Create a new dashboard.

    Args:
        name: Dashboard name
        description: Dashboard description
        theme: Color theme
        time_range: Default time range
        owner: Owner user/tenant ID
        tags: Tags for organization

    Returns:
        Configured Dashboard instance
    """
    return Dashboard(
        id="",  # Auto-generated
        name=name,
        description=description,
        theme=theme,
        time_range=time_range,
        owner=owner,
        tags=tags or [],
    )


def create_executive_dashboard(owner: str = "") -> Dashboard:
    """
    Create a pre-configured executive dashboard.

    Includes:
    - Security score gauge
    - Finding summary metrics
    - Compliance overview
    - Trend chart
    - Top issues table

    Args:
        owner: Owner user/tenant ID

    Returns:
        Configured executive dashboard
    """
    dashboard = Dashboard(
        id="",
        name="Executive Security Dashboard",
        description="High-level security overview for executives",
        theme=DashboardTheme.LIGHT,
        owner=owner,
        time_range=TimeRange.LAST_30_DAYS,
        tags=["executive", "security", "overview"],
    )

    # Security score gauge
    dashboard.add_widget(Widget(
        id="security_score",
        widget_type=WidgetType.GAUGE,
        config=MetricConfig(
            title="Security Score",
            description="Overall security posture",
            unit="%",
            format_pattern="{value:.0f}%",
            threshold_warning=70,
            threshold_critical=50,
        ),
        data_source="security_metrics.security_score",
        position=(0, 0),
        size=(3, 2),
    ))

    # Critical findings metric
    dashboard.add_widget(Widget(
        id="critical_findings",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Critical Findings",
            description="Number of critical findings",
            show_trend=True,
            threshold_warning=1,
            threshold_critical=5,
            invert_threshold=False,
        ),
        data_source="security_metrics.critical_findings",
        position=(0, 3),
        size=(2, 1),
    ))

    # High findings metric
    dashboard.add_widget(Widget(
        id="high_findings",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="High Findings",
            description="Number of high severity findings",
            show_trend=True,
            threshold_warning=10,
            threshold_critical=50,
        ),
        data_source="security_metrics.high_findings",
        position=(0, 5),
        size=(2, 1),
    ))

    # Total findings metric
    dashboard.add_widget(Widget(
        id="total_findings",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Total Findings",
            description="Total security findings",
            show_trend=True,
        ),
        data_source="security_metrics.total_findings",
        position=(0, 7),
        size=(2, 1),
    ))

    # Assets at risk
    dashboard.add_widget(Widget(
        id="assets_at_risk",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Assets at Risk",
            description="Assets with critical/high findings",
            show_trend=True,
        ),
        data_source="security_metrics.assets_at_risk",
        position=(0, 9),
        size=(2, 1),
    ))

    # Compliance score
    dashboard.add_widget(Widget(
        id="avg_compliance",
        widget_type=WidgetType.GAUGE,
        config=MetricConfig(
            title="Avg Compliance",
            description="Average compliance score",
            unit="%",
            format_pattern="{value:.0f}%",
            threshold_warning=70,
            threshold_critical=50,
        ),
        data_source="compliance_metrics.average_compliance",
        position=(1, 0),
        size=(3, 2),
    ))

    # Findings trend chart
    dashboard.add_widget(Widget(
        id="findings_trend",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="Findings Trend",
            description="Finding count over time",
            chart_type=ChartType.LINE,
            x_axis_label="Date",
            y_axis_label="Count",
            show_legend=True,
        ),
        data_source="trends.findings_over_time",
        position=(2, 0),
        size=(6, 3),
    ))

    # Severity distribution
    dashboard.add_widget(Widget(
        id="severity_dist",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="Severity Distribution",
            chart_type=ChartType.DONUT,
            color_palette=["#DC2626", "#F97316", "#EAB308", "#3B82F6", "#6B7280"],
        ),
        data_source="findings.by_severity",
        position=(2, 6),
        size=(3, 3),
    ))

    # Compliance by framework
    dashboard.add_widget(Widget(
        id="compliance_frameworks",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="Compliance by Framework",
            chart_type=ChartType.BAR,
            y_axis_label="Score (%)",
        ),
        data_source="compliance.by_framework",
        position=(2, 9),
        size=(3, 3),
    ))

    # Top findings table
    dashboard.add_widget(Widget(
        id="top_findings",
        widget_type=WidgetType.TABLE,
        config=TableConfig(
            title="Top Findings",
            columns=["severity", "title", "asset", "age"],
            column_labels={
                "severity": "Severity",
                "title": "Finding",
                "asset": "Asset",
                "age": "Age",
            },
            page_size=10,
            sortable=True,
            default_sort_column="severity",
        ),
        data_source="findings.top",
        position=(5, 0),
        size=(12, 3),
    ))

    return dashboard


def create_security_ops_dashboard(owner: str = "") -> Dashboard:
    """
    Create a security operations dashboard.

    Includes:
    - Real-time alerts
    - Finding velocity
    - MTTR metrics
    - Asset inventory
    - Recent activity

    Args:
        owner: Owner user/tenant ID

    Returns:
        Configured security ops dashboard
    """
    dashboard = Dashboard(
        id="",
        name="Security Operations Dashboard",
        description="Real-time security operations view",
        theme=DashboardTheme.DARK,
        owner=owner,
        time_range=TimeRange.LAST_24_HOURS,
        auto_refresh=60,  # Refresh every minute
        tags=["secops", "operations", "real-time"],
    )

    # New findings today
    dashboard.add_widget(Widget(
        id="new_today",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="New Today",
            description="Findings discovered today",
            show_trend=False,
        ),
        data_source="findings.new_today",
        position=(0, 0),
        size=(2, 1),
    ))

    # Resolved today
    dashboard.add_widget(Widget(
        id="resolved_today",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Resolved Today",
            description="Findings resolved today",
            show_trend=False,
        ),
        data_source="findings.resolved_today",
        position=(0, 2),
        size=(2, 1),
    ))

    # MTTR
    dashboard.add_widget(Widget(
        id="mttr",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="MTTR",
            description="Mean Time to Remediate",
            unit="hours",
            format_pattern="{value:.1f}h",
            threshold_warning=72,
            threshold_critical=168,
        ),
        data_source="security_metrics.mttr_hours",
        position=(0, 4),
        size=(2, 1),
    ))

    # Finding velocity
    dashboard.add_widget(Widget(
        id="velocity",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Finding Velocity",
            description="New findings per day",
            format_pattern="{value:.1f}/day",
        ),
        data_source="security_metrics.findings_velocity",
        position=(0, 6),
        size=(2, 1),
    ))

    # Scan success rate
    dashboard.add_widget(Widget(
        id="scan_success",
        widget_type=WidgetType.GAUGE,
        config=MetricConfig(
            title="Scan Success",
            description="Collection success rate",
            unit="%",
            threshold_warning=95,
            threshold_critical=90,
        ),
        data_source="operational_metrics.collection_success_rate",
        position=(0, 8),
        size=(2, 2),
    ))

    # Active scans
    dashboard.add_widget(Widget(
        id="active_scans",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Active Scans",
            description="Currently running scans",
        ),
        data_source="operational.active_scans",
        position=(0, 10),
        size=(2, 1),
    ))

    # Real-time findings timeline
    dashboard.add_widget(Widget(
        id="activity_timeline",
        widget_type=WidgetType.TIMELINE,
        config=ChartConfig(
            title="Activity Timeline",
            description="Recent finding activity",
            time_range=TimeRange.LAST_24_HOURS,
        ),
        data_source="activity.timeline",
        position=(1, 0),
        size=(8, 3),
    ))

    # Alerts list
    dashboard.add_widget(Widget(
        id="active_alerts",
        widget_type=WidgetType.ALERT,
        config=TableConfig(
            title="Active Alerts",
            columns=["severity", "message", "time"],
            page_size=5,
        ),
        data_source="alerts.active",
        position=(1, 8),
        size=(4, 3),
    ))

    # Findings by cloud provider
    dashboard.add_widget(Widget(
        id="by_provider",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="By Cloud Provider",
            chart_type=ChartType.PIE,
        ),
        data_source="findings.by_provider",
        position=(4, 0),
        size=(4, 3),
    ))

    # Findings by region
    dashboard.add_widget(Widget(
        id="by_region",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="By Region",
            chart_type=ChartType.BAR,
        ),
        data_source="findings.by_region",
        position=(4, 4),
        size=(4, 3),
    ))

    # Recent scans
    dashboard.add_widget(Widget(
        id="recent_scans",
        widget_type=WidgetType.TABLE,
        config=TableConfig(
            title="Recent Scans",
            columns=["time", "account", "duration", "findings"],
            page_size=5,
        ),
        data_source="scans.recent",
        position=(4, 8),
        size=(4, 3),
    ))

    return dashboard


def create_compliance_dashboard(owner: str = "") -> Dashboard:
    """
    Create a compliance-focused dashboard.

    Includes:
    - Framework compliance scores
    - Control pass/fail rates
    - Compliance trend
    - Gap analysis
    - Failed controls list

    Args:
        owner: Owner user/tenant ID

    Returns:
        Configured compliance dashboard
    """
    dashboard = Dashboard(
        id="",
        name="Compliance Dashboard",
        description="Compliance status and gap analysis",
        theme=DashboardTheme.LIGHT,
        owner=owner,
        time_range=TimeRange.LAST_30_DAYS,
        tags=["compliance", "regulatory", "audit"],
    )

    # Average compliance
    dashboard.add_widget(Widget(
        id="avg_compliance",
        widget_type=WidgetType.GAUGE,
        config=MetricConfig(
            title="Average Compliance",
            description="Average score across frameworks",
            unit="%",
            format_pattern="{value:.0f}%",
            threshold_warning=70,
            threshold_critical=50,
        ),
        data_source="compliance_metrics.average_compliance",
        position=(0, 0),
        size=(4, 2),
    ))

    # Controls passed
    dashboard.add_widget(Widget(
        id="controls_passed",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Controls Passed",
            description="Total passing controls",
        ),
        data_source="compliance_metrics.controls_passed",
        position=(0, 4),
        size=(2, 1),
    ))

    # Controls failed
    dashboard.add_widget(Widget(
        id="controls_failed",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Controls Failed",
            description="Total failing controls",
            threshold_warning=10,
            threshold_critical=50,
        ),
        data_source="compliance_metrics.controls_failed",
        position=(0, 6),
        size=(2, 1),
    ))

    # Frameworks compliant
    dashboard.add_widget(Widget(
        id="frameworks_compliant",
        widget_type=WidgetType.METRIC,
        config=MetricConfig(
            title="Compliant Frameworks",
            description="Frameworks meeting target",
        ),
        data_source="compliance_metrics.frameworks_compliant",
        position=(0, 8),
        size=(2, 1),
    ))

    # Compliance by framework chart
    dashboard.add_widget(Widget(
        id="framework_scores",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="Framework Compliance Scores",
            chart_type=ChartType.HORIZONTAL_BAR,
            x_axis_label="Score (%)",
        ),
        data_source="compliance.by_framework",
        position=(1, 0),
        size=(6, 4),
    ))

    # Compliance trend
    dashboard.add_widget(Widget(
        id="compliance_trend",
        widget_type=WidgetType.CHART,
        config=ChartConfig(
            title="Compliance Trend",
            chart_type=ChartType.LINE,
            x_axis_label="Date",
            y_axis_label="Score (%)",
        ),
        data_source="trends.compliance_over_time",
        position=(1, 6),
        size=(6, 4),
    ))

    # Failed controls table
    dashboard.add_widget(Widget(
        id="failed_controls",
        widget_type=WidgetType.TABLE,
        config=TableConfig(
            title="Failed Controls",
            columns=["framework", "control_id", "description", "severity", "resources"],
            column_labels={
                "framework": "Framework",
                "control_id": "Control",
                "description": "Description",
                "severity": "Severity",
                "resources": "Affected",
            },
            page_size=10,
            sortable=True,
        ),
        data_source="compliance.failed_controls",
        position=(5, 0),
        size=(12, 4),
    ))

    return dashboard


# =============================================================================
# Report Factory Functions
# =============================================================================

def create_report(
    title: str,
    template: str = "executive_summary",
    format: ReportFormat = ReportFormat.PDF,
    time_range: TimeRange = TimeRange.LAST_30_DAYS,
    include_sections: Optional[List[str]] = None,
    filters: Optional[Dict[str, Any]] = None,
    branding: Optional[Dict[str, Any]] = None
) -> ReportConfig:
    """
    Create a report configuration.

    Args:
        title: Report title
        template: Template name
        format: Output format
        time_range: Data time range
        include_sections: Sections to include
        filters: Data filters
        branding: Custom branding

    Returns:
        Configured ReportConfig
    """
    return ReportConfig(
        title=title,
        template=template,
        format=format,
        time_range=time_range,
        include_sections=include_sections or [
            "executive_summary",
            "findings_overview",
            "compliance_status",
            "trends",
            "recommendations",
        ],
        filters=filters or {},
        branding=branding or {},
    )


def create_scheduled_report(
    name: str,
    config: ReportConfig,
    frequency: ReportFrequency = ReportFrequency.WEEKLY,
    delivery_email: Optional[List[str]] = None,
    delivery_webhook: Optional[str] = None,
    delivery_storage: Optional[str] = None,
    tenant_id: Optional[str] = None
) -> ScheduledReport:
    """
    Create a scheduled report.

    Args:
        name: Schedule name
        config: Report configuration
        frequency: Generation frequency
        delivery_email: Email recipients
        delivery_webhook: Webhook URL
        delivery_storage: Storage path
        tenant_id: Tenant ID for multi-tenant

    Returns:
        Configured ScheduledReport
    """
    deliveries = []

    if delivery_email:
        deliveries.append(ReportDelivery(
            channel="email",
            recipients=delivery_email,
            settings={
                "from_address": "reports@mantissa-stance.local",
                "subject": f"Security Report: {config.title}",
            }
        ))

    if delivery_webhook:
        deliveries.append(ReportDelivery(
            channel="webhook",
            recipients=[delivery_webhook],
            settings={
                "include_content": False,
            }
        ))

    if delivery_storage:
        deliveries.append(ReportDelivery(
            channel="storage",
            recipients=[delivery_storage],
            settings={}
        ))

    return ScheduledReport(
        id="",  # Auto-generated
        name=name,
        config=config,
        frequency=frequency,
        delivery=deliveries,
        tenant_id=tenant_id,
    )
