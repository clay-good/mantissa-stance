"""
Dashboard and report data models for Mantissa Stance.

Provides data structures for dashboards, widgets, reports, and scheduling.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union


# =============================================================================
# Enums
# =============================================================================

class WidgetType(Enum):
    """Types of dashboard widgets."""
    METRIC = "metric"
    CHART = "chart"
    TABLE = "table"
    LIST = "list"
    GAUGE = "gauge"
    HEATMAP = "heatmap"
    MAP = "map"
    TIMELINE = "timeline"
    TEXT = "text"
    ALERT = "alert"


class ChartType(Enum):
    """Types of charts."""
    LINE = "line"
    BAR = "bar"
    HORIZONTAL_BAR = "horizontal_bar"
    PIE = "pie"
    DONUT = "donut"
    AREA = "area"
    STACKED_AREA = "stacked_area"
    STACKED_BAR = "stacked_bar"
    SCATTER = "scatter"
    BUBBLE = "bubble"
    RADAR = "radar"
    TREEMAP = "treemap"
    FUNNEL = "funnel"
    SPARKLINE = "sparkline"


class TimeRange(Enum):
    """Time ranges for data queries."""
    LAST_HOUR = "last_hour"
    LAST_24_HOURS = "last_24_hours"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    LAST_YEAR = "last_year"
    CUSTOM = "custom"
    ALL_TIME = "all_time"

    def to_timedelta(self) -> Optional[timedelta]:
        """Convert to timedelta."""
        mapping = {
            TimeRange.LAST_HOUR: timedelta(hours=1),
            TimeRange.LAST_24_HOURS: timedelta(days=1),
            TimeRange.LAST_7_DAYS: timedelta(days=7),
            TimeRange.LAST_30_DAYS: timedelta(days=30),
            TimeRange.LAST_90_DAYS: timedelta(days=90),
            TimeRange.LAST_YEAR: timedelta(days=365),
        }
        return mapping.get(self)


class ReportFormat(Enum):
    """Report output formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"
    XLSX = "xlsx"


class ReportFrequency(Enum):
    """Report generation frequency."""
    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"

    def to_timedelta(self) -> Optional[timedelta]:
        """Convert to timedelta for scheduling."""
        mapping = {
            ReportFrequency.HOURLY: timedelta(hours=1),
            ReportFrequency.DAILY: timedelta(days=1),
            ReportFrequency.WEEKLY: timedelta(weeks=1),
            ReportFrequency.BIWEEKLY: timedelta(weeks=2),
            ReportFrequency.MONTHLY: timedelta(days=30),
            ReportFrequency.QUARTERLY: timedelta(days=90),
            ReportFrequency.YEARLY: timedelta(days=365),
        }
        return mapping.get(self)


class DashboardTheme(Enum):
    """Dashboard color themes."""
    LIGHT = "light"
    DARK = "dark"
    HIGH_CONTRAST = "high_contrast"
    COLORBLIND_SAFE = "colorblind_safe"
    PRINT = "print"


class MetricAggregation(Enum):
    """Metric aggregation methods."""
    SUM = "sum"
    AVG = "avg"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    LAST = "last"
    FIRST = "first"
    MEDIAN = "median"
    P95 = "p95"
    P99 = "p99"


# =============================================================================
# Widget Configurations
# =============================================================================

@dataclass
class WidgetConfig:
    """Base configuration for widgets."""
    title: str
    description: str = ""
    time_range: TimeRange = TimeRange.LAST_7_DAYS
    refresh_interval_seconds: int = 300
    show_legend: bool = True
    show_title: bool = True
    custom_css: str = ""
    click_action: Optional[str] = None
    drill_down_enabled: bool = False
    filters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChartConfig(WidgetConfig):
    """Configuration for chart widgets."""
    chart_type: ChartType = ChartType.LINE
    x_axis_label: str = ""
    y_axis_label: str = ""
    show_grid: bool = True
    show_data_labels: bool = False
    stacked: bool = False
    fill_area: bool = False
    smooth_lines: bool = True
    color_palette: List[str] = field(default_factory=lambda: [
        "#3B82F6", "#EF4444", "#10B981", "#F59E0B", "#8B5CF6",
        "#EC4899", "#06B6D4", "#84CC16", "#F97316", "#6366F1"
    ])
    min_y: Optional[float] = None
    max_y: Optional[float] = None


@dataclass
class MetricConfig(WidgetConfig):
    """Configuration for metric widgets."""
    unit: str = ""
    format_pattern: str = "{value}"
    show_trend: bool = True
    show_sparkline: bool = False
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    invert_threshold: bool = False  # True = lower is worse
    comparison_period: Optional[TimeRange] = None
    aggregation: MetricAggregation = MetricAggregation.LAST


@dataclass
class TableConfig(WidgetConfig):
    """Configuration for table widgets."""
    columns: List[str] = field(default_factory=list)
    column_labels: Dict[str, str] = field(default_factory=dict)
    sortable: bool = True
    default_sort_column: str = ""
    default_sort_ascending: bool = True
    page_size: int = 10
    show_pagination: bool = True
    highlight_rules: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    row_click_action: Optional[str] = None


# =============================================================================
# Widget and Dashboard
# =============================================================================

@dataclass
class Widget:
    """
    A dashboard widget displaying data.

    Attributes:
        id: Unique identifier
        widget_type: Type of widget
        config: Widget configuration
        data_source: Name of data source function
        position: Grid position (row, col)
        size: Widget size (width, height in grid units)
        visible: Whether widget is visible
        cached_data: Last fetched data
        last_updated: Last data refresh time
    """
    id: str
    widget_type: WidgetType
    config: WidgetConfig
    data_source: str
    position: tuple = (0, 0)  # (row, col)
    size: tuple = (1, 1)  # (width, height)
    visible: bool = True
    cached_data: Optional[Any] = None
    last_updated: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]

    def needs_refresh(self) -> bool:
        """Check if widget data needs refresh."""
        if self.last_updated is None:
            return True
        elapsed = (datetime.utcnow() - self.last_updated).total_seconds()
        return elapsed >= self.config.refresh_interval_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "widget_type": self.widget_type.value,
            "title": self.config.title,
            "data_source": self.data_source,
            "position": self.position,
            "size": self.size,
            "visible": self.visible,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }


@dataclass
class DashboardLayout:
    """Dashboard grid layout configuration."""
    columns: int = 12
    row_height: int = 100
    margin: int = 10
    responsive_breakpoints: Dict[str, int] = field(default_factory=lambda: {
        "xs": 480,
        "sm": 768,
        "md": 1024,
        "lg": 1280,
        "xl": 1920,
    })


@dataclass
class Dashboard:
    """
    A customizable dashboard with widgets.

    Attributes:
        id: Unique identifier
        name: Dashboard name
        description: Dashboard description
        owner: Owner user/tenant ID
        theme: Color theme
        layout: Grid layout configuration
        widgets: List of widgets
        filters: Global dashboard filters
        time_range: Default time range
        auto_refresh: Auto-refresh interval in seconds
        is_public: Whether dashboard is publicly accessible
        tags: Tags for organization
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """
    id: str
    name: str
    description: str = ""
    owner: str = ""
    theme: DashboardTheme = DashboardTheme.LIGHT
    layout: DashboardLayout = field(default_factory=DashboardLayout)
    widgets: List[Widget] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    time_range: TimeRange = TimeRange.LAST_7_DAYS
    auto_refresh: int = 300
    is_public: bool = False
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def add_widget(self, widget: Widget) -> None:
        """Add a widget to the dashboard."""
        self.widgets.append(widget)
        self.updated_at = datetime.utcnow()

    def remove_widget(self, widget_id: str) -> bool:
        """Remove a widget by ID."""
        for i, w in enumerate(self.widgets):
            if w.id == widget_id:
                self.widgets.pop(i)
                self.updated_at = datetime.utcnow()
                return True
        return False

    def get_widget(self, widget_id: str) -> Optional[Widget]:
        """Get a widget by ID."""
        for w in self.widgets:
            if w.id == widget_id:
                return w
        return None

    def get_widgets_by_type(self, widget_type: WidgetType) -> List[Widget]:
        """Get all widgets of a specific type."""
        return [w for w in self.widgets if w.widget_type == widget_type]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner": self.owner,
            "theme": self.theme.value,
            "widget_count": len(self.widgets),
            "widgets": [w.to_dict() for w in self.widgets],
            "time_range": self.time_range.value,
            "auto_refresh": self.auto_refresh,
            "is_public": self.is_public,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


# =============================================================================
# Report Models
# =============================================================================

@dataclass
class ReportSection:
    """
    A section within a report.

    Attributes:
        id: Section identifier
        title: Section title
        content_type: Type of content (text, chart, table, etc.)
        content: Section content
        order: Display order
        page_break_before: Insert page break before section
        visible: Whether section is included
    """
    id: str
    title: str
    content_type: str = "text"
    content: Any = None
    order: int = 0
    page_break_before: bool = False
    visible: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "content_type": self.content_type,
            "order": self.order,
            "visible": self.visible,
        }


@dataclass
class ReportConfig:
    """
    Configuration for report generation.

    Attributes:
        title: Report title
        subtitle: Report subtitle
        author: Author name
        format: Output format
        template: Template name to use
        time_range: Data time range
        include_sections: Sections to include
        filters: Data filters
        branding: Custom branding options
        page_size: Page size (A4, Letter, etc.)
        orientation: Portrait or landscape
    """
    title: str
    subtitle: str = ""
    author: str = "Mantissa Stance"
    format: ReportFormat = ReportFormat.PDF
    template: str = "default"
    time_range: TimeRange = TimeRange.LAST_30_DAYS
    include_sections: List[str] = field(default_factory=lambda: [
        "executive_summary",
        "findings_overview",
        "compliance_status",
        "trends",
        "recommendations",
    ])
    filters: Dict[str, Any] = field(default_factory=dict)
    branding: Dict[str, Any] = field(default_factory=lambda: {
        "logo_url": None,
        "primary_color": "#3B82F6",
        "secondary_color": "#1E40AF",
        "font_family": "Arial, sans-serif",
    })
    page_size: str = "A4"
    orientation: str = "portrait"
    include_charts: bool = True
    include_tables: bool = True
    include_appendix: bool = False
    watermark: str = ""
    confidentiality: str = "Internal"


@dataclass
class ReportDelivery:
    """
    Report delivery configuration.

    Attributes:
        channel: Delivery channel (email, webhook, storage)
        recipients: List of recipients
        settings: Channel-specific settings
    """
    channel: str
    recipients: List[str] = field(default_factory=list)
    settings: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "channel": self.channel,
            "recipients": self.recipients,
            "settings": self.settings,
        }


@dataclass
class ScheduledReport:
    """
    A scheduled report configuration.

    Attributes:
        id: Unique identifier
        name: Schedule name
        config: Report configuration
        frequency: Generation frequency
        delivery: Delivery options
        enabled: Whether schedule is active
        next_run: Next scheduled run time
        last_run: Last run time
        last_status: Status of last run
        run_count: Total runs
        failure_count: Failed runs
        created_at: Creation timestamp
        created_by: Creator user ID
    """
    id: str
    name: str
    config: ReportConfig
    frequency: ReportFrequency = ReportFrequency.WEEKLY
    delivery: List[ReportDelivery] = field(default_factory=list)
    enabled: bool = True
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    last_status: str = "pending"
    run_count: int = 0
    failure_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    tenant_id: Optional[str] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if self.next_run is None:
            self.next_run = self._calculate_next_run()

    def _calculate_next_run(self) -> datetime:
        """Calculate next run time based on frequency."""
        now = datetime.utcnow()
        delta = self.frequency.to_timedelta()
        if delta:
            return now + delta
        return now

    def update_after_run(self, success: bool) -> None:
        """Update schedule after a run."""
        self.last_run = datetime.utcnow()
        self.run_count += 1
        if success:
            self.last_status = "success"
        else:
            self.last_status = "failed"
            self.failure_count += 1
        self.next_run = self._calculate_next_run()

    def is_due(self) -> bool:
        """Check if report is due for generation."""
        if not self.enabled:
            return False
        if self.next_run is None:
            return True
        return datetime.utcnow() >= self.next_run

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "frequency": self.frequency.value,
            "enabled": self.enabled,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_status": self.last_status,
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "delivery_channels": [d.channel for d in self.delivery],
        }


@dataclass
class GeneratedReport:
    """
    A generated report instance.

    Attributes:
        id: Report instance ID
        schedule_id: Source schedule ID (if scheduled)
        config: Report configuration used
        format: Output format
        content: Report content (bytes or string)
        file_path: Path to saved file
        file_size: Size in bytes
        generated_at: Generation timestamp
        generation_time_seconds: Time to generate
        sections: Included sections
        metadata: Additional metadata
    """
    id: str
    schedule_id: Optional[str]
    config: ReportConfig
    format: ReportFormat
    content: Union[bytes, str, None] = None
    file_path: Optional[str] = None
    file_size: int = 0
    generated_at: datetime = field(default_factory=datetime.utcnow)
    generation_time_seconds: float = 0.0
    sections: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "schedule_id": self.schedule_id,
            "title": self.config.title,
            "format": self.format.value,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "generated_at": self.generated_at.isoformat(),
            "generation_time_seconds": self.generation_time_seconds,
            "sections": self.sections,
        }
