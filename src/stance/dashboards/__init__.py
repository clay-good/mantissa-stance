"""
Advanced Reporting & Dashboards module for Mantissa Stance.

Provides comprehensive reporting, visualization, and dashboard capabilities:
- Real-time security dashboards with customizable widgets
- Compliance report generation with multiple formats
- Executive and technical report templates
- Trend analysis and forecasting
- Chart and visualization generation
- Report scheduling and distribution
- Multi-tenant dashboard support
- Interactive charts with drill-down (Phase 94)
- Widget builder with drag-and-drop (Phase 94)
- Dashboard embedding and sharing (Phase 94)
- Real-time streaming updates via SSE/WebSocket (Phase 94)

Components:
- Dashboard: Customizable dashboard layouts and widgets
- Report Generator: Multi-format report generation
- Visualizations: Charts, graphs, and metrics displays
- Report Scheduler: Automated report generation and delivery
- Templates: Pre-built and custom report templates
- Interactive: Drill-down charts and interactive components
- Widget Builder: Drag-and-drop dashboard construction
- Embedding: Secure dashboard embedding and sharing
- Real-time: SSE/WebSocket streaming and live updates

Part of Phase 91: Advanced Reporting & Dashboards
Enhanced in Phase 94: Enhanced Visualization
"""

from stance.dashboards.models import (
    # Enums
    WidgetType,
    ChartType,
    TimeRange,
    ReportFormat,
    ReportFrequency,
    DashboardTheme,
    MetricAggregation,
    # Widget configurations
    WidgetConfig,
    ChartConfig,
    MetricConfig,
    TableConfig,
    # Widget and dashboard
    Widget,
    DashboardLayout,
    Dashboard,
    # Report models
    ReportSection,
    ReportConfig,
    ScheduledReport,
    ReportDelivery,
    GeneratedReport,
)

from stance.dashboards.visualizations import (
    # Chart data
    DataPoint,
    DataSeries,
    ChartData,
    # Chart builders
    ChartBuilder,
    LineChartBuilder,
    BarChartBuilder,
    PieChartBuilder,
    AreaChartBuilder,
    # Renderers
    ChartRenderer,
    SVGRenderer,
    ASCIIRenderer,
    # Visualization factory
    create_chart,
    create_trend_chart,
    create_severity_chart,
    create_compliance_chart,
)

from stance.dashboards.reports import (
    # Report templates
    ReportTemplate,
    ExecutiveSummaryTemplate,
    TechnicalDetailTemplate,
    ComplianceReportTemplate,
    TrendReportTemplate,
    # Report generator
    ReportGenerator,
    # Report sections
    SectionBuilder,
    ExecutiveSummarySection,
    FindingsSection,
    ComplianceSection,
    TrendSection,
    RecommendationsSection,
)

from stance.dashboards.scheduler import (
    # Scheduler
    ReportScheduler,
    ScheduleEntry,
    ScheduleStatus,
    # Delivery
    DeliveryChannel,
    EmailDelivery,
    WebhookDelivery,
    StorageDelivery,
    # Distribution
    ReportDistributor,
)

from stance.dashboards.metrics import (
    # Metric types
    DashboardMetric,
    MetricValue,
    MetricTrend,
    # Aggregators
    MetricsAggregator,
    SecurityMetrics,
    ComplianceMetrics,
    OperationalMetrics,
    # Calculators
    calculate_security_score,
    calculate_risk_trend,
    calculate_compliance_gap,
)

from stance.dashboards.factory import (
    # Factory functions
    create_dashboard,
    create_executive_dashboard,
    create_security_ops_dashboard,
    create_compliance_dashboard,
    create_report,
    create_scheduled_report,
)

# Phase 94: Enhanced Visualization
from stance.dashboards.realtime import (
    # Event types
    EventType,
    ConnectionState,
    # Event data
    RealtimeEvent,
    Subscription,
    ClientConnection,
    # Event system
    EventBus,
    DashboardStreamManager,
    SSEHandler,
    # Factory functions
    create_event_bus,
    create_stream_manager,
    create_sse_handler,
)

from stance.dashboards.interactive import (
    # Enums
    InteractionType,
    DrillDownLevel,
    SelectionMode,
    TooltipPosition,
    AnimationType,
    # Data structures
    DrillDownPath,
    ChartInteraction,
    TooltipConfig,
    ZoomConfig,
    SelectionConfig,
    AnimationConfig,
    InteractiveChartConfig,
    # Interactive charts
    InteractiveChart,
    DrillDownBarChart,
    TimeSeriesDrillChart,
    FilterableChart,
    # Manager
    ChartInteractionManager,
    # Factory functions
    create_interactive_chart,
    create_interaction_manager,
    create_drilldown_config,
)

from stance.dashboards.widget_builder import (
    # Enums
    DragState,
    DropZone,
    SnapMode,
    WidgetCategory,
    # Templates
    WidgetTemplate,
    WidgetPalette,
    # Drag and drop
    DragItem,
    DropTarget,
    DragDropManager,
    # Layout
    LayoutManager,
    # Builder
    WidgetBuilder,
    # Factory functions
    create_widget_builder,
    create_widget_palette,
    create_layout_manager,
    create_drag_manager,
)

from stance.dashboards.embedding import (
    # Enums
    ShareType,
    AccessLevel,
    EmbedMode,
    TokenType,
    # Sharing
    SharePermission,
    ShareSettings,
    # Tokens
    EmbedToken,
    ShareLink,
    # Manager
    EmbeddingManager,
    # Renderer
    EmbedConfig,
    EmbedRenderer,
    # Factory functions
    create_embedding_manager,
    create_embed_renderer,
    create_share_settings,
    create_embed_token,
    create_share_link,
)

from stance.dashboards.updates import (
    # Enums
    UpdateStrategy,
    UpdatePriority,
    WidgetStatus,
    # Data providers
    DataProviderConfig,
    DataProvider,
    RateLimitError,
    # State tracking
    WidgetUpdateState,
    # Update manager
    DashboardUpdateManager,
    BatchUpdateCoordinator,
    LiveMetricTracker,
    # Factory functions
    create_update_manager,
    create_batch_coordinator,
    create_metric_tracker,
    create_data_provider_config,
)

__all__ = [
    # Enums
    "WidgetType",
    "ChartType",
    "TimeRange",
    "ReportFormat",
    "ReportFrequency",
    "DashboardTheme",
    "MetricAggregation",
    # Widget configurations
    "WidgetConfig",
    "ChartConfig",
    "MetricConfig",
    "TableConfig",
    # Widget and dashboard
    "Widget",
    "DashboardLayout",
    "Dashboard",
    # Report models
    "ReportSection",
    "ReportConfig",
    "ScheduledReport",
    "ReportDelivery",
    "GeneratedReport",
    # Chart data
    "DataPoint",
    "DataSeries",
    "ChartData",
    # Chart builders
    "ChartBuilder",
    "LineChartBuilder",
    "BarChartBuilder",
    "PieChartBuilder",
    "AreaChartBuilder",
    # Renderers
    "ChartRenderer",
    "SVGRenderer",
    "ASCIIRenderer",
    # Visualization factory
    "create_chart",
    "create_trend_chart",
    "create_severity_chart",
    "create_compliance_chart",
    # Report templates
    "ReportTemplate",
    "ExecutiveSummaryTemplate",
    "TechnicalDetailTemplate",
    "ComplianceReportTemplate",
    "TrendReportTemplate",
    # Report generator
    "ReportGenerator",
    # Report sections
    "SectionBuilder",
    "ExecutiveSummarySection",
    "FindingsSection",
    "ComplianceSection",
    "TrendSection",
    "RecommendationsSection",
    # Scheduler
    "ReportScheduler",
    "ScheduleEntry",
    "ScheduleStatus",
    # Delivery
    "DeliveryChannel",
    "EmailDelivery",
    "WebhookDelivery",
    "StorageDelivery",
    # Distribution
    "ReportDistributor",
    # Metric types
    "DashboardMetric",
    "MetricValue",
    "MetricTrend",
    # Aggregators
    "MetricsAggregator",
    "SecurityMetrics",
    "ComplianceMetrics",
    "OperationalMetrics",
    # Calculators
    "calculate_security_score",
    "calculate_risk_trend",
    "calculate_compliance_gap",
    # Factory functions
    "create_dashboard",
    "create_executive_dashboard",
    "create_security_ops_dashboard",
    "create_compliance_dashboard",
    "create_report",
    "create_scheduled_report",
    # Phase 94: Real-time streaming
    "EventType",
    "ConnectionState",
    "RealtimeEvent",
    "Subscription",
    "ClientConnection",
    "EventBus",
    "DashboardStreamManager",
    "SSEHandler",
    "create_event_bus",
    "create_stream_manager",
    "create_sse_handler",
    # Phase 94: Interactive charts
    "InteractionType",
    "DrillDownLevel",
    "SelectionMode",
    "TooltipPosition",
    "AnimationType",
    "DrillDownPath",
    "ChartInteraction",
    "TooltipConfig",
    "ZoomConfig",
    "SelectionConfig",
    "AnimationConfig",
    "InteractiveChartConfig",
    "InteractiveChart",
    "DrillDownBarChart",
    "TimeSeriesDrillChart",
    "FilterableChart",
    "ChartInteractionManager",
    "create_interactive_chart",
    "create_interaction_manager",
    "create_drilldown_config",
    # Phase 94: Widget builder
    "DragState",
    "DropZone",
    "SnapMode",
    "WidgetCategory",
    "WidgetTemplate",
    "WidgetPalette",
    "DragItem",
    "DropTarget",
    "DragDropManager",
    "LayoutManager",
    "WidgetBuilder",
    "create_widget_builder",
    "create_widget_palette",
    "create_layout_manager",
    "create_drag_manager",
    # Phase 94: Embedding
    "ShareType",
    "AccessLevel",
    "EmbedMode",
    "TokenType",
    "SharePermission",
    "ShareSettings",
    "EmbedToken",
    "ShareLink",
    "EmbeddingManager",
    "EmbedConfig",
    "EmbedRenderer",
    "create_embedding_manager",
    "create_embed_renderer",
    "create_share_settings",
    "create_embed_token",
    "create_share_link",
    # Phase 94: Updates
    "UpdateStrategy",
    "UpdatePriority",
    "WidgetStatus",
    "DataProviderConfig",
    "DataProvider",
    "RateLimitError",
    "WidgetUpdateState",
    "DashboardUpdateManager",
    "BatchUpdateCoordinator",
    "LiveMetricTracker",
    "create_update_manager",
    "create_batch_coordinator",
    "create_metric_tracker",
    "create_data_provider_config",
]
