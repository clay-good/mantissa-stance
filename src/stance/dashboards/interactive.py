"""
Interactive chart components with drill-down capabilities for Mantissa Stance.

Provides interactive charts, drill-down navigation, data exploration,
click handlers, tooltips, and zoom/pan capabilities.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from stance.dashboards.models import (
    ChartType,
    ChartConfig,
    TimeRange,
    WidgetType,
)
from stance.dashboards.visualizations import (
    ChartData,
    DataPoint,
    DataSeries,
)


# =============================================================================
# Interactive Chart Enums
# =============================================================================

class InteractionType(Enum):
    """Types of chart interactions."""
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    HOVER = "hover"
    DRAG = "drag"
    ZOOM = "zoom"
    PAN = "pan"
    SELECT = "select"
    BRUSH = "brush"
    CONTEXT_MENU = "context_menu"


class DrillDownLevel(Enum):
    """Drill-down hierarchy levels."""
    OVERVIEW = "overview"
    CATEGORY = "category"
    SUBCATEGORY = "subcategory"
    ITEM = "item"
    DETAIL = "detail"


class SelectionMode(Enum):
    """Data selection modes."""
    SINGLE = "single"
    MULTIPLE = "multiple"
    RANGE = "range"
    LASSO = "lasso"


class TooltipPosition(Enum):
    """Tooltip positioning."""
    TOP = "top"
    BOTTOM = "bottom"
    LEFT = "left"
    RIGHT = "right"
    AUTO = "auto"
    CURSOR = "cursor"


class AnimationType(Enum):
    """Chart animation types."""
    NONE = "none"
    FADE = "fade"
    SLIDE = "slide"
    SCALE = "scale"
    BOUNCE = "bounce"
    SPRING = "spring"


# =============================================================================
# Interactive Data Structures
# =============================================================================

@dataclass
class DrillDownPath:
    """
    Represents a path through drill-down hierarchy.

    Tracks the navigation path from overview to current view.
    """
    levels: List[Dict[str, Any]] = field(default_factory=list)
    current_level: DrillDownLevel = DrillDownLevel.OVERVIEW
    max_depth: int = 5

    def push(self, level: DrillDownLevel, context: Dict[str, Any]) -> bool:
        """Push a new level onto the path."""
        if len(self.levels) >= self.max_depth:
            return False

        self.levels.append({
            "level": level,
            "context": context,
            "timestamp": datetime.utcnow().isoformat(),
        })
        self.current_level = level
        return True

    def pop(self) -> Optional[Dict[str, Any]]:
        """Pop the current level and return to parent."""
        if not self.levels:
            return None

        popped = self.levels.pop()
        if self.levels:
            self.current_level = self.levels[-1]["level"]
        else:
            self.current_level = DrillDownLevel.OVERVIEW
        return popped

    def peek(self) -> Optional[Dict[str, Any]]:
        """Get current level context without popping."""
        if not self.levels:
            return None
        return self.levels[-1]

    def get_breadcrumbs(self) -> List[str]:
        """Get breadcrumb trail for navigation UI."""
        crumbs = ["Overview"]
        for level in self.levels:
            ctx = level.get("context", {})
            label = ctx.get("label", ctx.get("id", level["level"].value))
            crumbs.append(str(label))
        return crumbs

    def reset(self) -> None:
        """Reset to overview level."""
        self.levels.clear()
        self.current_level = DrillDownLevel.OVERVIEW

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "levels": self.levels,
            "current_level": self.current_level.value,
            "breadcrumbs": self.get_breadcrumbs(),
            "can_drill_up": len(self.levels) > 0,
            "depth": len(self.levels),
        }


@dataclass
class ChartInteraction:
    """
    Represents a user interaction with a chart.

    Captures interaction type, target element, and event data.
    """
    id: str = ""
    interaction_type: InteractionType = InteractionType.CLICK
    chart_id: str = ""
    element_type: str = ""  # point, bar, slice, legend, axis, etc.
    element_index: int = -1
    series_index: int = -1
    data_point: Optional[DataPoint] = None
    coordinates: Tuple[float, float] = (0.0, 0.0)
    modifier_keys: Set[str] = field(default_factory=set)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.interaction_type.value,
            "chart_id": self.chart_id,
            "element_type": self.element_type,
            "element_index": self.element_index,
            "series_index": self.series_index,
            "coordinates": self.coordinates,
            "modifier_keys": list(self.modifier_keys),
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class TooltipConfig:
    """Configuration for chart tooltips."""
    enabled: bool = True
    position: TooltipPosition = TooltipPosition.AUTO
    delay_ms: int = 200
    show_series_name: bool = True
    show_value: bool = True
    show_percentage: bool = False
    format_value: str = "{value}"
    custom_template: Optional[str] = None
    background_color: str = "#1F2937"
    text_color: str = "#FFFFFF"
    border_radius: int = 4
    padding: int = 8
    max_width: int = 300


@dataclass
class ZoomConfig:
    """Configuration for chart zoom/pan."""
    enabled: bool = True
    enable_x: bool = True
    enable_y: bool = True
    min_zoom: float = 0.1
    max_zoom: float = 10.0
    zoom_speed: float = 0.1
    enable_wheel_zoom: bool = True
    enable_pinch_zoom: bool = True
    enable_drag_pan: bool = True
    reset_on_double_click: bool = True


@dataclass
class SelectionConfig:
    """Configuration for data selection."""
    enabled: bool = True
    mode: SelectionMode = SelectionMode.SINGLE
    highlight_selected: bool = True
    dim_unselected: bool = True
    selected_color: str = "#3B82F6"
    unselected_opacity: float = 0.3
    enable_keyboard_nav: bool = True


@dataclass
class AnimationConfig:
    """Configuration for chart animations."""
    enabled: bool = True
    type: AnimationType = AnimationType.FADE
    duration_ms: int = 300
    easing: str = "ease-out"
    stagger_ms: int = 50  # Delay between elements
    on_load: bool = True
    on_update: bool = True
    on_hover: bool = True


# =============================================================================
# Interactive Chart Components
# =============================================================================

@dataclass
class InteractiveChartConfig:
    """
    Configuration for interactive charts.

    Combines all interactive features into a single config.
    """
    chart_config: ChartConfig = field(default_factory=lambda: ChartConfig(title="Interactive Chart"))
    tooltip: TooltipConfig = field(default_factory=TooltipConfig)
    zoom: ZoomConfig = field(default_factory=ZoomConfig)
    selection: SelectionConfig = field(default_factory=SelectionConfig)
    animation: AnimationConfig = field(default_factory=AnimationConfig)
    drill_down_enabled: bool = True
    drill_down_levels: Dict[str, DrillDownLevel] = field(default_factory=dict)
    click_handler: Optional[str] = None
    context_menu_items: List[Dict[str, Any]] = field(default_factory=list)
    keyboard_shortcuts: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        # Default keyboard shortcuts
        if not self.keyboard_shortcuts:
            self.keyboard_shortcuts = {
                "Escape": "deselect_all",
                "Enter": "drill_down",
                "Backspace": "drill_up",
                "ArrowUp": "select_prev",
                "ArrowDown": "select_next",
                "+": "zoom_in",
                "-": "zoom_out",
                "r": "reset_zoom",
            }

        # Default context menu items
        if not self.context_menu_items:
            self.context_menu_items = [
                {"id": "drill_down", "label": "Drill Down", "icon": "search"},
                {"id": "filter", "label": "Filter by This", "icon": "filter"},
                {"id": "exclude", "label": "Exclude This", "icon": "x"},
                {"id": "separator", "type": "separator"},
                {"id": "export", "label": "Export Data", "icon": "download"},
                {"id": "copy", "label": "Copy Value", "icon": "copy"},
            ]


class InteractiveChart:
    """
    Base class for interactive charts.

    Provides drill-down, zoom, selection, and event handling.
    """

    def __init__(
        self,
        chart_id: str,
        config: Optional[InteractiveChartConfig] = None,
    ):
        self.chart_id = chart_id
        self.config = config or InteractiveChartConfig()
        self.data: Optional[ChartData] = None
        self.drill_path = DrillDownPath()
        self.selected_indices: Set[int] = set()
        self.zoom_state = {"x": [0, 1], "y": [0, 1], "scale": 1.0}
        self.interaction_handlers: Dict[InteractionType, List[Callable]] = {}
        self.interaction_history: List[ChartInteraction] = []
        self.data_provider: Optional[Callable[[DrillDownPath], ChartData]] = None

    def set_data(self, data: ChartData) -> None:
        """Set chart data."""
        self.data = data

    def set_data_provider(
        self,
        provider: Callable[[DrillDownPath], ChartData]
    ) -> None:
        """Set data provider function for drill-down."""
        self.data_provider = provider

    def register_handler(
        self,
        interaction_type: InteractionType,
        handler: Callable[[ChartInteraction], None]
    ) -> None:
        """Register an interaction handler."""
        if interaction_type not in self.interaction_handlers:
            self.interaction_handlers[interaction_type] = []
        self.interaction_handlers[interaction_type].append(handler)

    def handle_interaction(self, interaction: ChartInteraction) -> Dict[str, Any]:
        """
        Process a chart interaction.

        Returns response with any state changes.
        """
        # Record interaction
        self.interaction_history.append(interaction)
        if len(self.interaction_history) > 100:
            self.interaction_history = self.interaction_history[-50:]

        response: Dict[str, Any] = {
            "handled": True,
            "interaction_id": interaction.id,
            "actions": [],
        }

        # Handle based on type
        if interaction.interaction_type == InteractionType.CLICK:
            response["actions"].extend(self._handle_click(interaction))
        elif interaction.interaction_type == InteractionType.DOUBLE_CLICK:
            response["actions"].extend(self._handle_double_click(interaction))
        elif interaction.interaction_type == InteractionType.HOVER:
            response["actions"].extend(self._handle_hover(interaction))
        elif interaction.interaction_type == InteractionType.ZOOM:
            response["actions"].extend(self._handle_zoom(interaction))
        elif interaction.interaction_type == InteractionType.SELECT:
            response["actions"].extend(self._handle_select(interaction))

        # Notify registered handlers
        handlers = self.interaction_handlers.get(interaction.interaction_type, [])
        for handler in handlers:
            try:
                handler(interaction)
            except Exception:
                pass  # Ignore handler errors

        return response

    def _handle_click(self, interaction: ChartInteraction) -> List[Dict[str, Any]]:
        """Handle click interaction."""
        actions = []

        # Selection logic
        if self.config.selection.enabled and interaction.element_type in ("point", "bar", "slice"):
            if self.config.selection.mode == SelectionMode.SINGLE:
                self.selected_indices = {interaction.element_index}
            elif self.config.selection.mode == SelectionMode.MULTIPLE:
                if "Shift" in interaction.modifier_keys or "Meta" in interaction.modifier_keys:
                    if interaction.element_index in self.selected_indices:
                        self.selected_indices.discard(interaction.element_index)
                    else:
                        self.selected_indices.add(interaction.element_index)
                else:
                    self.selected_indices = {interaction.element_index}

            actions.append({
                "type": "selection_changed",
                "selected": list(self.selected_indices),
            })

        return actions

    def _handle_double_click(self, interaction: ChartInteraction) -> List[Dict[str, Any]]:
        """Handle double-click interaction."""
        actions = []

        # Drill down on double-click
        if self.config.drill_down_enabled and interaction.element_type in ("point", "bar", "slice"):
            drill_result = self.drill_down(
                interaction.element_index,
                interaction.metadata
            )
            if drill_result:
                actions.append({
                    "type": "drill_down",
                    "path": self.drill_path.to_dict(),
                    "new_data": drill_result.to_dict() if hasattr(drill_result, "to_dict") else None,
                })

        # Reset zoom on empty area double-click
        if interaction.element_type == "background" and self.config.zoom.reset_on_double_click:
            self.reset_zoom()
            actions.append({"type": "zoom_reset"})

        return actions

    def _handle_hover(self, interaction: ChartInteraction) -> List[Dict[str, Any]]:
        """Handle hover interaction."""
        actions = []

        if self.config.tooltip.enabled and interaction.data_point:
            tooltip_data = self._build_tooltip(interaction)
            actions.append({
                "type": "show_tooltip",
                "data": tooltip_data,
                "position": interaction.coordinates,
            })

        return actions

    def _handle_zoom(self, interaction: ChartInteraction) -> List[Dict[str, Any]]:
        """Handle zoom interaction."""
        actions = []

        if not self.config.zoom.enabled:
            return actions

        zoom_delta = interaction.metadata.get("delta", 0)
        center = interaction.coordinates

        new_scale = self.zoom_state["scale"] * (1 + zoom_delta * self.config.zoom.zoom_speed)
        new_scale = max(self.config.zoom.min_zoom, min(self.config.zoom.max_zoom, new_scale))

        self.zoom_state["scale"] = new_scale

        actions.append({
            "type": "zoom_changed",
            "scale": new_scale,
            "center": center,
        })

        return actions

    def _handle_select(self, interaction: ChartInteraction) -> List[Dict[str, Any]]:
        """Handle explicit select interaction."""
        actions = []

        indices = interaction.metadata.get("indices", [])
        if self.config.selection.mode == SelectionMode.MULTIPLE:
            self.selected_indices = set(indices)
        elif indices:
            self.selected_indices = {indices[0]}

        actions.append({
            "type": "selection_changed",
            "selected": list(self.selected_indices),
        })

        return actions

    def _build_tooltip(self, interaction: ChartInteraction) -> Dict[str, Any]:
        """Build tooltip data for display."""
        point = interaction.data_point
        if not point:
            return {}

        tooltip = {
            "x": point.x if isinstance(point.x, str) else (
                point.x.isoformat() if isinstance(point.x, datetime) else str(point.x)
            ),
            "y": point.y,
            "label": point.label,
        }

        # Add series name if available and configured
        if self.config.tooltip.show_series_name and self.data:
            if 0 <= interaction.series_index < len(self.data.series):
                tooltip["series"] = self.data.series[interaction.series_index].name

        # Calculate percentage if needed
        if self.config.tooltip.show_percentage and self.data:
            total = sum(
                sum(p.y for p in s.points)
                for s in self.data.series
            )
            if total > 0:
                tooltip["percentage"] = (point.y / total) * 100

        # Apply custom formatting
        if self.config.tooltip.custom_template:
            tooltip["html"] = self._apply_template(
                self.config.tooltip.custom_template,
                tooltip
            )

        return tooltip

    def _apply_template(self, template: str, data: Dict[str, Any]) -> str:
        """Apply template with data substitution."""
        result = template
        for key, value in data.items():
            placeholder = f"{{{key}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))
        return result

    def drill_down(
        self,
        element_index: int,
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[ChartData]:
        """
        Drill down into a data element.

        Returns new chart data for the drill-down view.
        """
        if not self.config.drill_down_enabled:
            return None

        # Determine next level
        current = self.drill_path.current_level
        next_level = self._get_next_drill_level(current)

        if next_level is None:
            return None  # Already at deepest level

        # Build context
        drill_context = context or {}
        drill_context["element_index"] = element_index

        if self.data and 0 <= element_index:
            # Get label from first series
            for series in self.data.series:
                if element_index < len(series.points):
                    point = series.points[element_index]
                    drill_context["label"] = point.label or str(point.x)
                    drill_context["value"] = point.y
                    drill_context["x"] = point.x
                    break

        # Push to path
        if not self.drill_path.push(next_level, drill_context):
            return None

        # Get new data from provider
        if self.data_provider:
            new_data = self.data_provider(self.drill_path)
            if new_data:
                self.data = new_data
                return new_data

        return None

    def drill_up(self) -> Optional[ChartData]:
        """
        Drill up to parent level.

        Returns chart data for the parent view.
        """
        if not self.drill_path.levels:
            return None

        self.drill_path.pop()

        # Get data for new level
        if self.data_provider:
            new_data = self.data_provider(self.drill_path)
            if new_data:
                self.data = new_data
                return new_data

        return None

    def drill_to_level(self, level_index: int) -> Optional[ChartData]:
        """Jump to a specific level in the drill path."""
        while len(self.drill_path.levels) > level_index:
            self.drill_path.pop()

        if self.data_provider:
            new_data = self.data_provider(self.drill_path)
            if new_data:
                self.data = new_data
                return new_data

        return None

    def _get_next_drill_level(self, current: DrillDownLevel) -> Optional[DrillDownLevel]:
        """Get the next drill level based on current."""
        level_order = [
            DrillDownLevel.OVERVIEW,
            DrillDownLevel.CATEGORY,
            DrillDownLevel.SUBCATEGORY,
            DrillDownLevel.ITEM,
            DrillDownLevel.DETAIL,
        ]

        try:
            current_idx = level_order.index(current)
            if current_idx + 1 < len(level_order):
                return level_order[current_idx + 1]
        except ValueError:
            pass

        return None

    def reset_zoom(self) -> None:
        """Reset zoom to default state."""
        self.zoom_state = {"x": [0, 1], "y": [0, 1], "scale": 1.0}

    def zoom_to_range(
        self,
        x_range: Optional[Tuple[float, float]] = None,
        y_range: Optional[Tuple[float, float]] = None
    ) -> None:
        """Zoom to specific data ranges."""
        if x_range:
            self.zoom_state["x"] = list(x_range)
        if y_range:
            self.zoom_state["y"] = list(y_range)

    def select_all(self) -> None:
        """Select all data points."""
        if self.data:
            total_points = sum(len(s.points) for s in self.data.series)
            self.selected_indices = set(range(total_points))

    def deselect_all(self) -> None:
        """Clear all selections."""
        self.selected_indices.clear()

    def get_selected_data(self) -> List[DataPoint]:
        """Get currently selected data points."""
        if not self.data:
            return []

        selected = []
        point_index = 0
        for series in self.data.series:
            for point in series.points:
                if point_index in self.selected_indices:
                    selected.append(point)
                point_index += 1

        return selected

    def to_dict(self) -> Dict[str, Any]:
        """Convert chart state to dictionary."""
        return {
            "chart_id": self.chart_id,
            "drill_path": self.drill_path.to_dict(),
            "selected_indices": list(self.selected_indices),
            "zoom_state": self.zoom_state,
            "has_data": self.data is not None,
            "data": self.data.to_dict() if self.data else None,
        }


# =============================================================================
# Specialized Interactive Charts
# =============================================================================

class DrillDownBarChart(InteractiveChart):
    """
    Bar chart with drill-down support.

    Supports drilling from category -> subcategory -> items.
    """

    def __init__(
        self,
        chart_id: str,
        config: Optional[InteractiveChartConfig] = None,
    ):
        super().__init__(chart_id, config)
        self.category_data: Dict[str, Dict[str, Any]] = {}

    def set_hierarchical_data(
        self,
        data: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Set hierarchical data for drill-down.

        Structure: {
            "category1": {
                "value": 100,
                "subcategories": {
                    "sub1": {"value": 50, "items": [...]},
                    "sub2": {"value": 50, "items": [...]}
                }
            }
        }
        """
        self.category_data = data
        self._build_overview_data()

    def _build_overview_data(self) -> None:
        """Build overview chart data from hierarchical data."""
        from stance.dashboards.visualizations import DataSeries, DataPoint, ChartData

        series = DataSeries(name="Overview")
        for category, cat_data in self.category_data.items():
            value = cat_data.get("value", 0)
            if isinstance(cat_data, dict) and "subcategories" in cat_data:
                value = sum(
                    sub.get("value", 0)
                    for sub in cat_data["subcategories"].values()
                )
            series.points.append(DataPoint(x=category, y=value, label=category))

        chart_data = ChartData(
            title=self.config.chart_config.title,
            chart_type=ChartType.BAR,
        )
        chart_data.add_series(series)
        self.data = chart_data

    def create_data_provider(self) -> Callable[[DrillDownPath], ChartData]:
        """Create a data provider for this chart."""
        def provider(path: DrillDownPath) -> ChartData:
            from stance.dashboards.visualizations import DataSeries, DataPoint, ChartData

            series = DataSeries(name="Data")
            title = "Overview"

            if path.current_level == DrillDownLevel.OVERVIEW:
                # Top level - show all categories
                for category, cat_data in self.category_data.items():
                    value = cat_data.get("value", 0)
                    series.points.append(DataPoint(x=category, y=value, label=category))

            elif path.current_level == DrillDownLevel.CATEGORY:
                # Category level - show subcategories
                ctx = path.peek()
                if ctx:
                    category = ctx["context"].get("label", "")
                    cat_data = self.category_data.get(category, {})
                    subcats = cat_data.get("subcategories", {})
                    title = f"{category} - Subcategories"
                    for subcat, sub_data in subcats.items():
                        value = sub_data.get("value", 0)
                        series.points.append(DataPoint(x=subcat, y=value, label=subcat))

            elif path.current_level == DrillDownLevel.SUBCATEGORY:
                # Subcategory level - show items
                if len(path.levels) >= 2:
                    cat_ctx = path.levels[0]["context"]
                    sub_ctx = path.levels[1]["context"]
                    category = cat_ctx.get("label", "")
                    subcategory = sub_ctx.get("label", "")

                    cat_data = self.category_data.get(category, {})
                    sub_data = cat_data.get("subcategories", {}).get(subcategory, {})
                    items = sub_data.get("items", [])
                    title = f"{category} > {subcategory} - Items"

                    for item in items:
                        if isinstance(item, dict):
                            label = item.get("name", str(item))
                            value = item.get("value", 0)
                        else:
                            label = str(item)
                            value = 1
                        series.points.append(DataPoint(x=label, y=value, label=label))

            chart_data = ChartData(title=title, chart_type=ChartType.BAR)
            chart_data.add_series(series)
            return chart_data

        self.set_data_provider(provider)
        return provider


class TimeSeriesDrillChart(InteractiveChart):
    """
    Time series chart with temporal drill-down.

    Supports drilling from year -> month -> week -> day -> hour.
    """

    def __init__(
        self,
        chart_id: str,
        config: Optional[InteractiveChartConfig] = None,
    ):
        super().__init__(chart_id, config)
        self.time_data: List[Tuple[datetime, float]] = []
        self.aggregation_levels = ["year", "month", "week", "day", "hour"]

    def set_time_data(self, data: List[Tuple[datetime, float]]) -> None:
        """Set time series data."""
        self.time_data = sorted(data, key=lambda x: x[0])
        self._build_aggregated_data("year")

    def _build_aggregated_data(
        self,
        granularity: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> None:
        """Build chart data at specified granularity."""
        from stance.dashboards.visualizations import DataSeries, DataPoint, ChartData

        # Filter data by time range
        filtered = self.time_data
        if start_time:
            filtered = [(t, v) for t, v in filtered if t >= start_time]
        if end_time:
            filtered = [(t, v) for t, v in filtered if t <= end_time]

        # Aggregate by granularity
        aggregated: Dict[str, float] = {}

        for dt, value in filtered:
            if granularity == "year":
                key = str(dt.year)
            elif granularity == "month":
                key = f"{dt.year}-{dt.month:02d}"
            elif granularity == "week":
                key = f"{dt.year}-W{dt.isocalendar()[1]:02d}"
            elif granularity == "day":
                key = dt.strftime("%Y-%m-%d")
            elif granularity == "hour":
                key = dt.strftime("%Y-%m-%d %H:00")
            else:
                key = dt.isoformat()

            aggregated[key] = aggregated.get(key, 0) + value

        # Build series
        series = DataSeries(name="Value")
        for key in sorted(aggregated.keys()):
            series.points.append(DataPoint(x=key, y=aggregated[key], label=key))

        chart_data = ChartData(
            title=f"Data by {granularity.title()}",
            chart_type=ChartType.LINE,
            x_label="Time",
            y_label="Value",
        )
        chart_data.add_series(series)
        self.data = chart_data

    def create_data_provider(self) -> Callable[[DrillDownPath], ChartData]:
        """Create a data provider for temporal drill-down."""
        def provider(path: DrillDownPath) -> ChartData:
            depth = len(path.levels)

            if depth == 0:
                granularity = "year"
                start_time = None
                end_time = None
            else:
                granularity = self.aggregation_levels[min(depth, len(self.aggregation_levels) - 1)]

                # Get time range from context
                ctx = path.peek()
                if ctx:
                    time_str = ctx["context"].get("x", "")
                    start_time, end_time = self._parse_time_range(time_str, self.aggregation_levels[depth - 1])
                else:
                    start_time = None
                    end_time = None

            self._build_aggregated_data(granularity, start_time, end_time)
            return self.data

        self.set_data_provider(provider)
        return provider

    def _parse_time_range(
        self,
        time_str: str,
        level: str
    ) -> Tuple[Optional[datetime], Optional[datetime]]:
        """Parse time string to range based on level."""
        try:
            if level == "year":
                year = int(time_str)
                return datetime(year, 1, 1), datetime(year, 12, 31, 23, 59, 59)
            elif level == "month":
                parts = time_str.split("-")
                year, month = int(parts[0]), int(parts[1])
                start = datetime(year, month, 1)
                # Get last day of month
                if month == 12:
                    end = datetime(year + 1, 1, 1) - timedelta(seconds=1)
                else:
                    end = datetime(year, month + 1, 1) - timedelta(seconds=1)
                return start, end
            elif level == "week":
                parts = time_str.split("-W")
                year, week = int(parts[0]), int(parts[1])
                start = datetime.strptime(f"{year}-W{week:02d}-1", "%Y-W%W-%w")
                end = start + timedelta(days=6, hours=23, minutes=59, seconds=59)
                return start, end
            elif level == "day":
                dt = datetime.strptime(time_str, "%Y-%m-%d")
                return dt, dt.replace(hour=23, minute=59, second=59)
        except Exception:
            pass

        return None, None


class FilterableChart(InteractiveChart):
    """
    Chart with dynamic filtering capabilities.

    Supports filter by value range, categories, and search.
    """

    def __init__(
        self,
        chart_id: str,
        config: Optional[InteractiveChartConfig] = None,
    ):
        super().__init__(chart_id, config)
        self.original_data: Optional[ChartData] = None
        self.filters: Dict[str, Any] = {}

    def set_data(self, data: ChartData) -> None:
        """Set chart data and preserve original."""
        self.original_data = data
        self.data = self._apply_filters(data)

    def add_filter(self, filter_id: str, filter_config: Dict[str, Any]) -> None:
        """
        Add a filter.

        filter_config examples:
        - {"type": "range", "field": "y", "min": 0, "max": 100}
        - {"type": "category", "field": "x", "values": ["A", "B"]}
        - {"type": "search", "field": "label", "query": "error"}
        """
        self.filters[filter_id] = filter_config
        if self.original_data:
            self.data = self._apply_filters(self.original_data)

    def remove_filter(self, filter_id: str) -> None:
        """Remove a filter."""
        if filter_id in self.filters:
            del self.filters[filter_id]
            if self.original_data:
                self.data = self._apply_filters(self.original_data)

    def clear_filters(self) -> None:
        """Clear all filters."""
        self.filters.clear()
        if self.original_data:
            self.data = self._apply_filters(self.original_data)

    def _apply_filters(self, data: ChartData) -> ChartData:
        """Apply all filters to data."""
        from stance.dashboards.visualizations import DataSeries, ChartData as CD

        if not self.filters:
            return data

        filtered_series = []
        for series in data.series:
            new_series = DataSeries(
                name=series.name,
                color=series.color,
                style=series.style,
                visible=series.visible,
            )

            for point in series.points:
                if self._point_passes_filters(point):
                    new_series.points.append(point)

            filtered_series.append(new_series)

        result = CD(
            title=data.title,
            x_label=data.x_label,
            y_label=data.y_label,
            chart_type=data.chart_type,
            annotations=data.annotations,
        )
        result.series = filtered_series
        return result

    def _point_passes_filters(self, point: DataPoint) -> bool:
        """Check if a point passes all filters."""
        for filter_config in self.filters.values():
            filter_type = filter_config.get("type")

            if filter_type == "range":
                field = filter_config.get("field", "y")
                value = getattr(point, field, point.y)
                if isinstance(value, (int, float)):
                    min_val = filter_config.get("min", float("-inf"))
                    max_val = filter_config.get("max", float("inf"))
                    if not (min_val <= value <= max_val):
                        return False

            elif filter_type == "category":
                field = filter_config.get("field", "x")
                value = getattr(point, field, point.x)
                allowed = filter_config.get("values", [])
                if allowed and value not in allowed:
                    return False

            elif filter_type == "search":
                field = filter_config.get("field", "label")
                value = str(getattr(point, field, point.label))
                query = filter_config.get("query", "").lower()
                if query and query not in value.lower():
                    return False

        return True

    def get_filter_summary(self) -> Dict[str, Any]:
        """Get summary of active filters."""
        return {
            "active_filters": len(self.filters),
            "filters": self.filters,
            "original_count": sum(
                len(s.points) for s in (self.original_data.series if self.original_data else [])
            ),
            "filtered_count": sum(
                len(s.points) for s in (self.data.series if self.data else [])
            ),
        }


# =============================================================================
# Chart Interaction Manager
# =============================================================================

class ChartInteractionManager:
    """
    Manages interactions across multiple charts.

    Supports linked charts, cross-filtering, and coordinated views.
    """

    def __init__(self):
        self.charts: Dict[str, InteractiveChart] = {}
        self.chart_links: Dict[str, Set[str]] = {}  # chart_id -> linked chart_ids
        self.global_filters: Dict[str, Any] = {}
        self.event_log: List[Dict[str, Any]] = []

    def register_chart(self, chart: InteractiveChart) -> None:
        """Register a chart for management."""
        self.charts[chart.chart_id] = chart

    def unregister_chart(self, chart_id: str) -> None:
        """Unregister a chart."""
        if chart_id in self.charts:
            del self.charts[chart_id]
        if chart_id in self.chart_links:
            del self.chart_links[chart_id]
        # Remove from other charts' links
        for links in self.chart_links.values():
            links.discard(chart_id)

    def link_charts(self, chart_id_1: str, chart_id_2: str) -> None:
        """Link two charts for coordinated updates."""
        if chart_id_1 not in self.chart_links:
            self.chart_links[chart_id_1] = set()
        if chart_id_2 not in self.chart_links:
            self.chart_links[chart_id_2] = set()

        self.chart_links[chart_id_1].add(chart_id_2)
        self.chart_links[chart_id_2].add(chart_id_1)

    def unlink_charts(self, chart_id_1: str, chart_id_2: str) -> None:
        """Unlink two charts."""
        if chart_id_1 in self.chart_links:
            self.chart_links[chart_id_1].discard(chart_id_2)
        if chart_id_2 in self.chart_links:
            self.chart_links[chart_id_2].discard(chart_id_1)

    def handle_chart_interaction(
        self,
        chart_id: str,
        interaction: ChartInteraction
    ) -> Dict[str, Any]:
        """Handle interaction and propagate to linked charts."""
        if chart_id not in self.charts:
            return {"error": f"Unknown chart: {chart_id}"}

        # Log event
        self.event_log.append({
            "chart_id": chart_id,
            "interaction": interaction.to_dict(),
            "timestamp": datetime.utcnow().isoformat(),
        })
        if len(self.event_log) > 1000:
            self.event_log = self.event_log[-500:]

        # Handle on primary chart
        chart = self.charts[chart_id]
        result = chart.handle_interaction(interaction)

        # Propagate to linked charts
        linked_results = {}
        linked_ids = self.chart_links.get(chart_id, set())

        for linked_id in linked_ids:
            if linked_id in self.charts:
                linked_chart = self.charts[linked_id]

                # Create a derived interaction for linked chart
                linked_interaction = ChartInteraction(
                    interaction_type=interaction.interaction_type,
                    chart_id=linked_id,
                    metadata={
                        "source_chart": chart_id,
                        "source_interaction": interaction.id,
                        **interaction.metadata,
                    },
                )

                linked_results[linked_id] = linked_chart.handle_interaction(linked_interaction)

        result["linked_results"] = linked_results
        return result

    def apply_global_filter(
        self,
        filter_id: str,
        filter_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply a filter across all registered filterable charts."""
        self.global_filters[filter_id] = filter_config

        results = {}
        for chart_id, chart in self.charts.items():
            if isinstance(chart, FilterableChart):
                chart.add_filter(f"global_{filter_id}", filter_config)
                results[chart_id] = chart.get_filter_summary()

        return results

    def remove_global_filter(self, filter_id: str) -> None:
        """Remove a global filter."""
        if filter_id in self.global_filters:
            del self.global_filters[filter_id]

        for chart in self.charts.values():
            if isinstance(chart, FilterableChart):
                chart.remove_filter(f"global_{filter_id}")

    def get_chart_states(self) -> Dict[str, Dict[str, Any]]:
        """Get state of all registered charts."""
        return {
            chart_id: chart.to_dict()
            for chart_id, chart in self.charts.items()
        }

    def sync_selections(self, source_chart_id: str) -> None:
        """Sync selections from source chart to all linked charts."""
        if source_chart_id not in self.charts:
            return

        source = self.charts[source_chart_id]
        selected = source.selected_indices

        linked_ids = self.chart_links.get(source_chart_id, set())
        for linked_id in linked_ids:
            if linked_id in self.charts:
                self.charts[linked_id].selected_indices = selected.copy()


# =============================================================================
# Factory Functions
# =============================================================================

def create_interactive_chart(
    chart_id: str,
    chart_type: str = "basic",
    config: Optional[InteractiveChartConfig] = None,
) -> InteractiveChart:
    """Create an interactive chart of the specified type."""
    config = config or InteractiveChartConfig()

    if chart_type == "drilldown_bar":
        return DrillDownBarChart(chart_id, config)
    elif chart_type == "timeseries":
        return TimeSeriesDrillChart(chart_id, config)
    elif chart_type == "filterable":
        return FilterableChart(chart_id, config)
    else:
        return InteractiveChart(chart_id, config)


def create_interaction_manager() -> ChartInteractionManager:
    """Create a chart interaction manager."""
    return ChartInteractionManager()


def create_drilldown_config(
    title: str = "Drill-Down Chart",
    enable_zoom: bool = True,
    enable_selection: bool = True,
) -> InteractiveChartConfig:
    """Create a configuration for drill-down charts."""
    return InteractiveChartConfig(
        chart_config=ChartConfig(title=title, drill_down_enabled=True),
        zoom=ZoomConfig(enabled=enable_zoom),
        selection=SelectionConfig(enabled=enable_selection),
        drill_down_enabled=True,
        context_menu_items=[
            {"id": "drill_down", "label": "Drill Down", "icon": "search"},
            {"id": "drill_up", "label": "Drill Up", "icon": "arrow-up"},
            {"id": "separator", "type": "separator"},
            {"id": "filter", "label": "Filter by This", "icon": "filter"},
            {"id": "export", "label": "Export Data", "icon": "download"},
        ],
    )
