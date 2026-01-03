"""
Widget builder with drag-and-drop capabilities for Mantissa Stance.

Provides visual dashboard construction, widget positioning,
layout management, and configuration UI support.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import copy
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from stance.dashboards.models import (
    Dashboard,
    DashboardLayout,
    DashboardTheme,
    Widget,
    WidgetType,
    WidgetConfig,
    ChartConfig,
    MetricConfig,
    TableConfig,
    ChartType,
    TimeRange,
    MetricAggregation,
)


# =============================================================================
# Widget Builder Enums
# =============================================================================

class DragState(Enum):
    """State of a drag operation."""
    IDLE = "idle"
    DRAGGING = "dragging"
    RESIZING = "resizing"
    DROPPING = "dropping"


class DropZone(Enum):
    """Drop zone positions."""
    LEFT = "left"
    RIGHT = "right"
    TOP = "top"
    BOTTOM = "bottom"
    CENTER = "center"
    OUTSIDE = "outside"


class SnapMode(Enum):
    """Grid snapping modes."""
    NONE = "none"
    GRID = "grid"
    GUIDES = "guides"
    BOTH = "both"


class WidgetCategory(Enum):
    """Categories for widget palette."""
    METRICS = "metrics"
    CHARTS = "charts"
    TABLES = "tables"
    TEXT = "text"
    ALERTS = "alerts"
    CUSTOM = "custom"


# =============================================================================
# Widget Template System
# =============================================================================

@dataclass
class WidgetTemplate:
    """
    Template for creating new widgets.

    Provides pre-configured widget settings for quick creation.
    """
    id: str
    name: str
    description: str
    category: WidgetCategory
    widget_type: WidgetType
    icon: str = "square"
    preview_image: str = ""
    default_config: Dict[str, Any] = field(default_factory=dict)
    default_size: Tuple[int, int] = (4, 3)  # (width, height) in grid units
    min_size: Tuple[int, int] = (2, 2)
    max_size: Tuple[int, int] = (12, 8)
    data_source_type: str = ""
    required_permissions: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def create_widget(
        self,
        position: Tuple[int, int] = (0, 0),
        custom_config: Optional[Dict[str, Any]] = None,
    ) -> Widget:
        """Create a widget instance from this template."""
        config_data = {**self.default_config}
        if custom_config:
            config_data.update(custom_config)

        # Create appropriate config type
        if self.widget_type == WidgetType.CHART:
            config = ChartConfig(
                title=config_data.get("title", self.name),
                chart_type=ChartType(config_data.get("chart_type", "line")),
                **{k: v for k, v in config_data.items() if k not in ("title", "chart_type")}
            )
        elif self.widget_type == WidgetType.METRIC:
            config = MetricConfig(
                title=config_data.get("title", self.name),
                **{k: v for k, v in config_data.items() if k != "title"}
            )
        elif self.widget_type == WidgetType.TABLE:
            config = TableConfig(
                title=config_data.get("title", self.name),
                **{k: v for k, v in config_data.items() if k != "title"}
            )
        else:
            config = WidgetConfig(
                title=config_data.get("title", self.name),
                **{k: v for k, v in config_data.items() if k != "title"}
            )

        return Widget(
            id=str(uuid.uuid4())[:8],
            widget_type=self.widget_type,
            config=config,
            data_source=self.data_source_type,
            position=position,
            size=self.default_size,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API/UI."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "widget_type": self.widget_type.value,
            "icon": self.icon,
            "preview_image": self.preview_image,
            "default_size": self.default_size,
            "min_size": self.min_size,
            "max_size": self.max_size,
            "tags": self.tags,
        }


# =============================================================================
# Widget Palette
# =============================================================================

class WidgetPalette:
    """
    Palette of available widget templates.

    Provides a library of widgets for the builder.
    """

    def __init__(self):
        self.templates: Dict[str, WidgetTemplate] = {}
        self._load_default_templates()

    def _load_default_templates(self) -> None:
        """Load default widget templates."""
        # Metric widgets
        self.add_template(WidgetTemplate(
            id="metric_single",
            name="Single Metric",
            description="Display a single numeric value with trend",
            category=WidgetCategory.METRICS,
            widget_type=WidgetType.METRIC,
            icon="hash",
            default_size=(3, 2),
            min_size=(2, 2),
            default_config={
                "title": "Metric",
                "show_trend": True,
                "show_sparkline": True,
            },
            tags=["metric", "kpi", "number"],
        ))

        self.add_template(WidgetTemplate(
            id="metric_gauge",
            name="Gauge",
            description="Circular gauge for percentage or threshold values",
            category=WidgetCategory.METRICS,
            widget_type=WidgetType.GAUGE,
            icon="activity",
            default_size=(3, 3),
            min_size=(2, 2),
            default_config={
                "title": "Progress",
                "threshold_warning": 70,
                "threshold_critical": 90,
            },
            tags=["gauge", "percentage", "progress"],
        ))

        # Chart widgets
        self.add_template(WidgetTemplate(
            id="chart_line",
            name="Line Chart",
            description="Time series or trend line chart",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.CHART,
            icon="trending-up",
            default_size=(6, 4),
            min_size=(4, 3),
            default_config={
                "title": "Trend",
                "chart_type": "line",
                "show_legend": True,
                "smooth_lines": True,
            },
            tags=["chart", "line", "trend", "timeseries"],
        ))

        self.add_template(WidgetTemplate(
            id="chart_bar",
            name="Bar Chart",
            description="Vertical bar chart for comparisons",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.CHART,
            icon="bar-chart-2",
            default_size=(6, 4),
            min_size=(4, 3),
            default_config={
                "title": "Comparison",
                "chart_type": "bar",
                "show_data_labels": True,
            },
            tags=["chart", "bar", "comparison"],
        ))

        self.add_template(WidgetTemplate(
            id="chart_pie",
            name="Pie Chart",
            description="Distribution or proportion visualization",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.CHART,
            icon="pie-chart",
            default_size=(4, 4),
            min_size=(3, 3),
            default_config={
                "title": "Distribution",
                "chart_type": "pie",
                "show_legend": True,
            },
            tags=["chart", "pie", "distribution"],
        ))

        self.add_template(WidgetTemplate(
            id="chart_donut",
            name="Donut Chart",
            description="Donut chart with center value",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.CHART,
            icon="circle",
            default_size=(4, 4),
            min_size=(3, 3),
            default_config={
                "title": "Breakdown",
                "chart_type": "donut",
            },
            tags=["chart", "donut", "breakdown"],
        ))

        self.add_template(WidgetTemplate(
            id="chart_area",
            name="Area Chart",
            description="Filled area chart for volume visualization",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.CHART,
            icon="layers",
            default_size=(6, 4),
            min_size=(4, 3),
            default_config={
                "title": "Volume",
                "chart_type": "area",
                "fill_area": True,
            },
            tags=["chart", "area", "volume"],
        ))

        self.add_template(WidgetTemplate(
            id="chart_heatmap",
            name="Heatmap",
            description="Matrix visualization with color intensity",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.HEATMAP,
            icon="grid",
            default_size=(6, 4),
            min_size=(4, 4),
            default_config={
                "title": "Heatmap",
            },
            tags=["chart", "heatmap", "matrix"],
        ))

        # Table widgets
        self.add_template(WidgetTemplate(
            id="table_basic",
            name="Data Table",
            description="Tabular data with sorting and pagination",
            category=WidgetCategory.TABLES,
            widget_type=WidgetType.TABLE,
            icon="table",
            default_size=(6, 4),
            min_size=(4, 3),
            default_config={
                "title": "Data",
                "sortable": True,
                "show_pagination": True,
                "page_size": 10,
            },
            tags=["table", "data", "list"],
        ))

        self.add_template(WidgetTemplate(
            id="table_findings",
            name="Findings List",
            description="Security findings with severity indicators",
            category=WidgetCategory.TABLES,
            widget_type=WidgetType.TABLE,
            icon="alert-triangle",
            default_size=(8, 5),
            min_size=(6, 4),
            default_config={
                "title": "Findings",
                "columns": ["title", "severity", "status", "resource"],
                "sortable": True,
            },
            data_source_type="findings_query",
            tags=["table", "findings", "security"],
        ))

        # Text widgets
        self.add_template(WidgetTemplate(
            id="text_markdown",
            name="Markdown Text",
            description="Rich text content with markdown support",
            category=WidgetCategory.TEXT,
            widget_type=WidgetType.TEXT,
            icon="file-text",
            default_size=(4, 3),
            min_size=(2, 2),
            default_config={
                "title": "",
            },
            tags=["text", "markdown", "content"],
        ))

        # Alert widgets
        self.add_template(WidgetTemplate(
            id="alert_list",
            name="Active Alerts",
            description="Real-time alert notifications",
            category=WidgetCategory.ALERTS,
            widget_type=WidgetType.ALERT,
            icon="bell",
            default_size=(4, 4),
            min_size=(3, 3),
            default_config={
                "title": "Alerts",
                "refresh_interval_seconds": 30,
            },
            data_source_type="alerts_stream",
            tags=["alerts", "notifications", "realtime"],
        ))

        # Map widget
        self.add_template(WidgetTemplate(
            id="geo_map",
            name="Geographic Map",
            description="Location-based data visualization",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.MAP,
            icon="map",
            default_size=(6, 5),
            min_size=(4, 4),
            default_config={
                "title": "Geographic Distribution",
            },
            tags=["map", "geo", "location"],
        ))

        # Timeline widget
        self.add_template(WidgetTemplate(
            id="timeline",
            name="Event Timeline",
            description="Chronological event visualization",
            category=WidgetCategory.CHARTS,
            widget_type=WidgetType.TIMELINE,
            icon="clock",
            default_size=(8, 4),
            min_size=(6, 3),
            default_config={
                "title": "Timeline",
            },
            tags=["timeline", "events", "history"],
        ))

    def add_template(self, template: WidgetTemplate) -> None:
        """Add a template to the palette."""
        self.templates[template.id] = template

    def get_template(self, template_id: str) -> Optional[WidgetTemplate]:
        """Get a template by ID."""
        return self.templates.get(template_id)

    def get_templates_by_category(
        self,
        category: WidgetCategory
    ) -> List[WidgetTemplate]:
        """Get all templates in a category."""
        return [
            t for t in self.templates.values()
            if t.category == category
        ]

    def search_templates(self, query: str) -> List[WidgetTemplate]:
        """Search templates by name, description, or tags."""
        query = query.lower()
        results = []
        for template in self.templates.values():
            if (query in template.name.lower() or
                query in template.description.lower() or
                any(query in tag for tag in template.tags)):
                results.append(template)
        return results

    def get_all_templates(self) -> List[WidgetTemplate]:
        """Get all templates."""
        return list(self.templates.values())

    def to_dict(self) -> Dict[str, Any]:
        """Convert palette to dictionary for API."""
        by_category: Dict[str, List[Dict]] = {}
        for template in self.templates.values():
            cat = template.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(template.to_dict())

        return {
            "categories": [c.value for c in WidgetCategory],
            "templates": by_category,
            "total_count": len(self.templates),
        }


# =============================================================================
# Drag and Drop System
# =============================================================================

@dataclass
class DragItem:
    """
    Represents an item being dragged.

    Tracks position, source, and drag state.
    """
    id: str = ""
    item_type: str = ""  # "template", "widget", "resize_handle"
    source: str = ""  # "palette", "canvas"
    template_id: Optional[str] = None
    widget_id: Optional[str] = None
    start_position: Tuple[int, int] = (0, 0)
    current_position: Tuple[int, int] = (0, 0)
    offset: Tuple[int, int] = (0, 0)
    state: DragState = DragState.IDLE
    started_at: Optional[datetime] = None

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())[:8]

    def update_position(self, x: int, y: int) -> None:
        """Update current drag position."""
        self.current_position = (x, y)

    def get_delta(self) -> Tuple[int, int]:
        """Get position delta from start."""
        return (
            self.current_position[0] - self.start_position[0],
            self.current_position[1] - self.start_position[1],
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "item_type": self.item_type,
            "source": self.source,
            "template_id": self.template_id,
            "widget_id": self.widget_id,
            "start_position": self.start_position,
            "current_position": self.current_position,
            "state": self.state.value,
        }


@dataclass
class DropTarget:
    """
    Represents a potential drop target.

    Used for drop zone highlighting and validation.
    """
    target_type: str = ""  # "canvas", "widget", "row", "column"
    target_id: str = ""
    zone: DropZone = DropZone.CENTER
    position: Tuple[int, int] = (0, 0)
    size: Tuple[int, int] = (1, 1)
    valid: bool = True
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_type": self.target_type,
            "target_id": self.target_id,
            "zone": self.zone.value,
            "position": self.position,
            "size": self.size,
            "valid": self.valid,
        }


class DragDropManager:
    """
    Manages drag and drop operations.

    Handles widget dragging, resizing, and placement.
    """

    def __init__(self, layout: DashboardLayout):
        self.layout = layout
        self.current_drag: Optional[DragItem] = None
        self.drop_targets: List[DropTarget] = []
        self.snap_mode = SnapMode.GRID
        self.grid_size = 1  # Grid units
        self.show_guides = True
        self.snap_threshold = 10  # Pixels

    def start_drag(
        self,
        item_type: str,
        position: Tuple[int, int],
        source: str = "palette",
        template_id: Optional[str] = None,
        widget_id: Optional[str] = None,
        offset: Tuple[int, int] = (0, 0),
    ) -> DragItem:
        """Start a drag operation."""
        self.current_drag = DragItem(
            item_type=item_type,
            source=source,
            template_id=template_id,
            widget_id=widget_id,
            start_position=position,
            current_position=position,
            offset=offset,
            state=DragState.DRAGGING,
            started_at=datetime.utcnow(),
        )
        return self.current_drag

    def update_drag(self, position: Tuple[int, int]) -> Optional[DragItem]:
        """Update current drag position."""
        if not self.current_drag:
            return None

        # Apply snapping
        snapped_pos = self._apply_snapping(position)
        self.current_drag.update_position(snapped_pos[0], snapped_pos[1])

        # Update drop targets
        self._update_drop_targets()

        return self.current_drag

    def end_drag(self) -> Optional[Tuple[DragItem, Optional[DropTarget]]]:
        """End drag operation and return result."""
        if not self.current_drag:
            return None

        drag = self.current_drag
        drag.state = DragState.DROPPING

        # Find best drop target
        target = self._find_best_drop_target()

        self.current_drag = None
        self.drop_targets.clear()

        return (drag, target)

    def cancel_drag(self) -> None:
        """Cancel current drag operation."""
        self.current_drag = None
        self.drop_targets.clear()

    def start_resize(
        self,
        widget_id: str,
        handle: str,  # "n", "s", "e", "w", "ne", "nw", "se", "sw"
        position: Tuple[int, int],
    ) -> DragItem:
        """Start a resize operation."""
        self.current_drag = DragItem(
            item_type="resize_handle",
            source="canvas",
            widget_id=widget_id,
            start_position=position,
            current_position=position,
            state=DragState.RESIZING,
            started_at=datetime.utcnow(),
        )
        self.current_drag.metadata = {"handle": handle}
        return self.current_drag

    def _apply_snapping(self, position: Tuple[int, int]) -> Tuple[int, int]:
        """Apply grid/guide snapping to position."""
        if self.snap_mode == SnapMode.NONE:
            return position

        x, y = position

        if self.snap_mode in (SnapMode.GRID, SnapMode.BOTH):
            # Snap to grid
            cell_width = self.layout.row_height  # Assuming square cells
            cell_height = self.layout.row_height

            x = round(x / cell_width) * cell_width
            y = round(y / cell_height) * cell_height

        return (x, y)

    def _update_drop_targets(self) -> None:
        """Update available drop targets based on current drag."""
        self.drop_targets.clear()

        if not self.current_drag:
            return

        # Canvas is always a valid target
        self.drop_targets.append(DropTarget(
            target_type="canvas",
            target_id="main",
            zone=DropZone.CENTER,
            valid=True,
            priority=0,
        ))

    def _find_best_drop_target(self) -> Optional[DropTarget]:
        """Find the best drop target for current position."""
        if not self.drop_targets:
            return None

        valid_targets = [t for t in self.drop_targets if t.valid]
        if not valid_targets:
            return None

        # Return highest priority valid target
        return max(valid_targets, key=lambda t: t.priority)

    def pixel_to_grid(self, x: int, y: int) -> Tuple[int, int]:
        """Convert pixel coordinates to grid position."""
        cell_width = self.layout.row_height
        cell_height = self.layout.row_height
        margin = self.layout.margin

        grid_x = max(0, (x - margin) // cell_width)
        grid_y = max(0, (y - margin) // cell_height)

        return (int(grid_x), int(grid_y))

    def grid_to_pixel(self, col: int, row: int) -> Tuple[int, int]:
        """Convert grid position to pixel coordinates."""
        cell_width = self.layout.row_height
        cell_height = self.layout.row_height
        margin = self.layout.margin

        x = margin + col * cell_width
        y = margin + row * cell_height

        return (x, y)

    def get_state(self) -> Dict[str, Any]:
        """Get current drag/drop state."""
        return {
            "is_dragging": self.current_drag is not None,
            "drag_item": self.current_drag.to_dict() if self.current_drag else None,
            "drop_targets": [t.to_dict() for t in self.drop_targets],
            "snap_mode": self.snap_mode.value,
            "show_guides": self.show_guides,
        }


# =============================================================================
# Layout Manager
# =============================================================================

class LayoutManager:
    """
    Manages widget layout within a dashboard.

    Handles positioning, collision detection, and auto-arrangement.
    """

    def __init__(self, layout: DashboardLayout):
        self.layout = layout
        self.widgets: Dict[str, Widget] = {}
        self.grid: List[List[Optional[str]]] = []  # 2D grid of widget IDs
        self._init_grid()

    def _init_grid(self, rows: int = 20) -> None:
        """Initialize the layout grid."""
        self.grid = [
            [None for _ in range(self.layout.columns)]
            for _ in range(rows)
        ]

    def add_widget(
        self,
        widget: Widget,
        auto_position: bool = True
    ) -> bool:
        """Add a widget to the layout."""
        if auto_position:
            # Find first available position
            position = self._find_free_position(widget.size)
            if position is None:
                return False
            widget.position = position

        # Check for collisions
        if self._check_collision(widget):
            if auto_position:
                # Try to resolve collision
                resolved = self._resolve_collision(widget)
                if not resolved:
                    return False
            else:
                return False

        # Place widget
        self._place_widget(widget)
        self.widgets[widget.id] = widget
        return True

    def remove_widget(self, widget_id: str) -> bool:
        """Remove a widget from the layout."""
        if widget_id not in self.widgets:
            return False

        widget = self.widgets[widget_id]
        self._clear_widget(widget)
        del self.widgets[widget_id]
        return True

    def move_widget(
        self,
        widget_id: str,
        new_position: Tuple[int, int]
    ) -> bool:
        """Move a widget to a new position."""
        if widget_id not in self.widgets:
            return False

        widget = self.widgets[widget_id]
        old_position = widget.position

        # Clear old position
        self._clear_widget(widget)

        # Try new position
        widget.position = new_position
        if self._check_collision(widget):
            # Revert
            widget.position = old_position
            self._place_widget(widget)
            return False

        self._place_widget(widget)
        return True

    def resize_widget(
        self,
        widget_id: str,
        new_size: Tuple[int, int]
    ) -> bool:
        """Resize a widget."""
        if widget_id not in self.widgets:
            return False

        widget = self.widgets[widget_id]
        old_size = widget.size

        # Clear old position
        self._clear_widget(widget)

        # Try new size
        widget.size = new_size

        # Check bounds
        col, row = widget.position
        if col + new_size[0] > self.layout.columns:
            widget.size = old_size
            self._place_widget(widget)
            return False

        if self._check_collision(widget):
            widget.size = old_size
            self._place_widget(widget)
            return False

        self._place_widget(widget)
        return True

    def _find_free_position(
        self,
        size: Tuple[int, int]
    ) -> Optional[Tuple[int, int]]:
        """Find first free position for given size."""
        width, height = size

        for row in range(len(self.grid)):
            for col in range(self.layout.columns - width + 1):
                if self._is_area_free(col, row, width, height):
                    return (col, row)

        # Extend grid if needed
        new_row = len(self.grid)
        self._extend_grid(height)
        return (0, new_row)

    def _is_area_free(
        self,
        col: int,
        row: int,
        width: int,
        height: int
    ) -> bool:
        """Check if an area is free."""
        # Extend grid if needed
        while row + height > len(self.grid):
            self._extend_grid(1)

        for r in range(row, row + height):
            for c in range(col, col + width):
                if c >= self.layout.columns:
                    return False
                if self.grid[r][c] is not None:
                    return False
        return True

    def _extend_grid(self, rows: int) -> None:
        """Extend grid by adding rows."""
        for _ in range(rows):
            self.grid.append([None for _ in range(self.layout.columns)])

    def _check_collision(self, widget: Widget) -> bool:
        """Check if widget collides with existing widgets."""
        col, row = widget.position
        width, height = widget.size

        for r in range(row, row + height):
            if r >= len(self.grid):
                continue
            for c in range(col, col + width):
                if c >= self.layout.columns:
                    return True  # Out of bounds
                cell = self.grid[r][c]
                if cell is not None and cell != widget.id:
                    return True

        return False

    def _resolve_collision(self, widget: Widget) -> bool:
        """Try to resolve collision by finding new position."""
        new_pos = self._find_free_position(widget.size)
        if new_pos:
            widget.position = new_pos
            return True
        return False

    def _place_widget(self, widget: Widget) -> None:
        """Place widget on grid."""
        col, row = widget.position
        width, height = widget.size

        # Extend grid if needed
        while row + height > len(self.grid):
            self._extend_grid(1)

        for r in range(row, row + height):
            for c in range(col, col + width):
                if c < self.layout.columns:
                    self.grid[r][c] = widget.id

    def _clear_widget(self, widget: Widget) -> None:
        """Clear widget from grid."""
        for r in range(len(self.grid)):
            for c in range(len(self.grid[r])):
                if self.grid[r][c] == widget.id:
                    self.grid[r][c] = None

    def compact_layout(self) -> None:
        """Compact layout by moving widgets up."""
        # Sort widgets by row position
        sorted_widgets = sorted(
            self.widgets.values(),
            key=lambda w: (w.position[1], w.position[0])
        )

        # Clear grid
        self._init_grid(len(self.grid))

        # Reposition each widget
        for widget in sorted_widgets:
            col = widget.position[0]
            # Find lowest available row for this column
            for row in range(len(self.grid)):
                if self._is_area_free(col, row, widget.size[0], widget.size[1]):
                    widget.position = (col, row)
                    self._place_widget(widget)
                    break

    def auto_arrange(self, arrangement: str = "grid") -> None:
        """Auto-arrange all widgets."""
        if arrangement == "grid":
            self._arrange_grid()
        elif arrangement == "stack":
            self._arrange_stack()
        elif arrangement == "flow":
            self._arrange_flow()

    def _arrange_grid(self) -> None:
        """Arrange widgets in a grid pattern."""
        sorted_widgets = sorted(
            self.widgets.values(),
            key=lambda w: w.config.title
        )

        # Clear grid
        self._init_grid(len(self.grid))

        col, row = 0, 0
        max_height_in_row = 0

        for widget in sorted_widgets:
            width, height = widget.size

            # Check if widget fits in current row
            if col + width > self.layout.columns:
                col = 0
                row += max_height_in_row
                max_height_in_row = 0

            widget.position = (col, row)
            self._place_widget(widget)

            col += width
            max_height_in_row = max(max_height_in_row, height)

    def _arrange_stack(self) -> None:
        """Arrange widgets in a vertical stack."""
        sorted_widgets = sorted(
            self.widgets.values(),
            key=lambda w: w.config.title
        )

        # Clear grid
        self._init_grid(len(self.grid))

        row = 0
        for widget in sorted_widgets:
            widget.position = (0, row)
            # Make widget full width
            widget.size = (self.layout.columns, widget.size[1])
            self._place_widget(widget)
            row += widget.size[1]

    def _arrange_flow(self) -> None:
        """Arrange widgets in a flow layout."""
        sorted_widgets = sorted(
            self.widgets.values(),
            key=lambda w: -w.size[0]  # Largest first
        )

        # Clear grid
        self._init_grid(len(self.grid))

        for widget in sorted_widgets:
            pos = self._find_free_position(widget.size)
            if pos:
                widget.position = pos
                self._place_widget(widget)

    def get_layout_info(self) -> Dict[str, Any]:
        """Get layout information."""
        # Find actual grid height in use
        max_row = 0
        for widget in self.widgets.values():
            widget_bottom = widget.position[1] + widget.size[1]
            max_row = max(max_row, widget_bottom)

        return {
            "columns": self.layout.columns,
            "rows": max_row,
            "widget_count": len(self.widgets),
            "widgets": [
                {
                    "id": w.id,
                    "position": w.position,
                    "size": w.size,
                    "title": w.config.title,
                }
                for w in self.widgets.values()
            ],
        }


# =============================================================================
# Widget Builder
# =============================================================================

class WidgetBuilder:
    """
    Main widget builder class.

    Provides drag-and-drop dashboard construction.
    """

    def __init__(self, dashboard: Optional[Dashboard] = None):
        if dashboard:
            self.dashboard = dashboard
        else:
            self.dashboard = Dashboard(
                id=str(uuid.uuid4()),
                name="New Dashboard",
            )

        self.palette = WidgetPalette()
        self.layout_manager = LayoutManager(self.dashboard.layout)
        self.drag_manager = DragDropManager(self.dashboard.layout)
        self.history: List[Dict[str, Any]] = []
        self.history_index = -1
        self.max_history = 50
        self.clipboard: Optional[Widget] = None

        # Load existing widgets
        for widget in self.dashboard.widgets:
            self.layout_manager.widgets[widget.id] = widget

    def get_palette(self) -> Dict[str, Any]:
        """Get widget palette for UI."""
        return self.palette.to_dict()

    def create_widget_from_template(
        self,
        template_id: str,
        position: Optional[Tuple[int, int]] = None,
        custom_config: Optional[Dict[str, Any]] = None,
    ) -> Optional[Widget]:
        """Create a widget from a template."""
        template = self.palette.get_template(template_id)
        if not template:
            return None

        widget = template.create_widget(
            position=position or (0, 0),
            custom_config=custom_config,
        )

        # Add to layout
        auto_position = position is None
        if self.layout_manager.add_widget(widget, auto_position=auto_position):
            self.dashboard.add_widget(widget)
            self._save_history("create_widget", {"widget_id": widget.id})
            return widget

        return None

    def delete_widget(self, widget_id: str) -> bool:
        """Delete a widget."""
        widget = self.dashboard.get_widget(widget_id)
        if not widget:
            return False

        # Save for undo
        self._save_history("delete_widget", {
            "widget_id": widget_id,
            "widget_data": self._serialize_widget(widget),
        })

        self.layout_manager.remove_widget(widget_id)
        self.dashboard.remove_widget(widget_id)
        return True

    def duplicate_widget(self, widget_id: str) -> Optional[Widget]:
        """Duplicate a widget."""
        original = self.dashboard.get_widget(widget_id)
        if not original:
            return None

        # Deep copy widget
        new_widget = Widget(
            id=str(uuid.uuid4())[:8],
            widget_type=original.widget_type,
            config=copy.deepcopy(original.config),
            data_source=original.data_source,
            position=(0, 0),
            size=original.size,
        )
        new_widget.config.title = f"{original.config.title} (Copy)"

        if self.layout_manager.add_widget(new_widget, auto_position=True):
            self.dashboard.add_widget(new_widget)
            self._save_history("duplicate_widget", {"widget_id": new_widget.id})
            return new_widget

        return None

    def move_widget(
        self,
        widget_id: str,
        position: Tuple[int, int]
    ) -> bool:
        """Move a widget to a new position."""
        widget = self.dashboard.get_widget(widget_id)
        if not widget:
            return False

        old_position = widget.position
        if self.layout_manager.move_widget(widget_id, position):
            self._save_history("move_widget", {
                "widget_id": widget_id,
                "old_position": old_position,
                "new_position": position,
            })
            return True
        return False

    def resize_widget(
        self,
        widget_id: str,
        size: Tuple[int, int]
    ) -> bool:
        """Resize a widget."""
        widget = self.dashboard.get_widget(widget_id)
        if not widget:
            return False

        old_size = widget.size
        if self.layout_manager.resize_widget(widget_id, size):
            self._save_history("resize_widget", {
                "widget_id": widget_id,
                "old_size": old_size,
                "new_size": size,
            })
            return True
        return False

    def update_widget_config(
        self,
        widget_id: str,
        config_updates: Dict[str, Any]
    ) -> bool:
        """Update widget configuration."""
        widget = self.dashboard.get_widget(widget_id)
        if not widget:
            return False

        old_config = self._serialize_widget_config(widget.config)

        # Update config fields
        for key, value in config_updates.items():
            if hasattr(widget.config, key):
                setattr(widget.config, key, value)

        self._save_history("update_config", {
            "widget_id": widget_id,
            "old_config": old_config,
            "new_config": config_updates,
        })
        return True

    def copy_widget(self, widget_id: str) -> bool:
        """Copy widget to clipboard."""
        widget = self.dashboard.get_widget(widget_id)
        if not widget:
            return False

        self.clipboard = copy.deepcopy(widget)
        return True

    def paste_widget(
        self,
        position: Optional[Tuple[int, int]] = None
    ) -> Optional[Widget]:
        """Paste widget from clipboard."""
        if not self.clipboard:
            return None

        new_widget = Widget(
            id=str(uuid.uuid4())[:8],
            widget_type=self.clipboard.widget_type,
            config=copy.deepcopy(self.clipboard.config),
            data_source=self.clipboard.data_source,
            position=position or (0, 0),
            size=self.clipboard.size,
        )

        auto_position = position is None
        if self.layout_manager.add_widget(new_widget, auto_position=auto_position):
            self.dashboard.add_widget(new_widget)
            self._save_history("paste_widget", {"widget_id": new_widget.id})
            return new_widget

        return None

    def undo(self) -> bool:
        """Undo last action."""
        if self.history_index < 0:
            return False

        action = self.history[self.history_index]
        self._apply_undo(action)
        self.history_index -= 1
        return True

    def redo(self) -> bool:
        """Redo last undone action."""
        if self.history_index >= len(self.history) - 1:
            return False

        self.history_index += 1
        action = self.history[self.history_index]
        self._apply_redo(action)
        return True

    def compact_layout(self) -> None:
        """Compact the dashboard layout."""
        self._save_history("compact", {
            "layout": self.layout_manager.get_layout_info()
        })
        self.layout_manager.compact_layout()

    def auto_arrange(self, arrangement: str = "grid") -> None:
        """Auto-arrange widgets."""
        self._save_history("auto_arrange", {
            "layout": self.layout_manager.get_layout_info(),
            "arrangement": arrangement,
        })
        self.layout_manager.auto_arrange(arrangement)

    def handle_drag_start(
        self,
        source: str,
        position: Tuple[int, int],
        template_id: Optional[str] = None,
        widget_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Handle drag start event."""
        if template_id:
            item_type = "template"
        elif widget_id:
            item_type = "widget"
        else:
            return {"error": "No template or widget specified"}

        drag = self.drag_manager.start_drag(
            item_type=item_type,
            position=position,
            source=source,
            template_id=template_id,
            widget_id=widget_id,
        )
        return self.drag_manager.get_state()

    def handle_drag_move(self, position: Tuple[int, int]) -> Dict[str, Any]:
        """Handle drag move event."""
        self.drag_manager.update_drag(position)
        return self.drag_manager.get_state()

    def handle_drag_end(self, position: Tuple[int, int]) -> Dict[str, Any]:
        """Handle drag end event."""
        result = self.drag_manager.end_drag()
        if not result:
            return {"success": False, "error": "No active drag"}

        drag, target = result

        if not target or not target.valid:
            return {"success": False, "error": "Invalid drop target"}

        # Convert pixel position to grid position
        grid_pos = self.drag_manager.pixel_to_grid(position[0], position[1])

        if drag.item_type == "template" and drag.template_id:
            widget = self.create_widget_from_template(
                drag.template_id,
                position=grid_pos,
            )
            return {
                "success": widget is not None,
                "widget_id": widget.id if widget else None,
            }

        elif drag.item_type == "widget" and drag.widget_id:
            success = self.move_widget(drag.widget_id, grid_pos)
            return {"success": success, "widget_id": drag.widget_id}

        return {"success": False}

    def handle_drag_cancel(self) -> None:
        """Handle drag cancel."""
        self.drag_manager.cancel_drag()

    def get_state(self) -> Dict[str, Any]:
        """Get complete builder state."""
        return {
            "dashboard": self.dashboard.to_dict(),
            "layout": self.layout_manager.get_layout_info(),
            "drag_state": self.drag_manager.get_state(),
            "can_undo": self.history_index >= 0,
            "can_redo": self.history_index < len(self.history) - 1,
            "has_clipboard": self.clipboard is not None,
        }

    def _save_history(self, action_type: str, data: Dict[str, Any]) -> None:
        """Save action to history."""
        # Truncate future history if we're not at the end
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]

        self.history.append({
            "type": action_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        })

        # Limit history size
        if len(self.history) > self.max_history:
            self.history = self.history[-self.max_history:]

        self.history_index = len(self.history) - 1

    def _apply_undo(self, action: Dict[str, Any]) -> None:
        """Apply undo for an action."""
        action_type = action["type"]
        data = action["data"]

        if action_type == "create_widget":
            widget_id = data["widget_id"]
            self.layout_manager.remove_widget(widget_id)
            self.dashboard.remove_widget(widget_id)

        elif action_type == "delete_widget":
            widget = self._deserialize_widget(data["widget_data"])
            self.layout_manager.add_widget(widget, auto_position=False)
            self.dashboard.add_widget(widget)

        elif action_type == "move_widget":
            self.layout_manager.move_widget(
                data["widget_id"],
                data["old_position"]
            )

        elif action_type == "resize_widget":
            self.layout_manager.resize_widget(
                data["widget_id"],
                data["old_size"]
            )

    def _apply_redo(self, action: Dict[str, Any]) -> None:
        """Apply redo for an action."""
        action_type = action["type"]
        data = action["data"]

        if action_type == "create_widget":
            # Widget already deleted by undo, recreate
            pass  # Complex - would need full widget data

        elif action_type == "delete_widget":
            widget_id = data["widget_id"]
            self.layout_manager.remove_widget(widget_id)
            self.dashboard.remove_widget(widget_id)

        elif action_type == "move_widget":
            self.layout_manager.move_widget(
                data["widget_id"],
                data["new_position"]
            )

        elif action_type == "resize_widget":
            self.layout_manager.resize_widget(
                data["widget_id"],
                data["new_size"]
            )

    def _serialize_widget(self, widget: Widget) -> Dict[str, Any]:
        """Serialize widget for storage."""
        return {
            "id": widget.id,
            "widget_type": widget.widget_type.value,
            "config": self._serialize_widget_config(widget.config),
            "data_source": widget.data_source,
            "position": widget.position,
            "size": widget.size,
            "visible": widget.visible,
        }

    def _deserialize_widget(self, data: Dict[str, Any]) -> Widget:
        """Deserialize widget from storage."""
        widget_type = WidgetType(data["widget_type"])
        config_data = data["config"]

        # Create appropriate config
        if widget_type == WidgetType.CHART:
            config = ChartConfig(**config_data)
        elif widget_type == WidgetType.METRIC:
            config = MetricConfig(**config_data)
        elif widget_type == WidgetType.TABLE:
            config = TableConfig(**config_data)
        else:
            config = WidgetConfig(**config_data)

        return Widget(
            id=data["id"],
            widget_type=widget_type,
            config=config,
            data_source=data["data_source"],
            position=tuple(data["position"]),
            size=tuple(data["size"]),
            visible=data["visible"],
        )

    def _serialize_widget_config(self, config: WidgetConfig) -> Dict[str, Any]:
        """Serialize widget config."""
        result = {}
        for key in dir(config):
            if not key.startswith("_"):
                value = getattr(config, key)
                if not callable(value):
                    # Handle enums
                    if isinstance(value, Enum):
                        result[key] = value.value
                    else:
                        result[key] = value
        return result


# =============================================================================
# Factory Functions
# =============================================================================

def create_widget_builder(
    dashboard: Optional[Dashboard] = None
) -> WidgetBuilder:
    """Create a widget builder instance."""
    return WidgetBuilder(dashboard)


def create_widget_palette() -> WidgetPalette:
    """Create a widget palette."""
    return WidgetPalette()


def create_layout_manager(layout: DashboardLayout) -> LayoutManager:
    """Create a layout manager."""
    return LayoutManager(layout)


def create_drag_manager(layout: DashboardLayout) -> DragDropManager:
    """Create a drag/drop manager."""
    return DragDropManager(layout)
