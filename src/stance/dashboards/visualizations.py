"""
Visualization and chart generation for Mantissa Stance dashboards.

Provides chart builders, renderers, and visualization utilities.

Part of Phase 91: Advanced Reporting & Dashboards
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from stance.dashboards.models import ChartType, ChartConfig


# =============================================================================
# Chart Data Structures
# =============================================================================

@dataclass
class DataPoint:
    """
    A single data point for charts.

    Attributes:
        x: X-axis value (can be numeric, string, or datetime)
        y: Y-axis value
        label: Optional label
        metadata: Additional data
    """
    x: Union[float, str, datetime]
    y: float
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        x_val = self.x
        if isinstance(self.x, datetime):
            x_val = self.x.isoformat()
        return {
            "x": x_val,
            "y": self.y,
            "label": self.label,
        }


@dataclass
class DataSeries:
    """
    A series of data points for charts.

    Attributes:
        name: Series name
        points: List of data points
        color: Series color
        style: Line/bar style
    """
    name: str
    points: List[DataPoint] = field(default_factory=list)
    color: str = "#3B82F6"
    style: str = "solid"
    visible: bool = True

    def add_point(self, x: Union[float, str, datetime], y: float,
                  label: str = "") -> None:
        """Add a data point to the series."""
        self.points.append(DataPoint(x=x, y=y, label=label))

    def get_x_values(self) -> List[Any]:
        """Get all X values."""
        return [p.x for p in self.points]

    def get_y_values(self) -> List[float]:
        """Get all Y values."""
        return [p.y for p in self.points]

    def get_min_y(self) -> float:
        """Get minimum Y value."""
        if not self.points:
            return 0.0
        return min(p.y for p in self.points)

    def get_max_y(self) -> float:
        """Get maximum Y value."""
        if not self.points:
            return 0.0
        return max(p.y for p in self.points)

    def get_sum(self) -> float:
        """Get sum of Y values."""
        return sum(p.y for p in self.points)

    def get_avg(self) -> float:
        """Get average of Y values."""
        if not self.points:
            return 0.0
        return self.get_sum() / len(self.points)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "points": [p.to_dict() for p in self.points],
            "color": self.color,
            "style": self.style,
            "visible": self.visible,
        }


@dataclass
class ChartData:
    """
    Complete data for a chart.

    Attributes:
        title: Chart title
        series: List of data series
        x_label: X-axis label
        y_label: Y-axis label
        chart_type: Type of chart
    """
    title: str = ""
    series: List[DataSeries] = field(default_factory=list)
    x_label: str = ""
    y_label: str = ""
    chart_type: ChartType = ChartType.LINE
    annotations: List[Dict[str, Any]] = field(default_factory=list)

    def add_series(self, series: DataSeries) -> None:
        """Add a data series."""
        self.series.append(series)

    def get_all_x_values(self) -> List[Any]:
        """Get all unique X values across series."""
        all_x = set()
        for s in self.series:
            all_x.update(s.get_x_values())
        return sorted(list(all_x))

    def get_y_range(self) -> Tuple[float, float]:
        """Get the Y-axis range across all series."""
        if not self.series:
            return (0.0, 100.0)

        min_y = min(s.get_min_y() for s in self.series)
        max_y = max(s.get_max_y() for s in self.series)

        # Add padding
        padding = (max_y - min_y) * 0.1
        return (min_y - padding, max_y + padding)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "series": [s.to_dict() for s in self.series],
            "x_label": self.x_label,
            "y_label": self.y_label,
            "chart_type": self.chart_type.value,
            "annotations": self.annotations,
        }


# =============================================================================
# Chart Builders
# =============================================================================

class ChartBuilder(ABC):
    """Abstract base class for chart builders."""

    def __init__(self, config: Optional[ChartConfig] = None):
        self.config = config or ChartConfig(title="Chart")
        self.data = ChartData(
            title=self.config.title,
            x_label=self.config.x_axis_label,
            y_label=self.config.y_axis_label,
        )

    @abstractmethod
    def build(self) -> ChartData:
        """Build the chart data."""
        pass

    def set_title(self, title: str) -> "ChartBuilder":
        """Set chart title."""
        self.data.title = title
        return self

    def set_labels(self, x_label: str = "", y_label: str = "") -> "ChartBuilder":
        """Set axis labels."""
        self.data.x_label = x_label
        self.data.y_label = y_label
        return self

    def add_series(self, name: str, points: List[Tuple[Any, float]],
                   color: str = "#3B82F6") -> "ChartBuilder":
        """Add a data series."""
        series = DataSeries(name=name, color=color)
        for x, y in points:
            series.add_point(x, y)
        self.data.add_series(series)
        return self

    def add_annotation(self, x: Any, y: float, text: str) -> "ChartBuilder":
        """Add an annotation."""
        self.data.annotations.append({
            "x": x,
            "y": y,
            "text": text,
        })
        return self


class LineChartBuilder(ChartBuilder):
    """Builder for line charts."""

    def __init__(self, config: Optional[ChartConfig] = None):
        super().__init__(config)
        self.data.chart_type = ChartType.LINE

    def build(self) -> ChartData:
        """Build line chart data."""
        return self.data

    def with_trend_line(self, series_index: int = 0) -> "LineChartBuilder":
        """Add a linear trend line for a series."""
        if series_index >= len(self.data.series):
            return self

        series = self.data.series[series_index]
        if len(series.points) < 2:
            return self

        # Calculate linear regression
        x_vals = list(range(len(series.points)))
        y_vals = series.get_y_values()

        n = len(x_vals)
        sum_x = sum(x_vals)
        sum_y = sum(y_vals)
        sum_xy = sum(x * y for x, y in zip(x_vals, y_vals))
        sum_x2 = sum(x * x for x in x_vals)

        denom = n * sum_x2 - sum_x * sum_x
        if denom == 0:
            return self

        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n

        # Create trend line series
        trend = DataSeries(
            name=f"{series.name} (Trend)",
            color="#94A3B8",
            style="dashed"
        )
        for i, point in enumerate(series.points):
            trend.add_point(point.x, intercept + slope * i)

        self.data.add_series(trend)
        return self


class BarChartBuilder(ChartBuilder):
    """Builder for bar charts."""

    def __init__(self, config: Optional[ChartConfig] = None, horizontal: bool = False):
        super().__init__(config)
        self.data.chart_type = ChartType.HORIZONTAL_BAR if horizontal else ChartType.BAR

    def build(self) -> ChartData:
        """Build bar chart data."""
        return self.data

    def from_dict(self, data: Dict[str, float], name: str = "Data",
                  color: str = "#3B82F6") -> "BarChartBuilder":
        """Create bars from a dictionary."""
        series = DataSeries(name=name, color=color)
        for label, value in data.items():
            series.add_point(label, value, label=label)
        self.data.add_series(series)
        return self


class PieChartBuilder(ChartBuilder):
    """Builder for pie/donut charts."""

    def __init__(self, config: Optional[ChartConfig] = None, donut: bool = False):
        super().__init__(config)
        self.data.chart_type = ChartType.DONUT if donut else ChartType.PIE
        self._colors = config.color_palette if config else [
            "#3B82F6", "#EF4444", "#10B981", "#F59E0B", "#8B5CF6",
            "#EC4899", "#06B6D4", "#84CC16", "#F97316", "#6366F1"
        ]

    def build(self) -> ChartData:
        """Build pie chart data."""
        return self.data

    def from_dict(self, data: Dict[str, float], name: str = "Data") -> "PieChartBuilder":
        """Create slices from a dictionary."""
        series = DataSeries(name=name)
        for i, (label, value) in enumerate(data.items()):
            color = self._colors[i % len(self._colors)]
            point = DataPoint(x=label, y=value, label=label, metadata={"color": color})
            series.points.append(point)
        self.data.add_series(series)
        return self


class AreaChartBuilder(ChartBuilder):
    """Builder for area charts."""

    def __init__(self, config: Optional[ChartConfig] = None, stacked: bool = False):
        super().__init__(config)
        self.data.chart_type = ChartType.STACKED_AREA if stacked else ChartType.AREA

    def build(self) -> ChartData:
        """Build area chart data."""
        return self.data


# =============================================================================
# Chart Renderers
# =============================================================================

class ChartRenderer(ABC):
    """Abstract base class for chart renderers."""

    @abstractmethod
    def render(self, data: ChartData, width: int = 800,
               height: int = 400) -> str:
        """Render chart to string output."""
        pass


class SVGRenderer(ChartRenderer):
    """Renders charts to SVG format."""

    def __init__(self, theme: str = "light"):
        self.theme = theme
        self._colors = {
            "light": {
                "background": "#FFFFFF",
                "text": "#1F2937",
                "grid": "#E5E7EB",
                "axis": "#9CA3AF",
            },
            "dark": {
                "background": "#1F2937",
                "text": "#F9FAFB",
                "grid": "#374151",
                "axis": "#6B7280",
            }
        }

    def render(self, data: ChartData, width: int = 800,
               height: int = 400) -> str:
        """Render chart to SVG string."""
        colors = self._colors.get(self.theme, self._colors["light"])

        # Calculate margins
        margin = {"top": 40, "right": 40, "bottom": 60, "left": 70}
        chart_width = width - margin["left"] - margin["right"]
        chart_height = height - margin["top"] - margin["bottom"]

        svg_parts = [
            f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
            f'<rect width="{width}" height="{height}" fill="{colors["background"]}"/>',
        ]

        # Title
        if data.title:
            svg_parts.append(
                f'<text x="{width/2}" y="25" text-anchor="middle" '
                f'font-size="16" font-weight="bold" fill="{colors["text"]}">'
                f'{self._escape(data.title)}</text>'
            )

        # Axis labels
        if data.x_label:
            svg_parts.append(
                f'<text x="{width/2}" y="{height - 10}" text-anchor="middle" '
                f'font-size="12" fill="{colors["axis"]}">{self._escape(data.x_label)}</text>'
            )
        if data.y_label:
            svg_parts.append(
                f'<text x="15" y="{height/2}" text-anchor="middle" '
                f'font-size="12" fill="{colors["axis"]}" '
                f'transform="rotate(-90, 15, {height/2})">{self._escape(data.y_label)}</text>'
            )

        # Render chart based on type
        if data.chart_type in [ChartType.LINE, ChartType.AREA]:
            svg_parts.append(self._render_line_chart(
                data, margin, chart_width, chart_height, colors
            ))
        elif data.chart_type in [ChartType.BAR, ChartType.HORIZONTAL_BAR]:
            svg_parts.append(self._render_bar_chart(
                data, margin, chart_width, chart_height, colors
            ))
        elif data.chart_type in [ChartType.PIE, ChartType.DONUT]:
            svg_parts.append(self._render_pie_chart(
                data, width, height, colors
            ))
        else:
            svg_parts.append(self._render_line_chart(
                data, margin, chart_width, chart_height, colors
            ))

        svg_parts.append("</svg>")
        return "\n".join(svg_parts)

    def _escape(self, text: str) -> str:
        """Escape special characters for XML."""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

    def _render_line_chart(self, data: ChartData, margin: Dict[str, int],
                          chart_width: int, chart_height: int,
                          colors: Dict[str, str]) -> str:
        """Render line/area chart."""
        parts = []

        if not data.series:
            return ""

        # Get data range
        min_y, max_y = data.get_y_range()
        y_range = max_y - min_y if max_y != min_y else 1

        # Draw grid
        num_grid_lines = 5
        for i in range(num_grid_lines + 1):
            y = margin["top"] + (chart_height * i / num_grid_lines)
            parts.append(
                f'<line x1="{margin["left"]}" y1="{y}" '
                f'x2="{margin["left"] + chart_width}" y2="{y}" '
                f'stroke="{colors["grid"]}" stroke-width="1"/>'
            )
            # Y-axis labels
            y_val = max_y - (y_range * i / num_grid_lines)
            parts.append(
                f'<text x="{margin["left"] - 10}" y="{y + 4}" '
                f'text-anchor="end" font-size="10" fill="{colors["axis"]}">'
                f'{y_val:.0f}</text>'
            )

        # Draw each series
        for series in data.series:
            if not series.points or not series.visible:
                continue

            # Calculate points
            num_points = len(series.points)
            path_points = []

            for i, point in enumerate(series.points):
                x = margin["left"] + (chart_width * i / max(num_points - 1, 1))
                y = margin["top"] + chart_height - (
                    (point.y - min_y) / y_range * chart_height
                )
                path_points.append((x, y))

            # Draw line
            if len(path_points) > 1:
                path_d = f"M {path_points[0][0]},{path_points[0][1]} "
                path_d += " ".join(f"L {x},{y}" for x, y in path_points[1:])

                stroke_dash = "5,5" if series.style == "dashed" else ""
                parts.append(
                    f'<path d="{path_d}" fill="none" stroke="{series.color}" '
                    f'stroke-width="2" stroke-dasharray="{stroke_dash}"/>'
                )

            # Draw points
            for x, y in path_points:
                parts.append(
                    f'<circle cx="{x}" cy="{y}" r="4" fill="{series.color}"/>'
                )

        # X-axis labels
        if data.series and data.series[0].points:
            points = data.series[0].points
            step = max(1, len(points) // 6)
            for i in range(0, len(points), step):
                x = margin["left"] + (chart_width * i / max(len(points) - 1, 1))
                label = str(points[i].x)
                if isinstance(points[i].x, datetime):
                    label = points[i].x.strftime("%m/%d")
                parts.append(
                    f'<text x="{x}" y="{margin["top"] + chart_height + 20}" '
                    f'text-anchor="middle" font-size="10" fill="{colors["axis"]}">'
                    f'{self._escape(label)}</text>'
                )

        # Legend
        legend_y = margin["top"] + chart_height + 45
        legend_x = margin["left"]
        for i, series in enumerate(data.series):
            if not series.visible:
                continue
            parts.append(
                f'<rect x="{legend_x + i * 100}" y="{legend_y - 8}" '
                f'width="12" height="12" fill="{series.color}"/>'
            )
            parts.append(
                f'<text x="{legend_x + i * 100 + 18}" y="{legend_y}" '
                f'font-size="10" fill="{colors["text"]}">'
                f'{self._escape(series.name)}</text>'
            )

        return "\n".join(parts)

    def _render_bar_chart(self, data: ChartData, margin: Dict[str, int],
                         chart_width: int, chart_height: int,
                         colors: Dict[str, str]) -> str:
        """Render bar chart."""
        parts = []

        if not data.series or not data.series[0].points:
            return ""

        series = data.series[0]
        num_bars = len(series.points)
        bar_width = (chart_width / num_bars) * 0.7
        bar_gap = (chart_width / num_bars) * 0.15

        max_y = series.get_max_y()
        if max_y == 0:
            max_y = 1

        for i, point in enumerate(series.points):
            x = margin["left"] + bar_gap + (chart_width * i / num_bars)
            bar_height = (point.y / max_y) * chart_height
            y = margin["top"] + chart_height - bar_height

            color = point.metadata.get("color", series.color)

            parts.append(
                f'<rect x="{x}" y="{y}" width="{bar_width}" height="{bar_height}" '
                f'fill="{color}" rx="2"/>'
            )

            # Value label
            parts.append(
                f'<text x="{x + bar_width/2}" y="{y - 5}" '
                f'text-anchor="middle" font-size="10" fill="{colors["text"]}">'
                f'{point.y:.0f}</text>'
            )

            # X-axis label
            label = str(point.x)[:10]
            parts.append(
                f'<text x="{x + bar_width/2}" y="{margin["top"] + chart_height + 20}" '
                f'text-anchor="middle" font-size="10" fill="{colors["axis"]}">'
                f'{self._escape(label)}</text>'
            )

        return "\n".join(parts)

    def _render_pie_chart(self, data: ChartData, width: int, height: int,
                         colors: Dict[str, str]) -> str:
        """Render pie/donut chart."""
        parts = []

        if not data.series or not data.series[0].points:
            return ""

        series = data.series[0]
        total = sum(p.y for p in series.points)
        if total == 0:
            return ""

        cx = width / 2
        cy = height / 2
        radius = min(width, height) * 0.35
        inner_radius = radius * 0.5 if data.chart_type == ChartType.DONUT else 0

        start_angle = -90  # Start at top

        default_colors = [
            "#3B82F6", "#EF4444", "#10B981", "#F59E0B", "#8B5CF6",
            "#EC4899", "#06B6D4", "#84CC16", "#F97316", "#6366F1"
        ]

        for i, point in enumerate(series.points):
            slice_angle = (point.y / total) * 360
            end_angle = start_angle + slice_angle

            # Calculate arc path
            start_rad = math.radians(start_angle)
            end_rad = math.radians(end_angle)

            x1 = cx + radius * math.cos(start_rad)
            y1 = cy + radius * math.sin(start_rad)
            x2 = cx + radius * math.cos(end_rad)
            y2 = cy + radius * math.sin(end_rad)

            large_arc = 1 if slice_angle > 180 else 0
            color = point.metadata.get("color", default_colors[i % len(default_colors)])

            if inner_radius > 0:
                # Donut
                ix1 = cx + inner_radius * math.cos(start_rad)
                iy1 = cy + inner_radius * math.sin(start_rad)
                ix2 = cx + inner_radius * math.cos(end_rad)
                iy2 = cy + inner_radius * math.sin(end_rad)

                path = (
                    f"M {x1},{y1} "
                    f"A {radius},{radius} 0 {large_arc},1 {x2},{y2} "
                    f"L {ix2},{iy2} "
                    f"A {inner_radius},{inner_radius} 0 {large_arc},0 {ix1},{iy1} "
                    f"Z"
                )
            else:
                # Pie
                path = (
                    f"M {cx},{cy} "
                    f"L {x1},{y1} "
                    f"A {radius},{radius} 0 {large_arc},1 {x2},{y2} "
                    f"Z"
                )

            parts.append(f'<path d="{path}" fill="{color}" stroke="white" stroke-width="2"/>')

            start_angle = end_angle

        # Legend
        legend_x = 20
        legend_y = height - len(series.points) * 20 - 10
        for i, point in enumerate(series.points):
            color = point.metadata.get("color", default_colors[i % len(default_colors)])
            pct = (point.y / total) * 100
            parts.append(
                f'<rect x="{legend_x}" y="{legend_y + i * 20}" '
                f'width="12" height="12" fill="{color}"/>'
            )
            parts.append(
                f'<text x="{legend_x + 18}" y="{legend_y + i * 20 + 10}" '
                f'font-size="10" fill="{colors["text"]}">'
                f'{self._escape(str(point.x))}: {pct:.1f}%</text>'
            )

        return "\n".join(parts)


class ASCIIRenderer(ChartRenderer):
    """Renders charts to ASCII art for terminal display."""

    def __init__(self, width: int = 60, height: int = 20):
        self.width = width
        self.height = height

    def render(self, data: ChartData, width: int = 60,
               height: int = 20) -> str:
        """Render chart to ASCII string."""
        if data.chart_type in [ChartType.BAR, ChartType.HORIZONTAL_BAR]:
            return self._render_bar(data, width)
        elif data.chart_type in [ChartType.PIE, ChartType.DONUT]:
            return self._render_pie(data)
        else:
            return self._render_line(data, width, height)

    def _render_line(self, data: ChartData, width: int, height: int) -> str:
        """Render line chart as ASCII."""
        lines = []

        if not data.series:
            return "No data"

        # Title
        if data.title:
            lines.append(data.title.center(width))
            lines.append("")

        # Get range
        min_y, max_y = data.get_y_range()
        y_range = max_y - min_y if max_y != min_y else 1

        # Create grid
        grid = [[" " for _ in range(width)] for _ in range(height)]

        # Plot points
        for series in data.series:
            if not series.points:
                continue

            char = "●" if series.style != "dashed" else "○"
            num_points = len(series.points)

            for i, point in enumerate(series.points):
                x = int((i / max(num_points - 1, 1)) * (width - 1))
                y = int((1 - (point.y - min_y) / y_range) * (height - 1))
                y = max(0, min(height - 1, y))
                x = max(0, min(width - 1, x))
                grid[y][x] = char

        # Add Y-axis labels
        for i, row in enumerate(grid):
            y_val = max_y - (y_range * i / (height - 1))
            label = f"{y_val:6.0f} │"
            lines.append(label + "".join(row))

        # X-axis
        lines.append("       └" + "─" * width)

        # Legend
        if len(data.series) > 1:
            lines.append("")
            legend_parts = []
            for series in data.series:
                char = "●" if series.style != "dashed" else "○"
                legend_parts.append(f"{char} {series.name}")
            lines.append("  ".join(legend_parts))

        return "\n".join(lines)

    def _render_bar(self, data: ChartData, width: int) -> str:
        """Render bar chart as ASCII."""
        lines = []

        if not data.series or not data.series[0].points:
            return "No data"

        # Title
        if data.title:
            lines.append(data.title)
            lines.append("")

        series = data.series[0]
        max_y = series.get_max_y()
        if max_y == 0:
            max_y = 1

        max_label_len = max(len(str(p.x)[:12]) for p in series.points)
        bar_width = width - max_label_len - 15

        for point in series.points:
            label = str(point.x)[:12].ljust(max_label_len)
            bar_len = int((point.y / max_y) * bar_width)
            bar = "█" * bar_len
            lines.append(f"{label} │{bar} {point.y:.0f}")

        return "\n".join(lines)

    def _render_pie(self, data: ChartData) -> str:
        """Render pie chart as ASCII list."""
        lines = []

        if not data.series or not data.series[0].points:
            return "No data"

        # Title
        if data.title:
            lines.append(data.title)
            lines.append("")

        series = data.series[0]
        total = sum(p.y for p in series.points)
        if total == 0:
            return "No data"

        max_label = max(len(str(p.x)) for p in series.points)

        for point in series.points:
            pct = (point.y / total) * 100
            bar_len = int(pct / 2)
            bar = "█" * bar_len
            label = str(point.x).ljust(max_label)
            lines.append(f"{label} │{bar} {pct:.1f}%")

        lines.append("")
        lines.append(f"Total: {total:.0f}")

        return "\n".join(lines)


# =============================================================================
# Visualization Factory Functions
# =============================================================================

def create_chart(chart_type: ChartType, config: Optional[ChartConfig] = None) -> ChartBuilder:
    """Create a chart builder for the specified type."""
    if chart_type == ChartType.LINE:
        return LineChartBuilder(config)
    elif chart_type in [ChartType.BAR, ChartType.STACKED_BAR]:
        return BarChartBuilder(config)
    elif chart_type == ChartType.HORIZONTAL_BAR:
        return BarChartBuilder(config, horizontal=True)
    elif chart_type == ChartType.PIE:
        return PieChartBuilder(config)
    elif chart_type == ChartType.DONUT:
        return PieChartBuilder(config, donut=True)
    elif chart_type in [ChartType.AREA, ChartType.STACKED_AREA]:
        return AreaChartBuilder(config, stacked=(chart_type == ChartType.STACKED_AREA))
    else:
        return LineChartBuilder(config)


def create_trend_chart(
    data: List[Tuple[datetime, float]],
    title: str = "Trend",
    series_name: str = "Value",
    include_trend_line: bool = True
) -> ChartData:
    """Create a trend chart from time-series data."""
    builder = LineChartBuilder()
    builder.set_title(title)
    builder.set_labels("Date", "Count")
    builder.add_series(series_name, data, "#3B82F6")

    if include_trend_line and len(data) >= 2:
        builder.with_trend_line(0)

    return builder.build()


def create_severity_chart(
    critical: int,
    high: int,
    medium: int,
    low: int,
    info: int = 0,
    title: str = "Findings by Severity"
) -> ChartData:
    """Create a severity distribution chart."""
    builder = PieChartBuilder()
    builder.set_title(title)

    data = {}
    colors = []
    if critical > 0:
        data["Critical"] = critical
        colors.append("#DC2626")
    if high > 0:
        data["High"] = high
        colors.append("#F97316")
    if medium > 0:
        data["Medium"] = medium
        colors.append("#EAB308")
    if low > 0:
        data["Low"] = low
        colors.append("#3B82F6")
    if info > 0:
        data["Info"] = info
        colors.append("#6B7280")

    # Assign colors manually
    series = DataSeries(name="Severity")
    for i, (label, value) in enumerate(data.items()):
        color = colors[i] if i < len(colors) else "#6B7280"
        series.points.append(DataPoint(
            x=label, y=value, label=label, metadata={"color": color}
        ))
    builder.data.add_series(series)

    return builder.build()


def create_compliance_chart(
    framework_scores: Dict[str, float],
    title: str = "Compliance Scores"
) -> ChartData:
    """Create a compliance score comparison chart."""
    builder = BarChartBuilder()
    builder.set_title(title)
    builder.set_labels("Framework", "Score (%)")

    # Color code by score
    series = DataSeries(name="Compliance")
    for framework, score in framework_scores.items():
        if score >= 90:
            color = "#10B981"  # Green
        elif score >= 70:
            color = "#EAB308"  # Yellow
        elif score >= 50:
            color = "#F97316"  # Orange
        else:
            color = "#DC2626"  # Red

        series.points.append(DataPoint(
            x=framework, y=score, label=framework, metadata={"color": color}
        ))

    builder.data.add_series(series)
    return builder.build()
