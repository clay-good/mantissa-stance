"""
SVG Chart Generators for Mantissa Stance.

This module provides pure SVG chart generators that work in both
the web dashboard and static HTML exports without requiring JavaScript
charting libraries.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from stance.ui.design_tokens import Colors


def _escape_svg(text: str) -> str:
    """Escape text for SVG content."""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# =============================================================================
# Severity Bar Chart
# =============================================================================

def render_severity_bar_chart(
    counts: Dict[str, int],
    width: int = 600,
    height: int = 40,
) -> str:
    """
    Render a horizontal stacked bar chart showing severity distribution.

    Args:
        counts: Dict mapping severity names to counts
        width: Chart width in pixels
        height: Chart height in pixels

    Returns:
        SVG string
    """
    total = sum(counts.values())
    if total == 0:
        return ""

    severity_colors = {
        "critical": Colors.SEVERITY_CRITICAL,
        "high": Colors.SEVERITY_HIGH,
        "medium": Colors.SEVERITY_MEDIUM,
        "low": Colors.SEVERITY_LOW,
        "info": Colors.SEVERITY_INFO,
    }

    segments = []
    x_offset = 0

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(severity, 0)
        if count > 0:
            segment_width = (count / total) * width
            color = severity_colors.get(severity, Colors.SEVERITY_INFO)

            segments.append(f"""
            <g class="severity-segment" data-severity="{severity}" data-count="{count}">
                <rect x="{x_offset}" y="0" width="{segment_width}" height="{height}"
                      fill="{color}" rx="0" ry="0">
                    <title>{severity.title()}: {count}</title>
                </rect>
                {"" if segment_width < 30 else f'<text x="{x_offset + segment_width/2}" y="{height/2 + 5}" fill="white" text-anchor="middle" font-size="12" font-weight="600">{count}</text>'}
            </g>
            """)

            x_offset += segment_width

    return f"""
    <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"
         xmlns="http://www.w3.org/2000/svg" class="stance-severity-chart">
        <rect x="0" y="0" width="{width}" height="{height}" fill="#e5e7eb" rx="6" ry="6"/>
        <g clip-path="url(#bar-clip)">
            {" ".join(segments)}
        </g>
        <defs>
            <clipPath id="bar-clip">
                <rect x="0" y="0" width="{width}" height="{height}" rx="6" ry="6"/>
            </clipPath>
        </defs>
    </svg>
    """


# =============================================================================
# Donut Chart
# =============================================================================

def render_donut_chart(
    data: Dict[str, int],
    colors: Optional[Dict[str, str]] = None,
    size: int = 200,
    inner_radius_ratio: float = 0.6,
    show_legend: bool = True,
    title: Optional[str] = None,
    center_text: Optional[str] = None,
    center_subtext: Optional[str] = None,
) -> str:
    """
    Render a donut chart.

    Args:
        data: Dict mapping labels to values
        colors: Optional dict mapping labels to colors
        size: Chart size in pixels
        inner_radius_ratio: Ratio of inner to outer radius (0-1)
        show_legend: Whether to show legend
        title: Optional chart title
        center_text: Optional text in center of donut
        center_subtext: Optional subtext below center text

    Returns:
        SVG string
    """
    total = sum(data.values())
    if total == 0:
        return ""

    # Default colors if not provided
    if colors is None:
        default_colors = [
            Colors.SEVERITY_CRITICAL,
            Colors.SEVERITY_HIGH,
            Colors.SEVERITY_MEDIUM,
            Colors.SEVERITY_LOW,
            Colors.SEVERITY_INFO,
            "#8b5cf6", "#ec4899", "#14b8a6",
        ]
        colors = {label: default_colors[i % len(default_colors)]
                  for i, label in enumerate(data.keys())}

    center = size / 2
    outer_radius = size / 2 - 10
    inner_radius = outer_radius * inner_radius_ratio

    # Generate pie segments
    segments = []
    start_angle = -90  # Start from top

    for label, value in data.items():
        if value == 0:
            continue

        angle = (value / total) * 360
        end_angle = start_angle + angle

        # Calculate arc path
        start_rad = math.radians(start_angle)
        end_rad = math.radians(end_angle)

        # Outer arc
        x1_outer = center + outer_radius * math.cos(start_rad)
        y1_outer = center + outer_radius * math.sin(start_rad)
        x2_outer = center + outer_radius * math.cos(end_rad)
        y2_outer = center + outer_radius * math.sin(end_rad)

        # Inner arc
        x1_inner = center + inner_radius * math.cos(end_rad)
        y1_inner = center + inner_radius * math.sin(end_rad)
        x2_inner = center + inner_radius * math.cos(start_rad)
        y2_inner = center + inner_radius * math.sin(start_rad)

        large_arc = 1 if angle > 180 else 0
        color = colors.get(label, Colors.SEVERITY_INFO)

        path = f"""
        M {x1_outer} {y1_outer}
        A {outer_radius} {outer_radius} 0 {large_arc} 1 {x2_outer} {y2_outer}
        L {x1_inner} {y1_inner}
        A {inner_radius} {inner_radius} 0 {large_arc} 0 {x2_inner} {y2_inner}
        Z
        """

        percentage = (value / total) * 100
        segments.append(f"""
        <path d="{path}" fill="{color}" stroke="white" stroke-width="2">
            <title>{_escape_svg(label)}: {value} ({percentage:.1f}%)</title>
        </path>
        """)

        start_angle = end_angle

    # Center text
    center_html = ""
    if center_text:
        center_html = f"""
        <text x="{center}" y="{center - 5 if center_subtext else center + 5}"
              text-anchor="middle" font-size="24" font-weight="700" fill="#111827">
            {_escape_svg(center_text)}
        </text>
        """
        if center_subtext:
            center_html += f"""
            <text x="{center}" y="{center + 18}"
                  text-anchor="middle" font-size="12" fill="#6b7280">
                {_escape_svg(center_subtext)}
            </text>
            """

    # Title
    title_html = ""
    if title:
        title_html = f"""
        <text x="{center}" y="20" text-anchor="middle"
              font-size="14" font-weight="600" fill="#111827">
            {_escape_svg(title)}
        </text>
        """

    chart_svg = f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}"
         xmlns="http://www.w3.org/2000/svg" class="stance-donut-chart">
        {title_html}
        <g transform="translate(0, {20 if title else 0})">
            {"".join(segments)}
            {center_html}
        </g>
    </svg>
    """

    # Legend
    legend_html = ""
    if show_legend:
        legend_items = []
        for label, value in data.items():
            color = colors.get(label, Colors.SEVERITY_INFO)
            percentage = (value / total) * 100 if total > 0 else 0
            legend_items.append(f"""
            <div class="stance-legend__item">
                <div class="stance-legend__color" style="background: {color}"></div>
                <span>{_escape_svg(label)}</span>
                <span style="color: #6b7280; margin-left: auto;">{value} ({percentage:.1f}%)</span>
            </div>
            """)

        legend_html = f"""
        <div class="stance-legend" style="flex-direction: column; gap: 8px; margin-top: 16px;">
            {"".join(legend_items)}
        </div>
        """

    return f"""
    <div class="stance-donut-container">
        {chart_svg}
        {legend_html}
    </div>
    """


# =============================================================================
# Trend Line Chart
# =============================================================================

def render_trend_line_chart(
    data: List[Tuple[datetime, int]],
    width: int = 600,
    height: int = 200,
    title: Optional[str] = None,
    show_points: bool = True,
    show_area: bool = True,
    line_color: str = Colors.BRAND_PRIMARY,
) -> str:
    """
    Render a trend line chart.

    Args:
        data: List of (datetime, value) tuples
        width: Chart width in pixels
        height: Chart height in pixels
        title: Optional chart title
        show_points: Whether to show data points
        show_area: Whether to show filled area under line
        line_color: Line color

    Returns:
        SVG string
    """
    if not data or len(data) < 2:
        return ""

    padding = {"top": 30, "right": 20, "bottom": 40, "left": 50}
    chart_width = width - padding["left"] - padding["right"]
    chart_height = height - padding["top"] - padding["bottom"]

    # Calculate scales
    values = [v for _, v in data]
    min_val = min(values)
    max_val = max(values)
    val_range = max_val - min_val or 1

    dates = [d for d, _ in data]
    min_date = min(dates)
    max_date = max(dates)
    date_range = (max_date - min_date).total_seconds() or 1

    def scale_x(d: datetime) -> float:
        return padding["left"] + ((d - min_date).total_seconds() / date_range) * chart_width

    def scale_y(v: int) -> float:
        return padding["top"] + chart_height - ((v - min_val) / val_range) * chart_height

    # Build line path
    points = [(scale_x(d), scale_y(v)) for d, v in data]
    line_path = f"M {points[0][0]} {points[0][1]}"
    for x, y in points[1:]:
        line_path += f" L {x} {y}"

    # Area path (for filled area)
    area_path = ""
    if show_area:
        area_path = line_path
        area_path += f" L {points[-1][0]} {padding['top'] + chart_height}"
        area_path += f" L {points[0][0]} {padding['top'] + chart_height} Z"

    # Grid lines
    grid_lines = []
    num_y_lines = 5
    for i in range(num_y_lines + 1):
        y = padding["top"] + (i / num_y_lines) * chart_height
        value = max_val - (i / num_y_lines) * val_range
        grid_lines.append(f"""
        <line x1="{padding['left']}" y1="{y}" x2="{width - padding['right']}" y2="{y}"
              stroke="#e5e7eb" stroke-dasharray="4"/>
        <text x="{padding['left'] - 8}" y="{y + 4}" text-anchor="end"
              font-size="11" fill="#6b7280">{int(value)}</text>
        """)

    # X-axis labels (show first, middle, last)
    x_labels = []
    label_indices = [0, len(data) // 2, len(data) - 1]
    for idx in label_indices:
        d, _ = data[idx]
        x = scale_x(d)
        x_labels.append(f"""
        <text x="{x}" y="{height - 10}" text-anchor="middle"
              font-size="11" fill="#6b7280">{d.strftime("%m/%d")}</text>
        """)

    # Data points
    point_circles = ""
    if show_points:
        circles = []
        for i, (x, y) in enumerate(points):
            _, value = data[i]
            circles.append(f"""
            <circle cx="{x}" cy="{y}" r="4" fill="{line_color}" stroke="white" stroke-width="2">
                <title>{data[i][0].strftime("%Y-%m-%d")}: {value}</title>
            </circle>
            """)
        point_circles = "".join(circles)

    # Title
    title_html = ""
    if title:
        title_html = f"""
        <text x="{width / 2}" y="18" text-anchor="middle"
              font-size="14" font-weight="600" fill="#111827">
            {_escape_svg(title)}
        </text>
        """

    return f"""
    <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"
         xmlns="http://www.w3.org/2000/svg" class="stance-trend-chart">
        {title_html}

        <!-- Grid -->
        {"".join(grid_lines)}

        <!-- Area fill -->
        {f'<path d="{area_path}" fill="{line_color}" fill-opacity="0.1"/>' if show_area else ''}

        <!-- Line -->
        <path d="{line_path}" fill="none" stroke="{line_color}"
              stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>

        <!-- Points -->
        {point_circles}

        <!-- X-axis labels -->
        {"".join(x_labels)}

        <!-- Axes -->
        <line x1="{padding['left']}" y1="{padding['top'] + chart_height}"
              x2="{width - padding['right']}" y2="{padding['top'] + chart_height}"
              stroke="#d1d5db"/>
    </svg>
    """


# =============================================================================
# Compliance Gauge
# =============================================================================

def render_compliance_gauge(
    score: float,
    max_score: float = 100,
    size: int = 160,
    label: Optional[str] = None,
) -> str:
    """
    Render a semicircular compliance gauge.

    Args:
        score: Current compliance score
        max_score: Maximum score (default 100)
        size: Gauge size in pixels
        label: Optional label below score

    Returns:
        SVG string
    """
    percentage = min(100, (score / max_score) * 100) if max_score > 0 else 0

    # Determine color based on score
    if percentage >= 80:
        color = Colors.SUCCESS
    elif percentage >= 60:
        color = Colors.WARNING
    else:
        color = Colors.ERROR

    center_x = size / 2
    center_y = size * 0.6
    radius = size * 0.4
    stroke_width = size * 0.1

    # Calculate arc
    start_angle = 180
    end_angle = 180 + (percentage / 100) * 180
    total_arc = 180

    # Background arc (full semicircle)
    bg_path = _arc_path(center_x, center_y, radius, 180, 360)

    # Value arc
    value_path = _arc_path(center_x, center_y, radius, start_angle, end_angle)

    return f"""
    <svg width="{size}" height="{size * 0.7}" viewBox="0 0 {size} {size * 0.7}"
         xmlns="http://www.w3.org/2000/svg" class="stance-gauge">

        <!-- Background arc -->
        <path d="{bg_path}" fill="none" stroke="#e5e7eb"
              stroke-width="{stroke_width}" stroke-linecap="round"/>

        <!-- Value arc -->
        <path d="{value_path}" fill="none" stroke="{color}"
              stroke-width="{stroke_width}" stroke-linecap="round"/>

        <!-- Score text -->
        <text x="{center_x}" y="{center_y - 5}" text-anchor="middle"
              font-size="{size * 0.2}" font-weight="700" fill="#111827">
            {score:.0f}%
        </text>

        <!-- Label -->
        {f'<text x="{center_x}" y="{center_y + size * 0.12}" text-anchor="middle" font-size="{size * 0.08}" fill="#6b7280">{_escape_svg(label)}</text>' if label else ''}
    </svg>
    """


def _arc_path(cx: float, cy: float, r: float, start_deg: float, end_deg: float) -> str:
    """Generate SVG arc path."""
    start_rad = math.radians(start_deg)
    end_rad = math.radians(end_deg)

    x1 = cx + r * math.cos(start_rad)
    y1 = cy + r * math.sin(start_rad)
    x2 = cx + r * math.cos(end_rad)
    y2 = cy + r * math.sin(end_rad)

    large_arc = 1 if (end_deg - start_deg) > 180 else 0

    return f"M {x1} {y1} A {r} {r} 0 {large_arc} 1 {x2} {y2}"


# =============================================================================
# Mini Sparkline
# =============================================================================

def render_sparkline(
    values: List[int],
    width: int = 100,
    height: int = 30,
    line_color: str = Colors.BRAND_PRIMARY,
    fill: bool = True,
) -> str:
    """
    Render a small sparkline chart.

    Args:
        values: List of numeric values
        width: Chart width in pixels
        height: Chart height in pixels
        line_color: Line color
        fill: Whether to fill area under line

    Returns:
        SVG string
    """
    if not values or len(values) < 2:
        return ""

    min_val = min(values)
    max_val = max(values)
    val_range = max_val - min_val or 1

    padding = 2
    chart_width = width - padding * 2
    chart_height = height - padding * 2

    points = []
    for i, v in enumerate(values):
        x = padding + (i / (len(values) - 1)) * chart_width
        y = padding + chart_height - ((v - min_val) / val_range) * chart_height
        points.append((x, y))

    # Line path
    line_path = f"M {points[0][0]} {points[0][1]}"
    for x, y in points[1:]:
        line_path += f" L {x} {y}"

    # Area path
    area_path = ""
    if fill:
        area_path = line_path
        area_path += f" L {points[-1][0]} {height - padding}"
        area_path += f" L {points[0][0]} {height - padding} Z"

    return f"""
    <svg width="{width}" height="{height}" viewBox="0 0 {width} {height}"
         xmlns="http://www.w3.org/2000/svg" class="stance-sparkline">
        {f'<path d="{area_path}" fill="{line_color}" fill-opacity="0.15"/>' if fill else ''}
        <path d="{line_path}" fill="none" stroke="{line_color}"
              stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    """
