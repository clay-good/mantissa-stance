"""
Mantissa Stance Unified UI Design System.

This module provides a shared design system used by both the web dashboard
and static HTML exports to ensure visual consistency across all outputs.

Components:
- design_tokens: Colors, typography, spacing, and other design constants
- components: Reusable HTML component generators
- styles: CSS stylesheet generation
- charts: SVG chart generators
"""

from stance.ui.design_tokens import (
    Colors,
    Typography,
    Spacing,
    Shadows,
    BorderRadius,
    Breakpoints,
    get_css_variables,
)
from stance.ui.components import (
    ComponentBuilder,
    render_summary_card,
    render_badge,
    render_status_badge,
    render_data_table,
    render_finding_card,
    render_tabs,
    render_chart_container,
    render_header,
    render_footer,
    render_empty_state,
    render_progress_bar,
    render_metric_grid,
)
from stance.ui.styles import (
    get_base_styles,
    get_component_styles,
    get_full_stylesheet,
    get_print_styles,
)
from stance.ui.charts import (
    render_severity_bar_chart,
    render_donut_chart,
    render_trend_line_chart,
    render_compliance_gauge,
)

__all__ = [
    # Design Tokens
    "Colors",
    "Typography",
    "Spacing",
    "Shadows",
    "BorderRadius",
    "Breakpoints",
    "get_css_variables",
    # Components
    "ComponentBuilder",
    "render_summary_card",
    "render_badge",
    "render_status_badge",
    "render_data_table",
    "render_finding_card",
    "render_tabs",
    "render_chart_container",
    "render_header",
    "render_footer",
    "render_empty_state",
    "render_progress_bar",
    "render_metric_grid",
    # Styles
    "get_base_styles",
    "get_component_styles",
    "get_full_stylesheet",
    "get_print_styles",
    # Charts
    "render_severity_bar_chart",
    "render_donut_chart",
    "render_trend_line_chart",
    "render_compliance_gauge",
]
