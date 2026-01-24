"""
Reusable UI Components for Mantissa Stance.

This module provides component generator functions that output consistent
HTML markup used by both the web dashboard and static exports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from html import escape as html_escape

from stance.ui.design_tokens import Colors


@dataclass
class ComponentBuilder:
    """
    Builder for creating HTML components with consistent styling.

    Provides a fluent interface for constructing complex HTML structures.
    """

    _html_parts: List[str] = field(default_factory=list)

    def add(self, html: str) -> "ComponentBuilder":
        """Add HTML content."""
        self._html_parts.append(html)
        return self

    def build(self) -> str:
        """Build and return the final HTML string."""
        return "".join(self._html_parts)


def _escape(text: Any) -> str:
    """Safely escape text for HTML output."""
    if text is None:
        return ""
    return html_escape(str(text))


def _truncate(text: str, max_length: int = 50) -> str:
    """Truncate text with ellipsis."""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length] + "..."


# =============================================================================
# Header Component
# =============================================================================

def render_header(
    title: str,
    subtitle: Optional[str] = None,
    generated_at: Optional[datetime] = None,
    author: Optional[str] = None,
    extra_meta: Optional[List[Dict[str, str]]] = None,
) -> str:
    """
    Render the report/page header.

    Args:
        title: Main title text
        subtitle: Optional subtitle
        generated_at: Report generation timestamp
        author: Report author name
        extra_meta: Additional metadata items

    Returns:
        HTML string
    """
    meta_items = []

    if generated_at:
        formatted_date = generated_at.strftime("%B %d, %Y at %H:%M UTC")
        meta_items.append(f'<span class="stance-header__meta-item">📅 {_escape(formatted_date)}</span>')

    if author:
        meta_items.append(f'<span class="stance-header__meta-item">👤 {_escape(author)}</span>')

    if extra_meta:
        for item in extra_meta:
            icon = item.get("icon", "")
            label = item.get("label", "")
            meta_items.append(f'<span class="stance-header__meta-item">{icon} {_escape(label)}</span>')

    meta_html = f'<div class="stance-header__meta">{"".join(meta_items)}</div>' if meta_items else ""
    subtitle_html = f'<p class="stance-header__subtitle">{_escape(subtitle)}</p>' if subtitle else ""

    return f"""
    <header class="stance-header">
        <h1 class="stance-header__title">{_escape(title)}</h1>
        {subtitle_html}
        {meta_html}
    </header>
    """


# =============================================================================
# Summary Cards
# =============================================================================

def render_summary_card(
    value: Any,
    label: str,
    variant: Optional[str] = None,
    trend: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Render a summary metric card.

    Args:
        value: The metric value to display
        label: Label describing the metric
        variant: Color variant (critical, high, medium, low, success)
        trend: Optional trend data with 'direction' and 'value' keys

    Returns:
        HTML string
    """
    variant_class = f" stance-card--{variant}" if variant else ""

    # Format value
    if isinstance(value, (int, float)):
        formatted_value = f"{value:,}" if isinstance(value, int) else f"{value:.1f}"
    else:
        formatted_value = str(value)

    trend_html = ""
    if trend:
        direction = trend.get("direction", "stable")
        trend_value = trend.get("value", "")
        direction_class = f"stance-card__trend--{direction}"
        arrow = "↑" if direction == "up" else "↓" if direction == "down" else "→"
        trend_html = f'<div class="stance-card__trend {direction_class}">{arrow} {_escape(str(trend_value))}</div>'

    return f"""
    <div class="stance-card stance-card--summary{variant_class}">
        <div class="stance-card__value">{formatted_value}</div>
        <div class="stance-card__label">{_escape(label)}</div>
        {trend_html}
    </div>
    """


def render_metric_grid(metrics: List[Dict[str, Any]]) -> str:
    """
    Render a grid of summary metric cards.

    Args:
        metrics: List of metric dicts with value, label, variant, trend

    Returns:
        HTML string
    """
    cards = [
        render_summary_card(
            value=m.get("value", 0),
            label=m.get("label", ""),
            variant=m.get("variant"),
            trend=m.get("trend"),
        )
        for m in metrics
    ]

    return f"""
    <div class="stance-summary-grid">
        {"".join(cards)}
    </div>
    """


# =============================================================================
# Badges
# =============================================================================

def render_badge(
    text: str,
    variant: str = "info",
) -> str:
    """
    Render a severity/category badge.

    Args:
        text: Badge text
        variant: Color variant (critical, high, medium, low, info)

    Returns:
        HTML string
    """
    return f'<span class="stance-badge stance-badge--{variant}">{_escape(text)}</span>'


def render_status_badge(
    status: str,
    show_dot: bool = True,
) -> str:
    """
    Render a status badge with optional indicator dot.

    Args:
        status: Status value (open, resolved, suppressed, false_positive)
        show_dot: Whether to show the status indicator dot

    Returns:
        HTML string
    """
    status_normalized = status.lower().replace(" ", "-").replace("_", "-")
    display_text = status.replace("_", " ").title()

    dot_html = '<span class="stance-status__dot"></span>' if show_dot else ""

    return f"""
    <span class="stance-status stance-status--{status_normalized}">
        {dot_html}
        {_escape(display_text)}
    </span>
    """


# =============================================================================
# Tabs
# =============================================================================

def render_tabs(
    tabs: List[Dict[str, Any]],
    active_tab: Optional[str] = None,
) -> str:
    """
    Render a tabbed navigation component.

    Args:
        tabs: List of tab dicts with id, label, count (optional)
        active_tab: ID of the currently active tab

    Returns:
        HTML string
    """
    if not active_tab and tabs:
        active_tab = tabs[0].get("id")

    tab_buttons = []
    for tab in tabs:
        tab_id = tab.get("id", "")
        label = tab.get("label", "")
        count = tab.get("count")

        active_class = " stance-tabs__tab--active" if tab_id == active_tab else ""
        count_html = f'<span class="stance-tabs__tab-count">{count}</span>' if count is not None else ""

        tab_buttons.append(f"""
        <button class="stance-tabs__tab{active_class}"
                onclick="showTab('{tab_id}')"
                role="tab"
                aria-selected="{'true' if tab_id == active_tab else 'false'}">
            {_escape(label)}{count_html}
        </button>
        """)

    return f"""
    <nav class="stance-tabs" role="tablist">
        {"".join(tab_buttons)}
    </nav>
    """


def render_tab_content(
    tab_id: str,
    content: str,
    is_active: bool = False,
) -> str:
    """
    Render a tab content panel.

    Args:
        tab_id: Tab identifier
        content: HTML content for the tab
        is_active: Whether this tab is currently active

    Returns:
        HTML string
    """
    active_class = " stance-tab-content--active" if is_active else ""

    return f"""
    <div id="{tab_id}"
         class="stance-tab-content{active_class}"
         role="tabpanel">
        {content}
    </div>
    """


# =============================================================================
# Data Tables
# =============================================================================

def render_data_table(
    columns: List[Dict[str, Any]],
    rows: List[Dict[str, Any]],
    table_id: Optional[str] = None,
    empty_message: str = "No data to display",
) -> str:
    """
    Render a data table.

    Args:
        columns: List of column dicts with key, label, width (optional), render (optional)
        rows: List of row data dicts
        table_id: Optional table ID for JavaScript interactions
        empty_message: Message to show when table is empty

    Returns:
        HTML string
    """
    if not rows:
        return render_empty_state(message=empty_message)

    # Build header
    header_cells = []
    for col in columns:
        width_style = f' style="width: {col["width"]}"' if col.get("width") else ""
        sortable_class = " th--sortable" if col.get("sortable") else ""
        header_cells.append(f'<th{width_style} class="{sortable_class}">{_escape(col.get("label", ""))}</th>')

    # Build rows
    body_rows = []
    for row in rows:
        cells = []
        for col in columns:
            key = col.get("key", "")
            value = row.get(key, "")

            # Custom render function
            render_fn = col.get("render")
            if render_fn and callable(render_fn):
                cell_content = render_fn(value, row)
            else:
                cell_content = _escape(str(value)) if value is not None else ""

            cells.append(f"<td>{cell_content}</td>")

        body_rows.append(f"<tr>{''.join(cells)}</tr>")

    id_attr = f' id="{table_id}"' if table_id else ""

    return f"""
    <div class="stance-table-container">
        <table class="stance-table"{id_attr}>
            <thead>
                <tr>{"".join(header_cells)}</tr>
            </thead>
            <tbody>
                {"".join(body_rows)}
            </tbody>
        </table>
    </div>
    """


# =============================================================================
# Finding Cards
# =============================================================================

def render_finding_card(
    title: str,
    description: str,
    severity: str,
    status: str,
    rule_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    first_seen: Optional[datetime] = None,
    remediation: Optional[str] = None,
) -> str:
    """
    Render a finding detail card.

    Args:
        title: Finding title
        description: Finding description
        severity: Severity level
        status: Finding status
        rule_id: Policy rule ID
        asset_id: Affected asset ID
        first_seen: When finding was first detected
        remediation: Remediation guidance

    Returns:
        HTML string
    """
    severity_lower = severity.lower()

    # Meta items
    meta_items = []
    if rule_id:
        meta_items.append(f'<span class="stance-finding__meta-item">🏷️ Rule: {_escape(rule_id)}</span>')
    if asset_id:
        truncated_asset = _truncate(asset_id, 40)
        meta_items.append(f'<span class="stance-finding__meta-item">📦 Asset: {_escape(truncated_asset)}</span>')
    if first_seen:
        meta_items.append(f'<span class="stance-finding__meta-item">📅 First seen: {first_seen.strftime("%Y-%m-%d")}</span>')

    meta_html = f'<div class="stance-finding__meta">{"".join(meta_items)}</div>' if meta_items else ""

    # Remediation section
    remediation_html = ""
    if remediation:
        remediation_html = f"""
        <div class="stance-finding__remediation">
            <div class="stance-finding__remediation-title">Remediation</div>
            {_escape(remediation)}
        </div>
        """

    return f"""
    <article class="stance-finding stance-finding--{severity_lower}">
        <header class="stance-finding__header">
            <h3 class="stance-finding__title">{_escape(title)}</h3>
            <div class="stance-finding__badges">
                {render_badge(severity, severity_lower)}
                {render_status_badge(status)}
            </div>
        </header>
        {meta_html}
        <div class="stance-finding__description">{_escape(description)}</div>
        {remediation_html}
    </article>
    """


def render_findings_list(
    findings: List[Dict[str, Any]],
    empty_message: str = "No findings to display",
) -> str:
    """
    Render a list of finding cards.

    Args:
        findings: List of finding dicts
        empty_message: Message when no findings

    Returns:
        HTML string
    """
    if not findings:
        return render_empty_state(message=empty_message)

    cards = [
        render_finding_card(
            title=f.get("title", ""),
            description=f.get("description", ""),
            severity=f.get("severity", "info"),
            status=f.get("status", "open"),
            rule_id=f.get("rule_id"),
            asset_id=f.get("asset_id"),
            first_seen=f.get("first_seen"),
            remediation=f.get("remediation_guidance"),
        )
        for f in findings
    ]

    return "".join(cards)


# =============================================================================
# Section Headers
# =============================================================================

def render_section_header(
    title: str,
    count: Optional[int] = None,
    subtitle: Optional[str] = None,
) -> str:
    """
    Render a section header with optional count badge.

    Args:
        title: Section title
        count: Optional count to display
        subtitle: Optional subtitle text

    Returns:
        HTML string
    """
    count_html = f'<span class="stance-section__count">{count}</span>' if count is not None else ""
    subtitle_html = f'<p class="stance-section__subtitle">{_escape(subtitle)}</p>' if subtitle else ""

    return f"""
    <header class="stance-section__header">
        <div>
            <h2 class="stance-section__title">{_escape(title)}</h2>
            {subtitle_html}
        </div>
        {count_html}
    </header>
    """


# =============================================================================
# Charts & Visualizations
# =============================================================================

def render_chart_container(
    title: str,
    content: str,
) -> str:
    """
    Render a chart container with title.

    Args:
        title: Chart title
        content: Chart HTML content

    Returns:
        HTML string
    """
    return f"""
    <div class="stance-chart">
        <h3 class="stance-chart__title">{_escape(title)}</h3>
        {content}
    </div>
    """


def render_severity_bar(
    counts: Dict[str, int],
) -> str:
    """
    Render a horizontal severity distribution bar.

    Args:
        counts: Dict mapping severity names to counts

    Returns:
        HTML string
    """
    total = sum(counts.values()) or 1

    segments = []
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(severity, 0)
        if count > 0:
            pct = (count / total) * 100
            segments.append(f"""
            <div class="stance-severity-bar__segment stance-severity-bar__segment--{severity}"
                 style="width: {pct}%"
                 title="{severity.title()}: {count}">
                {count}
            </div>
            """)

    # Legend
    legend_items = []
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(severity, 0)
        color = getattr(Colors, f"SEVERITY_{severity.upper()}", Colors.SEVERITY_INFO)
        legend_items.append(f"""
        <div class="stance-legend__item">
            <div class="stance-legend__color" style="background: {color}"></div>
            {severity.title()} ({count})
        </div>
        """)

    return f"""
    <div class="stance-severity-bar">
        {"".join(segments)}
    </div>
    <div class="stance-legend">
        {"".join(legend_items)}
    </div>
    """


def render_status_summary(
    counts: Dict[str, int],
) -> str:
    """
    Render a status summary grid.

    Args:
        counts: Dict mapping status names to counts

    Returns:
        HTML string
    """
    statuses = [
        ("open", "Open"),
        ("resolved", "Resolved"),
        ("suppressed", "Suppressed"),
        ("false_positive", "False Positive"),
    ]

    cards = []
    for status_key, status_label in statuses:
        count = counts.get(status_key, 0)
        cards.append(f"""
        <div class="stance-status-card stance-status-card--{status_key.replace('_', '-')}">
            <div class="stance-status-card__value">{count}</div>
            <div class="stance-status-card__label">{status_label}</div>
        </div>
        """)

    return f"""
    <div class="stance-status-grid">
        {"".join(cards)}
    </div>
    """


def render_progress_bar(
    value: float,
    max_value: float = 100,
    label: Optional[str] = None,
    variant: Optional[str] = None,
) -> str:
    """
    Render a progress/compliance bar.

    Args:
        value: Current value
        max_value: Maximum value (default 100)
        label: Optional label text
        variant: Color variant (success, warning, error) or auto-detect

    Returns:
        HTML string
    """
    percentage = min(100, (value / max_value) * 100) if max_value > 0 else 0

    # Auto-detect variant based on percentage
    if variant is None:
        if percentage >= 80:
            variant = "success"
        elif percentage >= 60:
            variant = "warning"
        else:
            variant = "error"

    label_html = f'<span class="stance-progress__label">{_escape(label)}</span>' if label else ""

    return f"""
    <div class="stance-progress">
        {label_html}
        <div class="stance-progress__bar">
            <div class="stance-progress__fill stance-progress__fill--{variant}"
                 style="width: {percentage}%"></div>
        </div>
        <span class="stance-progress__value">{value:.0f}%</span>
    </div>
    """


# =============================================================================
# Empty States
# =============================================================================

def render_empty_state(
    message: str = "No data to display",
    icon: str = "📭",
    description: Optional[str] = None,
) -> str:
    """
    Render an empty state placeholder.

    Args:
        message: Main message
        icon: Emoji or icon character
        description: Additional description text

    Returns:
        HTML string
    """
    description_html = f'<p class="stance-empty__description">{_escape(description)}</p>' if description else ""

    return f"""
    <div class="stance-empty">
        <div class="stance-empty__icon">{icon}</div>
        <h3 class="stance-empty__title">{_escape(message)}</h3>
        {description_html}
    </div>
    """


# =============================================================================
# Footer
# =============================================================================

def render_footer(
    extra_text: Optional[str] = None,
) -> str:
    """
    Render the page/report footer.

    Args:
        extra_text: Additional footer text

    Returns:
        HTML string
    """
    extra_html = f'<p>{_escape(extra_text)}</p>' if extra_text else ""

    return f"""
    <footer class="stance-footer">
        <p>Generated by <span class="stance-footer__brand">Mantissa Stance</span> — Cloud Security Posture Management</p>
        {extra_html}
    </footer>
    """
