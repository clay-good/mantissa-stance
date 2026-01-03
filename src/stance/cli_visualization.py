"""
CLI commands for Enhanced Visualization features in Mantissa Stance.

Provides dashboard management, widget operations, embedding controls,
and real-time streaming management.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import click

from stance.dashboards import (
    # Dashboard models
    Dashboard,
    DashboardLayout,
    DashboardTheme,
    Widget,
    WidgetType,
    ChartType,
    TimeRange,
    # Widget builder
    WidgetBuilder,
    WidgetPalette,
    create_widget_builder,
    create_widget_palette,
    # Embedding
    EmbeddingManager,
    ShareType,
    AccessLevel,
    EmbedMode,
    create_embedding_manager,
    create_embed_renderer,
    # Real-time
    EventBus,
    DashboardStreamManager,
    DashboardUpdateManager,
    create_event_bus,
    create_stream_manager,
    create_update_manager,
    # Interactive
    InteractiveChart,
    create_interactive_chart,
)


@click.group()
def viz():
    """Enhanced visualization commands."""
    pass


# =============================================================================
# Widget Builder Commands
# =============================================================================

@viz.group()
def widget():
    """Widget management commands."""
    pass


@widget.command("list-templates")
@click.option("--category", "-c", help="Filter by category")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def list_widget_templates(category: Optional[str], json_output: bool):
    """List available widget templates."""
    palette = create_widget_palette()

    if category:
        from stance.dashboards.widget_builder import WidgetCategory
        try:
            cat = WidgetCategory(category)
            templates = palette.get_templates_by_category(cat)
        except ValueError:
            click.echo(f"Unknown category: {category}", err=True)
            click.echo(f"Available: {[c.value for c in WidgetCategory]}")
            sys.exit(1)
    else:
        templates = palette.get_all_templates()

    if json_output:
        output = [t.to_dict() for t in templates]
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\nAvailable Widget Templates ({len(templates)}):\n")

        # Group by category
        by_category: Dict[str, List] = {}
        for t in templates:
            cat = t.category.value
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(t)

        for cat, cat_templates in sorted(by_category.items()):
            click.echo(f"  {cat.upper()}:")
            for t in cat_templates:
                click.echo(f"    - {t.id}: {t.name}")
                click.echo(f"      {t.description}")
                click.echo(f"      Size: {t.default_size[0]}x{t.default_size[1]} | Tags: {', '.join(t.tags)}")
            click.echo()


@widget.command("search")
@click.argument("query")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def search_widgets(query: str, json_output: bool):
    """Search widget templates."""
    palette = create_widget_palette()
    results = palette.search_templates(query)

    if json_output:
        output = [t.to_dict() for t in results]
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\nSearch results for '{query}' ({len(results)} found):\n")
        for t in results:
            click.echo(f"  {t.id}: {t.name} [{t.category.value}]")
            click.echo(f"    {t.description}")
        click.echo()


@widget.command("create")
@click.option("--dashboard-id", "-d", required=True, help="Target dashboard ID")
@click.option("--template", "-t", required=True, help="Widget template ID")
@click.option("--title", help="Widget title")
@click.option("--position", type=(int, int), default=(0, 0), help="Position (col, row)")
@click.option("--size", type=(int, int), help="Size (width, height)")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def create_widget(
    dashboard_id: str,
    template: str,
    title: Optional[str],
    position: tuple,
    size: Optional[tuple],
    json_output: bool
):
    """Create a widget from a template."""
    # Create a dummy dashboard for demonstration
    dashboard = Dashboard(id=dashboard_id, name="Dashboard")
    builder = create_widget_builder(dashboard)

    config = {}
    if title:
        config["title"] = title

    widget = builder.create_widget_from_template(
        template_id=template,
        position=position,
        custom_config=config,
    )

    if not widget:
        click.echo(f"Failed to create widget. Template '{template}' not found.", err=True)
        sys.exit(1)

    if size:
        builder.resize_widget(widget.id, size)

    if json_output:
        click.echo(json.dumps(widget.to_dict(), indent=2))
    else:
        click.echo(f"\nWidget created successfully!")
        click.echo(f"  ID: {widget.id}")
        click.echo(f"  Type: {widget.widget_type.value}")
        click.echo(f"  Title: {widget.config.title}")
        click.echo(f"  Position: {widget.position}")
        click.echo(f"  Size: {widget.size}")


# =============================================================================
# Dashboard Builder Commands
# =============================================================================

@viz.group()
def dashboard():
    """Dashboard management commands."""
    pass


@dashboard.command("create")
@click.option("--name", "-n", required=True, help="Dashboard name")
@click.option("--description", "-d", default="", help="Dashboard description")
@click.option("--theme", type=click.Choice(["light", "dark", "high_contrast"]), default="light")
@click.option("--columns", type=int, default=12, help="Grid columns")
@click.option("--public", is_flag=True, help="Make dashboard public")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def create_dashboard(
    name: str,
    description: str,
    theme: str,
    columns: int,
    public: bool,
    json_output: bool
):
    """Create a new dashboard."""
    layout = DashboardLayout(columns=columns)
    db = Dashboard(
        id="",  # Will be auto-generated
        name=name,
        description=description,
        theme=DashboardTheme(theme),
        layout=layout,
        is_public=public,
    )

    if json_output:
        click.echo(json.dumps(db.to_dict(), indent=2))
    else:
        click.echo(f"\nDashboard created!")
        click.echo(f"  ID: {db.id}")
        click.echo(f"  Name: {db.name}")
        click.echo(f"  Theme: {db.theme.value}")
        click.echo(f"  Columns: {db.layout.columns}")
        click.echo(f"  Public: {db.is_public}")


@dashboard.command("layout")
@click.argument("dashboard_id")
@click.option("--compact", is_flag=True, help="Compact layout")
@click.option("--arrange", type=click.Choice(["grid", "stack", "flow"]), help="Auto-arrange widgets")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def manage_layout(
    dashboard_id: str,
    compact: bool,
    arrange: Optional[str],
    json_output: bool
):
    """Manage dashboard layout."""
    # Create a dummy dashboard for demonstration
    dashboard = Dashboard(id=dashboard_id, name="Dashboard")
    builder = create_widget_builder(dashboard)

    if compact:
        builder.compact_layout()
        click.echo("Layout compacted.")

    if arrange:
        builder.auto_arrange(arrange)
        click.echo(f"Widgets arranged in '{arrange}' mode.")

    state = builder.get_state()
    if json_output:
        click.echo(json.dumps(state["layout"], indent=2))
    else:
        click.echo(f"\nLayout Info:")
        click.echo(f"  Columns: {state['layout']['columns']}")
        click.echo(f"  Rows: {state['layout']['rows']}")
        click.echo(f"  Widgets: {state['layout']['widget_count']}")


# =============================================================================
# Embedding Commands
# =============================================================================

@viz.group()
def embed():
    """Dashboard embedding commands."""
    pass


@embed.command("create-token")
@click.argument("dashboard_id")
@click.option("--expires", "-e", type=int, help="Expires in hours")
@click.option("--mode", type=click.Choice(["full", "compact", "widget", "kiosk"]), default="full")
@click.option("--max-uses", type=int, help="Maximum uses")
@click.option("--origins", "-o", multiple=True, help="Allowed origins")
@click.option("--hide-controls", is_flag=True, help="Hide controls")
@click.option("--hide-title", is_flag=True, help="Hide title")
@click.option("--theme", type=click.Choice(["light", "dark"]), help="Theme override")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def create_embed_token(
    dashboard_id: str,
    expires: Optional[int],
    mode: str,
    max_uses: Optional[int],
    origins: tuple,
    hide_controls: bool,
    hide_title: bool,
    theme: Optional[str],
    json_output: bool
):
    """Create an embed token for a dashboard."""
    manager = create_embedding_manager()

    token = manager.create_embed_token(
        dashboard_id=dashboard_id,
        created_by="cli-user",
        embed_mode=EmbedMode(mode),
        expires_in=timedelta(hours=expires) if expires else None,
        max_uses=max_uses,
        allowed_origins=list(origins) if origins else None,
        hide_controls=hide_controls,
        hide_title=hide_title,
        theme=theme,
    )

    if json_output:
        output = token.to_dict()
        output["token_value"] = token.token  # Include token for JSON output
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\nEmbed token created!")
        click.echo(f"  Token ID: {token.id}")
        click.echo(f"  Token: {token.token}")
        click.echo(f"  Mode: {token.embed_mode.value}")
        click.echo(f"  Expires: {token.expires_at.isoformat() if token.expires_at else 'Never'}")
        click.echo(f"  Max Uses: {token.max_uses or 'Unlimited'}")

        # Show embed code
        click.echo(f"\nEmbed URL (replace BASE_URL):")
        click.echo(f"  BASE_URL/embed/dashboard/{dashboard_id}?token={token.token}")

        click.echo(f"\nIframe Code:")
        click.echo(token.get_iframe_html("YOUR_BASE_URL"))


@embed.command("create-link")
@click.argument("dashboard_id")
@click.option("--expires", "-e", type=int, help="Expires in days")
@click.option("--password", "-p", help="Link password")
@click.option("--max-uses", type=int, help="Maximum uses")
@click.option("--require-login", is_flag=True, help="Require user login")
@click.option("--allowed-emails", multiple=True, help="Allowed emails")
@click.option("--allowed-domains", multiple=True, help="Allowed domains")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def create_share_link(
    dashboard_id: str,
    expires: Optional[int],
    password: Optional[str],
    max_uses: Optional[int],
    require_login: bool,
    allowed_emails: tuple,
    allowed_domains: tuple,
    json_output: bool
):
    """Create a share link for a dashboard."""
    manager = create_embedding_manager()

    link = manager.create_share_link(
        dashboard_id=dashboard_id,
        created_by="cli-user",
        expires_in=timedelta(days=expires) if expires else None,
        password=password,
        require_login=require_login,
        allowed_emails=list(allowed_emails) if allowed_emails else None,
        allowed_domains=list(allowed_domains) if allowed_domains else None,
        max_uses=max_uses,
    )

    if json_output:
        output = link.to_dict()
        click.echo(json.dumps(output, indent=2))
    else:
        click.echo(f"\nShare link created!")
        click.echo(f"  Link ID: {link.id}")
        click.echo(f"  Short Code: {link.short_code}")
        click.echo(f"  URL: YOUR_BASE_URL/share/{link.short_code}")
        click.echo(f"  Password Protected: {bool(link.password_hash)}")
        click.echo(f"  Require Login: {link.require_login}")
        click.echo(f"  Expires: {link.expires_at.isoformat() if link.expires_at else 'Never'}")
        click.echo(f"  Max Uses: {link.max_uses or 'Unlimited'}")


@embed.command("share")
@click.argument("dashboard_id")
@click.option("--user", "-u", help="Share with user ID")
@click.option("--email", "-e", help="Share with email")
@click.option("--domain", "-d", help="Share with domain")
@click.option("--access", type=click.Choice(["view", "interact", "comment", "edit"]), default="view")
@click.option("--expires", type=int, help="Expires in days")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def share_dashboard(
    dashboard_id: str,
    user: Optional[str],
    email: Optional[str],
    domain: Optional[str],
    access: str,
    expires: Optional[int],
    json_output: bool
):
    """Share a dashboard with users."""
    manager = create_embedding_manager()
    access_level = AccessLevel(access)
    expires_at = datetime.utcnow() + timedelta(days=expires) if expires else None

    permission = None
    if user:
        permission = manager.share_with_user(
            dashboard_id, user, access_level, "cli-user", expires_at
        )
    elif email:
        permission = manager.share_with_email(
            dashboard_id, email, access_level, "cli-user", expires_at
        )
    elif domain:
        permission = manager.share_with_domain(
            dashboard_id, domain, access_level, "cli-user"
        )
    else:
        click.echo("Please specify --user, --email, or --domain", err=True)
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(permission.to_dict(), indent=2))
    else:
        click.echo(f"\nDashboard shared!")
        click.echo(f"  Permission ID: {permission.id}")
        click.echo(f"  Grantee: {permission.grantee_type} - {permission.grantee_id}")
        click.echo(f"  Access Level: {permission.access_level.value}")
        click.echo(f"  Expires: {permission.expires_at.isoformat() if permission.expires_at else 'Never'}")


@embed.command("status")
@click.argument("dashboard_id")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def embedding_status(dashboard_id: str, json_output: bool):
    """Show embedding status for a dashboard."""
    manager = create_embedding_manager()
    summary = manager.get_dashboard_sharing_summary(dashboard_id)

    if json_output:
        click.echo(json.dumps(summary, indent=2))
    else:
        click.echo(f"\nSharing Status for Dashboard: {dashboard_id}\n")
        click.echo(f"  Share Type: {summary['share_type']}")
        click.echo(f"  Permissions: {summary['permission_count']}")
        click.echo(f"  Embed Tokens: {summary['embed_token_count']}")
        click.echo(f"  Share Links: {summary['share_link_count']}")
        click.echo(f"  Total Views: {summary['total_views']}")
        click.echo(f"  Embedding Allowed: {summary['allow_embedding']}")
        click.echo(f"  Password Protected: {summary['password_protected']}")


# =============================================================================
# Real-time Streaming Commands
# =============================================================================

@viz.group()
def realtime():
    """Real-time streaming commands."""
    pass


@realtime.command("status")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def realtime_status(json_output: bool):
    """Show real-time streaming status."""
    event_bus = create_event_bus()
    stats = event_bus.get_stats()

    if json_output:
        click.echo(json.dumps(stats, indent=2))
    else:
        click.echo(f"\nReal-time Streaming Status:\n")
        click.echo(f"  Connected Clients: {stats['connected_clients']}")
        click.echo(f"  Active Subscriptions: {stats['active_subscriptions']}")
        click.echo(f"  Events Published: {stats['events_published']}")
        click.echo(f"  Events Delivered: {stats['events_delivered']}")
        click.echo(f"  Queue Size: {stats['queue_size']}")


@realtime.command("publish")
@click.argument("event_type")
@click.option("--data", "-d", help="Event data (JSON)")
@click.option("--dashboard-id", help="Target dashboard ID")
@click.option("--widget-id", help="Target widget ID")
def publish_event(
    event_type: str,
    data: Optional[str],
    dashboard_id: Optional[str],
    widget_id: Optional[str]
):
    """Publish a test event."""
    from stance.dashboards.realtime import EventType, RealtimeEvent

    try:
        evt_type = EventType(event_type)
    except ValueError:
        click.echo(f"Unknown event type: {event_type}", err=True)
        click.echo(f"Available: {[e.value for e in EventType]}")
        sys.exit(1)

    event_data = json.loads(data) if data else {}

    event = RealtimeEvent(
        event_type=evt_type,
        data=event_data,
        dashboard_id=dashboard_id,
        widget_id=widget_id,
    )

    event_bus = create_event_bus()
    count = event_bus.publish(event)

    click.echo(f"Event published to {count} subscriber(s)")
    click.echo(f"  Event ID: {event.event_id}")
    click.echo(f"  Type: {event.event_type.value}")


@realtime.command("events")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def list_event_types(json_output: bool):
    """List available event types."""
    from stance.dashboards.realtime import EventType

    events = [{"name": e.name, "value": e.value} for e in EventType]

    if json_output:
        click.echo(json.dumps(events, indent=2))
    else:
        click.echo(f"\nAvailable Event Types:\n")
        for e in EventType:
            click.echo(f"  {e.value}: {e.name}")


# =============================================================================
# Interactive Charts Commands
# =============================================================================

@viz.group()
def chart():
    """Interactive chart commands."""
    pass


@chart.command("types")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def list_chart_types(json_output: bool):
    """List available chart types."""
    from stance.dashboards.interactive import InteractionType, DrillDownLevel

    chart_types = [{"name": ct.name, "value": ct.value} for ct in ChartType]
    interaction_types = [{"name": it.name, "value": it.value} for it in InteractionType]
    drill_levels = [{"name": dl.name, "value": dl.value} for dl in DrillDownLevel]

    if json_output:
        click.echo(json.dumps({
            "chart_types": chart_types,
            "interaction_types": interaction_types,
            "drill_down_levels": drill_levels,
        }, indent=2))
    else:
        click.echo(f"\nChart Types:")
        for ct in ChartType:
            click.echo(f"  {ct.value}")

        click.echo(f"\nInteraction Types:")
        for it in InteractionType:
            click.echo(f"  {it.value}")

        click.echo(f"\nDrill-Down Levels:")
        for dl in DrillDownLevel:
            click.echo(f"  {dl.value}")


@chart.command("create")
@click.option("--type", "-t", "chart_type", default="basic",
              type=click.Choice(["basic", "drilldown_bar", "timeseries", "filterable"]))
@click.option("--title", default="Interactive Chart", help="Chart title")
@click.option("--enable-zoom", is_flag=True, help="Enable zoom")
@click.option("--enable-selection", is_flag=True, help="Enable selection")
@click.option("--enable-drilldown", is_flag=True, help="Enable drill-down")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def create_chart(
    chart_type: str,
    title: str,
    enable_zoom: bool,
    enable_selection: bool,
    enable_drilldown: bool,
    json_output: bool
):
    """Create an interactive chart configuration."""
    from stance.dashboards.interactive import (
        InteractiveChartConfig,
        ZoomConfig,
        SelectionConfig,
    )
    from stance.dashboards.models import ChartConfig

    config = InteractiveChartConfig(
        chart_config=ChartConfig(title=title),
        zoom=ZoomConfig(enabled=enable_zoom),
        selection=SelectionConfig(enabled=enable_selection),
        drill_down_enabled=enable_drilldown,
    )

    chart = create_interactive_chart(
        chart_id=f"chart-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        chart_type=chart_type,
        config=config,
    )

    state = chart.to_dict()

    if json_output:
        click.echo(json.dumps(state, indent=2))
    else:
        click.echo(f"\nInteractive Chart Created:")
        click.echo(f"  ID: {chart.chart_id}")
        click.echo(f"  Type: {chart_type}")
        click.echo(f"  Zoom Enabled: {enable_zoom}")
        click.echo(f"  Selection Enabled: {enable_selection}")
        click.echo(f"  Drill-Down Enabled: {enable_drilldown}")


# =============================================================================
# Update Manager Commands
# =============================================================================

@viz.group()
def updates():
    """Dashboard update manager commands."""
    pass


@updates.command("status")
@click.argument("dashboard_id")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def update_status(dashboard_id: str, json_output: bool):
    """Show update status for a dashboard."""
    manager = create_update_manager()

    # Register a dummy dashboard
    dashboard = Dashboard(id=dashboard_id, name="Test Dashboard")
    manager.register_dashboard(dashboard)

    status = manager.get_dashboard_status(dashboard_id)

    if json_output:
        click.echo(json.dumps(status, indent=2))
    else:
        click.echo(f"\nUpdate Status for Dashboard: {dashboard_id}\n")
        click.echo(f"  Widget Count: {status['widget_count']}")
        click.echo(f"  Subscribers: {status['subscriber_count']}")
        click.echo(f"  Queue Size: {status['queue_size']}")


@updates.command("refresh")
@click.argument("dashboard_id")
@click.option("--widget", "-w", help="Specific widget ID")
@click.option("--priority", type=click.Choice(["critical", "high", "normal", "low"]), default="normal")
def refresh_dashboard(dashboard_id: str, widget: Optional[str], priority: str):
    """Trigger a dashboard refresh."""
    from stance.dashboards.updates import UpdatePriority

    manager = create_update_manager()
    priority_level = UpdatePriority[priority.upper()]

    # Register a dummy dashboard
    dashboard = Dashboard(id=dashboard_id, name="Test Dashboard")
    manager.register_dashboard(dashboard)

    if widget:
        manager.refresh_widget(dashboard_id, widget, priority_level)
        click.echo(f"Widget {widget} queued for refresh (priority: {priority})")
    else:
        manager.refresh_dashboard(dashboard_id, priority_level)
        click.echo(f"Dashboard {dashboard_id} queued for refresh (priority: {priority})")


# =============================================================================
# Main CLI Registration
# =============================================================================

def register_visualization_commands(cli):
    """Register visualization commands with the main CLI."""
    cli.add_command(viz)


if __name__ == "__main__":
    viz()
