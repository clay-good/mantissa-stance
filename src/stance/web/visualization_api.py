"""
Web API endpoints for Enhanced Visualization features.

Provides REST API handlers for dashboards, widgets, embedding,
real-time streaming, and interactive charts.

Part of Phase 94: Enhanced Visualization
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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
    WidgetCategory,
    create_widget_builder,
    create_widget_palette,
    # Embedding
    EmbeddingManager,
    ShareType,
    AccessLevel,
    EmbedMode,
    create_embedding_manager,
    # Real-time
    EventBus,
    EventType,
    RealtimeEvent,
    DashboardStreamManager,
    DashboardUpdateManager,
    create_event_bus,
    create_stream_manager,
    create_update_manager,
    # Interactive
    InteractiveChart,
    create_interactive_chart,
    create_drilldown_config,
)


class VisualizationAPI:
    """
    API handlers for visualization endpoints.

    Provides REST API functionality for Phase 94 features.
    """

    def __init__(self):
        self.widget_palette = create_widget_palette()
        self.embedding_manager = create_embedding_manager()
        self.event_bus = create_event_bus()
        self.stream_manager = create_stream_manager(self.event_bus)
        self.update_manager = create_update_manager(self.event_bus)
        self.dashboards: Dict[str, Dashboard] = {}
        self.interactive_charts: Dict[str, InteractiveChart] = {}

    # =========================================================================
    # Widget Template Endpoints
    # =========================================================================

    def widget_templates_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available widget templates."""
        category = params.get("category", [None])[0]

        if category:
            try:
                cat = WidgetCategory(category)
                templates = self.widget_palette.get_templates_by_category(cat)
            except ValueError:
                return {
                    "error": f"Unknown category: {category}",
                    "categories": [c.value for c in WidgetCategory],
                }
        else:
            templates = self.widget_palette.get_all_templates()

        return {
            "templates": [t.to_dict() for t in templates],
            "count": len(templates),
            "categories": [c.value for c in WidgetCategory],
        }

    def widget_templates_search(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search widget templates."""
        query = params.get("q", [""])[0]
        if not query:
            return {"error": "Query parameter 'q' is required"}

        results = self.widget_palette.search_templates(query)
        return {
            "query": query,
            "results": [t.to_dict() for t in results],
            "count": len(results),
        }

    def widget_template_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get widget template info."""
        template_id = params.get("id", [None])[0]
        if not template_id:
            return {"error": "Template ID is required"}

        template = self.widget_palette.get_template(template_id)
        if not template:
            return {"error": f"Template not found: {template_id}"}

        return template.to_dict()

    # =========================================================================
    # Widget Builder Endpoints
    # =========================================================================

    def widget_create(self, body: bytes) -> Dict[str, Any]:
        """Create a widget from template."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        template_id = data.get("template_id")
        position = data.get("position", [0, 0])
        config = data.get("config", {})

        if not dashboard_id or not template_id:
            return {"error": "dashboard_id and template_id are required"}

        # Get or create dashboard
        if dashboard_id not in self.dashboards:
            self.dashboards[dashboard_id] = Dashboard(
                id=dashboard_id,
                name=f"Dashboard {dashboard_id}",
            )

        builder = create_widget_builder(self.dashboards[dashboard_id])
        widget = builder.create_widget_from_template(
            template_id=template_id,
            position=tuple(position),
            custom_config=config,
        )

        if not widget:
            return {"error": f"Failed to create widget. Template '{template_id}' not found."}

        return {
            "success": True,
            "widget": widget.to_dict(),
        }

    def widget_delete(self, body: bytes) -> Dict[str, Any]:
        """Delete a widget."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        widget_id = data.get("widget_id")

        if not dashboard_id or not widget_id:
            return {"error": "dashboard_id and widget_id are required"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        success = builder.delete_widget(widget_id)

        return {"success": success}

    def widget_move(self, body: bytes) -> Dict[str, Any]:
        """Move a widget."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        widget_id = data.get("widget_id")
        position = data.get("position")

        if not all([dashboard_id, widget_id, position]):
            return {"error": "dashboard_id, widget_id, and position are required"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        success = builder.move_widget(widget_id, tuple(position))

        return {"success": success}

    def widget_resize(self, body: bytes) -> Dict[str, Any]:
        """Resize a widget."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        widget_id = data.get("widget_id")
        size = data.get("size")

        if not all([dashboard_id, widget_id, size]):
            return {"error": "dashboard_id, widget_id, and size are required"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        success = builder.resize_widget(widget_id, tuple(size))

        return {"success": success}

    # =========================================================================
    # Dashboard Layout Endpoints
    # =========================================================================

    def dashboard_layout_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get dashboard layout info."""
        dashboard_id = params.get("id", [None])[0]
        if not dashboard_id:
            return {"error": "Dashboard ID is required"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        return builder.get_state()["layout"]

    def dashboard_layout_compact(self, body: bytes) -> Dict[str, Any]:
        """Compact dashboard layout."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        builder.compact_layout()

        return {
            "success": True,
            "layout": builder.get_state()["layout"],
        }

    def dashboard_layout_arrange(self, body: bytes) -> Dict[str, Any]:
        """Auto-arrange dashboard widgets."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        arrangement = data.get("arrangement", "grid")

        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        if arrangement not in ("grid", "stack", "flow"):
            return {"error": "arrangement must be 'grid', 'stack', or 'flow'"}

        if dashboard_id not in self.dashboards:
            return {"error": f"Dashboard not found: {dashboard_id}"}

        builder = create_widget_builder(self.dashboards[dashboard_id])
        builder.auto_arrange(arrangement)

        return {
            "success": True,
            "arrangement": arrangement,
            "layout": builder.get_state()["layout"],
        }

    # =========================================================================
    # Embedding Endpoints
    # =========================================================================

    def embed_token_create(self, body: bytes) -> Dict[str, Any]:
        """Create an embed token."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        expires_hours = data.get("expires_hours")
        token = self.embedding_manager.create_embed_token(
            dashboard_id=dashboard_id,
            created_by=data.get("user_id", "api-user"),
            embed_mode=EmbedMode(data.get("mode", "full")),
            expires_in=timedelta(hours=expires_hours) if expires_hours else None,
            max_uses=data.get("max_uses"),
            allowed_origins=data.get("allowed_origins"),
            hide_controls=data.get("hide_controls", False),
            hide_title=data.get("hide_title", False),
            theme=data.get("theme"),
        )

        result = token.to_dict()
        result["token_value"] = token.token
        result["embed_url"] = token.get_embed_url(data.get("base_url", "/"))
        result["iframe_html"] = token.get_iframe_html(data.get("base_url", "/"))

        return result

    def embed_token_validate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate an embed token."""
        token_value = params.get("token", [None])[0]
        origin = params.get("origin", [None])[0]

        if not token_value:
            return {"error": "Token is required"}

        token = self.embedding_manager.validate_embed_token(
            token_value,
            origin=origin,
        )

        if not token:
            return {"valid": False, "error": "Invalid or expired token"}

        return {
            "valid": True,
            "token": token.to_dict(),
        }

    def embed_token_revoke(self, body: bytes) -> Dict[str, Any]:
        """Revoke an embed token."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        token_id = data.get("token_id")
        if not token_id:
            return {"error": "token_id is required"}

        success = self.embedding_manager.revoke_embed_token(token_id)
        return {"success": success}

    def embed_tokens_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List embed tokens for a dashboard."""
        dashboard_id = params.get("dashboard_id", [None])[0]
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        tokens = self.embedding_manager.get_embed_tokens(dashboard_id)
        return {
            "dashboard_id": dashboard_id,
            "tokens": [t.to_dict() for t in tokens],
            "count": len(tokens),
        }

    def share_link_create(self, body: bytes) -> Dict[str, Any]:
        """Create a share link."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        expires_days = data.get("expires_days")
        link = self.embedding_manager.create_share_link(
            dashboard_id=dashboard_id,
            created_by=data.get("user_id", "api-user"),
            expires_in=timedelta(days=expires_days) if expires_days else None,
            password=data.get("password"),
            require_login=data.get("require_login", False),
            allowed_emails=data.get("allowed_emails"),
            allowed_domains=data.get("allowed_domains"),
            max_uses=data.get("max_uses"),
        )

        result = link.to_dict()
        result["url"] = link.get_url(data.get("base_url", "/"))

        return result

    def share_link_validate(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a share link."""
        short_code = params.get("code", [None])[0]
        password = params.get("password", [None])[0]
        email = params.get("email", [None])[0]

        if not short_code:
            return {"error": "Share code is required"}

        link = self.embedding_manager.validate_share_link(
            short_code,
            password=password,
            email=email,
        )

        if not link:
            return {"valid": False, "error": "Invalid or expired link"}

        return {
            "valid": True,
            "link": link.to_dict(),
        }

    def share_links_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List share links for a dashboard."""
        dashboard_id = params.get("dashboard_id", [None])[0]
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        links = self.embedding_manager.get_share_links(dashboard_id)
        return {
            "dashboard_id": dashboard_id,
            "links": [l.to_dict() for l in links],
            "count": len(links),
        }

    def share_dashboard(self, body: bytes) -> Dict[str, Any]:
        """Share dashboard with user/email/domain."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        share_type = data.get("type")  # "user", "email", "domain"
        grantee = data.get("grantee")
        access = data.get("access", "view")

        if not all([dashboard_id, share_type, grantee]):
            return {"error": "dashboard_id, type, and grantee are required"}

        access_level = AccessLevel(access)
        expires_days = data.get("expires_days")
        expires_at = datetime.utcnow() + timedelta(days=expires_days) if expires_days else None

        if share_type == "user":
            permission = self.embedding_manager.share_with_user(
                dashboard_id, grantee, access_level, "api-user", expires_at
            )
        elif share_type == "email":
            permission = self.embedding_manager.share_with_email(
                dashboard_id, grantee, access_level, "api-user", expires_at
            )
        elif share_type == "domain":
            permission = self.embedding_manager.share_with_domain(
                dashboard_id, grantee, access_level, "api-user"
            )
        else:
            return {"error": "type must be 'user', 'email', or 'domain'"}

        return {
            "success": True,
            "permission": permission.to_dict(),
        }

    def share_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get sharing status for a dashboard."""
        dashboard_id = params.get("dashboard_id", [None])[0]
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        return self.embedding_manager.get_dashboard_sharing_summary(dashboard_id)

    # =========================================================================
    # Real-time Streaming Endpoints
    # =========================================================================

    def realtime_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get real-time streaming status."""
        return self.event_bus.get_stats()

    def realtime_event_types(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available event types."""
        return {
            "event_types": [
                {"name": e.name, "value": e.value}
                for e in EventType
            ],
        }

    def realtime_publish(self, body: bytes) -> Dict[str, Any]:
        """Publish a real-time event."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        event_type_str = data.get("event_type")
        if not event_type_str:
            return {"error": "event_type is required"}

        try:
            event_type = EventType(event_type_str)
        except ValueError:
            return {
                "error": f"Unknown event type: {event_type_str}",
                "available": [e.value for e in EventType],
            }

        event = RealtimeEvent(
            event_type=event_type,
            data=data.get("data", {}),
            dashboard_id=data.get("dashboard_id"),
            widget_id=data.get("widget_id"),
        )

        delivered = self.event_bus.publish(event)

        return {
            "success": True,
            "event_id": event.event_id,
            "delivered_to": delivered,
        }

    def realtime_subscribe(self, body: bytes) -> Dict[str, Any]:
        """Subscribe to real-time events."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        client_id = data.get("client_id")
        user_id = data.get("user_id", "anonymous")
        tenant_id = data.get("tenant_id", "default")
        dashboard_id = data.get("dashboard_id")

        if not client_id:
            return {"error": "client_id is required"}

        # Connect client
        connection = self.event_bus.connect(client_id, user_id, tenant_id)

        # Subscribe to dashboard if specified
        subscription = None
        if dashboard_id:
            subscription = self.stream_manager.subscribe_dashboard(
                client_id=client_id,
                dashboard_id=dashboard_id,
            )

        return {
            "success": True,
            "client_id": client_id,
            "connected": True,
            "subscription": subscription.to_dict() if subscription else None,
        }

    def realtime_unsubscribe(self, body: bytes) -> Dict[str, Any]:
        """Unsubscribe from real-time events."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        client_id = data.get("client_id")
        if not client_id:
            return {"error": "client_id is required"}

        success = self.event_bus.disconnect(client_id)

        return {"success": success}

    def realtime_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get pending messages for a client."""
        client_id = params.get("client_id", [None])[0]
        timeout = int(params.get("timeout", [1000])[0])
        max_messages = int(params.get("max", [10])[0])

        if not client_id:
            return {"error": "client_id is required"}

        messages = self.event_bus.get_messages(
            client_id,
            timeout=timeout,
            max_messages=max_messages,
        )

        return {
            "client_id": client_id,
            "messages": [m.to_dict() for m in messages],
            "count": len(messages),
        }

    # =========================================================================
    # Interactive Charts Endpoints
    # =========================================================================

    def chart_types(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """List available chart types."""
        from stance.dashboards.interactive import InteractionType, DrillDownLevel

        return {
            "chart_types": [{"name": ct.name, "value": ct.value} for ct in ChartType],
            "interaction_types": [{"name": it.name, "value": it.value} for it in InteractionType],
            "drill_levels": [{"name": dl.name, "value": dl.value} for dl in DrillDownLevel],
        }

    def chart_create(self, body: bytes) -> Dict[str, Any]:
        """Create an interactive chart."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        chart_id = data.get("chart_id") or f"chart-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        chart_type = data.get("type", "basic")
        title = data.get("title", "Interactive Chart")

        config = create_drilldown_config(
            title=title,
            enable_zoom=data.get("enable_zoom", True),
            enable_selection=data.get("enable_selection", True),
        )

        chart = create_interactive_chart(
            chart_id=chart_id,
            chart_type=chart_type,
            config=config,
        )

        self.interactive_charts[chart_id] = chart

        return {
            "success": True,
            "chart": chart.to_dict(),
        }

    def chart_interact(self, body: bytes) -> Dict[str, Any]:
        """Handle chart interaction."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        chart_id = data.get("chart_id")
        if not chart_id or chart_id not in self.interactive_charts:
            return {"error": f"Chart not found: {chart_id}"}

        from stance.dashboards.interactive import ChartInteraction, InteractionType

        interaction = ChartInteraction(
            interaction_type=InteractionType(data.get("type", "click")),
            chart_id=chart_id,
            element_type=data.get("element_type", "point"),
            element_index=data.get("element_index", 0),
            series_index=data.get("series_index", 0),
            coordinates=tuple(data.get("coordinates", [0, 0])),
            metadata=data.get("metadata", {}),
        )

        chart = self.interactive_charts[chart_id]
        result = chart.handle_interaction(interaction)

        return {
            "success": True,
            "result": result,
            "chart_state": chart.to_dict(),
        }

    def chart_drill_down(self, body: bytes) -> Dict[str, Any]:
        """Drill down in a chart."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        chart_id = data.get("chart_id")
        if not chart_id or chart_id not in self.interactive_charts:
            return {"error": f"Chart not found: {chart_id}"}

        element_index = data.get("element_index", 0)
        context = data.get("context", {})

        chart = self.interactive_charts[chart_id]
        new_data = chart.drill_down(element_index, context)

        return {
            "success": new_data is not None,
            "drill_path": chart.drill_path.to_dict(),
            "new_data": new_data.to_dict() if new_data else None,
        }

    def chart_drill_up(self, body: bytes) -> Dict[str, Any]:
        """Drill up in a chart."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        chart_id = data.get("chart_id")
        if not chart_id or chart_id not in self.interactive_charts:
            return {"error": f"Chart not found: {chart_id}"}

        chart = self.interactive_charts[chart_id]
        new_data = chart.drill_up()

        return {
            "success": True,
            "drill_path": chart.drill_path.to_dict(),
            "new_data": new_data.to_dict() if new_data else None,
        }

    # =========================================================================
    # Update Manager Endpoints
    # =========================================================================

    def updates_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get update status for a dashboard."""
        dashboard_id = params.get("dashboard_id", [None])[0]
        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        return self.update_manager.get_dashboard_status(dashboard_id)

    def updates_refresh(self, body: bytes) -> Dict[str, Any]:
        """Trigger dashboard refresh."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        from stance.dashboards.updates import UpdatePriority

        dashboard_id = data.get("dashboard_id")
        widget_id = data.get("widget_id")
        priority = data.get("priority", "normal")

        if not dashboard_id:
            return {"error": "dashboard_id is required"}

        priority_level = UpdatePriority[priority.upper()]

        if widget_id:
            self.update_manager.refresh_widget(dashboard_id, widget_id, priority_level)
            return {"success": True, "refreshed": "widget", "widget_id": widget_id}
        else:
            self.update_manager.refresh_dashboard(dashboard_id, priority_level)
            return {"success": True, "refreshed": "dashboard", "dashboard_id": dashboard_id}

    def updates_invalidate(self, body: bytes) -> Dict[str, Any]:
        """Invalidate cached data."""
        try:
            data = json.loads(body.decode())
        except json.JSONDecodeError:
            return {"error": "Invalid JSON body"}

        dashboard_id = data.get("dashboard_id")
        widget_id = data.get("widget_id")

        if widget_id:
            self.update_manager.invalidate_widget(widget_id)
            return {"success": True, "invalidated": "widget", "widget_id": widget_id}
        elif dashboard_id:
            self.update_manager.invalidate_dashboard(dashboard_id)
            return {"success": True, "invalidated": "dashboard", "dashboard_id": dashboard_id}
        else:
            return {"error": "dashboard_id or widget_id is required"}


# Global API instance
_viz_api: Optional[VisualizationAPI] = None


def get_visualization_api() -> VisualizationAPI:
    """Get the singleton visualization API instance."""
    global _viz_api
    if _viz_api is None:
        _viz_api = VisualizationAPI()
    return _viz_api
