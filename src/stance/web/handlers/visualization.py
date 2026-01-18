"""
Visualization handlers for the Stance web API.

This module handles all /api/viz/* endpoints for dashboard visualization,
widgets, charts, embedding, sharing, and real-time updates.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import BaseHandler, HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class VisualizationHandler(RoutedHandler):
    """
    Handler for visualization API endpoints.

    Handles:
    - Widget templates and management
    - Dashboard layouts
    - Embedding and sharing
    - Real-time updates
    - Chart operations
    """

    base_path = "/api/viz/"

    def __init__(self, *args, **kwargs) -> None:
        """Initialize handler with visualization API reference."""
        super().__init__(*args, **kwargs)
        self._viz_api = None

    def _get_viz_api(self) -> Any:
        """Get or create visualization API instance."""
        if self._viz_api is None:
            from stance.web.visualization_api import get_visualization_api
            self._viz_api = get_visualization_api()
        return self._viz_api

    # =========================================================================
    # Widget Template GET endpoints
    # =========================================================================

    @route("widget/templates")
    def widget_templates(self, params: dict, body: dict | None) -> HandlerResponse:
        """List available widget templates."""
        try:
            result = self._get_viz_api().widget_templates_list(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list widget templates")
            return HandlerResponse.server_error(str(e))

    @route("widget/search")
    def widget_search(self, params: dict, body: dict | None) -> HandlerResponse:
        """Search widget templates."""
        try:
            result = self._get_viz_api().widget_templates_search(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to search widget templates")
            return HandlerResponse.server_error(str(e))

    @route("widget/info")
    def widget_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get widget template info."""
        try:
            result = self._get_viz_api().widget_template_info(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get widget info")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Layout GET endpoints
    # =========================================================================

    @route("layout/info")
    def layout_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get dashboard layout info."""
        try:
            result = self._get_viz_api().dashboard_layout_info(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get layout info")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Embedding GET endpoints
    # =========================================================================

    @route("embed/tokens")
    def embed_tokens(self, params: dict, body: dict | None) -> HandlerResponse:
        """List embed tokens."""
        try:
            result = self._get_viz_api().embed_tokens_list(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list embed tokens")
            return HandlerResponse.server_error(str(e))

    @route("embed/validate")
    def embed_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate an embed token."""
        try:
            result = self._get_viz_api().embed_token_validate(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to validate embed token")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Sharing GET endpoints
    # =========================================================================

    @route("share/links")
    def share_links(self, params: dict, body: dict | None) -> HandlerResponse:
        """List share links."""
        try:
            result = self._get_viz_api().share_links_list(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to list share links")
            return HandlerResponse.server_error(str(e))

    @route("share/validate")
    def share_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Validate a share link."""
        try:
            result = self._get_viz_api().share_link_validate(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to validate share link")
            return HandlerResponse.server_error(str(e))

    @route("share/status")
    def share_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get sharing status."""
        try:
            result = self._get_viz_api().share_status(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get share status")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Real-time GET endpoints
    # =========================================================================

    @route("realtime/status")
    def realtime_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get real-time connection status."""
        try:
            result = self._get_viz_api().realtime_status(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get realtime status")
            return HandlerResponse.server_error(str(e))

    @route("realtime/events")
    def realtime_events(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available real-time event types."""
        try:
            result = self._get_viz_api().realtime_event_types(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get realtime events")
            return HandlerResponse.server_error(str(e))

    @route("realtime/messages")
    def realtime_messages(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get real-time messages."""
        try:
            result = self._get_viz_api().realtime_messages(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get realtime messages")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Chart GET endpoints
    # =========================================================================

    @route("chart/types")
    def chart_types(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get available chart types."""
        try:
            result = self._get_viz_api().chart_types(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get chart types")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Updates GET endpoints
    # =========================================================================

    @route("updates/status")
    def updates_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get updates status."""
        try:
            result = self._get_viz_api().updates_status(params)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to get updates status")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Widget POST endpoints
    # =========================================================================

    @route("widget/create", methods=["POST"])
    def widget_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a new widget."""
        try:
            result = self._get_viz_api().widget_create(body)
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create widget")
            return HandlerResponse.server_error(str(e))

    @route("widget/delete", methods=["POST"])
    def widget_delete(self, params: dict, body: dict | None) -> HandlerResponse:
        """Delete a widget."""
        try:
            result = self._get_viz_api().widget_delete(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to delete widget")
            return HandlerResponse.server_error(str(e))

    @route("widget/move", methods=["POST"])
    def widget_move(self, params: dict, body: dict | None) -> HandlerResponse:
        """Move a widget."""
        try:
            result = self._get_viz_api().widget_move(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to move widget")
            return HandlerResponse.server_error(str(e))

    @route("widget/resize", methods=["POST"])
    def widget_resize(self, params: dict, body: dict | None) -> HandlerResponse:
        """Resize a widget."""
        try:
            result = self._get_viz_api().widget_resize(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to resize widget")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Layout POST endpoints
    # =========================================================================

    @route("layout/compact", methods=["POST"])
    def layout_compact(self, params: dict, body: dict | None) -> HandlerResponse:
        """Compact dashboard layout."""
        try:
            result = self._get_viz_api().dashboard_layout_compact(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to compact layout")
            return HandlerResponse.server_error(str(e))

    @route("layout/arrange", methods=["POST"])
    def layout_arrange(self, params: dict, body: dict | None) -> HandlerResponse:
        """Arrange dashboard layout."""
        try:
            result = self._get_viz_api().dashboard_layout_arrange(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to arrange layout")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Embedding POST endpoints
    # =========================================================================

    @route("embed/create", methods=["POST"])
    def embed_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create an embed token."""
        try:
            result = self._get_viz_api().embed_token_create(body)
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create embed token")
            return HandlerResponse.server_error(str(e))

    @route("embed/revoke", methods=["POST"])
    def embed_revoke(self, params: dict, body: dict | None) -> HandlerResponse:
        """Revoke an embed token."""
        try:
            result = self._get_viz_api().embed_token_revoke(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to revoke embed token")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Sharing POST endpoints
    # =========================================================================

    @route("share/create", methods=["POST"])
    def share_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a share link."""
        try:
            result = self._get_viz_api().share_link_create(body)
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create share link")
            return HandlerResponse.server_error(str(e))

    @route("share/dashboard", methods=["POST"])
    def share_dashboard(self, params: dict, body: dict | None) -> HandlerResponse:
        """Share a dashboard."""
        try:
            result = self._get_viz_api().share_dashboard(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to share dashboard")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Real-time POST endpoints
    # =========================================================================

    @route("realtime/publish", methods=["POST"])
    def realtime_publish(self, params: dict, body: dict | None) -> HandlerResponse:
        """Publish a real-time event."""
        try:
            result = self._get_viz_api().realtime_publish(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to publish realtime event")
            return HandlerResponse.server_error(str(e))

    @route("realtime/subscribe", methods=["POST"])
    def realtime_subscribe(self, params: dict, body: dict | None) -> HandlerResponse:
        """Subscribe to real-time events."""
        try:
            result = self._get_viz_api().realtime_subscribe(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to subscribe to realtime")
            return HandlerResponse.server_error(str(e))

    @route("realtime/unsubscribe", methods=["POST"])
    def realtime_unsubscribe(self, params: dict, body: dict | None) -> HandlerResponse:
        """Unsubscribe from real-time events."""
        try:
            result = self._get_viz_api().realtime_unsubscribe(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to unsubscribe from realtime")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Chart POST endpoints
    # =========================================================================

    @route("chart/create", methods=["POST"])
    def chart_create(self, params: dict, body: dict | None) -> HandlerResponse:
        """Create a chart."""
        try:
            result = self._get_viz_api().chart_create(body)
            return HandlerResponse.success(result, HttpStatus.CREATED)
        except Exception as e:
            logger.exception("Failed to create chart")
            return HandlerResponse.server_error(str(e))

    @route("chart/interact", methods=["POST"])
    def chart_interact(self, params: dict, body: dict | None) -> HandlerResponse:
        """Handle chart interaction."""
        try:
            result = self._get_viz_api().chart_interact(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to handle chart interaction")
            return HandlerResponse.server_error(str(e))

    @route("chart/drill-down", methods=["POST"])
    def chart_drill_down(self, params: dict, body: dict | None) -> HandlerResponse:
        """Drill down in chart."""
        try:
            result = self._get_viz_api().chart_drill_down(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to drill down")
            return HandlerResponse.server_error(str(e))

    @route("chart/drill-up", methods=["POST"])
    def chart_drill_up(self, params: dict, body: dict | None) -> HandlerResponse:
        """Drill up in chart."""
        try:
            result = self._get_viz_api().chart_drill_up(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to drill up")
            return HandlerResponse.server_error(str(e))

    # =========================================================================
    # Updates POST endpoints
    # =========================================================================

    @route("updates/refresh", methods=["POST"])
    def updates_refresh(self, params: dict, body: dict | None) -> HandlerResponse:
        """Refresh updates."""
        try:
            result = self._get_viz_api().updates_refresh(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to refresh updates")
            return HandlerResponse.server_error(str(e))

    @route("updates/invalidate", methods=["POST"])
    def updates_invalidate(self, params: dict, body: dict | None) -> HandlerResponse:
        """Invalidate updates cache."""
        try:
            result = self._get_viz_api().updates_invalidate(body)
            return HandlerResponse.success(result)
        except Exception as e:
            logger.exception("Failed to invalidate updates")
            return HandlerResponse.server_error(str(e))
