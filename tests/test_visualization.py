"""
Tests for Enhanced Visualization features.

Tests real-time streaming, interactive charts, widget builder,
dashboard embedding, and update manager components.

Part of Phase 94: Enhanced Visualization
"""

import json
import time
import unittest
from datetime import datetime, timedelta
from typing import Any, Dict

from stance.dashboards import (
    # Core models
    Dashboard,
    DashboardLayout,
    Widget,
    WidgetType,
    ChartType,
    TimeRange,
    # Real-time streaming
    EventBus,
    EventType,
    RealtimeEvent,
    ConnectionState,
    DashboardStreamManager,
    create_event_bus,
    create_stream_manager,
    # Interactive charts
    InteractiveChart,
    DrillDownPath,
    DrillDownLevel,
    InteractionType,
    ChartInteraction,
    ChartInteractionManager,
    create_interactive_chart,
    create_drilldown_config,
    # Widget builder
    WidgetBuilder,
    WidgetPalette,
    WidgetCategory,
    LayoutManager,
    DragDropManager,
    create_widget_builder,
    create_widget_palette,
    # Embedding
    EmbeddingManager,
    ShareType,
    AccessLevel,
    EmbedMode,
    EmbedToken,
    ShareLink,
    create_embedding_manager,
    # Updates
    DashboardUpdateManager,
    UpdatePriority,
    WidgetStatus,
    create_update_manager,
)
from stance.dashboards.visualizations import DataPoint, DataSeries, ChartData


class TestEventBus(unittest.TestCase):
    """Tests for EventBus real-time streaming."""

    def setUp(self):
        """Set up test fixtures."""
        self.event_bus = create_event_bus()

    def test_connect_disconnect(self):
        """Test client connection and disconnection."""
        connection = self.event_bus.connect("client1", "user1", "tenant1")
        self.assertIsNotNone(connection)
        self.assertEqual(connection.client_id, "client1")
        self.assertEqual(connection.state, ConnectionState.CONNECTED)

        stats = self.event_bus.get_stats()
        self.assertEqual(stats["connected_clients"], 1)

        result = self.event_bus.disconnect("client1")
        self.assertTrue(result)

        stats = self.event_bus.get_stats()
        self.assertEqual(stats["connected_clients"], 0)

    def test_subscribe(self):
        """Test event subscription."""
        self.event_bus.connect("client1", "user1", "tenant1")

        subscription = self.event_bus.subscribe(
            client_id="client1",
            event_types=[EventType.FINDING_CREATED, EventType.ALERT_TRIGGERED],
            dashboard_id="dash1",
        )

        self.assertIsNotNone(subscription)
        self.assertEqual(subscription.dashboard_id, "dash1")
        self.assertIn(EventType.FINDING_CREATED, subscription.event_types)

    def test_publish_event(self):
        """Test event publishing."""
        self.event_bus.connect("client1", "user1", "tenant1")
        self.event_bus.subscribe(
            client_id="client1",
            event_types=[EventType.METRIC_UPDATE],
        )

        event = RealtimeEvent(
            event_type=EventType.METRIC_UPDATE,
            data={"metric": "findings_count", "value": 42},
        )

        delivered = self.event_bus.publish(event)
        self.assertGreaterEqual(delivered, 1)

        messages = self.event_bus.get_messages("client1", timeout=100)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].event_type, EventType.METRIC_UPDATE)

    def test_event_filtering(self):
        """Test that events are filtered by subscription."""
        self.event_bus.connect("client1", "user1", "tenant1")
        self.event_bus.subscribe(
            client_id="client1",
            event_types=[EventType.FINDING_CREATED],
            dashboard_id="dash1",
        )

        # Event that matches
        event1 = RealtimeEvent(
            event_type=EventType.FINDING_CREATED,
            dashboard_id="dash1",
            data={"finding_id": "f1"},
        )
        # Event that doesn't match (wrong type)
        event2 = RealtimeEvent(
            event_type=EventType.METRIC_UPDATE,
            dashboard_id="dash1",
            data={"metric": "count"},
        )
        # Event that doesn't match (wrong dashboard)
        event3 = RealtimeEvent(
            event_type=EventType.FINDING_CREATED,
            dashboard_id="dash2",
            data={"finding_id": "f2"},
        )

        self.event_bus.publish(event1)
        self.event_bus.publish(event2)
        self.event_bus.publish(event3)

        messages = self.event_bus.get_messages("client1", timeout=100, max_messages=10)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].data["finding_id"], "f1")


class TestDashboardStreamManager(unittest.TestCase):
    """Tests for DashboardStreamManager."""

    def setUp(self):
        """Set up test fixtures."""
        self.event_bus = create_event_bus()
        self.stream_manager = create_stream_manager(self.event_bus)

    def test_subscribe_dashboard(self):
        """Test dashboard subscription."""
        self.event_bus.connect("client1", "user1", "tenant1")

        subscription = self.stream_manager.subscribe_dashboard(
            client_id="client1",
            dashboard_id="dash1",
        )

        self.assertIsNotNone(subscription)
        self.assertEqual(subscription.dashboard_id, "dash1")

    def test_push_metric_update(self):
        """Test pushing metric updates."""
        self.event_bus.connect("client1", "user1", "tenant1")
        self.stream_manager.subscribe_dashboard("client1", "dash1")

        self.stream_manager.push_metric_update(
            metric_name="findings_count",
            value=100,
            previous_value=95,
            dashboard_id="dash1",
        )

        messages = self.event_bus.get_messages("client1", timeout=100)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].event_type, EventType.METRIC_UPDATE)


class TestInteractiveChart(unittest.TestCase):
    """Tests for interactive chart components."""

    def test_create_chart(self):
        """Test creating an interactive chart."""
        chart = create_interactive_chart(
            chart_id="chart1",
            chart_type="basic",
        )

        self.assertEqual(chart.chart_id, "chart1")
        self.assertIsNotNone(chart.config)

    def test_drill_down_path(self):
        """Test drill-down path navigation."""
        path = DrillDownPath()
        self.assertEqual(path.current_level, DrillDownLevel.OVERVIEW)
        self.assertEqual(len(path.get_breadcrumbs()), 1)

        path.push(DrillDownLevel.CATEGORY, {"label": "Security"})
        self.assertEqual(path.current_level, DrillDownLevel.CATEGORY)
        self.assertEqual(len(path.get_breadcrumbs()), 2)

        path.push(DrillDownLevel.SUBCATEGORY, {"label": "IAM"})
        self.assertEqual(len(path.get_breadcrumbs()), 3)

        path.pop()
        self.assertEqual(path.current_level, DrillDownLevel.CATEGORY)

        path.reset()
        self.assertEqual(path.current_level, DrillDownLevel.OVERVIEW)

    def test_chart_interaction(self):
        """Test handling chart interactions."""
        config = create_drilldown_config(
            title="Test Chart",
            enable_zoom=True,
            enable_selection=True,
        )
        chart = create_interactive_chart("chart1", "basic", config)

        # Set some data
        data = ChartData(title="Test")
        series = DataSeries(name="Data")
        series.add_point("A", 10)
        series.add_point("B", 20)
        data.add_series(series)
        chart.set_data(data)

        # Handle click interaction
        interaction = ChartInteraction(
            interaction_type=InteractionType.CLICK,
            chart_id="chart1",
            element_type="bar",
            element_index=0,
        )

        result = chart.handle_interaction(interaction)
        self.assertTrue(result["handled"])
        self.assertIn(0, chart.selected_indices)

    def test_chart_manager(self):
        """Test chart interaction manager."""
        manager = ChartInteractionManager()

        chart1 = create_interactive_chart("chart1", "basic")
        chart2 = create_interactive_chart("chart2", "basic")

        manager.register_chart(chart1)
        manager.register_chart(chart2)
        manager.link_charts("chart1", "chart2")

        states = manager.get_chart_states()
        self.assertIn("chart1", states)
        self.assertIn("chart2", states)


class TestWidgetBuilder(unittest.TestCase):
    """Tests for widget builder."""

    def test_widget_palette(self):
        """Test widget palette."""
        palette = create_widget_palette()

        templates = palette.get_all_templates()
        self.assertGreater(len(templates), 0)

        chart_templates = palette.get_templates_by_category(WidgetCategory.CHARTS)
        self.assertGreater(len(chart_templates), 0)

        results = palette.search_templates("line")
        self.assertGreater(len(results), 0)

    def test_create_widget_from_template(self):
        """Test creating widgets from templates."""
        dashboard = Dashboard(id="dash1", name="Test Dashboard")
        builder = create_widget_builder(dashboard)

        widget = builder.create_widget_from_template(
            template_id="chart_line",
            position=(0, 0),
            custom_config={"title": "My Line Chart"},
        )

        self.assertIsNotNone(widget)
        self.assertEqual(widget.widget_type, WidgetType.CHART)
        self.assertEqual(widget.config.title, "My Line Chart")

    def test_widget_operations(self):
        """Test widget move, resize, delete."""
        dashboard = Dashboard(id="dash1", name="Test Dashboard")
        builder = create_widget_builder(dashboard)

        widget = builder.create_widget_from_template("metric_single")
        self.assertIsNotNone(widget)

        # Move widget
        success = builder.move_widget(widget.id, (2, 2))
        self.assertTrue(success)

        # Resize widget
        success = builder.resize_widget(widget.id, (4, 4))
        self.assertTrue(success)

        # Delete widget
        success = builder.delete_widget(widget.id)
        self.assertTrue(success)

    def test_layout_manager(self):
        """Test layout manager."""
        layout = DashboardLayout(columns=12)
        manager = LayoutManager(layout)

        # Add widget
        from stance.dashboards.models import WidgetConfig
        widget = Widget(
            id="w1",
            widget_type=WidgetType.METRIC,
            config=WidgetConfig(title="Test"),
            data_source="test",
            position=(0, 0),
            size=(3, 2),
        )

        success = manager.add_widget(widget)
        self.assertTrue(success)

        # Check collision
        widget2 = Widget(
            id="w2",
            widget_type=WidgetType.METRIC,
            config=WidgetConfig(title="Test2"),
            data_source="test",
            position=(0, 0),
            size=(3, 2),
        )

        success = manager.add_widget(widget2, auto_position=True)
        self.assertTrue(success)
        # Should have been moved to avoid collision
        self.assertNotEqual(widget2.position, (0, 0))


class TestEmbedding(unittest.TestCase):
    """Tests for dashboard embedding and sharing."""

    def setUp(self):
        """Set up test fixtures."""
        self.manager = create_embedding_manager()

    def test_create_embed_token(self):
        """Test creating embed tokens."""
        token = self.manager.create_embed_token(
            dashboard_id="dash1",
            created_by="user1",
            embed_mode=EmbedMode.FULL,
            expires_in=timedelta(hours=24),
            max_uses=100,
        )

        self.assertIsNotNone(token)
        self.assertIsNotNone(token.token)
        self.assertEqual(token.dashboard_id, "dash1")
        self.assertTrue(token.is_valid())

    def test_validate_embed_token(self):
        """Test validating embed tokens."""
        token = self.manager.create_embed_token(
            dashboard_id="dash1",
            created_by="user1",
        )

        # Valid token
        validated = self.manager.validate_embed_token(token.token)
        self.assertIsNotNone(validated)
        self.assertEqual(validated.id, token.id)

        # Invalid token
        validated = self.manager.validate_embed_token("invalid-token")
        self.assertIsNone(validated)

    def test_origin_validation(self):
        """Test origin validation for embed tokens."""
        token = self.manager.create_embed_token(
            dashboard_id="dash1",
            created_by="user1",
            allowed_origins=["https://example.com", "*.trusted.com"],
        )

        # Valid origins
        self.assertTrue(token.validate_origin("https://example.com"))
        self.assertTrue(token.validate_origin("https://sub.trusted.com"))

        # Invalid origin
        self.assertFalse(token.validate_origin("https://evil.com"))

    def test_create_share_link(self):
        """Test creating share links."""
        link = self.manager.create_share_link(
            dashboard_id="dash1",
            created_by="user1",
            expires_in=timedelta(days=7),
            password="secret",
        )

        self.assertIsNotNone(link)
        self.assertIsNotNone(link.short_code)
        self.assertTrue(link.is_valid())

        # Password verification
        self.assertTrue(link.verify_password("secret"))
        self.assertFalse(link.verify_password("wrong"))

    def test_share_permissions(self):
        """Test sharing permissions."""
        permission = self.manager.share_with_email(
            dashboard_id="dash1",
            email="user@example.com",
            access_level=AccessLevel.VIEW,
            granted_by="admin",
        )

        self.assertIsNotNone(permission)
        self.assertTrue(permission.can_view())
        self.assertFalse(permission.can_edit())

        # Check access
        access = self.manager.check_access(
            dashboard_id="dash1",
            email="user@example.com",
        )
        self.assertEqual(access, AccessLevel.VIEW)

    def test_revoke_token(self):
        """Test revoking embed tokens."""
        token = self.manager.create_embed_token(
            dashboard_id="dash1",
            created_by="user1",
        )

        self.assertTrue(token.is_valid())

        success = self.manager.revoke_embed_token(token.id)
        self.assertTrue(success)
        self.assertFalse(token.is_valid())


class TestDashboardUpdateManager(unittest.TestCase):
    """Tests for dashboard update manager."""

    def setUp(self):
        """Set up test fixtures."""
        self.event_bus = create_event_bus()
        self.manager = create_update_manager(self.event_bus)

    def test_register_dashboard(self):
        """Test registering dashboards."""
        dashboard = Dashboard(id="dash1", name="Test")
        self.manager.register_dashboard(dashboard)

        status = self.manager.get_dashboard_status("dash1")
        self.assertEqual(status["dashboard_id"], "dash1")

    def test_queue_widget_update(self):
        """Test queuing widget updates."""
        dashboard = Dashboard(id="dash1", name="Test")
        self.manager.register_dashboard(dashboard)

        self.manager.queue_widget_update(
            "dash1", "widget1", UpdatePriority.HIGH
        )

        status = self.manager.get_dashboard_status("dash1")
        self.assertGreater(status["queue_size"], 0)

    def test_refresh_dashboard(self):
        """Test dashboard refresh."""
        dashboard = Dashboard(id="dash1", name="Test")
        self.manager.register_dashboard(dashboard)

        self.manager.refresh_dashboard("dash1")
        # No widgets, so nothing queued
        status = self.manager.get_dashboard_status("dash1")
        self.assertEqual(status["queue_size"], 0)

    def test_widget_status_tracking(self):
        """Test widget status tracking."""
        from stance.dashboards.updates import WidgetUpdateState

        state = WidgetUpdateState(widget_id="w1")
        self.assertEqual(state.status, WidgetStatus.STALE)

        state.mark_updating()
        self.assertEqual(state.status, WidgetStatus.UPDATING)

        state.mark_updated(100.0)
        self.assertEqual(state.status, WidgetStatus.FRESH)
        self.assertEqual(state.update_count, 1)

        state.mark_error("Connection failed")
        self.assertEqual(state.status, WidgetStatus.ERROR)
        self.assertEqual(state.error_count, 1)


class TestRealtimeEvent(unittest.TestCase):
    """Tests for RealtimeEvent."""

    def test_event_creation(self):
        """Test event creation."""
        event = RealtimeEvent(
            event_type=EventType.FINDING_CREATED,
            data={"finding_id": "f1", "severity": "critical"},
            dashboard_id="dash1",
        )

        self.assertIsNotNone(event.event_id)
        self.assertEqual(event.event_type, EventType.FINDING_CREATED)
        self.assertEqual(event.data["finding_id"], "f1")

    def test_event_serialization(self):
        """Test event serialization."""
        event = RealtimeEvent(
            event_type=EventType.METRIC_UPDATE,
            data={"value": 42},
        )

        # To dict
        event_dict = event.to_dict()
        self.assertIn("event_id", event_dict)
        self.assertIn("event_type", event_dict)
        self.assertEqual(event_dict["data"]["value"], 42)

        # To SSE format
        sse = event.to_sse()
        self.assertIn("event:", sse)
        self.assertIn("data:", sse)

        # To JSON
        json_str = event.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["event_type"], "metric_update")


class TestFilterableChart(unittest.TestCase):
    """Tests for filterable charts."""

    def test_filter_by_range(self):
        """Test filtering by value range."""
        from stance.dashboards.interactive import FilterableChart

        chart = FilterableChart("chart1")

        data = ChartData(title="Test")
        series = DataSeries(name="Data")
        series.add_point("A", 10)
        series.add_point("B", 50)
        series.add_point("C", 100)
        data.add_series(series)

        chart.set_data(data)
        chart.add_filter("range1", {
            "type": "range",
            "field": "y",
            "min": 20,
            "max": 80,
        })

        summary = chart.get_filter_summary()
        self.assertEqual(summary["filtered_count"], 1)  # Only B

    def test_filter_by_category(self):
        """Test filtering by category."""
        from stance.dashboards.interactive import FilterableChart

        chart = FilterableChart("chart1")

        data = ChartData(title="Test")
        series = DataSeries(name="Data")
        series.add_point("Critical", 10)
        series.add_point("High", 20)
        series.add_point("Medium", 30)
        series.add_point("Low", 40)
        data.add_series(series)

        chart.set_data(data)
        chart.add_filter("severity", {
            "type": "category",
            "field": "x",
            "values": ["Critical", "High"],
        })

        summary = chart.get_filter_summary()
        self.assertEqual(summary["filtered_count"], 2)


class TestTimeSeriesDrillChart(unittest.TestCase):
    """Tests for time series drill-down charts."""

    def test_time_aggregation(self):
        """Test time-based aggregation."""
        from stance.dashboards.interactive import TimeSeriesDrillChart

        chart = TimeSeriesDrillChart("chart1")

        # Create test data
        data = []
        for i in range(30):
            dt = datetime(2024, 1, 1) + timedelta(days=i)
            data.append((dt, float(i * 10)))

        chart.set_time_data(data)

        # Check data is aggregated
        self.assertIsNotNone(chart.data)
        self.assertGreater(len(chart.data.series), 0)


if __name__ == "__main__":
    unittest.main()
