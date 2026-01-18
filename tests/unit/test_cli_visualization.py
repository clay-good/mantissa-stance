"""
Unit tests for Visualization CLI commands.

Tests the Click-based CLI interface for:
- Widget management
- Dashboard management
- Embedding controls
- Real-time streaming
- Interactive charts
- Update manager
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

import pytest
from click.testing import CliRunner

from stance.cli_visualization import (
    viz,
    widget,
    dashboard,
    embed,
    realtime,
    chart,
    updates,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def runner():
    """Create Click CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_widget_template():
    """Create mock widget template."""
    template = MagicMock()
    template.id = "template-001"
    template.name = "Test Template"
    template.description = "A test template"
    template.category = MagicMock()
    template.category.value = "security"
    template.default_size = (4, 3)
    template.tags = ["test", "security"]
    template.to_dict.return_value = {
        "id": "template-001",
        "name": "Test Template",
        "category": "security",
    }
    return template


@pytest.fixture
def mock_widget():
    """Create mock widget."""
    widget = MagicMock()
    widget.id = "widget-001"
    widget.widget_type = MagicMock()
    widget.widget_type.value = "chart"
    widget.config = MagicMock()
    widget.config.title = "Test Widget"
    widget.position = (0, 0)
    widget.size = (4, 3)
    widget.to_dict.return_value = {
        "id": "widget-001",
        "type": "chart",
        "title": "Test Widget",
    }
    return widget


@pytest.fixture
def mock_dashboard():
    """Create mock dashboard."""
    dashboard = MagicMock()
    dashboard.id = "dash-001"
    dashboard.name = "Test Dashboard"
    dashboard.theme = MagicMock()
    dashboard.theme.value = "light"
    dashboard.layout = MagicMock()
    dashboard.layout.columns = 12
    dashboard.is_public = False
    dashboard.to_dict.return_value = {
        "id": "dash-001",
        "name": "Test Dashboard",
        "theme": "light",
    }
    return dashboard


@pytest.fixture
def mock_embed_token():
    """Create mock embed token."""
    token = MagicMock()
    token.id = "token-001"
    token.token = "abc123"
    token.embed_mode = MagicMock()
    token.embed_mode.value = "full"
    token.expires_at = datetime.utcnow() + timedelta(hours=24)
    token.max_uses = None
    token.to_dict.return_value = {
        "id": "token-001",
        "mode": "full",
    }
    token.get_iframe_html.return_value = '<iframe src="..."></iframe>'
    return token


@pytest.fixture
def mock_share_link():
    """Create mock share link."""
    link = MagicMock()
    link.id = "link-001"
    link.short_code = "abc123"
    link.password_hash = None
    link.require_login = False
    link.expires_at = None
    link.max_uses = None
    link.to_dict.return_value = {
        "id": "link-001",
        "short_code": "abc123",
    }
    return link


@pytest.fixture
def mock_permission():
    """Create mock permission."""
    permission = MagicMock()
    permission.id = "perm-001"
    permission.grantee_type = "user"
    permission.grantee_id = "user-123"
    permission.access_level = MagicMock()
    permission.access_level.value = "view"
    permission.expires_at = None
    permission.to_dict.return_value = {
        "id": "perm-001",
        "grantee_type": "user",
    }
    return permission


# =============================================================================
# Widget Commands Tests
# =============================================================================


class TestWidgetCommands:
    """Tests for widget CLI commands."""

    @patch("stance.cli_visualization.create_widget_palette")
    def test_list_templates_table(self, mock_palette_fn, runner, mock_widget_template):
        """Test list-templates with table output."""
        mock_palette = MagicMock()
        mock_palette.get_all_templates.return_value = [mock_widget_template]
        mock_palette_fn.return_value = mock_palette

        result = runner.invoke(viz, ["widget", "list-templates"])

        assert result.exit_code == 0
        assert "Widget Templates" in result.output
        assert "template-001" in result.output

    @patch("stance.cli_visualization.create_widget_palette")
    def test_list_templates_json(self, mock_palette_fn, runner, mock_widget_template):
        """Test list-templates with JSON output."""
        mock_palette = MagicMock()
        mock_palette.get_all_templates.return_value = [mock_widget_template]
        mock_palette_fn.return_value = mock_palette

        result = runner.invoke(viz, ["widget", "list-templates", "-j"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert isinstance(output, list)
        assert len(output) == 1

    @patch("stance.cli_visualization.create_widget_palette")
    def test_search_widgets(self, mock_palette_fn, runner, mock_widget_template):
        """Test search command."""
        mock_palette = MagicMock()
        mock_palette.search_templates.return_value = [mock_widget_template]
        mock_palette_fn.return_value = mock_palette

        result = runner.invoke(viz, ["widget", "search", "security"])

        assert result.exit_code == 0
        assert "Search results" in result.output
        assert "template-001" in result.output

    @patch("stance.cli_visualization.create_widget_builder")
    @patch("stance.cli_visualization.Dashboard")
    def test_create_widget(self, mock_dash_class, mock_builder_fn, runner, mock_widget):
        """Test create command."""
        mock_builder = MagicMock()
        mock_builder.create_widget_from_template.return_value = mock_widget
        mock_builder_fn.return_value = mock_builder

        result = runner.invoke(viz, [
            "widget", "create",
            "-d", "dash-001",
            "-t", "template-001",
            "--title", "My Widget",
        ])

        assert result.exit_code == 0
        assert "Widget created" in result.output
        assert "widget-001" in result.output


# =============================================================================
# Dashboard Commands Tests
# =============================================================================


class TestDashboardCommands:
    """Tests for dashboard CLI commands."""

    @patch("stance.cli_visualization.Dashboard")
    @patch("stance.cli_visualization.DashboardLayout")
    def test_create_dashboard_table(self, mock_layout_class, mock_dash_class, runner):
        """Test create dashboard with table output."""
        mock_dashboard = MagicMock()
        mock_dashboard.id = "dash-new"
        mock_dashboard.name = "New Dashboard"
        mock_dashboard.theme = MagicMock()
        mock_dashboard.theme.value = "light"
        mock_dashboard.layout = MagicMock()
        mock_dashboard.layout.columns = 12
        mock_dashboard.is_public = False
        mock_dash_class.return_value = mock_dashboard

        result = runner.invoke(viz, [
            "dashboard", "create",
            "-n", "New Dashboard",
        ])

        assert result.exit_code == 0
        assert "Dashboard created" in result.output
        assert "New Dashboard" in result.output

    @patch("stance.cli_visualization.Dashboard")
    @patch("stance.cli_visualization.DashboardLayout")
    def test_create_dashboard_json(self, mock_layout_class, mock_dash_class, runner):
        """Test create dashboard with JSON output."""
        mock_dashboard = MagicMock()
        mock_dashboard.to_dict.return_value = {
            "id": "dash-new",
            "name": "New Dashboard",
            "theme": "light",
        }
        mock_dash_class.return_value = mock_dashboard

        result = runner.invoke(viz, [
            "dashboard", "create",
            "-n", "New Dashboard",
            "-j",
        ])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "name" in output

    @patch("stance.cli_visualization.create_widget_builder")
    @patch("stance.cli_visualization.Dashboard")
    def test_manage_layout(self, mock_dash_class, mock_builder_fn, runner):
        """Test layout management command."""
        mock_builder = MagicMock()
        mock_builder.get_state.return_value = {
            "layout": {
                "columns": 12,
                "rows": 4,
                "widget_count": 3,
            }
        }
        mock_builder_fn.return_value = mock_builder

        result = runner.invoke(viz, [
            "dashboard", "layout", "dash-001",
            "--compact",
        ])

        assert result.exit_code == 0
        assert "Layout compacted" in result.output


# =============================================================================
# Embedding Commands Tests
# =============================================================================


class TestEmbedCommands:
    """Tests for embed CLI commands."""

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_create_embed_token(self, mock_manager_fn, runner, mock_embed_token):
        """Test create-token command."""
        mock_manager = MagicMock()
        mock_manager.create_embed_token.return_value = mock_embed_token
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "embed", "create-token", "dash-001",
            "--expires", "24",
            "--mode", "full",
        ])

        assert result.exit_code == 0
        assert "Embed token created" in result.output
        assert "token-001" in result.output

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_create_embed_token_json(self, mock_manager_fn, runner, mock_embed_token):
        """Test create-token command with JSON output."""
        mock_manager = MagicMock()
        mock_manager.create_embed_token.return_value = mock_embed_token
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "embed", "create-token", "dash-001",
            "-j",
        ])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "id" in output

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_create_share_link(self, mock_manager_fn, runner, mock_share_link):
        """Test create-link command."""
        mock_manager = MagicMock()
        mock_manager.create_share_link.return_value = mock_share_link
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "embed", "create-link", "dash-001",
            "--expires", "7",
        ])

        assert result.exit_code == 0
        assert "Share link created" in result.output
        assert "abc123" in result.output

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_share_dashboard_with_user(self, mock_manager_fn, runner, mock_permission):
        """Test share command with user."""
        mock_manager = MagicMock()
        mock_manager.share_with_user.return_value = mock_permission
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "embed", "share", "dash-001",
            "--user", "user-123",
            "--access", "view",
        ])

        assert result.exit_code == 0
        assert "Dashboard shared" in result.output

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_share_dashboard_with_email(self, mock_manager_fn, runner, mock_permission):
        """Test share command with email."""
        mock_manager = MagicMock()
        mock_manager.share_with_email.return_value = mock_permission
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "embed", "share", "dash-001",
            "--email", "user@example.com",
        ])

        assert result.exit_code == 0
        assert "Dashboard shared" in result.output

    @patch("stance.cli_visualization.create_embedding_manager")
    def test_embedding_status(self, mock_manager_fn, runner):
        """Test status command."""
        mock_manager = MagicMock()
        mock_manager.get_dashboard_sharing_summary.return_value = {
            "share_type": "private",
            "permission_count": 3,
            "embed_token_count": 1,
            "share_link_count": 2,
            "total_views": 100,
            "allow_embedding": True,
            "password_protected": False,
        }
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, ["embed", "status", "dash-001"])

        assert result.exit_code == 0
        assert "Sharing Status" in result.output
        assert "Permissions: 3" in result.output


# =============================================================================
# Real-time Commands Tests
# =============================================================================


class TestRealtimeCommands:
    """Tests for real-time CLI commands."""

    @patch("stance.cli_visualization.create_event_bus")
    def test_realtime_status(self, mock_bus_fn, runner):
        """Test status command."""
        mock_bus = MagicMock()
        mock_bus.get_stats.return_value = {
            "connected_clients": 5,
            "active_subscriptions": 10,
            "events_published": 100,
            "events_delivered": 95,
            "queue_size": 5,
        }
        mock_bus_fn.return_value = mock_bus

        result = runner.invoke(viz, ["realtime", "status"])

        assert result.exit_code == 0
        assert "Real-time Streaming Status" in result.output
        assert "Connected Clients: 5" in result.output

    @patch("stance.cli_visualization.create_event_bus")
    def test_realtime_status_json(self, mock_bus_fn, runner):
        """Test status command with JSON output."""
        mock_bus = MagicMock()
        mock_bus.get_stats.return_value = {
            "connected_clients": 5,
            "active_subscriptions": 10,
        }
        mock_bus_fn.return_value = mock_bus

        result = runner.invoke(viz, ["realtime", "status", "-j"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "connected_clients" in output

    @patch("stance.dashboards.realtime.RealtimeEvent")
    @patch("stance.cli_visualization.create_event_bus")
    def test_publish_event(self, mock_bus_fn, mock_event_class, runner):
        """Test publish command."""
        mock_bus = MagicMock()
        mock_bus.publish.return_value = 3
        mock_bus_fn.return_value = mock_bus

        mock_event = MagicMock()
        mock_event.event_id = "evt-001"
        mock_event.event_type = MagicMock()
        mock_event.event_type.value = "dashboard_update"
        mock_event_class.return_value = mock_event

        result = runner.invoke(viz, [
            "realtime", "publish", "dashboard_update",
            "--data", '{"test": "data"}',
            "--dashboard-id", "dash-001",
        ])

        assert result.exit_code == 0
        assert "Event published to 3 subscriber(s)" in result.output

    def test_list_event_types(self, runner):
        """Test events command."""
        result = runner.invoke(viz, ["realtime", "events"])

        assert result.exit_code == 0
        assert "Event Types" in result.output


# =============================================================================
# Chart Commands Tests
# =============================================================================


class TestChartCommands:
    """Tests for chart CLI commands."""

    def test_list_chart_types(self, runner):
        """Test types command."""
        result = runner.invoke(viz, ["chart", "types"])

        assert result.exit_code == 0
        assert "Chart Types:" in result.output

    def test_list_chart_types_json(self, runner):
        """Test types command with JSON output."""
        result = runner.invoke(viz, ["chart", "types", "-j"])

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert "chart_types" in output

    @patch("stance.cli_visualization.create_interactive_chart")
    def test_create_chart(self, mock_create_fn, runner):
        """Test create command."""
        mock_chart = MagicMock()
        mock_chart.chart_id = "chart-001"
        mock_chart.to_dict.return_value = {
            "chart_id": "chart-001",
            "type": "basic",
        }
        mock_create_fn.return_value = mock_chart

        result = runner.invoke(viz, [
            "chart", "create",
            "--type", "basic",
            "--title", "My Chart",
            "--enable-zoom",
        ])

        assert result.exit_code == 0
        assert "Interactive Chart Created" in result.output


# =============================================================================
# Updates Commands Tests
# =============================================================================


class TestUpdatesCommands:
    """Tests for updates CLI commands."""

    @patch("stance.cli_visualization.create_update_manager")
    @patch("stance.cli_visualization.Dashboard")
    def test_update_status(self, mock_dash_class, mock_manager_fn, runner):
        """Test status command."""
        mock_manager = MagicMock()
        mock_manager.get_dashboard_status.return_value = {
            "widget_count": 5,
            "subscriber_count": 3,
            "queue_size": 0,
        }
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, ["updates", "status", "dash-001"])

        assert result.exit_code == 0
        assert "Update Status" in result.output
        assert "Widget Count: 5" in result.output

    @patch("stance.cli_visualization.create_update_manager")
    @patch("stance.cli_visualization.Dashboard")
    def test_refresh_dashboard(self, mock_dash_class, mock_manager_fn, runner):
        """Test refresh command for dashboard."""
        mock_manager = MagicMock()
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "updates", "refresh", "dash-001",
            "--priority", "high",
        ])

        assert result.exit_code == 0
        assert "queued for refresh" in result.output
        assert "high" in result.output

    @patch("stance.cli_visualization.create_update_manager")
    @patch("stance.cli_visualization.Dashboard")
    def test_refresh_widget(self, mock_dash_class, mock_manager_fn, runner):
        """Test refresh command for widget."""
        mock_manager = MagicMock()
        mock_manager_fn.return_value = mock_manager

        result = runner.invoke(viz, [
            "updates", "refresh", "dash-001",
            "--widget", "widget-001",
        ])

        assert result.exit_code == 0
        assert "Widget widget-001 queued for refresh" in result.output


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for error handling in CLI commands."""

    def test_share_without_target(self, runner):
        """Test share command without user/email/domain fails."""
        with patch("stance.cli_visualization.create_embedding_manager"):
            result = runner.invoke(viz, ["embed", "share", "dash-001"])

            assert result.exit_code == 1
            assert "Please specify" in result.output

    @patch("stance.cli_visualization.create_widget_builder")
    @patch("stance.cli_visualization.Dashboard")
    def test_create_widget_template_not_found(self, mock_dash_class, mock_builder_fn, runner):
        """Test create widget with invalid template."""
        mock_builder = MagicMock()
        mock_builder.create_widget_from_template.return_value = None
        mock_builder_fn.return_value = mock_builder

        result = runner.invoke(viz, [
            "widget", "create",
            "-d", "dash-001",
            "-t", "invalid-template",
        ])

        assert result.exit_code == 1
        assert "Failed to create widget" in result.output


# =============================================================================
# Integration Tests
# =============================================================================


class TestCLIIntegration:
    """Integration tests for CLI commands."""

    def test_viz_group_exists(self, runner):
        """Test main viz group exists and shows help."""
        result = runner.invoke(viz, ["--help"])

        assert result.exit_code == 0
        assert "Enhanced visualization" in result.output

    def test_widget_subgroup_exists(self, runner):
        """Test widget subgroup exists."""
        result = runner.invoke(viz, ["widget", "--help"])

        assert result.exit_code == 0
        assert "Widget management" in result.output

    def test_dashboard_subgroup_exists(self, runner):
        """Test dashboard subgroup exists."""
        result = runner.invoke(viz, ["dashboard", "--help"])

        assert result.exit_code == 0
        assert "Dashboard management" in result.output

    def test_embed_subgroup_exists(self, runner):
        """Test embed subgroup exists."""
        result = runner.invoke(viz, ["embed", "--help"])

        assert result.exit_code == 0
        assert "embedding" in result.output

    def test_realtime_subgroup_exists(self, runner):
        """Test realtime subgroup exists."""
        result = runner.invoke(viz, ["realtime", "--help"])

        assert result.exit_code == 0
        assert "streaming" in result.output

    def test_chart_subgroup_exists(self, runner):
        """Test chart subgroup exists."""
        result = runner.invoke(viz, ["chart", "--help"])

        assert result.exit_code == 0
        assert "chart" in result.output

    def test_updates_subgroup_exists(self, runner):
        """Test updates subgroup exists."""
        result = runner.invoke(viz, ["updates", "--help"])

        assert result.exit_code == 0
        assert "update manager" in result.output
