"""
Unit tests for Web API notifications endpoints.

Tests the notifications REST API endpoints for listing, showing,
configuring, and managing notifications.
"""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


class TestNotificationsListEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/list endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._get_sample_notifications = StanceRequestHandler._get_sample_notifications.__get__(
            self.handler, StanceRequestHandler
        )
        self.handler._notifications_list = StanceRequestHandler._notifications_list.__get__(
            self.handler, StanceRequestHandler
        )

    def test_list_default_params(self):
        """Test list with default parameters."""
        result = self.handler._notifications_list({})

        self.assertIn("notifications", result)
        self.assertIn("total", result)
        self.assertIn("limit", result)
        self.assertIn("offset", result)
        self.assertEqual(result["limit"], 50)
        self.assertEqual(result["offset"], 0)

    def test_list_with_limit(self):
        """Test list with custom limit."""
        result = self.handler._notifications_list({"limit": ["2"]})

        self.assertEqual(result["limit"], 2)
        self.assertLessEqual(len(result["notifications"]), 2)

    def test_list_with_offset(self):
        """Test list with offset."""
        result = self.handler._notifications_list({"offset": ["1"]})

        self.assertEqual(result["offset"], 1)

    def test_list_with_type_filter(self):
        """Test list with type filter."""
        result = self.handler._notifications_list({"type": ["scan_complete"]})

        for notif in result["notifications"]:
            self.assertEqual(notif["notification_type"], "scan_complete")

    def test_list_none_params(self):
        """Test list with None params."""
        result = self.handler._notifications_list(None)

        self.assertIn("notifications", result)


class TestNotificationsShowEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/show endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._get_sample_notifications = StanceRequestHandler._get_sample_notifications.__get__(
            self.handler, StanceRequestHandler
        )
        self.handler._notifications_show = StanceRequestHandler._notifications_show.__get__(
            self.handler, StanceRequestHandler
        )

    def test_show_first_notification(self):
        """Test showing first notification."""
        result = self.handler._notifications_show({"index": ["0"]})

        self.assertIn("notification_type", result)
        self.assertIn("timestamp", result)
        self.assertIn("message", result)

    def test_show_default_index(self):
        """Test showing with default index."""
        result = self.handler._notifications_show({})

        self.assertIn("notification_type", result)

    def test_show_invalid_index(self):
        """Test showing with invalid index."""
        result = self.handler._notifications_show({"index": ["999"]})

        self.assertIn("error", result)

    def test_show_negative_index(self):
        """Test showing with negative index."""
        result = self.handler._notifications_show({"index": ["-1"]})

        self.assertIn("error", result)


class TestNotificationsTypesEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/types endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_types = StanceRequestHandler._notifications_types.__get__(
            self.handler, StanceRequestHandler
        )

    def test_types_returns_all(self):
        """Test types endpoint returns all notification types."""
        result = self.handler._notifications_types({})

        self.assertIn("types", result)
        self.assertIn("total", result)
        self.assertEqual(result["total"], 7)

        type_values = [t["value"] for t in result["types"]]
        self.assertIn("scan_complete", type_values)
        self.assertIn("scan_failed", type_values)
        self.assertIn("new_findings", type_values)
        self.assertIn("critical_finding", type_values)
        self.assertIn("findings_resolved", type_values)
        self.assertIn("trend_alert", type_values)
        self.assertIn("scheduled_report", type_values)

    def test_types_structure(self):
        """Test that each type has proper structure."""
        result = self.handler._notifications_types({})

        for type_info in result["types"]:
            self.assertIn("value", type_info)
            self.assertIn("name", type_info)
            self.assertIn("description", type_info)


class TestNotificationsConfigEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/config endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_config_get = StanceRequestHandler._notifications_config_get.__get__(
            self.handler, StanceRequestHandler
        )

    def test_config_returns_all_fields(self):
        """Test config endpoint returns all configuration fields."""
        result = self.handler._notifications_config_get({})

        self.assertIn("notify_on_scan_complete", result)
        self.assertIn("notify_on_scan_failure", result)
        self.assertIn("notify_on_new_findings", result)
        self.assertIn("notify_on_critical", result)
        self.assertIn("notify_on_resolved", result)
        self.assertIn("notify_on_trend_change", result)
        self.assertIn("min_severity_for_new", result)
        self.assertIn("critical_threshold", result)
        self.assertIn("trend_threshold_percent", result)
        self.assertIn("include_summary", result)
        self.assertIn("include_details", result)
        self.assertIn("destinations", result)

    def test_config_default_values(self):
        """Test config endpoint returns proper default values."""
        result = self.handler._notifications_config_get({})

        self.assertTrue(result["notify_on_scan_complete"])
        self.assertTrue(result["notify_on_critical"])
        self.assertFalse(result["notify_on_resolved"])
        self.assertEqual(result["min_severity_for_new"], "high")
        self.assertEqual(result["critical_threshold"], 1)


class TestNotificationsStatusEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/status endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._get_sample_notifications = StanceRequestHandler._get_sample_notifications.__get__(
            self.handler, StanceRequestHandler
        )
        self.handler._notifications_config_get = StanceRequestHandler._notifications_config_get.__get__(
            self.handler, StanceRequestHandler
        )
        self.handler._notifications_status = StanceRequestHandler._notifications_status.__get__(
            self.handler, StanceRequestHandler
        )

    def test_status_returns_module_info(self):
        """Test status endpoint returns module information."""
        result = self.handler._notifications_status({})

        self.assertEqual(result["module"], "notifications")
        self.assertIn("version", result)
        self.assertEqual(result["status"], "active")

    def test_status_returns_statistics(self):
        """Test status endpoint returns statistics."""
        result = self.handler._notifications_status({})

        self.assertIn("history_count", result)
        self.assertIn("max_history", result)
        self.assertIn("enabled_types", result)
        self.assertIn("notifications_by_type", result)

    def test_status_returns_capabilities(self):
        """Test status endpoint returns capabilities."""
        result = self.handler._notifications_status({})

        self.assertIn("capabilities", result)
        caps = result["capabilities"]
        self.assertTrue(caps["scan_complete"])
        self.assertTrue(caps["critical_finding"])
        self.assertTrue(caps["alert_routing"])


class TestNotificationsSetEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/set endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_set = StanceRequestHandler._notifications_set.__get__(
            self.handler, StanceRequestHandler
        )

    def test_set_valid_option(self):
        """Test setting a valid option."""
        body = json.dumps({"option": "notify_on_critical", "value": True}).encode()
        result = self.handler._notifications_set(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["option"], "notify_on_critical")
        self.assertEqual(result["value"], True)

    def test_set_missing_option(self):
        """Test setting without option."""
        body = json.dumps({"value": True}).encode()
        result = self.handler._notifications_set(body)

        self.assertIn("error", result)

    def test_set_missing_value(self):
        """Test setting without value."""
        body = json.dumps({"option": "notify_on_critical"}).encode()
        result = self.handler._notifications_set(body)

        self.assertIn("error", result)

    def test_set_unknown_option(self):
        """Test setting unknown option."""
        body = json.dumps({"option": "unknown_option", "value": True}).encode()
        result = self.handler._notifications_set(body)

        self.assertIn("error", result)
        self.assertIn("valid_options", result)

    def test_set_invalid_json(self):
        """Test setting with invalid JSON."""
        result = self.handler._notifications_set(b"not json")

        self.assertIn("error", result)

    def test_set_empty_body(self):
        """Test setting with empty body."""
        result = self.handler._notifications_set(b"")

        self.assertIn("error", result)


class TestNotificationsEnableEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/enable endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_enable = StanceRequestHandler._notifications_enable.__get__(
            self.handler, StanceRequestHandler
        )

    def test_enable_specific_type(self):
        """Test enabling a specific type."""
        body = json.dumps({"type": "critical"}).encode()
        result = self.handler._notifications_enable(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "critical")
        self.assertTrue(result["enabled"])

    def test_enable_all(self):
        """Test enabling all types."""
        body = json.dumps({"type": "all"}).encode()
        result = self.handler._notifications_enable(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "all")
        self.assertIn("all", result["message"])

    def test_enable_missing_type(self):
        """Test enabling without type."""
        body = json.dumps({}).encode()
        result = self.handler._notifications_enable(body)

        self.assertIn("error", result)

    def test_enable_unknown_type(self):
        """Test enabling unknown type."""
        body = json.dumps({"type": "unknown"}).encode()
        result = self.handler._notifications_enable(body)

        self.assertIn("error", result)
        self.assertIn("valid_types", result)

    def test_enable_invalid_json(self):
        """Test enabling with invalid JSON."""
        result = self.handler._notifications_enable(b"not json")

        self.assertIn("error", result)


class TestNotificationsDisableEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/disable endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_disable = StanceRequestHandler._notifications_disable.__get__(
            self.handler, StanceRequestHandler
        )

    def test_disable_specific_type(self):
        """Test disabling a specific type."""
        body = json.dumps({"type": "critical"}).encode()
        result = self.handler._notifications_disable(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "critical")
        self.assertFalse(result["enabled"])

    def test_disable_all(self):
        """Test disabling all types."""
        body = json.dumps({"type": "all"}).encode()
        result = self.handler._notifications_disable(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["type"], "all")
        self.assertIn("all", result["message"])

    def test_disable_missing_type(self):
        """Test disabling without type."""
        body = json.dumps({}).encode()
        result = self.handler._notifications_disable(body)

        self.assertIn("error", result)

    def test_disable_unknown_type(self):
        """Test disabling unknown type."""
        body = json.dumps({"type": "unknown"}).encode()
        result = self.handler._notifications_disable(body)

        self.assertIn("error", result)

    def test_disable_invalid_json(self):
        """Test disabling with invalid JSON."""
        result = self.handler._notifications_disable(b"not json")

        self.assertIn("error", result)


class TestNotificationsTestEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/test endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_test = StanceRequestHandler._notifications_test.__get__(
            self.handler, StanceRequestHandler
        )

    def test_test_default_type(self):
        """Test sending test notification with default type."""
        result = self.handler._notifications_test(b"{}")

        self.assertTrue(result["success"])
        self.assertIn("notification", result)
        self.assertEqual(result["notification"]["notification_type"], "scan_complete")

    def test_test_specific_type(self):
        """Test sending test notification with specific type."""
        body = json.dumps({"type": "critical"}).encode()
        result = self.handler._notifications_test(body)

        self.assertTrue(result["success"])
        self.assertEqual(result["notification"]["notification_type"], "critical")

    def test_test_all_valid_types(self):
        """Test sending test notification for all valid types."""
        valid_types = ["scan_complete", "scan_failed", "new_findings", "critical", "resolved", "trend_alert"]

        for notification_type in valid_types:
            body = json.dumps({"type": notification_type}).encode()
            result = self.handler._notifications_test(body)

            self.assertTrue(result["success"])
            self.assertEqual(result["notification"]["notification_type"], notification_type)

    def test_test_unknown_type(self):
        """Test sending test notification with unknown type."""
        body = json.dumps({"type": "unknown"}).encode()
        result = self.handler._notifications_test(body)

        self.assertIn("error", result)
        self.assertIn("valid_types", result)

    def test_test_notification_structure(self):
        """Test that test notification has proper structure."""
        result = self.handler._notifications_test(b"{}")

        notif = result["notification"]
        self.assertIn("notification_type", notif)
        self.assertIn("timestamp", notif)
        self.assertIn("scan_id", notif)
        self.assertIn("message", notif)
        self.assertTrue(notif.get("is_test", False))

    def test_test_invalid_json(self):
        """Test sending test notification with invalid JSON."""
        result = self.handler._notifications_test(b"not json")

        self.assertIn("error", result)


class TestNotificationsClearEndpoint(unittest.TestCase):
    """Tests for the /api/notifications/clear endpoint."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._notifications_clear = StanceRequestHandler._notifications_clear.__get__(
            self.handler, StanceRequestHandler
        )

    def test_clear_with_force(self):
        """Test clearing with force=true."""
        body = json.dumps({"force": True}).encode()
        result = self.handler._notifications_clear(body)

        self.assertTrue(result["success"])
        self.assertIn("cleared_count", result)

    def test_clear_without_force(self):
        """Test clearing without force."""
        body = json.dumps({}).encode()
        result = self.handler._notifications_clear(body)

        self.assertIn("error", result)

    def test_clear_force_false(self):
        """Test clearing with force=false."""
        body = json.dumps({"force": False}).encode()
        result = self.handler._notifications_clear(body)

        self.assertIn("error", result)

    def test_clear_invalid_json(self):
        """Test clearing with invalid JSON."""
        result = self.handler._notifications_clear(b"not json")

        self.assertIn("error", result)


class TestGetSampleNotifications(unittest.TestCase):
    """Tests for the sample notifications helper."""

    def setUp(self):
        """Set up test fixtures."""
        from stance.web.server import StanceRequestHandler

        self.handler = MagicMock(spec=StanceRequestHandler)
        self.handler._get_sample_notifications = StanceRequestHandler._get_sample_notifications.__get__(
            self.handler, StanceRequestHandler
        )

    def test_returns_list(self):
        """Test that sample notifications returns a list."""
        result = self.handler._get_sample_notifications()

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 5)

    def test_notification_types_covered(self):
        """Test that all key notification types are covered."""
        result = self.handler._get_sample_notifications()

        types = [n["notification_type"] for n in result]
        self.assertIn("scan_complete", types)
        self.assertIn("critical_finding", types)
        self.assertIn("new_findings", types)
        self.assertIn("trend_alert", types)
        self.assertIn("scan_failed", types)

    def test_notification_structure(self):
        """Test that notifications have proper structure."""
        result = self.handler._get_sample_notifications()

        for notif in result:
            self.assertIn("notification_type", notif)
            self.assertIn("timestamp", notif)
            self.assertIn("scan_id", notif)
            self.assertIn("message", notif)

    def test_scan_complete_has_details(self):
        """Test that scan_complete has additional details."""
        result = self.handler._get_sample_notifications()

        scan_complete = next(
            n for n in result if n["notification_type"] == "scan_complete"
        )
        self.assertIn("success", scan_complete)
        self.assertIn("duration_seconds", scan_complete)
        self.assertIn("assets_scanned", scan_complete)
        self.assertIn("findings_total", scan_complete)

    def test_trend_alert_has_details(self):
        """Test that trend_alert has additional details."""
        result = self.handler._get_sample_notifications()

        trend_alert = next(
            n for n in result if n["notification_type"] == "trend_alert"
        )
        self.assertIn("direction", trend_alert)
        self.assertIn("change_percent", trend_alert)
        self.assertIn("current_findings", trend_alert)
        self.assertIn("previous_findings", trend_alert)


class TestNotificationsEndpointRouting(unittest.TestCase):
    """Tests for endpoint routing in do_GET and do_POST."""

    def test_get_endpoints_exist(self):
        """Test that GET endpoints are defined."""
        from stance.web.server import StanceRequestHandler

        # Check that the handler class has the required methods
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_list'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_show'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_types'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_config_get'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_status'))

    def test_post_endpoints_exist(self):
        """Test that POST endpoints are defined."""
        from stance.web.server import StanceRequestHandler

        # Check that the handler class has the required methods
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_set'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_enable'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_disable'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_test'))
        self.assertTrue(hasattr(StanceRequestHandler, '_notifications_clear'))


if __name__ == '__main__':
    unittest.main()
