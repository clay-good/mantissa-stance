"""
Unit tests for CLI notifications commands.

Tests the notifications CLI commands for listing, showing,
configuring, and managing notifications.
"""

from __future__ import annotations

import argparse
import json
import unittest
from datetime import datetime, timezone
from io import StringIO
from unittest.mock import patch, MagicMock

from stance.cli_notifications import (
    cmd_notifications,
    add_notifications_parser,
    get_notification_handler,
    _format_notification_table,
    _format_notification_detail,
    _format_config,
    _get_demo_notifications,
    _create_test_notification,
)
from stance.automation import (
    NotificationHandler,
    NotificationConfig,
    NotificationType,
    ScanNotification,
    ScanSummaryNotification,
    FindingNotification,
    TrendNotification,
)


class TestNotificationsListCommand(unittest.TestCase):
    """Tests for the notifications list command."""

    def test_list_demo_mode_table(self):
        """Test list command in demo mode with table output."""
        args = argparse.Namespace(
            notifications_action='list',
            format='table',
            limit=50,
            type=None,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("scan_complete", output)
        self.assertIn("Total:", output)

    def test_list_demo_mode_json(self):
        """Test list command in demo mode with JSON output."""
        args = argparse.Namespace(
            notifications_action='list',
            format='json',
            limit=50,
            type=None,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_list_with_type_filter(self):
        """Test list command with type filter."""
        args = argparse.Namespace(
            notifications_action='list',
            format='table',
            limit=50,
            type='scan_complete',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("scan_complete", output)

    def test_list_invalid_type_filter(self):
        """Test list command with invalid type filter."""
        args = argparse.Namespace(
            notifications_action='list',
            format='table',
            limit=50,
            type='invalid_type',
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)


class TestNotificationsShowCommand(unittest.TestCase):
    """Tests for the notifications show command."""

    def test_show_demo_mode_text(self):
        """Test show command in demo mode with text output."""
        args = argparse.Namespace(
            notifications_action='show',
            index=0,
            format='text',
            verbose=False,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Type:", output)
        self.assertIn("Timestamp:", output)

    def test_show_demo_mode_json(self):
        """Test show command in demo mode with JSON output."""
        args = argparse.Namespace(
            notifications_action='show',
            index=0,
            format='json',
            verbose=False,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("notification_type", data)

    def test_show_demo_mode_verbose(self):
        """Test show command in demo mode with verbose output."""
        args = argparse.Namespace(
            notifications_action='show',
            index=0,
            format='text',
            verbose=True,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Type:", output)

    def test_show_invalid_index(self):
        """Test show command with invalid index."""
        args = argparse.Namespace(
            notifications_action='show',
            index=999,
            format='text',
            verbose=False,
            demo=True,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)


class TestNotificationsTypesCommand(unittest.TestCase):
    """Tests for the notifications types command."""

    def test_types_table_output(self):
        """Test types command with table output."""
        args = argparse.Namespace(
            notifications_action='types',
            format='table',
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Notification Types:", output)
        self.assertIn("scan_complete", output)
        self.assertIn("scan_failed", output)
        self.assertIn("new_findings", output)
        self.assertIn("critical_finding", output)

    def test_types_json_output(self):
        """Test types command with JSON output."""
        args = argparse.Namespace(
            notifications_action='types',
            format='json',
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 7)  # 7 notification types


class TestNotificationsConfigCommand(unittest.TestCase):
    """Tests for the notifications config command."""

    def test_config_text_output(self):
        """Test config command with text output."""
        args = argparse.Namespace(
            notifications_action='config',
            format='text',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Notification Configuration:", output)
        self.assertIn("Notify on scan complete:", output)

    def test_config_json_output(self):
        """Test config command with JSON output."""
        args = argparse.Namespace(
            notifications_action='config',
            format='json',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertIn("notify_on_scan_complete", data)
        self.assertIn("notify_on_critical", data)


class TestNotificationsSetCommand(unittest.TestCase):
    """Tests for the notifications set command."""

    def test_set_missing_option(self):
        """Test set command without option."""
        args = argparse.Namespace(
            notifications_action='set',
            option=None,
            value=None,
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)

    def test_set_demo_mode(self):
        """Test set command in demo mode."""
        args = argparse.Namespace(
            notifications_action='set',
            option='notify_on_critical',
            value='true',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Demo", output)

    def test_set_boolean_option(self):
        """Test set command with boolean option."""
        args = argparse.Namespace(
            notifications_action='set',
            option='notify_on_critical',
            value='true',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("notify_on_critical", output)

    def test_set_severity_option(self):
        """Test set command with min_severity option."""
        args = argparse.Namespace(
            notifications_action='set',
            option='min_severity',
            value='critical',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("min_severity", output)

    def test_set_invalid_severity(self):
        """Test set command with invalid severity."""
        args = argparse.Namespace(
            notifications_action='set',
            option='min_severity',
            value='invalid',
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)

    def test_set_numeric_option(self):
        """Test set command with numeric option."""
        args = argparse.Namespace(
            notifications_action='set',
            option='critical_threshold',
            value='5',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("critical_threshold", output)

    def test_set_unknown_option(self):
        """Test set command with unknown option."""
        args = argparse.Namespace(
            notifications_action='set',
            option='unknown_option',
            value='value',
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)


class TestNotificationsEnableCommand(unittest.TestCase):
    """Tests for the notifications enable command."""

    def test_enable_missing_type(self):
        """Test enable command without type."""
        args = argparse.Namespace(
            notifications_action='enable',
            type=None,
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)

    def test_enable_demo_mode(self):
        """Test enable command in demo mode."""
        args = argparse.Namespace(
            notifications_action='enable',
            type='critical',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Demo", output)

    def test_enable_specific_type(self):
        """Test enable command with specific type."""
        args = argparse.Namespace(
            notifications_action='enable',
            type='critical',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Enabled critical", output)

    def test_enable_all_types(self):
        """Test enable command with 'all'."""
        args = argparse.Namespace(
            notifications_action='enable',
            type='all',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Enabled all", output)

    def test_enable_unknown_type(self):
        """Test enable command with unknown type."""
        args = argparse.Namespace(
            notifications_action='enable',
            type='unknown',
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)


class TestNotificationsDisableCommand(unittest.TestCase):
    """Tests for the notifications disable command."""

    def test_disable_missing_type(self):
        """Test disable command without type."""
        args = argparse.Namespace(
            notifications_action='disable',
            type=None,
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)

    def test_disable_demo_mode(self):
        """Test disable command in demo mode."""
        args = argparse.Namespace(
            notifications_action='disable',
            type='critical',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Demo", output)

    def test_disable_specific_type(self):
        """Test disable command with specific type."""
        args = argparse.Namespace(
            notifications_action='disable',
            type='critical',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Disabled critical", output)

    def test_disable_all_types(self):
        """Test disable command with 'all'."""
        args = argparse.Namespace(
            notifications_action='disable',
            type='all',
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Disabled all", output)


class TestNotificationsClearCommand(unittest.TestCase):
    """Tests for the notifications clear command."""

    def test_clear_without_force(self):
        """Test clear command without force flag."""
        args = argparse.Namespace(
            notifications_action='clear',
            force=False,
            demo=False,
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)

    def test_clear_demo_mode(self):
        """Test clear command in demo mode."""
        args = argparse.Namespace(
            notifications_action='clear',
            force=False,
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Demo", output)

    def test_clear_with_force(self):
        """Test clear command with force flag."""
        args = argparse.Namespace(
            notifications_action='clear',
            force=True,
            demo=False,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("cleared", output)


class TestNotificationsTestCommand(unittest.TestCase):
    """Tests for the notifications test command."""

    def test_test_demo_mode(self):
        """Test test command in demo mode."""
        args = argparse.Namespace(
            notifications_action='test',
            type='scan_complete',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Demo", output)
        self.assertIn("preview", output)

    def test_test_all_types(self):
        """Test test command with different types."""
        types = ['scan_complete', 'scan_failed', 'new_findings', 'critical', 'resolved', 'trend_alert']

        for test_type in types:
            args = argparse.Namespace(
                notifications_action='test',
                type=test_type,
                demo=False,
            )
            with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
                result = cmd_notifications(args)
                output = mock_stdout.getvalue()

            self.assertEqual(result, 0)
            self.assertIn("Test notification sent", output)


class TestNotificationsStatusCommand(unittest.TestCase):
    """Tests for the notifications status command."""

    def test_status_text_output(self):
        """Test status command with text output."""
        args = argparse.Namespace(
            notifications_action='status',
            format='text',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Notifications Module Status", output)
        self.assertIn("Status:", output)

    def test_status_json_output(self):
        """Test status command with JSON output."""
        args = argparse.Namespace(
            notifications_action='status',
            format='json',
            demo=True,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        data = json.loads(output)
        self.assertEqual(data["module"], "notifications")
        self.assertIn("status", data)
        self.assertIn("enabled_types", data)


class TestNotificationsNoAction(unittest.TestCase):
    """Tests for notifications command without action."""

    def test_no_action_shows_help(self):
        """Test that no action shows available commands."""
        args = argparse.Namespace(
            notifications_action=None,
        )
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            result = cmd_notifications(args)
            output = mock_stdout.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("Usage:", output)
        self.assertIn("list", output)
        self.assertIn("show", output)
        self.assertIn("config", output)


class TestNotificationsUnknownAction(unittest.TestCase):
    """Tests for notifications command with unknown action."""

    def test_unknown_action(self):
        """Test that unknown action returns error."""
        args = argparse.Namespace(
            notifications_action='unknown',
        )
        with patch('sys.stderr', new_callable=StringIO):
            result = cmd_notifications(args)

        self.assertEqual(result, 1)


class TestFormatFunctions(unittest.TestCase):
    """Tests for formatting functions."""

    def test_format_notification_table_empty(self):
        """Test formatting empty notification list."""
        result = _format_notification_table([])
        self.assertEqual(result, "No notifications found.")

    def test_format_notification_table_with_data(self):
        """Test formatting notification table with data."""
        notifications = _get_demo_notifications()
        result = _format_notification_table(notifications)

        self.assertIn("Type", result)
        self.assertIn("Scan ID", result)
        self.assertIn("Timestamp", result)

    def test_format_notification_detail(self):
        """Test formatting notification detail."""
        notifications = _get_demo_notifications()
        result = _format_notification_detail(notifications[0])

        self.assertIn("Type:", result)
        self.assertIn("Timestamp:", result)
        self.assertIn("Scan ID:", result)

    def test_format_notification_detail_verbose(self):
        """Test formatting notification detail with verbose flag."""
        notifications = _get_demo_notifications()
        result = _format_notification_detail(notifications[0], verbose=True)

        self.assertIn("Type:", result)

    def test_format_config(self):
        """Test formatting notification configuration."""
        config = NotificationConfig()
        result = _format_config(config)

        self.assertIn("Notification Configuration:", result)
        self.assertIn("Notify on scan complete:", result)
        self.assertIn("Min severity for new:", result)


class TestCreateTestNotification(unittest.TestCase):
    """Tests for creating test notifications."""

    def test_create_scan_complete(self):
        """Test creating scan complete test notification."""
        notif = _create_test_notification('scan_complete')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.SCAN_COMPLETE)

    def test_create_scan_failed(self):
        """Test creating scan failed test notification."""
        notif = _create_test_notification('scan_failed')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.SCAN_FAILED)

    def test_create_new_findings(self):
        """Test creating new findings test notification."""
        notif = _create_test_notification('new_findings')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.NEW_FINDINGS)

    def test_create_critical(self):
        """Test creating critical finding test notification."""
        notif = _create_test_notification('critical')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.CRITICAL_FINDING)

    def test_create_resolved(self):
        """Test creating resolved findings test notification."""
        notif = _create_test_notification('resolved')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.FINDINGS_RESOLVED)

    def test_create_trend_alert(self):
        """Test creating trend alert test notification."""
        notif = _create_test_notification('trend_alert')
        self.assertIsNotNone(notif)
        self.assertEqual(notif.notification_type, NotificationType.TREND_ALERT)

    def test_create_unknown_type(self):
        """Test creating notification with unknown type."""
        notif = _create_test_notification('unknown')
        self.assertIsNone(notif)


class TestGetDemoNotifications(unittest.TestCase):
    """Tests for getting demo notifications."""

    def test_get_demo_notifications(self):
        """Test getting demo notifications."""
        notifications = _get_demo_notifications()

        self.assertIsInstance(notifications, list)
        self.assertEqual(len(notifications), 5)

        # Check types
        types = [n.notification_type for n in notifications]
        self.assertIn(NotificationType.SCAN_COMPLETE, types)
        self.assertIn(NotificationType.CRITICAL_FINDING, types)
        self.assertIn(NotificationType.NEW_FINDINGS, types)
        self.assertIn(NotificationType.TREND_ALERT, types)
        self.assertIn(NotificationType.SCAN_FAILED, types)


class TestAddNotificationsParser(unittest.TestCase):
    """Tests for the notifications parser setup."""

    def test_add_parser(self):
        """Test adding notifications parser to argparse."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_notifications_parser(subparsers)

        # Parse a test command
        args = parser.parse_args(['notifications', 'list', '--demo'])
        self.assertEqual(args.notifications_action, 'list')
        self.assertTrue(args.demo)

    def test_parser_all_commands(self):
        """Test that all commands are registered."""
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        add_notifications_parser(subparsers)

        commands = [
            ['notifications', 'list'],
            ['notifications', 'show'],
            ['notifications', 'types'],
            ['notifications', 'config'],
            ['notifications', 'status'],
        ]

        for cmd in commands:
            args = parser.parse_args(cmd)
            self.assertEqual(args.notifications_action, cmd[1])


class TestGetNotificationHandler(unittest.TestCase):
    """Tests for getting the notification handler."""

    def test_get_handler_singleton(self):
        """Test that handler is singleton."""
        handler1 = get_notification_handler()
        handler2 = get_notification_handler()

        self.assertIs(handler1, handler2)

    def test_handler_type(self):
        """Test that handler is correct type."""
        handler = get_notification_handler()
        self.assertIsInstance(handler, NotificationHandler)


if __name__ == '__main__':
    unittest.main()
