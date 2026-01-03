"""
Unit tests for the Mantissa Stance automation module.

Tests notification handling, scheduler integration, and alert routing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.automation import (
    NotificationHandler,
    NotificationConfig,
    NotificationType,
    ScanNotification,
    ScanSummaryNotification,
    FindingNotification,
    TrendNotification,
)
from stance.models.finding import Finding, FindingCollection, FindingStatus, FindingType, Severity
from stance.scheduling import ScanResult, ScanComparison, ScanDiff, DiffType


class TestNotificationConfig:
    """Tests for NotificationConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = NotificationConfig()

        assert config.notify_on_scan_complete is True
        assert config.notify_on_scan_failure is True
        assert config.notify_on_new_findings is True
        assert config.notify_on_critical is True
        assert config.notify_on_resolved is False
        assert config.min_severity_for_new == Severity.HIGH
        assert config.critical_threshold == 1

    def test_custom_config(self):
        """Test custom configuration values."""
        config = NotificationConfig(
            notify_on_scan_complete=False,
            notify_on_resolved=True,
            min_severity_for_new=Severity.MEDIUM,
            critical_threshold=3,
            trend_threshold_percent=15.0,
        )

        assert config.notify_on_scan_complete is False
        assert config.notify_on_resolved is True
        assert config.min_severity_for_new == Severity.MEDIUM
        assert config.critical_threshold == 3
        assert config.trend_threshold_percent == 15.0

    def test_config_to_dict(self):
        """Test converting config to dictionary."""
        config = NotificationConfig(
            notify_on_critical=True,
            destinations=["slack", "email"],
        )

        result = config.to_dict()

        assert result["notify_on_critical"] is True
        assert result["destinations"] == ["slack", "email"]
        assert result["min_severity_for_new"] == "high"

    def test_config_from_dict(self):
        """Test creating config from dictionary."""
        data = {
            "notify_on_scan_complete": False,
            "min_severity_for_new": "medium",
            "critical_threshold": 5,
        }

        config = NotificationConfig.from_dict(data)

        assert config.notify_on_scan_complete is False
        assert config.min_severity_for_new == Severity.MEDIUM
        assert config.critical_threshold == 5


class TestScanNotification:
    """Tests for ScanNotification dataclass."""

    def test_create_notification(self):
        """Test creating a scan notification."""
        notification = ScanNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
            scan_id="scan-123",
            job_name="daily-scan",
            message="Scan completed",
        )

        assert notification.notification_type == NotificationType.SCAN_COMPLETE
        assert notification.scan_id == "scan-123"
        assert notification.job_name == "daily-scan"

    def test_notification_to_dict(self):
        """Test converting notification to dictionary."""
        notification = ScanNotification(
            notification_type=NotificationType.SCAN_FAILED,
            timestamp=datetime(2025, 1, 1, 12, 0, 0),
            scan_id="scan-456",
            message="Scan failed",
        )

        result = notification.to_dict()

        assert result["notification_type"] == "scan_failed"
        assert result["scan_id"] == "scan-456"
        assert "timestamp" in result


class TestScanSummaryNotification:
    """Tests for ScanSummaryNotification dataclass."""

    def test_create_summary_notification(self):
        """Test creating a summary notification."""
        notification = ScanSummaryNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=datetime.utcnow(),
            scan_id="scan-789",
            success=True,
            duration_seconds=120.5,
            assets_scanned=100,
            findings_total=25,
            findings_by_severity={"critical": 2, "high": 5, "medium": 18},
        )

        assert notification.success is True
        assert notification.duration_seconds == 120.5
        assert notification.assets_scanned == 100
        assert notification.findings_total == 25

    def test_summary_notification_to_dict(self):
        """Test converting summary notification to dictionary."""
        notification = ScanSummaryNotification(
            notification_type=NotificationType.SCAN_COMPLETE,
            timestamp=datetime.utcnow(),
            scan_id="scan-abc",
            success=True,
            findings_total=10,
        )

        result = notification.to_dict()

        assert result["success"] is True
        assert result["findings_total"] == 10
        assert "duration_seconds" in result


class TestFindingNotification:
    """Tests for FindingNotification dataclass."""

    def test_create_finding_notification(self):
        """Test creating a finding notification."""
        findings = [
            Finding(
                id="finding-1",
                asset_id="asset-1",
                finding_type=FindingType.MISCONFIGURATION,
                title="Test Finding",
                description="Test description",
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
            )
        ]

        notification = FindingNotification(
            notification_type=NotificationType.NEW_FINDINGS,
            timestamp=datetime.utcnow(),
            scan_id="scan-def",
            findings=findings,
            is_new=True,
        )

        assert notification.is_new is True
        assert len(notification.findings) == 1

    def test_finding_notification_to_dict(self):
        """Test converting finding notification to dictionary."""
        findings = [
            Finding(
                id="finding-2",
                asset_id="asset-2",
                finding_type=FindingType.VULNERABILITY,
                title="Vuln Finding",
                description="Vuln description",
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
            )
        ]

        notification = FindingNotification(
            notification_type=NotificationType.CRITICAL_FINDING,
            timestamp=datetime.utcnow(),
            scan_id="scan-ghi",
            findings=findings,
        )

        result = notification.to_dict()

        assert result["findings_count"] == 1
        assert "finding-2" in result["finding_ids"]


class TestTrendNotification:
    """Tests for TrendNotification dataclass."""

    def test_create_trend_notification(self):
        """Test creating a trend notification."""
        notification = TrendNotification(
            notification_type=NotificationType.TREND_ALERT,
            timestamp=datetime.utcnow(),
            scan_id="scan-jkl",
            direction="improving",
            change_percent=-15.5,
            current_findings=85,
            previous_findings=100,
            period_days=7,
        )

        assert notification.direction == "improving"
        assert notification.change_percent == -15.5
        assert notification.current_findings == 85

    def test_trend_notification_to_dict(self):
        """Test converting trend notification to dictionary."""
        notification = TrendNotification(
            notification_type=NotificationType.TREND_ALERT,
            timestamp=datetime.utcnow(),
            scan_id="scan-mno",
            direction="declining",
            change_percent=20.0,
            current_findings=120,
            previous_findings=100,
        )

        result = notification.to_dict()

        assert result["direction"] == "declining"
        assert result["change_percent"] == 20.0
        assert result["period_days"] == 7  # default


class TestNotificationHandler:
    """Tests for NotificationHandler class."""

    @pytest.fixture
    def handler(self):
        """Create a notification handler for testing."""
        return NotificationHandler()

    @pytest.fixture
    def configured_handler(self):
        """Create a configured notification handler."""
        config = NotificationConfig(
            notify_on_scan_complete=True,
            notify_on_critical=True,
            min_severity_for_new=Severity.HIGH,
        )
        return NotificationHandler(config=config)

    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample scan result."""
        return ScanResult(
            job_id="job-123",
            scan_id="scan-123",
            started_at=datetime.utcnow() - timedelta(minutes=5),
            completed_at=datetime.utcnow(),
            success=True,
            assets_scanned=100,
            findings_count=25,
        )

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            Finding(
                id=f"finding-{i}",
                asset_id=f"asset-{i}",
                finding_type=FindingType.MISCONFIGURATION,
                title=f"Finding {i}",
                description=f"Description {i}",
                severity=Severity.CRITICAL if i == 0 else Severity.HIGH,
                status=FindingStatus.OPEN,
            )
            for i in range(3)
        ]

    def test_handler_initialization(self, handler):
        """Test handler initialization."""
        assert handler.config is not None
        assert handler.config.notify_on_scan_complete is True

    def test_configure(self, handler):
        """Test updating handler configuration."""
        new_config = NotificationConfig(
            notify_on_scan_complete=False,
            critical_threshold=5,
        )

        handler.configure(new_config)

        assert handler.config.notify_on_scan_complete is False
        assert handler.config.critical_threshold == 5

    def test_add_callback(self, handler):
        """Test adding notification callbacks."""
        callback_called = []

        def test_callback(notification):
            callback_called.append(notification)

        handler.add_callback(test_callback)

        # Trigger a notification
        result = ScanResult(
            job_id="job-1",
            scan_id="scan-1",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
            assets_scanned=10,
            findings_count=5,
        )
        handler.on_scan_complete(result)

        assert len(callback_called) == 1
        assert callback_called[0].notification_type == NotificationType.SCAN_COMPLETE

    def test_on_scan_complete_success(self, handler, sample_scan_result):
        """Test handling successful scan completion."""
        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_scan_complete(sample_scan_result)

        assert len(notifications) == 1
        assert notifications[0].notification_type == NotificationType.SCAN_COMPLETE

    def test_on_scan_complete_failure(self, handler):
        """Test handling failed scan completion."""
        failed_result = ScanResult(
            job_id="job-fail",
            scan_id="scan-fail",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=False,
            error="Connection timeout",
        )

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_scan_complete(failed_result)

        assert len(notifications) == 1
        assert notifications[0].notification_type == NotificationType.SCAN_FAILED

    def test_on_scan_complete_disabled(self, handler, sample_scan_result):
        """Test that disabled notifications are not sent."""
        handler.configure(NotificationConfig(
            notify_on_scan_complete=False,
        ))

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_scan_complete(sample_scan_result)

        assert len(notifications) == 0

    def test_on_findings_detected_new_findings(self, handler, sample_findings):
        """Test handling new findings detection."""
        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
            current_timestamp=datetime.utcnow(),
            new_findings=[
                ScanDiff(
                    finding_id=f.id,
                    diff_type=DiffType.NEW,
                    finding=f,
                )
                for f in sample_findings
            ],
        )

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_findings_detected(
            scan_id="scan-new",
            findings=FindingCollection(findings=sample_findings),
            comparison=comparison,
        )

        # Should get NEW_FINDINGS and CRITICAL_FINDING notifications
        assert len(notifications) >= 1
        types = [n.notification_type for n in notifications]
        assert NotificationType.NEW_FINDINGS in types

    def test_on_findings_detected_critical(self, handler, sample_findings):
        """Test handling critical findings."""
        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        # Ensure handler is configured for critical notifications
        handler.configure(NotificationConfig(
            notify_on_critical=True,
            critical_threshold=1,
        ))

        handler.on_findings_detected(
            scan_id="scan-critical",
            findings=FindingCollection(findings=sample_findings),
        )

        # Should get critical finding notification
        assert len(notifications) >= 1
        types = [n.notification_type for n in notifications]
        assert NotificationType.CRITICAL_FINDING in types

    def test_on_findings_detected_resolved(self, handler, sample_findings):
        """Test handling resolved findings."""
        handler.configure(NotificationConfig(
            notify_on_resolved=True,
        ))

        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
            current_timestamp=datetime.utcnow(),
            resolved_findings=[
                ScanDiff(
                    finding_id=f.id,
                    diff_type=DiffType.RESOLVED,
                    finding=f,
                )
                for f in sample_findings
            ],
        )

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_findings_detected(
            scan_id="scan-resolved",
            findings=FindingCollection(findings=[]),
            comparison=comparison,
        )

        types = [n.notification_type for n in notifications]
        assert NotificationType.FINDINGS_RESOLVED in types

    def test_on_trend_change_improving(self, handler):
        """Test handling improving trend."""
        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_trend_change(
            scan_id="scan-trend",
            direction="improving",
            change_percent=-20.0,
            current_findings=80,
            previous_findings=100,
        )

        assert len(notifications) == 1
        assert notifications[0].notification_type == NotificationType.TREND_ALERT
        assert notifications[0].direction == "improving"

    def test_on_trend_change_declining(self, handler):
        """Test handling declining trend."""
        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_trend_change(
            scan_id="scan-trend-bad",
            direction="declining",
            change_percent=25.0,
            current_findings=125,
            previous_findings=100,
        )

        assert len(notifications) == 1
        assert notifications[0].direction == "declining"

    def test_on_trend_change_below_threshold(self, handler):
        """Test that small changes don't trigger alerts."""
        handler.configure(NotificationConfig(
            trend_threshold_percent=10.0,
        ))

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_trend_change(
            scan_id="scan-small-change",
            direction="improving",
            change_percent=-5.0,  # Below threshold
            current_findings=95,
            previous_findings=100,
        )

        assert len(notifications) == 0

    def test_get_history(self, handler, sample_scan_result):
        """Test retrieving notification history."""
        handler.on_scan_complete(sample_scan_result)
        handler.on_scan_complete(sample_scan_result)

        history = handler.get_history()

        assert len(history) == 2

    def test_get_history_with_limit(self, handler, sample_scan_result):
        """Test retrieving limited history."""
        for _ in range(5):
            handler.on_scan_complete(sample_scan_result)

        history = handler.get_history(limit=3)

        assert len(history) == 3

    def test_get_history_by_type(self, handler):
        """Test filtering history by notification type."""
        success_result = ScanResult(
            job_id="job-success",
            scan_id="scan-success",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
            assets_scanned=10,
            findings_count=5,
        )

        failed_result = ScanResult(
            job_id="job-fail",
            scan_id="scan-fail",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=False,
            error="Error",
        )

        handler.on_scan_complete(success_result)
        handler.on_scan_complete(failed_result)

        complete_only = handler.get_history(
            notification_type=NotificationType.SCAN_COMPLETE
        )
        failed_only = handler.get_history(
            notification_type=NotificationType.SCAN_FAILED
        )

        assert len(complete_only) == 1
        assert len(failed_only) == 1

    def test_clear_history(self, handler, sample_scan_result):
        """Test clearing notification history."""
        handler.on_scan_complete(sample_scan_result)
        assert len(handler.get_history()) == 1

        handler.clear_history()

        assert len(handler.get_history()) == 0

    def test_severity_threshold_filtering(self, handler):
        """Test that findings are filtered by severity threshold."""
        handler.configure(NotificationConfig(
            min_severity_for_new=Severity.HIGH,
        ))

        # Create findings with various severities
        findings = [
            Finding(
                id="critical-1",
                asset_id="asset-1",
                finding_type=FindingType.MISCONFIGURATION,
                title="Critical",
                description="Critical issue",
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
            ),
            Finding(
                id="low-1",
                asset_id="asset-2",
                finding_type=FindingType.MISCONFIGURATION,
                title="Low",
                description="Low issue",
                severity=Severity.LOW,
                status=FindingStatus.OPEN,
            ),
        ]

        comparison = ScanComparison(
            baseline_scan_id="baseline",
            current_scan_id="current",
            baseline_timestamp=datetime.utcnow() - timedelta(days=1),
            current_timestamp=datetime.utcnow(),
            new_findings=[
                ScanDiff(
                    finding_id=f.id,
                    diff_type=DiffType.NEW,
                    finding=f,
                )
                for f in findings
            ],
        )

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        handler.on_findings_detected(
            scan_id="scan-filtered",
            findings=FindingCollection(findings=findings),
            comparison=comparison,
        )

        # Should only include critical finding in new findings notification
        new_findings_notif = next(
            (n for n in notifications if n.notification_type == NotificationType.NEW_FINDINGS),
            None
        )
        assert new_findings_notif is not None
        assert len(new_findings_notif.findings) == 1
        assert new_findings_notif.findings[0].severity == Severity.CRITICAL


class TestNotificationHandlerWithRouter:
    """Tests for NotificationHandler with AlertRouter integration."""

    def test_set_router(self):
        """Test setting the alert router."""
        handler = NotificationHandler()
        mock_router = MagicMock()

        handler.set_router(mock_router)

        assert handler._router is mock_router

    def test_critical_findings_routed(self):
        """Test that critical findings are routed through the router."""
        mock_router = MagicMock()
        handler = NotificationHandler(
            router=mock_router,
            config=NotificationConfig(
                notify_on_critical=True,
                include_details=True,
            ),
        )

        findings = [
            Finding(
                id="critical-routed",
                asset_id="asset-routed",
                finding_type=FindingType.MISCONFIGURATION,
                title="Critical Issue",
                description="Description",
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
            )
        ]

        handler.on_findings_detected(
            scan_id="scan-route",
            findings=FindingCollection(findings=findings),
        )

        # Router should have been called
        assert mock_router.route.called


class TestCreateSchedulerCallback:
    """Tests for create_scheduler_callback function."""

    def test_create_callback(self):
        """Test creating a scheduler callback."""
        from stance.automation.notification_handler import create_scheduler_callback

        handler = NotificationHandler()
        callback = create_scheduler_callback(handler)

        assert callable(callback)

    def test_callback_invokes_handler(self):
        """Test that callback invokes the handler."""
        from stance.automation.notification_handler import create_scheduler_callback

        handler = NotificationHandler()
        callback = create_scheduler_callback(handler)

        notifications = []
        handler.add_callback(lambda n: notifications.append(n))

        result = ScanResult(
            job_id="job-cb",
            scan_id="scan-cb",
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            success=True,
            assets_scanned=50,
            findings_count=10,
        )

        callback(result)

        assert len(notifications) == 1
