"""
Integration tests for alert routing workflow.

Tests cover:
- Alert router configuration
- Routing findings to destinations
- Alert deduplication
- Severity-based routing
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import json

import pytest

from stance.models import (
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
)
from stance.alerting import (
    AlertRouter,
    AlertState,
    RoutingRule,
    SuppressionRule,
)
from stance.alerting.destinations import (
    BaseDestination,
    SlackDestination,
    PagerDutyDestination,
    EmailDestination,
    WebhookDestination,
    create_destination,
)


@pytest.fixture
def sample_critical_finding() -> Finding:
    """Create a critical severity finding."""
    return Finding(
        id="finding-critical-001",
        asset_id="arn:aws:s3:::exposed-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="S3 Bucket Publicly Accessible",
        description="The S3 bucket is configured to allow public access.",
        rule_id="aws-s3-public-access",
        compliance_frameworks=["CIS 2.1.5", "PCI-DSS 1.3"],
        remediation_guidance="Enable S3 Block Public Access on the bucket.",
        first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )


@pytest.fixture
def sample_high_finding() -> Finding:
    """Create a high severity finding."""
    return Finding(
        id="finding-high-001",
        asset_id="arn:aws:s3:::unencrypted-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="S3 Bucket Encryption Disabled",
        description="The S3 bucket does not have encryption enabled.",
        rule_id="aws-s3-encryption",
        compliance_frameworks=["CIS 2.1.1"],
        remediation_guidance="Enable default encryption on the bucket.",
        first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )


@pytest.fixture
def sample_vulnerability_finding() -> Finding:
    """Create a vulnerability finding."""
    return Finding(
        id="finding-vuln-001",
        asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
        finding_type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="Critical Vulnerability in OpenSSL",
        description="A critical vulnerability was found in OpenSSL.",
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        package_name="openssl",
        installed_version="1.0.2k",
        fixed_version="1.0.2u",
        remediation_guidance="Upgrade OpenSSL to version 1.0.2u or later.",
        first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
    )


class TestDestinationCreation:
    """Test destination creation and configuration."""

    def test_create_slack_destination(self):
        """Test creating Slack destination."""
        config = {
            "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ",
            "channel": "#security-alerts",
        }
        dest = create_destination("slack", "slack-main", config)

        assert isinstance(dest, SlackDestination)
        assert dest.name == "slack-main"

    def test_create_pagerduty_destination(self):
        """Test creating PagerDuty destination."""
        config = {
            "routing_key": "a" * 32,
            "service_name": "Stance",
        }
        dest = create_destination("pagerduty", "pd-main", config)

        assert isinstance(dest, PagerDutyDestination)
        assert dest.name == "pd-main"

    def test_create_email_destination(self):
        """Test creating email destination."""
        config = {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "from_address": "alerts@example.com",
            "to_addresses": ["security@example.com"],
        }
        dest = create_destination("email", "email-main", config)

        assert isinstance(dest, EmailDestination)

    def test_create_webhook_destination(self):
        """Test creating generic webhook destination."""
        config = {
            "url": "https://api.example.com/alerts",
            "method": "POST",
        }
        dest = create_destination("webhook", "webhook-main", config)

        assert isinstance(dest, WebhookDestination)

    def test_unknown_destination_raises(self):
        """Test that unknown destination type raises error."""
        with pytest.raises(ValueError):
            create_destination("unknown", "test", {})


class TestAlertRouting:
    """Test alert routing logic."""

    def test_router_routes_to_destination(self, sample_critical_finding):
        """Test router sends alerts to configured destinations."""
        mock_dest = MagicMock(spec=BaseDestination)
        mock_dest.name = "test-dest"
        mock_dest.send.return_value = True

        # AlertRouter uses add_destination and add_routing_rule methods
        router = AlertRouter(dedup_window_hours=24)
        router.add_destination(mock_dest)
        router.add_routing_rule(
            RoutingRule(
                name="all-findings",
                destinations=["test-dest"],
            )
        )

        result = router.route(sample_critical_finding)

        assert result.successful_destinations >= 1
        mock_dest.send.assert_called_once()

    def test_severity_based_routing(self, sample_critical_finding, sample_high_finding):
        """Test routing based on severity."""
        critical_dest = MagicMock(spec=BaseDestination)
        critical_dest.name = "critical-dest"
        critical_dest.send.return_value = True

        normal_dest = MagicMock(spec=BaseDestination)
        normal_dest.name = "normal-dest"
        normal_dest.send.return_value = True

        # Build router with individual method calls
        router = AlertRouter(dedup_window_hours=24)
        router.add_destination(critical_dest)
        router.add_destination(normal_dest)
        router.add_routing_rule(
            RoutingRule(
                name="critical-only",
                destinations=["critical-dest"],
                severities=[Severity.CRITICAL],
            )
        )
        router.add_routing_rule(
            RoutingRule(
                name="all-findings",
                destinations=["normal-dest"],
            )
        )

        # Route critical finding
        router.route(sample_critical_finding)

        # Critical should go to both destinations
        assert critical_dest.send.called
        assert normal_dest.send.called

        # Reset mocks
        critical_dest.reset_mock()
        normal_dest.reset_mock()

        # Route high finding
        router.route(sample_high_finding)

        # High should only go to normal destination
        assert not critical_dest.send.called
        assert normal_dest.send.called


class TestAlertDeduplication:
    """Test alert deduplication."""

    def test_duplicate_alerts_suppressed(self, sample_critical_finding):
        """Test that duplicate alerts are suppressed."""
        mock_dest = MagicMock(spec=BaseDestination)
        mock_dest.name = "test-dest"
        mock_dest.send.return_value = True

        # Build router with dedup window
        router = AlertRouter(dedup_window_hours=1)
        router.add_destination(mock_dest)
        router.add_routing_rule(
            RoutingRule(
                name="all-findings",
                destinations=["test-dest"],
            )
        )

        # First alert should be sent
        result1 = router.route(sample_critical_finding)
        assert result1.successful_destinations >= 1
        assert mock_dest.send.call_count == 1

        # Second alert for same finding should be deduplicated
        result2 = router.route(sample_critical_finding)
        # Depending on implementation, may still return True but not send
        assert mock_dest.send.call_count == 1  # Still only one call


class TestSuppressionRules:
    """Test alert suppression."""

    def test_suppressed_finding_not_routed(self, sample_critical_finding):
        """Test that suppressed findings are not routed."""
        mock_dest = MagicMock(spec=BaseDestination)
        mock_dest.name = "test-dest"
        mock_dest.send.return_value = True

        # Build router with suppression rule
        router = AlertRouter(dedup_window_hours=24)
        router.add_destination(mock_dest)
        router.add_routing_rule(
            RoutingRule(
                name="all-findings",
                destinations=["test-dest"],
            )
        )
        router.add_suppression_rule(
            SuppressionRule(
                name="suppress-rule",
                rule_ids=["aws-s3-public-access"],
            )
        )

        result = router.route(sample_critical_finding)

        # Finding should be suppressed
        assert mock_dest.send.call_count == 0


class TestSlackIntegration:
    """Test Slack webhook integration."""

    @patch("urllib.request.urlopen")
    def test_slack_sends_formatted_message(self, mock_urlopen, sample_critical_finding):
        """Test Slack destination sends properly formatted message."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = SlackDestination(
            name="slack-test",
            config={"webhook_url": "https://hooks.slack.com/test"},
        )

        result = dest.send(sample_critical_finding, {})

        assert result is True
        assert mock_urlopen.called

        # Verify the payload was properly formatted
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        payload = json.loads(request.data.decode("utf-8"))

        assert "blocks" in payload
        assert len(payload["blocks"]) > 0


class TestPagerDutyIntegration:
    """Test PagerDuty integration."""

    @patch("urllib.request.urlopen")
    def test_pagerduty_sends_event(self, mock_urlopen, sample_critical_finding):
        """Test PagerDuty destination sends event."""
        mock_response = MagicMock()
        mock_response.status = 202
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = PagerDutyDestination(
            name="pd-test",
            config={"routing_key": "a" * 32},
        )

        result = dest.send(sample_critical_finding, {})

        assert result is True
        assert mock_urlopen.called

        # Verify PagerDuty payload
        call_args = mock_urlopen.call_args
        request = call_args[0][0]
        payload = json.loads(request.data.decode("utf-8"))

        assert payload["routing_key"] == "a" * 32
        assert payload["event_action"] == "trigger"
        assert "payload" in payload
        assert payload["payload"]["severity"] == "critical"


class TestWebhookIntegration:
    """Test generic webhook integration."""

    @patch("urllib.request.urlopen")
    def test_webhook_sends_payload(self, mock_urlopen, sample_critical_finding):
        """Test webhook destination sends payload."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = WebhookDestination(
            name="webhook-test",
            config={
                "url": "https://api.example.com/alerts",
                "method": "POST",
            },
        )

        result = dest.send(sample_critical_finding, {"extra": "data"})

        assert result is True
        assert mock_urlopen.called


class TestAlertState:
    """Test alert state management."""

    def test_alert_state_tracks_sent_alerts(self, sample_critical_finding):
        """Test alert state tracks sent alerts."""
        state = AlertState()

        # Record alert using record_sent method
        record = state.record_sent(
            finding_id=sample_critical_finding.id,
            destination="slack",
            dedup_key=f"{sample_critical_finding.id}|slack",
        )

        # Check if recorded - use get_alerts_for_finding
        alerts = state.get_alerts_for_finding(sample_critical_finding.id)
        assert len(alerts) == 1
        assert alerts[0].destination == "slack"

    def test_alert_state_deduplication(self, sample_critical_finding):
        """Test alert state deduplication check."""
        from datetime import timedelta

        state = AlertState(dedup_window=timedelta(hours=1))

        # Create a dedup key
        dedup_key = f"{sample_critical_finding.id}|slack"

        # First, should not be a duplicate
        assert not state.is_duplicate(dedup_key)

        # Record the alert
        state.record_sent(
            finding_id=sample_critical_finding.id,
            destination="slack",
            dedup_key=dedup_key,
        )

        # Now it should be a duplicate within the window
        assert state.is_duplicate(dedup_key)
