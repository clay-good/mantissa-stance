"""
Tests for Mantissa Stance alerting module.

Tests cover:
- Alert router functionality
- Routing and suppression rules
- Alert destinations
- Alert state management
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    Finding,
    FindingType,
    Severity,
    FindingStatus,
)
from stance.alerting import (
    # Router
    AlertRouter,
    RoutingRule,
    SuppressionRule,
    RateLimit,
    AlertResult,
    RoutingResult,
    # Config
    AlertConfig,
    DestinationConfig,
    create_default_config,
    # State
    AlertRecord,
    AlertStateBackend,
    InMemoryAlertState,
    # Destinations
    BaseDestination,
    SlackDestination,
    PagerDutyDestination,
    EmailDestination,
    WebhookDestination,
    TeamsDestination,
    JiraDestination,
    create_destination,
)


# Fixtures

@pytest.fixture
def sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        id="finding-001",
        asset_id="arn:aws:s3:::test-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="S3 bucket encryption disabled",
        description="The S3 bucket does not have encryption enabled.",
        rule_id="aws-s3-001",
        first_seen=datetime(2024, 1, 10, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        remediation_guidance="Enable server-side encryption.",
    )


@pytest.fixture
def critical_finding() -> Finding:
    """Create a critical finding for testing."""
    return Finding(
        id="finding-002",
        asset_id="arn:aws:s3:::public-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="S3 bucket publicly accessible",
        description="The S3 bucket is publicly accessible.",
        rule_id="aws-s3-002",
    )


@pytest.fixture
def vulnerability_finding() -> Finding:
    """Create a vulnerability finding for testing."""
    return Finding(
        id="vuln-001",
        asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-123",
        finding_type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="Critical CVE detected",
        description="Critical vulnerability in package xyz.",
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        package_name="xyz-package",
        installed_version="1.0.0",
        fixed_version="1.0.1",
    )


class TestRoutingRule:
    """Tests for RoutingRule dataclass."""

    def test_routing_rule_creation(self):
        """Test RoutingRule creation with defaults."""
        rule = RoutingRule(
            name="critical-alerts",
            destinations=["slack", "pagerduty"],
        )

        assert rule.name == "critical-alerts"
        assert rule.destinations == ["slack", "pagerduty"]
        assert rule.severities == []
        assert rule.enabled is True
        assert rule.priority == 100

    def test_routing_rule_with_severities(self):
        """Test RoutingRule with severity filter."""
        rule = RoutingRule(
            name="high-severity",
            destinations=["slack"],
            severities=[Severity.CRITICAL, Severity.HIGH],
        )

        assert rule.severities == [Severity.CRITICAL, Severity.HIGH]

    def test_routing_rule_with_finding_types(self):
        """Test RoutingRule with finding type filter."""
        rule = RoutingRule(
            name="vulns-only",
            destinations=["pagerduty"],
            finding_types=["vulnerability"],
        )

        assert rule.finding_types == ["vulnerability"]


class TestSuppressionRule:
    """Tests for SuppressionRule dataclass."""

    def test_suppression_rule_creation(self):
        """Test SuppressionRule creation."""
        rule = SuppressionRule(
            name="suppress-dev",
            rule_ids=["aws-s3-001"],
            reason="Dev environment exception",
        )

        assert rule.name == "suppress-dev"
        assert rule.rule_ids == ["aws-s3-001"]
        assert rule.reason == "Dev environment exception"
        assert rule.enabled is True

    def test_suppression_rule_with_expiry(self):
        """Test SuppressionRule with expiration."""
        expires = datetime(2024, 12, 31, tzinfo=timezone.utc)
        rule = SuppressionRule(
            name="temp-suppression",
            rule_ids=["aws-s3-002"],
            expires_at=expires,
        )

        assert rule.expires_at == expires


class TestRateLimit:
    """Tests for RateLimit dataclass."""

    def test_rate_limit_defaults(self):
        """Test RateLimit default values."""
        limit = RateLimit()

        assert limit.max_alerts == 100
        assert limit.window_seconds == 3600
        assert limit.burst_limit == 10

    def test_rate_limit_custom(self):
        """Test RateLimit custom values."""
        limit = RateLimit(
            max_alerts=50,
            window_seconds=1800,
            burst_limit=5,
        )

        assert limit.max_alerts == 50
        assert limit.window_seconds == 1800
        assert limit.burst_limit == 5


class TestAlertResult:
    """Tests for AlertResult dataclass."""

    def test_alert_result_success(self):
        """Test AlertResult for successful send."""
        result = AlertResult(
            finding_id="finding-001",
            destination="slack",
            success=True,
        )

        assert result.success is True
        assert result.error == ""

    def test_alert_result_failure(self):
        """Test AlertResult for failed send."""
        result = AlertResult(
            finding_id="finding-001",
            destination="slack",
            success=False,
            error="Connection timeout",
        )

        assert result.success is False
        assert result.error == "Connection timeout"

    def test_alert_result_deduplicated(self):
        """Test AlertResult with deduplication flag."""
        result = AlertResult(
            finding_id="finding-001",
            destination="slack",
            deduplicated=True,
        )

        assert result.deduplicated is True

    def test_alert_result_suppressed(self):
        """Test AlertResult with suppression flag."""
        result = AlertResult(
            finding_id="finding-001",
            destination="slack",
            suppressed=True,
        )

        assert result.suppressed is True


class TestRoutingResult:
    """Tests for RoutingResult dataclass."""

    def test_routing_result_creation(self):
        """Test RoutingResult creation."""
        result = RoutingResult(finding_id="finding-001")

        assert result.finding_id == "finding-001"
        assert result.results == []
        assert result.matched_rules == []
        assert result.total_destinations == 0
        assert result.successful_destinations == 0

    def test_routing_result_with_results(self):
        """Test RoutingResult with alert results."""
        alert_result = AlertResult(
            finding_id="finding-001",
            destination="slack",
            success=True,
        )
        result = RoutingResult(
            finding_id="finding-001",
            results=[alert_result],
            matched_rules=["rule-1"],
            total_destinations=1,
            successful_destinations=1,
        )

        assert len(result.results) == 1
        assert result.matched_rules == ["rule-1"]
        assert result.total_destinations == 1
        assert result.successful_destinations == 1


class TestAlertRecord:
    """Tests for AlertRecord dataclass."""

    def test_alert_record_creation(self):
        """Test AlertRecord creation."""
        record = AlertRecord(
            id=str(uuid.uuid4()),
            finding_id="finding-001",
            destination="slack",
            sent_at=datetime.now(timezone.utc),
        )

        assert record.finding_id == "finding-001"
        assert record.destination == "slack"
        assert record.status == "sent"

    def test_alert_record_to_dict(self):
        """Test AlertRecord serialization."""
        now = datetime.now(timezone.utc)
        record = AlertRecord(
            id="alert-001",
            finding_id="finding-001",
            destination="slack",
            sent_at=now,
            dedup_key="test-key",
        )

        data = record.to_dict()

        assert data["id"] == "alert-001"
        assert data["finding_id"] == "finding-001"
        assert data["destination"] == "slack"
        assert data["dedup_key"] == "test-key"

    def test_alert_record_from_dict(self):
        """Test AlertRecord deserialization."""
        now = datetime.now(timezone.utc)
        data = {
            "id": "alert-001",
            "finding_id": "finding-001",
            "destination": "slack",
            "sent_at": now.isoformat(),
            "status": "sent",
        }

        record = AlertRecord.from_dict(data)

        assert record.id == "alert-001"
        assert record.finding_id == "finding-001"
        assert record.status == "sent"


class TestInMemoryAlertState:
    """Tests for InMemoryAlertState."""

    @pytest.fixture
    def state(self):
        """Create InMemoryAlertState instance."""
        return InMemoryAlertState()

    def test_record_alert(self, state, sample_finding):
        """Test recording an alert."""
        record = AlertRecord(
            id=str(uuid.uuid4()),
            finding_id=sample_finding.id,
            destination="slack",
            sent_at=datetime.now(timezone.utc),
            dedup_key=f"{sample_finding.id}:slack",
        )

        state.record_alert(record)

        # Should be able to retrieve it
        alerts = state.get_alerts_for_finding(sample_finding.id)
        assert len(alerts) >= 1

    def test_check_dedup(self, state, sample_finding):
        """Test deduplication check."""
        dedup_key = f"{sample_finding.id}:slack"

        # Initially not a duplicate
        assert not state.check_dedup(dedup_key, timedelta(hours=1))

        # Record the alert - use naive datetime to match check_dedup implementation
        record = AlertRecord(
            id=str(uuid.uuid4()),
            finding_id=sample_finding.id,
            destination="slack",
            sent_at=datetime.utcnow(),
            dedup_key=dedup_key,
        )
        state.record_alert(record)

        # Now should be a duplicate
        assert state.check_dedup(dedup_key, timedelta(hours=1))


class TestAlertConfig:
    """Tests for AlertConfig."""

    def test_create_default_config(self):
        """Test creating default config."""
        config = create_default_config()

        assert isinstance(config, AlertConfig)
        assert config.enabled is True
        assert config.dedup_window_hours == 24

    def test_destination_config(self):
        """Test DestinationConfig creation."""
        config = DestinationConfig(
            name="slack-alerts",
            type="slack",
            enabled=True,
            config={"webhook_url": "https://hooks.slack.com/test"},
        )

        assert config.name == "slack-alerts"
        assert config.type == "slack"
        assert config.enabled is True
        assert "webhook_url" in config.config

    def test_alert_config_to_dict(self):
        """Test AlertConfig serialization."""
        config = AlertConfig(
            enabled=True,
            dedup_window_hours=12,
        )

        data = config.to_dict()

        assert data["enabled"] is True
        assert data["dedup_window_hours"] == 12


class TestBaseDestination:
    """Tests for destination base functionality."""

    def test_format_title(self, sample_finding):
        """Test title formatting."""
        # Create a minimal concrete implementation for testing
        class TestDestination(BaseDestination):
            def send(self, finding, context):
                return True

            def test_connection(self):
                return True

        dest = TestDestination("test", {})
        title = dest.format_title(sample_finding)

        assert "[HIGH]" in title
        assert sample_finding.title in title

    def test_format_description(self, sample_finding):
        """Test description formatting."""
        class TestDestination(BaseDestination):
            def send(self, finding, context):
                return True

            def test_connection(self):
                return True

        dest = TestDestination("test", {})
        desc = dest.format_description(sample_finding)

        assert sample_finding.description in desc
        assert sample_finding.rule_id in desc

    def test_get_severity_color(self, sample_finding):
        """Test severity color mapping."""
        class TestDestination(BaseDestination):
            def send(self, finding, context):
                return True

            def test_connection(self):
                return True

        dest = TestDestination("test", {})

        # Test different severities
        assert dest.get_severity_color(Severity.CRITICAL) == "#FF0000"
        assert dest.get_severity_color(Severity.HIGH) == "#FF6600"
        assert dest.get_severity_color(Severity.MEDIUM) == "#FFCC00"
        assert dest.get_severity_color(Severity.LOW) == "#00CC00"
        assert dest.get_severity_color(Severity.INFO) == "#0066CC"


class TestSlackDestination:
    """Tests for SlackDestination."""

    def test_slack_destination_creation(self):
        """Test SlackDestination creation."""
        dest = SlackDestination(
            name="slack-alerts",
            config={"webhook_url": "https://hooks.slack.com/test"},
        )

        assert dest.name == "slack-alerts"

    def test_slack_destination_is_base_destination(self):
        """Test SlackDestination is BaseDestination."""
        dest = SlackDestination("test", {"webhook_url": "https://test"})
        assert isinstance(dest, BaseDestination)

    def test_slack_destination_has_required_methods(self):
        """Test SlackDestination has required methods."""
        dest = SlackDestination("test", {"webhook_url": "https://test"})

        assert hasattr(dest, "send")
        assert hasattr(dest, "test_connection")
        assert callable(dest.send)
        assert callable(dest.test_connection)


class TestPagerDutyDestination:
    """Tests for PagerDutyDestination."""

    def test_pagerduty_destination_creation(self):
        """Test PagerDutyDestination creation."""
        dest = PagerDutyDestination(
            name="pagerduty-alerts",
            config={"routing_key": "test-key"},
        )

        assert dest.name == "pagerduty-alerts"

    def test_pagerduty_destination_is_base_destination(self):
        """Test PagerDutyDestination is BaseDestination."""
        dest = PagerDutyDestination("test", {"routing_key": "key"})
        assert isinstance(dest, BaseDestination)


class TestEmailDestination:
    """Tests for EmailDestination."""

    def test_email_destination_creation(self):
        """Test EmailDestination creation."""
        dest = EmailDestination(
            name="email-alerts",
            config={
                "smtp_host": "smtp.example.com",
                "smtp_port": 587,
                "from_address": "alerts@example.com",
                "to_addresses": ["security@example.com"],
            },
        )

        assert dest.name == "email-alerts"


class TestWebhookDestination:
    """Tests for WebhookDestination."""

    def test_webhook_destination_creation(self):
        """Test WebhookDestination creation."""
        dest = WebhookDestination(
            name="webhook-alerts",
            config={"url": "https://example.com/webhook"},
        )

        assert dest.name == "webhook-alerts"

    def test_webhook_destination_is_base_destination(self):
        """Test WebhookDestination is BaseDestination."""
        dest = WebhookDestination("test", {"url": "https://test"})
        assert isinstance(dest, BaseDestination)


class TestCreateDestination:
    """Tests for create_destination factory function."""

    def test_create_slack_destination(self):
        """Test creating Slack destination."""
        dest = create_destination(
            destination_type="slack",
            name="slack",
            config={"webhook_url": "https://hooks.slack.com/test"},
        )

        assert isinstance(dest, SlackDestination)

    def test_create_pagerduty_destination(self):
        """Test creating PagerDuty destination."""
        dest = create_destination(
            destination_type="pagerduty",
            name="pagerduty",
            config={"routing_key": "test-key"},
        )

        assert isinstance(dest, PagerDutyDestination)

    def test_create_webhook_destination(self):
        """Test creating Webhook destination."""
        dest = create_destination(
            destination_type="webhook",
            name="webhook",
            config={"url": "https://example.com/webhook"},
        )

        assert isinstance(dest, WebhookDestination)

    def test_create_unknown_destination_raises(self):
        """Test unknown destination type raises error."""
        with pytest.raises(ValueError):
            create_destination(
                destination_type="unknown",
                name="test",
                config={},
            )


class TestAlertRouter:
    """Tests for AlertRouter."""

    @pytest.fixture
    def mock_destination(self):
        """Create a mock destination."""
        dest = MagicMock()
        dest.name = "test-dest"
        dest.send.return_value = True
        dest.test_connection.return_value = True
        return dest

    @pytest.fixture
    def router(self):
        """Create AlertRouter."""
        return AlertRouter()

    def test_router_creation(self):
        """Test AlertRouter creation."""
        router = AlertRouter()
        assert router is not None

    def test_router_creation_with_options(self):
        """Test AlertRouter creation with options."""
        router = AlertRouter(
            dedup_window_hours=12,
            default_rate_limit=RateLimit(max_alerts=50),
        )
        assert router is not None

    def test_add_destination(self, router, mock_destination):
        """Test adding destination to router."""
        router.add_destination(mock_destination)

        # Should be able to remove it
        router.remove_destination("test-dest")

    def test_add_routing_rule(self, router):
        """Test adding routing rule."""
        rule = RoutingRule(
            name="critical-rule",
            destinations=["slack"],
            severities=[Severity.CRITICAL],
        )
        router.add_routing_rule(rule)

        # Should not raise
        assert True

    def test_add_suppression_rule(self, router):
        """Test adding suppression rule."""
        rule = SuppressionRule(
            name="suppress-rule",
            rule_ids=["aws-s3-001"],
        )
        router.add_suppression_rule(rule)

        # Should not raise
        assert True

    def test_set_rate_limit(self, router):
        """Test setting rate limit."""
        limit = RateLimit(max_alerts=20)
        router.set_rate_limit("slack", limit)

        # Should not raise
        assert True

    def test_route_finding(self, router, mock_destination, sample_finding):
        """Test routing a finding."""
        # Add destination and rule
        router.add_destination(mock_destination)
        rule = RoutingRule(
            name="all-findings",
            destinations=["test-dest"],
        )
        router.add_routing_rule(rule)

        result = router.route(sample_finding)

        assert isinstance(result, RoutingResult)
        assert result.finding_id == sample_finding.id


class TestDestinationInterface:
    """Tests to verify destination interface compliance."""

    def test_base_destination_is_abstract(self):
        """Test BaseDestination cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseDestination("test", {})

    def test_slack_is_base_destination(self):
        """Test SlackDestination is BaseDestination."""
        dest = SlackDestination("test", {"webhook_url": "https://test"})
        assert isinstance(dest, BaseDestination)

    def test_pagerduty_is_base_destination(self):
        """Test PagerDutyDestination is BaseDestination."""
        dest = PagerDutyDestination("test", {"routing_key": "key"})
        assert isinstance(dest, BaseDestination)

    def test_webhook_is_base_destination(self):
        """Test WebhookDestination is BaseDestination."""
        dest = WebhookDestination("test", {"url": "https://test"})
        assert isinstance(dest, BaseDestination)


class TestAlertStateInterface:
    """Tests to verify AlertStateBackend interface."""

    def test_in_memory_state_is_backend(self):
        """Test InMemoryAlertState is AlertStateBackend."""
        state = InMemoryAlertState()
        assert isinstance(state, AlertStateBackend)

    def test_state_backend_has_required_methods(self):
        """Test state backend has required methods."""
        state = InMemoryAlertState()

        assert hasattr(state, "record_alert")
        assert hasattr(state, "get_alert")
        assert hasattr(state, "get_alerts_for_finding")
        assert hasattr(state, "check_dedup")


class TestTeamsDestination:
    """Tests for Microsoft Teams destination."""

    def test_teams_destination_creation(self):
        """Test TeamsDestination creation."""
        dest = TeamsDestination(
            name="teams-alerts",
            config={"webhook_url": "https://outlook.office.com/webhook/xxx"},
        )

        assert dest.name == "teams-alerts"

    def test_teams_destination_creation_default_name(self):
        """Test TeamsDestination creation with default name."""
        dest = TeamsDestination(config={"webhook_url": "https://test"})
        assert dest.name == "teams"

    def test_teams_destination_is_base_destination(self):
        """Test TeamsDestination is BaseDestination."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        assert isinstance(dest, BaseDestination)

    def test_teams_destination_has_required_methods(self):
        """Test TeamsDestination has required methods."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})

        assert hasattr(dest, "send")
        assert hasattr(dest, "test_connection")
        assert callable(dest.send)
        assert callable(dest.test_connection)

    def test_teams_destination_without_webhook_url(self):
        """Test TeamsDestination without webhook URL returns False."""
        dest = TeamsDestination("test", {})

        # test_connection should return False without URL
        assert dest.test_connection() is False

    def test_teams_destination_send_without_webhook_url(self, sample_finding):
        """Test TeamsDestination send returns False without URL."""
        dest = TeamsDestination("test", {})
        result = dest.send(sample_finding, {})

        assert result is False

    def test_teams_destination_build_payload(self, sample_finding):
        """Test TeamsDestination builds correct payload structure."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})

        # Access the internal method to test payload structure
        payload = dest._build_teams_payload(sample_finding, {})

        assert payload["type"] == "message"
        assert "attachments" in payload
        assert len(payload["attachments"]) == 1
        assert payload["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"

        # Check adaptive card structure
        content = payload["attachments"][0]["content"]
        assert content["type"] == "AdaptiveCard"
        assert "body" in content
        assert len(content["body"]) >= 3  # Container, FactSet, TextBlock

    def test_teams_destination_payload_contains_finding_info(self, sample_finding):
        """Test TeamsDestination payload contains finding information."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        payload = dest._build_teams_payload(sample_finding, {})

        content = payload["attachments"][0]["content"]

        # Check title is in container
        container = content["body"][0]
        assert container["type"] == "Container"
        title_block = container["items"][0]
        assert sample_finding.title in title_block["text"]

        # Check facts contain severity and type
        fact_set = content["body"][1]
        assert fact_set["type"] == "FactSet"
        facts = fact_set["facts"]

        fact_titles = [f["title"] for f in facts]
        assert "Severity" in fact_titles
        assert "Type" in fact_titles
        assert "Status" in fact_titles

    def test_teams_destination_payload_with_asset(self, sample_finding):
        """Test TeamsDestination payload includes asset when present."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        payload = dest._build_teams_payload(sample_finding, {})

        content = payload["attachments"][0]["content"]
        fact_set = content["body"][1]
        facts = fact_set["facts"]

        # sample_finding has asset_id
        fact_titles = [f["title"] for f in facts]
        assert "Asset" in fact_titles

    def test_teams_destination_payload_with_rule(self, sample_finding):
        """Test TeamsDestination payload includes rule when present."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        payload = dest._build_teams_payload(sample_finding, {})

        content = payload["attachments"][0]["content"]
        fact_set = content["body"][1]
        facts = fact_set["facts"]

        # sample_finding has rule_id
        fact_titles = [f["title"] for f in facts]
        assert "Rule" in fact_titles

    def test_teams_destination_payload_with_cve(self, vulnerability_finding):
        """Test TeamsDestination payload includes CVE when present."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        payload = dest._build_teams_payload(vulnerability_finding, {})

        content = payload["attachments"][0]["content"]
        fact_set = content["body"][1]
        facts = fact_set["facts"]

        # vulnerability_finding has cve_id
        fact_titles = [f["title"] for f in facts]
        assert "CVE" in fact_titles

    def test_teams_destination_payload_with_remediation(self, sample_finding):
        """Test TeamsDestination payload includes remediation when present."""
        dest = TeamsDestination("test", {"webhook_url": "https://test"})
        payload = dest._build_teams_payload(sample_finding, {})

        content = payload["attachments"][0]["content"]

        # sample_finding has remediation_guidance
        # Should have remediation container
        containers = [b for b in content["body"] if b.get("type") == "Container"]
        assert len(containers) >= 1

    def test_create_teams_destination(self):
        """Test creating Teams destination via factory."""
        dest = create_destination(
            destination_type="teams",
            name="teams-alerts",
            config={"webhook_url": "https://outlook.office.com/webhook/xxx"},
        )

        assert isinstance(dest, TeamsDestination)


class TestJiraDestination:
    """Tests for Jira destination."""

    def test_jira_destination_creation(self):
        """Test JiraDestination creation."""
        dest = JiraDestination(
            name="jira-issues",
            config={
                "url": "https://example.atlassian.net",
                "email": "user@example.com",
                "api_token": "test-token",
                "project_key": "SEC",
            },
        )

        assert dest.name == "jira-issues"

    def test_jira_destination_creation_default_name(self):
        """Test JiraDestination creation with default name."""
        dest = JiraDestination(config={})
        assert dest.name == "jira"

    def test_jira_destination_is_base_destination(self):
        """Test JiraDestination is BaseDestination."""
        dest = JiraDestination("test", {})
        assert isinstance(dest, BaseDestination)

    def test_jira_destination_has_required_methods(self):
        """Test JiraDestination has required methods."""
        dest = JiraDestination("test", {})

        assert hasattr(dest, "send")
        assert hasattr(dest, "test_connection")
        assert callable(dest.send)
        assert callable(dest.test_connection)

    def test_jira_destination_without_config_test_fails(self):
        """Test JiraDestination test_connection fails without config."""
        dest = JiraDestination("test", {})
        assert dest.test_connection() is False

    def test_jira_destination_send_without_config_fails(self, sample_finding):
        """Test JiraDestination send returns False without config."""
        dest = JiraDestination("test", {})
        result = dest.send(sample_finding, {})

        assert result is False

    def test_jira_destination_config_defaults(self):
        """Test JiraDestination has correct default values."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "TEST",
        })

        assert dest._issue_type == "Bug"
        assert dest._labels == ["security", "stance"]

    def test_jira_destination_custom_issue_type(self):
        """Test JiraDestination with custom issue type."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "TEST",
            "issue_type": "Task",
        })

        assert dest._issue_type == "Task"

    def test_jira_destination_custom_labels(self):
        """Test JiraDestination with custom labels."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "TEST",
            "labels": ["custom", "labels"],
        })

        assert dest._labels == ["custom", "labels"]

    def test_jira_destination_priority_mapping(self):
        """Test JiraDestination has priority mapping."""
        dest = JiraDestination("test", {})

        assert dest._priority_mapping["critical"] == "Highest"
        assert dest._priority_mapping["high"] == "High"
        assert dest._priority_mapping["medium"] == "Medium"
        assert dest._priority_mapping["low"] == "Low"
        assert dest._priority_mapping["info"] == "Lowest"

    def test_jira_destination_custom_priority_mapping(self):
        """Test JiraDestination with custom priority mapping."""
        custom_mapping = {
            "critical": "P1",
            "high": "P2",
            "medium": "P3",
            "low": "P4",
            "info": "P5",
        }
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "TEST",
            "priority_mapping": custom_mapping,
        })

        assert dest._priority_mapping == custom_mapping

    def test_jira_destination_build_payload(self, sample_finding):
        """Test JiraDestination builds correct payload structure."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })

        payload = dest._build_jira_payload(sample_finding, {})

        assert "fields" in payload
        fields = payload["fields"]
        assert fields["project"]["key"] == "SEC"
        assert "summary" in fields
        assert "description" in fields
        assert fields["issuetype"]["name"] == "Bug"

    def test_jira_destination_payload_contains_severity_label(self, sample_finding):
        """Test JiraDestination payload includes severity as label."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })

        payload = dest._build_jira_payload(sample_finding, {})
        labels = payload["fields"]["labels"]

        assert sample_finding.severity.value in labels

    def test_jira_destination_payload_summary_format(self, sample_finding):
        """Test JiraDestination payload summary format."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })

        payload = dest._build_jira_payload(sample_finding, {})
        summary = payload["fields"]["summary"]

        assert "[HIGH]" in summary
        assert sample_finding.title in summary

    def test_jira_destination_get_auth_headers(self):
        """Test JiraDestination generates correct auth headers."""
        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "test-token",
            "project_key": "SEC",
        })

        headers = dest._get_auth_headers()

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")
        assert headers["Content-Type"] == "application/json"

    def test_create_jira_destination(self):
        """Test creating Jira destination via factory."""
        dest = create_destination(
            destination_type="jira",
            name="jira-issues",
            config={
                "url": "https://example.atlassian.net",
                "email": "user@example.com",
                "api_token": "token",
                "project_key": "SEC",
            },
        )

        assert isinstance(dest, JiraDestination)


class TestTeamsDestinationIntegration:
    """Integration-style tests for Teams destination."""

    @patch("urllib.request.urlopen")
    def test_teams_send_success(self, mock_urlopen, sample_finding):
        """Test Teams send succeeds with mock."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = TeamsDestination("test", {
            "webhook_url": "https://outlook.office.com/webhook/xxx"
        })
        result = dest.send(sample_finding, {})

        assert result is True
        mock_urlopen.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_teams_test_connection_success(self, mock_urlopen):
        """Test Teams test_connection succeeds with mock."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = TeamsDestination("test", {
            "webhook_url": "https://outlook.office.com/webhook/xxx"
        })
        result = dest.test_connection()

        assert result is True

    @patch("urllib.request.urlopen")
    def test_teams_send_failure(self, mock_urlopen, sample_finding):
        """Test Teams send fails gracefully on error."""
        mock_urlopen.side_effect = Exception("Connection failed")

        dest = TeamsDestination("test", {
            "webhook_url": "https://outlook.office.com/webhook/xxx"
        })
        result = dest.send(sample_finding, {})

        assert result is False


class TestJiraDestinationIntegration:
    """Integration-style tests for Jira destination."""

    @patch("urllib.request.urlopen")
    def test_jira_test_connection_success(self, mock_urlopen):
        """Test Jira test_connection succeeds with mock."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })
        result = dest.test_connection()

        assert result is True

    @patch("urllib.request.urlopen")
    def test_jira_send_success(self, mock_urlopen, sample_finding):
        """Test Jira send succeeds with mock."""
        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.read.return_value = b'{"key": "SEC-123"}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })
        result = dest.send(sample_finding, {})

        assert result is True
        mock_urlopen.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_jira_send_failure(self, mock_urlopen, sample_finding):
        """Test Jira send fails gracefully on error."""
        mock_urlopen.side_effect = Exception("Connection failed")

        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })
        result = dest.send(sample_finding, {})

        assert result is False

    @patch("urllib.request.urlopen")
    def test_jira_test_connection_failure(self, mock_urlopen):
        """Test Jira test_connection fails gracefully on error."""
        mock_urlopen.side_effect = Exception("Connection failed")

        dest = JiraDestination("test", {
            "url": "https://test.atlassian.net",
            "email": "test@example.com",
            "api_token": "token",
            "project_key": "SEC",
        })
        result = dest.test_connection()

        assert result is False


class TestDestinationFactoryComplete:
    """Tests for complete destination factory coverage."""

    def test_factory_supports_all_types(self):
        """Test factory supports all documented destination types."""
        supported_types = ["slack", "pagerduty", "email", "webhook", "teams", "jira"]

        for dest_type in supported_types:
            # Should not raise ValueError
            config = {}
            if dest_type == "slack":
                config = {"webhook_url": "https://test"}
            elif dest_type == "pagerduty":
                config = {"routing_key": "key"}
            elif dest_type == "email":
                config = {
                    "smtp_host": "smtp.test.com",
                    "from_address": "test@test.com",
                    "to_addresses": ["test@test.com"],
                }
            elif dest_type == "webhook":
                config = {"url": "https://test"}
            elif dest_type == "teams":
                config = {"webhook_url": "https://test"}
            elif dest_type == "jira":
                config = {
                    "url": "https://test.atlassian.net",
                    "email": "test@test.com",
                    "api_token": "token",
                    "project_key": "TEST",
                }

            dest = create_destination(dest_type, f"{dest_type}-test", config)
            assert dest is not None
            assert isinstance(dest, BaseDestination)
