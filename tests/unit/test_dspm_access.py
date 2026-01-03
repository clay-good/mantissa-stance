"""
Unit tests for DSPM access review module.

Tests the access review analyzers for AWS CloudTrail, GCP Cloud Audit Logs,
and Azure Activity Logs.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, patch
import json

from stance.dspm.access.base import (
    AccessReviewConfig,
    AccessEvent,
    AccessSummary,
    StaleAccessFinding,
    AccessReviewResult,
    FindingType,
    BaseAccessAnalyzer,
)


# =============================================================================
# Tests for FindingType enum
# =============================================================================

class TestFindingType:
    """Tests for FindingType enum."""

    def test_finding_type_values(self):
        """Test all finding type values exist."""
        assert FindingType.STALE_ACCESS.value == "stale_access"
        assert FindingType.UNUSED_ROLE.value == "unused_role"
        assert FindingType.OVER_PRIVILEGED.value == "over_privileged"
        assert FindingType.NO_RECENT_ACCESS.value == "no_recent_access"
        assert FindingType.WRITE_NEVER_USED.value == "write_never_used"
        assert FindingType.DELETE_NEVER_USED.value == "delete_never_used"

    def test_finding_type_count(self):
        """Test correct number of finding types."""
        assert len(FindingType) == 6


# =============================================================================
# Tests for AccessReviewConfig
# =============================================================================

class TestAccessReviewConfig:
    """Tests for AccessReviewConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = AccessReviewConfig()
        assert config.stale_days == 90
        assert config.include_service_accounts is True
        assert config.include_roles is True
        assert config.include_users is True
        assert config.lookback_days == 180
        assert config.min_access_count == 1

    def test_custom_config(self):
        """Test custom configuration values."""
        config = AccessReviewConfig(
            stale_days=30,
            include_service_accounts=False,
            lookback_days=365,
        )
        assert config.stale_days == 30
        assert config.include_service_accounts is False
        assert config.lookback_days == 365


# =============================================================================
# Tests for AccessEvent
# =============================================================================

class TestAccessEvent:
    """Tests for AccessEvent dataclass."""

    def test_create_event(self):
        """Test creating an access event."""
        timestamp = datetime.now(timezone.utc)
        event = AccessEvent(
            event_id="evt-001",
            timestamp=timestamp,
            principal_id="user@example.com",
            principal_type="user",
            resource_id="my-bucket",
            action="read",
        )
        assert event.event_id == "evt-001"
        assert event.timestamp == timestamp
        assert event.principal_id == "user@example.com"
        assert event.principal_type == "user"
        assert event.resource_id == "my-bucket"
        assert event.action == "read"
        assert event.success is True

    def test_event_with_optional_fields(self):
        """Test event with optional fields."""
        event = AccessEvent(
            event_id="evt-002",
            timestamp=datetime.now(timezone.utc),
            principal_id="service@project.iam.gserviceaccount.com",
            principal_type="service_account",
            resource_id="my-bucket",
            action="write",
            source_ip="10.0.0.1",
            user_agent="gcloud/1.0",
            success=True,
            metadata={"region": "us-east-1"},
        )
        assert event.source_ip == "10.0.0.1"
        assert event.user_agent == "gcloud/1.0"
        assert event.metadata["region"] == "us-east-1"

    def test_event_to_dict(self):
        """Test event serialization."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        event = AccessEvent(
            event_id="evt-003",
            timestamp=timestamp,
            principal_id="test-user",
            principal_type="user",
            resource_id="bucket-1",
            action="delete",
        )
        result = event.to_dict()
        assert result["event_id"] == "evt-003"
        assert result["principal_id"] == "test-user"
        assert result["action"] == "delete"
        assert "2024-01-15" in result["timestamp"]


# =============================================================================
# Tests for AccessSummary
# =============================================================================

class TestAccessSummary:
    """Tests for AccessSummary dataclass."""

    def test_create_summary(self):
        """Test creating an access summary."""
        summary = AccessSummary(
            principal_id="user@example.com",
            principal_type="user",
            resource_id="my-bucket",
        )
        assert summary.principal_id == "user@example.com"
        assert summary.total_access_count == 0
        assert summary.read_count == 0
        assert summary.write_count == 0

    def test_summary_with_counts(self):
        """Test summary with access counts."""
        first_access = datetime(2024, 1, 1, tzinfo=timezone.utc)
        last_access = datetime(2024, 6, 15, tzinfo=timezone.utc)
        summary = AccessSummary(
            principal_id="user@example.com",
            principal_type="user",
            resource_id="my-bucket",
            total_access_count=100,
            read_count=80,
            write_count=15,
            delete_count=5,
            first_access=first_access,
            last_access=last_access,
            days_since_last_access=180,
        )
        assert summary.total_access_count == 100
        assert summary.read_count == 80
        assert summary.write_count == 15
        assert summary.delete_count == 5
        assert summary.days_since_last_access == 180

    def test_summary_to_dict(self):
        """Test summary serialization."""
        summary = AccessSummary(
            principal_id="test-user",
            principal_type="user",
            resource_id="bucket-1",
            total_access_count=50,
            permission_level="read",
        )
        result = summary.to_dict()
        assert result["principal_id"] == "test-user"
        assert result["total_access_count"] == 50
        assert result["permission_level"] == "read"


# =============================================================================
# Tests for StaleAccessFinding
# =============================================================================

class TestStaleAccessFinding:
    """Tests for StaleAccessFinding dataclass."""

    def test_create_finding(self):
        """Test creating a stale access finding."""
        finding = StaleAccessFinding(
            finding_id="finding-001",
            finding_type=FindingType.STALE_ACCESS,
            severity="high",
            title="Stale access for user@example.com",
            description="User hasn't accessed in 180 days",
            principal_id="user@example.com",
            principal_type="user",
            resource_id="my-bucket",
            days_since_last_access=180,
        )
        assert finding.finding_id == "finding-001"
        assert finding.finding_type == FindingType.STALE_ACCESS
        assert finding.severity == "high"
        assert finding.days_since_last_access == 180

    def test_finding_with_recommendation(self):
        """Test finding with recommended action."""
        finding = StaleAccessFinding(
            finding_id="finding-002",
            finding_type=FindingType.OVER_PRIVILEGED,
            severity="medium",
            title="Over-privileged access",
            description="Write permission but only reads",
            principal_id="service@project.iam.gserviceaccount.com",
            principal_type="service_account",
            resource_id="data-bucket",
            permission_level="write",
            recommended_action="Downgrade to read-only access",
        )
        assert finding.permission_level == "write"
        assert "read-only" in finding.recommended_action

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = StaleAccessFinding(
            finding_id="finding-003",
            finding_type=FindingType.NO_RECENT_ACCESS,
            severity="low",
            title="No recent access",
            description="No access in lookback period",
            principal_id="old-user",
            principal_type="user",
            resource_id="archive-bucket",
        )
        result = finding.to_dict()
        assert result["finding_id"] == "finding-003"
        assert result["finding_type"] == "no_recent_access"
        assert result["severity"] == "low"
        assert "detected_at" in result


# =============================================================================
# Tests for AccessReviewResult
# =============================================================================

class TestAccessReviewResult:
    """Tests for AccessReviewResult dataclass."""

    def test_create_result(self):
        """Test creating an access review result."""
        config = AccessReviewConfig()
        started_at = datetime.now(timezone.utc)
        result = AccessReviewResult(
            review_id="review-001",
            resource_id="my-bucket",
            config=config,
            started_at=started_at,
        )
        assert result.review_id == "review-001"
        assert result.resource_id == "my-bucket"
        assert result.has_findings is False
        assert result.total_principals_analyzed == 0

    def test_result_with_findings(self):
        """Test result with findings."""
        config = AccessReviewConfig()
        started_at = datetime.now(timezone.utc)
        completed_at = started_at + timedelta(seconds=30)

        findings = [
            StaleAccessFinding(
                finding_id="f1",
                finding_type=FindingType.STALE_ACCESS,
                severity="high",
                title="Stale 1",
                description="Desc 1",
                principal_id="user1",
                principal_type="user",
                resource_id="bucket",
            ),
            StaleAccessFinding(
                finding_id="f2",
                finding_type=FindingType.STALE_ACCESS,
                severity="medium",
                title="Stale 2",
                description="Desc 2",
                principal_id="user2",
                principal_type="user",
                resource_id="bucket",
            ),
            StaleAccessFinding(
                finding_id="f3",
                finding_type=FindingType.OVER_PRIVILEGED,
                severity="medium",
                title="Over 1",
                description="Desc 3",
                principal_id="user3",
                principal_type="user",
                resource_id="bucket",
            ),
        ]

        result = AccessReviewResult(
            review_id="review-002",
            resource_id="bucket",
            config=config,
            started_at=started_at,
            completed_at=completed_at,
            total_principals_analyzed=10,
            total_events_analyzed=500,
            findings=findings,
        )

        assert result.has_findings is True
        assert len(result.findings) == 3
        assert result.findings_by_type["stale_access"] == 2
        assert result.findings_by_type["over_privileged"] == 1
        assert result.findings_by_severity["high"] == 1
        assert result.findings_by_severity["medium"] == 2

    def test_stale_principals(self):
        """Test extracting stale principals."""
        config = AccessReviewConfig()
        findings = [
            StaleAccessFinding(
                finding_id="f1",
                finding_type=FindingType.STALE_ACCESS,
                severity="high",
                title="Stale",
                description="Desc",
                principal_id="stale-user",
                principal_type="user",
                resource_id="bucket",
            ),
            StaleAccessFinding(
                finding_id="f2",
                finding_type=FindingType.OVER_PRIVILEGED,
                severity="medium",
                title="Over",
                description="Desc",
                principal_id="other-user",
                principal_type="user",
                resource_id="bucket",
            ),
        ]

        result = AccessReviewResult(
            review_id="review-003",
            resource_id="bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
            findings=findings,
        )

        stale = result.stale_principals
        assert len(stale) == 1
        assert "stale-user" in stale

    def test_result_to_dict(self):
        """Test result serialization."""
        config = AccessReviewConfig(stale_days=60, lookback_days=120)
        result = AccessReviewResult(
            review_id="review-004",
            resource_id="test-bucket",
            config=config,
            started_at=datetime.now(timezone.utc),
            total_principals_analyzed=5,
            total_events_analyzed=100,
        )
        result_dict = result.to_dict()
        assert result_dict["review_id"] == "review-004"
        assert result_dict["config"]["stale_days"] == 60
        assert result_dict["config"]["lookback_days"] == 120
        assert result_dict["findings_count"] == 0


# =============================================================================
# Tests for BaseAccessAnalyzer
# =============================================================================

class ConcreteAccessAnalyzer(BaseAccessAnalyzer):
    """Concrete implementation for testing."""

    cloud_provider = "test"

    def analyze_resource(self, resource_id):
        return AccessReviewResult(
            review_id="test-001",
            resource_id=resource_id,
            config=self._config,
            started_at=datetime.now(timezone.utc),
        )

    def get_access_events(self, resource_id, start_time, end_time):
        return iter([])

    def get_resource_permissions(self, resource_id):
        return {}


class TestBaseAccessAnalyzer:
    """Tests for BaseAccessAnalyzer abstract class."""

    def test_analyzer_creation(self):
        """Test creating an analyzer with default config."""
        analyzer = ConcreteAccessAnalyzer()
        assert analyzer._config.stale_days == 90
        assert analyzer.cloud_provider == "test"

    def test_analyzer_with_custom_config(self):
        """Test creating an analyzer with custom config."""
        config = AccessReviewConfig(stale_days=30)
        analyzer = ConcreteAccessAnalyzer(config=config)
        assert analyzer._config.stale_days == 30

    def test_aggregate_events_empty(self):
        """Test aggregating empty events."""
        analyzer = ConcreteAccessAnalyzer()
        summaries = analyzer._aggregate_events(iter([]))
        assert len(summaries) == 0

    def test_aggregate_events_single_principal(self):
        """Test aggregating events from one principal."""
        analyzer = ConcreteAccessAnalyzer()
        now = datetime.now(timezone.utc)

        events = [
            AccessEvent(
                event_id="e1",
                timestamp=now - timedelta(days=30),
                principal_id="user@example.com",
                principal_type="user",
                resource_id="bucket",
                action="GetObject",
            ),
            AccessEvent(
                event_id="e2",
                timestamp=now - timedelta(days=20),
                principal_id="user@example.com",
                principal_type="user",
                resource_id="bucket",
                action="PutObject",
            ),
            AccessEvent(
                event_id="e3",
                timestamp=now - timedelta(days=10),
                principal_id="user@example.com",
                principal_type="user",
                resource_id="bucket",
                action="GetObject",
            ),
        ]

        summaries = analyzer._aggregate_events(iter(events))
        assert len(summaries) == 1
        assert "user@example.com" in summaries

        summary = summaries["user@example.com"]
        assert summary.total_access_count == 3
        assert summary.read_count == 2
        assert summary.write_count == 1
        assert summary.days_since_last_access is not None
        assert summary.days_since_last_access <= 10

    def test_aggregate_events_multiple_principals(self):
        """Test aggregating events from multiple principals."""
        analyzer = ConcreteAccessAnalyzer()
        now = datetime.now(timezone.utc)

        events = [
            AccessEvent(
                event_id="e1",
                timestamp=now - timedelta(days=5),
                principal_id="user1@example.com",
                principal_type="user",
                resource_id="bucket",
                action="read",
            ),
            AccessEvent(
                event_id="e2",
                timestamp=now - timedelta(days=100),
                principal_id="user2@example.com",
                principal_type="user",
                resource_id="bucket",
                action="write",
            ),
        ]

        summaries = analyzer._aggregate_events(iter(events))
        assert len(summaries) == 2
        assert summaries["user1@example.com"].days_since_last_access <= 5
        assert summaries["user2@example.com"].days_since_last_access >= 100

    def test_generate_findings_stale_access(self):
        """Test generating stale access findings."""
        config = AccessReviewConfig(stale_days=90)
        analyzer = ConcreteAccessAnalyzer(config=config)

        now = datetime.now(timezone.utc)
        summaries = {
            "stale-user": AccessSummary(
                principal_id="stale-user",
                principal_type="user",
                resource_id="bucket",
                total_access_count=10,
                read_count=10,
                last_access=now - timedelta(days=180),
                days_since_last_access=180,
            ),
        }

        permissions = {
            "stale-user": {"type": "user", "level": "read"},
        }

        findings = analyzer._generate_findings(summaries, permissions, "bucket")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.STALE_ACCESS
        assert findings[0].days_since_last_access == 180

    def test_generate_findings_no_access(self):
        """Test generating no-access findings."""
        analyzer = ConcreteAccessAnalyzer()

        summaries = {}  # No access events
        permissions = {
            "unused-user": {"type": "user", "level": "write"},
        }

        findings = analyzer._generate_findings(summaries, permissions, "bucket")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.NO_RECENT_ACCESS

    def test_generate_findings_over_privileged(self):
        """Test generating over-privileged findings."""
        analyzer = ConcreteAccessAnalyzer()
        now = datetime.now(timezone.utc)

        summaries = {
            "reader-user": AccessSummary(
                principal_id="reader-user",
                principal_type="user",
                resource_id="bucket",
                total_access_count=50,
                read_count=50,
                write_count=0,  # Never writes
                delete_count=0,
                last_access=now - timedelta(days=5),
                days_since_last_access=5,
            ),
        }

        permissions = {
            "reader-user": {"type": "user", "level": "write"},  # Has write permissions
        }

        findings = analyzer._generate_findings(summaries, permissions, "bucket")
        # Should find over-privileged (has write, only reads)
        over_priv = [f for f in findings if f.finding_type == FindingType.OVER_PRIVILEGED]
        assert len(over_priv) == 1

    def test_severity_for_stale(self):
        """Test severity calculation for stale access."""
        analyzer = ConcreteAccessAnalyzer()

        # Admin with 365+ days = critical
        assert analyzer._get_severity_for_stale(400, "admin") == "critical"
        # Admin with 180+ days = high
        assert analyzer._get_severity_for_stale(200, "admin") == "high"
        # Admin with less = medium
        assert analyzer._get_severity_for_stale(100, "admin") == "medium"

        # Write with 365+ = high
        assert analyzer._get_severity_for_stale(400, "write") == "high"
        # Write with 180+ = medium
        assert analyzer._get_severity_for_stale(200, "write") == "medium"

        # Read-only with 365+ = medium
        assert analyzer._get_severity_for_stale(400, "read") == "medium"
        # Read-only with less = low
        assert analyzer._get_severity_for_stale(100, "read") == "low"

    def test_severity_for_unused(self):
        """Test severity calculation for unused permissions."""
        analyzer = ConcreteAccessAnalyzer()

        assert analyzer._get_severity_for_unused("admin") == "high"
        assert analyzer._get_severity_for_unused("full") == "high"
        assert analyzer._get_severity_for_unused("write") == "medium"
        assert analyzer._get_severity_for_unused("read") == "low"

    def test_calculate_lookback_range(self):
        """Test lookback range calculation."""
        config = AccessReviewConfig(lookback_days=90)
        analyzer = ConcreteAccessAnalyzer(config=config)

        start, end = analyzer._calculate_lookback_range()
        assert end > start
        delta = end - start
        assert delta.days == 90

    def test_filter_by_principal_type(self):
        """Test filtering by principal type."""
        config = AccessReviewConfig(
            include_service_accounts=False,
            include_roles=True,
            include_users=True,
        )
        analyzer = ConcreteAccessAnalyzer(config=config)

        summaries = {}
        permissions = {
            "service@gcp.iam.gserviceaccount.com": {"type": "service_account", "level": "read"},
            "user@example.com": {"type": "user", "level": "read"},
        }

        findings = analyzer._generate_findings(summaries, permissions, "bucket")
        # Should only generate finding for user, not service account
        assert len(findings) == 1
        assert findings[0].principal_id == "user@example.com"


# =============================================================================
# Tests for CloudTrailAccessAnalyzer
# =============================================================================

class TestCloudTrailAccessAnalyzer:
    """Tests for CloudTrailAccessAnalyzer."""

    def test_creation_without_boto3(self):
        """Test that analyzer raises ImportError without boto3."""
        with patch.dict("sys.modules", {"boto3": None}):
            with patch("stance.dspm.access.cloudtrail.BOTO3_AVAILABLE", False):
                from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
                with pytest.raises(ImportError, match="boto3"):
                    CloudTrailAccessAnalyzer()

    @patch("stance.dspm.access.cloudtrail.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.access.cloudtrail.boto3")
    def test_creation_with_boto3(self, mock_boto3):
        """Test analyzer creation with boto3 available."""
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
        analyzer = CloudTrailAccessAnalyzer()

        assert analyzer.cloud_provider == "aws"
        assert analyzer._region == "us-east-1"

    @patch("stance.dspm.access.cloudtrail.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.access.cloudtrail.boto3")
    def test_actions_to_permission_level(self, mock_boto3):
        """Test action to permission level mapping."""
        from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        analyzer = CloudTrailAccessAnalyzer()

        assert analyzer._actions_to_permission_level(["s3:*"]) == "admin"
        assert analyzer._actions_to_permission_level(["s3:DeleteObject"]) == "admin"
        assert analyzer._actions_to_permission_level(["s3:PutObject"]) == "write"
        assert analyzer._actions_to_permission_level(["s3:GetObject"]) == "read"
        assert analyzer._actions_to_permission_level(["s3:ListBucket"]) == "read"

    @patch("stance.dspm.access.cloudtrail.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.access.cloudtrail.boto3")
    def test_map_principal_type(self, mock_boto3):
        """Test AWS identity type mapping."""
        from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        analyzer = CloudTrailAccessAnalyzer()

        assert analyzer._map_principal_type("IAMUser") == "user"
        assert analyzer._map_principal_type("AssumedRole") == "role"
        assert analyzer._map_principal_type("AWSService") == "service_account"
        assert analyzer._map_principal_type("Root") == "user"

    @patch("stance.dspm.access.cloudtrail.BOTO3_AVAILABLE", True)
    @patch("stance.dspm.access.cloudtrail.boto3")
    def test_guess_principal_type(self, mock_boto3):
        """Test guessing principal type from ARN."""
        from stance.dspm.access.cloudtrail import CloudTrailAccessAnalyzer
        mock_session = MagicMock()
        mock_boto3.Session.return_value = mock_session

        analyzer = CloudTrailAccessAnalyzer()

        assert analyzer._guess_principal_type("arn:aws:iam::123456789:user/alice") == "user"
        assert analyzer._guess_principal_type("arn:aws:iam::123456789:role/admin") == "role"
        # Root is detected as user (not account) based on :root pattern
        assert analyzer._guess_principal_type("arn:aws:iam::123456789:root") == "user"


# =============================================================================
# Tests for GCPAuditLogAnalyzer
# =============================================================================

class TestGCPAuditLogAnalyzer:
    """Tests for GCPAuditLogAnalyzer."""

    def test_creation_without_gcp_libs(self):
        """Test that analyzer raises ImportError without GCP libraries."""
        with patch("stance.dspm.access.gcp_audit.GCP_AVAILABLE", False):
            from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
            with pytest.raises(ImportError, match="google-cloud"):
                GCPAuditLogAnalyzer()

    @patch("stance.dspm.access.gcp_audit.GCP_AVAILABLE", True)
    @patch("stance.dspm.access.gcp_audit.cloud_logging")
    @patch("stance.dspm.access.gcp_audit.storage")
    def test_creation_with_gcp_libs(self, mock_storage, mock_logging):
        """Test analyzer creation with GCP libraries available."""
        from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
        analyzer = GCPAuditLogAnalyzer(project="test-project")

        assert analyzer.cloud_provider == "gcp"
        assert analyzer._project == "test-project"

    @patch("stance.dspm.access.gcp_audit.GCP_AVAILABLE", True)
    @patch("stance.dspm.access.gcp_audit.cloud_logging")
    @patch("stance.dspm.access.gcp_audit.storage")
    def test_guess_principal_type(self, mock_storage, mock_logging):
        """Test guessing GCP principal type."""
        from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
        analyzer = GCPAuditLogAnalyzer(project="test-project")

        assert analyzer._guess_principal_type("user@example.com") == "user"
        assert analyzer._guess_principal_type("sa@project.iam.gserviceaccount.com") == "service_account"
        assert analyzer._guess_principal_type("service-123@compute.iam.gserviceaccount.com") == "service_account"

    @patch("stance.dspm.access.gcp_audit.GCP_AVAILABLE", True)
    @patch("stance.dspm.access.gcp_audit.cloud_logging")
    @patch("stance.dspm.access.gcp_audit.storage")
    def test_role_to_permission_level(self, mock_storage, mock_logging):
        """Test GCP role to permission level mapping."""
        from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
        analyzer = GCPAuditLogAnalyzer(project="test-project")

        assert analyzer._role_to_permission_level("roles/storage.admin") == "admin"
        # objectAdmin contains "admin" so maps to admin
        assert analyzer._role_to_permission_level("roles/storage.objectAdmin") == "admin"
        assert analyzer._role_to_permission_level("roles/storage.objectCreator") == "write"
        assert analyzer._role_to_permission_level("roles/storage.objectViewer") == "read"
        assert analyzer._role_to_permission_level("roles/storage.legacyBucketReader") == "read"

    @patch("stance.dspm.access.gcp_audit.GCP_AVAILABLE", True)
    @patch("stance.dspm.access.gcp_audit.cloud_logging")
    @patch("stance.dspm.access.gcp_audit.storage")
    def test_member_type_mapping(self, mock_storage, mock_logging):
        """Test GCP member type to principal type mapping."""
        from stance.dspm.access.gcp_audit import GCPAuditLogAnalyzer
        analyzer = GCPAuditLogAnalyzer(project="test-project")

        assert analyzer._member_type_to_principal_type("user") == "user"
        assert analyzer._member_type_to_principal_type("serviceAccount") == "service_account"
        assert analyzer._member_type_to_principal_type("group") == "group"


# =============================================================================
# Tests for AzureActivityLogAnalyzer
# =============================================================================

class TestAzureActivityLogAnalyzer:
    """Tests for AzureActivityLogAnalyzer."""

    def test_creation_without_azure_libs(self):
        """Test that analyzer raises ImportError without Azure libraries."""
        with patch("stance.dspm.access.azure_activity.AZURE_AVAILABLE", False):
            from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer
            with pytest.raises(ImportError, match="azure"):
                AzureActivityLogAnalyzer()

    @patch("stance.dspm.access.azure_activity.AZURE_AVAILABLE", True)
    @patch("stance.dspm.access.azure_activity.DefaultAzureCredential")
    @patch("stance.dspm.access.azure_activity.MonitorManagementClient")
    @patch("stance.dspm.access.azure_activity.StorageManagementClient")
    def test_creation_with_azure_libs(self, mock_storage, mock_monitor, mock_cred):
        """Test analyzer creation with Azure libraries available."""
        from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer
        analyzer = AzureActivityLogAnalyzer(subscription_id="sub-123")

        assert analyzer.cloud_provider == "azure"
        assert analyzer._subscription_id == "sub-123"

    @patch("stance.dspm.access.azure_activity.AZURE_AVAILABLE", True)
    @patch("stance.dspm.access.azure_activity.DefaultAzureCredential")
    @patch("stance.dspm.access.azure_activity.MonitorManagementClient")
    @patch("stance.dspm.access.azure_activity.StorageManagementClient")
    def test_parse_container_name(self, mock_storage, mock_monitor, mock_cred):
        """Test parsing container name from various formats."""
        from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer
        analyzer = AzureActivityLogAnalyzer(subscription_id="sub-123")

        assert analyzer._parse_container_name("my-container") == "my-container"
        assert analyzer._parse_container_name("azure://my-container") == "my-container"
        assert analyzer._parse_container_name("account/container") == "container"

    @patch("stance.dspm.access.azure_activity.AZURE_AVAILABLE", True)
    @patch("stance.dspm.access.azure_activity.DefaultAzureCredential")
    @patch("stance.dspm.access.azure_activity.MonitorManagementClient")
    @patch("stance.dspm.access.azure_activity.StorageManagementClient")
    def test_guess_principal_type(self, mock_storage, mock_monitor, mock_cred):
        """Test guessing Azure principal type."""
        from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer
        analyzer = AzureActivityLogAnalyzer(subscription_id="sub-123")

        # GUID = service principal
        assert analyzer._guess_principal_type("12345678-1234-1234-1234-123456789abc") == "service_account"
        # Email = user
        assert analyzer._guess_principal_type("user@example.com") == "user"

    @patch("stance.dspm.access.azure_activity.AZURE_AVAILABLE", True)
    @patch("stance.dspm.access.azure_activity.DefaultAzureCredential")
    @patch("stance.dspm.access.azure_activity.MonitorManagementClient")
    @patch("stance.dspm.access.azure_activity.StorageManagementClient")
    def test_is_guid(self, mock_storage, mock_monitor, mock_cred):
        """Test GUID detection."""
        from stance.dspm.access.azure_activity import AzureActivityLogAnalyzer
        analyzer = AzureActivityLogAnalyzer(subscription_id="sub-123")

        assert analyzer._is_guid("12345678-1234-1234-1234-123456789abc") is True
        assert analyzer._is_guid("not-a-guid") is False
        assert analyzer._is_guid("user@example.com") is False


# =============================================================================
# Integration Tests
# =============================================================================

class TestAccessReviewIntegration:
    """Integration tests for access review module."""

    def test_module_imports(self):
        """Test that all classes can be imported from the access module."""
        from stance.dspm.access import (
            AccessReviewConfig,
            AccessEvent,
            AccessSummary,
            StaleAccessFinding,
            AccessReviewResult,
            FindingType,
            BaseAccessAnalyzer,
            CloudTrailAccessAnalyzer,
            GCPAuditLogAnalyzer,
            AzureActivityLogAnalyzer,
        )
        assert AccessReviewConfig is not None
        assert AccessEvent is not None
        assert BaseAccessAnalyzer is not None

    def test_dspm_module_exports(self):
        """Test that access classes are exported from main DSPM module."""
        from stance.dspm import (
            AccessReviewConfig,
            AccessEvent,
            AccessSummary,
            StaleAccessFinding,
            AccessReviewResult,
            FindingType,
            BaseAccessAnalyzer,
            CloudTrailAccessAnalyzer,
            GCPAuditLogAnalyzer,
            AzureActivityLogAnalyzer,
        )
        assert AccessReviewConfig is not None
        assert CloudTrailAccessAnalyzer is not None

    def test_finding_workflow(self):
        """Test complete finding generation workflow."""
        config = AccessReviewConfig(stale_days=30, lookback_days=90)
        analyzer = ConcreteAccessAnalyzer(config=config)

        # Simulate access events
        now = datetime.now(timezone.utc)
        events = [
            AccessEvent(
                event_id="e1",
                timestamp=now - timedelta(days=60),
                principal_id="stale-user@example.com",
                principal_type="user",
                resource_id="test-bucket",
                action="read",
            ),
            AccessEvent(
                event_id="e2",
                timestamp=now - timedelta(days=5),
                principal_id="active-user@example.com",
                principal_type="user",
                resource_id="test-bucket",
                action="read",
            ),
        ]

        # Aggregate
        summaries = analyzer._aggregate_events(iter(events))
        assert len(summaries) == 2

        # Permissions
        permissions = {
            "stale-user@example.com": {"type": "user", "level": "read"},
            "active-user@example.com": {"type": "user", "level": "read"},
            "unused-user@example.com": {"type": "user", "level": "write"},
        }

        # Generate findings
        findings = analyzer._generate_findings(summaries, permissions, "test-bucket")

        # Should have findings for stale and unused users
        stale_findings = [f for f in findings if f.finding_type == FindingType.STALE_ACCESS]
        no_access_findings = [f for f in findings if f.finding_type == FindingType.NO_RECENT_ACCESS]

        assert len(stale_findings) >= 1
        assert len(no_access_findings) >= 1

    def test_config_thresholds(self):
        """Test that config thresholds are respected."""
        # User with 45 days of staleness
        config_30 = AccessReviewConfig(stale_days=30)
        config_60 = AccessReviewConfig(stale_days=60)

        analyzer_30 = ConcreteAccessAnalyzer(config=config_30)
        analyzer_60 = ConcreteAccessAnalyzer(config=config_60)

        now = datetime.now(timezone.utc)
        summaries = {
            "test-user": AccessSummary(
                principal_id="test-user",
                principal_type="user",
                resource_id="bucket",
                total_access_count=10,
                last_access=now - timedelta(days=45),
                days_since_last_access=45,
            ),
        }
        permissions = {"test-user": {"type": "user", "level": "read"}}

        # With 30-day threshold, should find stale
        findings_30 = analyzer_30._generate_findings(summaries, permissions, "bucket")
        stale_30 = [f for f in findings_30 if f.finding_type == FindingType.STALE_ACCESS]
        assert len(stale_30) == 1

        # With 60-day threshold, should NOT find stale
        findings_60 = analyzer_60._generate_findings(summaries, permissions, "bucket")
        stale_60 = [f for f in findings_60 if f.finding_type == FindingType.STALE_ACCESS]
        assert len(stale_60) == 0
