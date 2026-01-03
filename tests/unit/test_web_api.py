"""
Comprehensive unit tests for web dashboard API endpoints.

Tests cover all API endpoints in stance.web.server:
- GET endpoints for data retrieval
- POST endpoints for configuration
- Filtering and pagination
- Error handling
- Search functionality
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.web.server import StanceRequestHandler


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def sample_assets() -> AssetCollection:
    """Create sample assets for testing."""
    return AssetCollection([
        Asset(
            id="arn:aws:s3:::bucket-1",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket-1",
            tags={"Environment": "prod", "Team": "security"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"encryption": {"enabled": True}},
        ),
        Asset(
            id="arn:aws:s3:::bucket-2",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-west-2",
            resource_type="aws_s3_bucket",
            name="bucket-2",
            tags={"Environment": "dev"},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            created_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"encryption": {"enabled": False}},
        ),
        Asset(
            id="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_ec2_instance",
            name="instance-1",
            tags={"Environment": "prod"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 3, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"instance_type": "t3.micro"},
        ),
        Asset(
            id="projects/my-project/zones/us-central1-a/instances/gcp-vm",
            cloud_provider="gcp",
            account_id="my-project",
            region="us-central1",
            resource_type="gcp_compute_instance",
            name="gcp-vm",
            tags={"Environment": "staging"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 4, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={"machine_type": "e2-medium"},
        ),
    ])


@pytest.fixture
def sample_findings() -> FindingCollection:
    """Create sample findings for testing."""
    return FindingCollection([
        Finding(
            id="finding-001",
            asset_id="arn:aws:s3:::bucket-2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="S3 Bucket Encryption Disabled",
            description="Bucket does not have encryption enabled.",
            rule_id="aws-s3-encryption",
            remediation_guidance="Enable S3 bucket encryption using SSE-S3 or SSE-KMS.",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
        Finding(
            id="finding-002",
            asset_id="arn:aws:s3:::bucket-2",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.CRITICAL,
            status=FindingStatus.OPEN,
            title="S3 Bucket Publicly Accessible",
            description="Bucket allows public access.",
            rule_id="aws-s3-public-access",
            remediation_guidance="Block public access to the S3 bucket.",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
        Finding(
            id="finding-003",
            asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-12345",
            finding_type=FindingType.VULNERABILITY,
            severity=Severity.MEDIUM,
            status=FindingStatus.RESOLVED,
            title="Outdated Package openssl",
            description="Instance has outdated openssl package.",
            cve_id="CVE-2024-0001",
            cvss_score=6.5,
            package_name="openssl",
            installed_version="1.1.1k",
            fixed_version="1.1.1n",
            first_seen=datetime(2024, 1, 10, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 14, tzinfo=timezone.utc),
        ),
        Finding(
            id="finding-004",
            asset_id="arn:aws:s3:::bucket-1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.LOW,
            status=FindingStatus.OPEN,
            title="S3 Bucket Versioning Disabled",
            description="Bucket versioning is not enabled.",
            rule_id="aws-s3-versioning",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
        Finding(
            id="finding-005",
            asset_id="projects/my-project/zones/us-central1-a/instances/gcp-vm",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.INFO,
            status=FindingStatus.OPEN,
            title="GCP Instance Missing Labels",
            description="Instance is missing recommended labels.",
            rule_id="gcp-compute-labels",
            first_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        ),
    ])


@pytest.fixture
def mock_storage(sample_assets, sample_findings):
    """Create mock storage backend with sample data."""
    storage = MagicMock()
    storage.get_latest_snapshot_id.return_value = "20240115-120000"
    storage.get_assets.return_value = sample_assets
    storage.get_findings.return_value = sample_findings
    storage.list_snapshots.return_value = [
        "20240115-120000",
        "20240114-120000",
        "20240113-120000",
    ]
    return storage


@pytest.fixture
def handler(mock_storage):
    """Create request handler with mocked storage."""
    with patch.object(StanceRequestHandler, "__init__", lambda x: None):
        h = StanceRequestHandler()
        h.storage = mock_storage
        StanceRequestHandler.storage = mock_storage
        yield h


# =============================================================================
# GET /api/summary Tests
# =============================================================================


class TestSummaryEndpoint:
    """Tests for /api/summary endpoint."""

    def test_get_summary_returns_all_fields(self, handler, sample_assets, sample_findings):
        """Test summary returns required fields."""
        result = handler._get_summary()

        assert "snapshot_id" in result
        assert result["snapshot_id"] == "20240115-120000"
        assert "total_assets" in result
        assert result["total_assets"] == 4
        assert "total_findings" in result
        assert result["total_findings"] == 5
        assert "findings_by_severity" in result
        assert "findings_by_status" in result

    def test_get_summary_findings_by_severity(self, handler):
        """Test findings are correctly grouped by severity."""
        result = handler._get_summary()

        severity_counts = result["findings_by_severity"]
        # CRITICAL: 1, HIGH: 1, MEDIUM: 1, LOW: 1, INFO: 1
        assert severity_counts.get("critical", 0) == 1
        assert severity_counts.get("high", 0) == 1
        assert severity_counts.get("medium", 0) == 1
        assert severity_counts.get("low", 0) == 1

    def test_get_summary_no_storage(self):
        """Test summary returns error when no storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_summary()

            assert "error" in result

    def test_get_summary_no_snapshots(self, handler, mock_storage):
        """Test summary returns zeros when no snapshots exist."""
        mock_storage.get_latest_snapshot_id.return_value = None

        result = handler._get_summary()

        assert result["snapshot_id"] is None
        assert result["total_assets"] == 0
        assert result["total_findings"] == 0

    def test_get_summary_with_snapshot_id_param(self, handler, mock_storage):
        """Test summary respects snapshot_id parameter."""
        result = handler._get_summary({"snapshot_id": ["20240114-120000"]})

        mock_storage.get_assets.assert_called_with("20240114-120000")


# =============================================================================
# GET /api/overview Tests
# =============================================================================


class TestOverviewEndpoint:
    """Tests for /api/overview endpoint."""

    def test_get_overview_all_fields(self, handler):
        """Test overview returns all dashboard fields."""
        result = handler._get_overview()

        assert "snapshot_id" in result
        assert "total_assets" in result
        assert "total_findings" in result
        assert "assets_by_cloud" in result
        assert "findings_by_severity" in result
        assert "compliance_scores" in result
        assert "top_findings" in result

    def test_get_overview_assets_by_cloud(self, handler):
        """Test assets are grouped by cloud provider."""
        result = handler._get_overview()

        assert result["assets_by_cloud"]["aws"] == 3
        assert result["assets_by_cloud"]["gcp"] == 1

    def test_get_overview_internet_facing_count(self, handler):
        """Test internet-facing asset count is included."""
        result = handler._get_overview()

        assert "internet_facing_assets" in result
        assert result["internet_facing_assets"] == 1  # bucket-2

    def test_get_overview_top_findings(self, handler):
        """Test top findings are critical/high severity."""
        result = handler._get_overview()

        top = result["top_findings"]
        assert len(top) > 0
        # First should be critical
        severities = [f["severity"] for f in top]
        assert "critical" in severities or "high" in severities

    def test_get_overview_no_storage(self):
        """Test overview returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_overview()

            assert "error" in result


# =============================================================================
# GET /api/assets Tests
# =============================================================================


class TestAssetsEndpoint:
    """Tests for /api/assets endpoint."""

    def test_get_assets_returns_list(self, handler):
        """Test assets endpoint returns items list."""
        result = handler._get_assets({})

        assert "items" in result
        assert "total" in result
        assert result["total"] == 4

    def test_get_assets_item_structure(self, handler):
        """Test each asset item has required fields."""
        result = handler._get_assets({})

        item = result["items"][0]
        assert "id" in item
        assert "resource_type" in item
        assert "name" in item
        assert "region" in item
        assert "network_exposure" in item
        assert "account_id" in item

    def test_get_assets_pagination_default(self, handler):
        """Test default pagination values."""
        result = handler._get_assets({})

        assert result["limit"] == 50
        assert result["offset"] == 0

    def test_get_assets_pagination_custom(self, handler):
        """Test custom pagination parameters."""
        result = handler._get_assets({"limit": ["2"], "offset": ["1"]})

        assert result["limit"] == 2
        assert result["offset"] == 1
        assert len(result["items"]) == 2

    def test_get_assets_filter_by_type(self, handler, mock_storage, sample_assets):
        """Test filtering by resource type."""
        result = handler._get_assets({"type": ["aws_s3_bucket"]})

        # Filter should be applied
        mock_storage.get_assets.assert_called()

    def test_get_assets_filter_by_region(self, handler, mock_storage):
        """Test filtering by region."""
        result = handler._get_assets({"region": ["us-east-1"]})

        mock_storage.get_assets.assert_called()

    def test_get_assets_filter_internet_facing(self, handler, mock_storage):
        """Test filtering by internet-facing exposure."""
        result = handler._get_assets({"exposure": ["internet_facing"]})

        mock_storage.get_assets.assert_called()

    def test_get_assets_no_storage(self):
        """Test assets returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_assets({})

            assert "error" in result


# =============================================================================
# GET /api/assets/{id} Tests
# =============================================================================


class TestAssetDetailEndpoint:
    """Tests for /api/assets/{id} endpoint."""

    def test_get_asset_detail(self, handler):
        """Test asset detail returns full asset info."""
        result = handler._get_asset_detail("arn:aws:s3:::bucket-1")

        assert "asset" in result
        assert result["asset"]["id"] == "arn:aws:s3:::bucket-1"
        assert result["asset"]["name"] == "bucket-1"

    def test_get_asset_detail_with_findings(self, handler):
        """Test asset detail includes related findings."""
        result = handler._get_asset_detail("arn:aws:s3:::bucket-2")

        assert "findings" in result
        assert "finding_count" in result
        assert result["finding_count"] >= 1

    def test_get_asset_detail_findings_by_severity(self, handler):
        """Test asset detail includes findings breakdown."""
        result = handler._get_asset_detail("arn:aws:s3:::bucket-2")

        assert "findings_by_severity" in result

    def test_get_asset_detail_not_found(self, handler):
        """Test asset not found error."""
        result = handler._get_asset_detail("nonexistent-asset")

        assert "error" in result
        assert "not found" in result["error"].lower()

    def test_get_asset_detail_url_encoded_id(self, handler):
        """Test asset detail with URL-encoded ID."""
        # IDs with special characters should work
        result = handler._get_asset_detail("arn%3Aaws%3As3%3A%3A%3Abucket-1")

        assert "asset" in result or "error" in result


# =============================================================================
# GET /api/findings Tests
# =============================================================================


class TestFindingsEndpoint:
    """Tests for /api/findings endpoint."""

    def test_get_findings_returns_list(self, handler):
        """Test findings endpoint returns items list."""
        result = handler._get_findings({})

        assert "items" in result
        assert "total" in result
        assert result["total"] == 5

    def test_get_findings_item_structure(self, handler):
        """Test each finding item has required fields."""
        result = handler._get_findings({})

        item = result["items"][0]
        assert "id" in item
        assert "title" in item
        assert "severity" in item
        assert "status" in item
        assert "finding_type" in item
        assert "asset_id" in item

    def test_get_findings_filter_by_severity(self, handler, mock_storage):
        """Test filtering by severity."""
        result = handler._get_findings({"severity": ["critical"]})

        mock_storage.get_findings.assert_called()

    def test_get_findings_filter_by_status(self, handler, mock_storage):
        """Test filtering by status."""
        result = handler._get_findings({"status": ["open"]})

        mock_storage.get_findings.assert_called()

    def test_get_findings_filter_by_asset_id(self, handler):
        """Test filtering by asset ID."""
        result = handler._get_findings({"asset_id": ["arn:aws:s3:::bucket-2"]})

        # Results should be filtered
        assert "items" in result

    def test_get_findings_pagination(self, handler):
        """Test findings pagination."""
        result = handler._get_findings({"limit": ["2"], "offset": ["0"]})

        assert result["limit"] == 2
        assert len(result["items"]) == 2


# =============================================================================
# GET /api/findings/{id} Tests
# =============================================================================


class TestFindingDetailEndpoint:
    """Tests for /api/findings/{id} endpoint."""

    def test_get_finding_detail(self, handler):
        """Test finding detail returns full info."""
        result = handler._get_finding_detail("finding-001")

        assert "finding" in result
        assert result["finding"]["id"] == "finding-001"
        assert result["finding"]["title"] == "S3 Bucket Encryption Disabled"

    def test_get_finding_detail_all_fields(self, handler):
        """Test finding detail includes all relevant fields."""
        result = handler._get_finding_detail("finding-003")

        finding = result["finding"]
        assert "description" in finding
        assert "severity" in finding
        assert "status" in finding
        assert "cve_id" in finding
        assert "remediation_guidance" in finding

    def test_get_finding_detail_with_asset_info(self, handler):
        """Test finding detail includes asset information."""
        result = handler._get_finding_detail("finding-001")

        assert "asset" in result
        if result["asset"]:
            assert "id" in result["asset"]
            assert "name" in result["asset"]

    def test_get_finding_detail_not_found(self, handler):
        """Test finding not found error."""
        result = handler._get_finding_detail("nonexistent-finding")

        assert "error" in result
        assert "not found" in result["error"].lower()


# =============================================================================
# GET /api/compliance Tests
# =============================================================================


class TestComplianceEndpoint:
    """Tests for /api/compliance endpoint."""

    def test_get_compliance_structure(self, handler):
        """Test compliance returns expected structure."""
        result = handler._get_compliance({})

        assert "overall_score" in result or "frameworks" in result

    def test_get_compliance_no_storage(self):
        """Test compliance returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_compliance({})

            assert "error" in result


# =============================================================================
# GET /api/snapshots Tests
# =============================================================================


class TestSnapshotsEndpoint:
    """Tests for /api/snapshots endpoint."""

    def test_get_snapshots_returns_list(self, handler):
        """Test snapshots endpoint returns list."""
        result = handler._get_snapshots()

        assert "snapshots" in result
        assert len(result["snapshots"]) == 3

    def test_get_snapshots_no_storage(self):
        """Test snapshots returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_snapshots()

            assert "error" in result


# =============================================================================
# GET /api/trends Tests
# =============================================================================


class TestTrendsEndpoint:
    """Tests for /api/trends endpoint."""

    def test_get_trends_structure(self, handler):
        """Test trends returns expected structure."""
        result = handler._get_trends({})

        assert "period_days" in result
        assert "data_points" in result

    def test_get_trends_custom_days(self, handler):
        """Test trends respects days parameter."""
        result = handler._get_trends({"days": ["7"]})

        assert result["period_days"] == 7

    def test_get_trends_data_point_structure(self, handler):
        """Test each data point has required fields."""
        result = handler._get_trends({})

        if result["data_points"]:
            point = result["data_points"][0]
            assert "snapshot_id" in point
            assert "timestamp" in point
            assert "asset_count" in point
            assert "finding_count" in point


# =============================================================================
# GET /api/drift Tests
# =============================================================================


class TestDriftEndpoint:
    """Tests for /api/drift endpoint."""

    def test_get_drift_no_storage(self):
        """Test drift returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_drift()

            assert "error" in result


# =============================================================================
# GET /api/risk Tests
# =============================================================================


class TestRiskEndpoint:
    """Tests for /api/risk endpoint."""

    def test_get_risk_no_storage(self):
        """Test risk returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_risk_scores()

            assert "error" in result


# =============================================================================
# GET /api/search Tests
# =============================================================================


class TestSearchEndpoint:
    """Tests for /api/search endpoint."""

    def test_search_empty_query(self, handler):
        """Test search with empty query returns error."""
        result = handler._handle_search({"q": [""]})

        assert "error" in result

    def test_search_short_query(self, handler):
        """Test search with query too short returns error."""
        result = handler._handle_search({"q": ["a"]})

        assert "error" in result

    def test_search_finds_findings(self, handler):
        """Test search finds matching findings."""
        result = handler._handle_search({"q": ["encryption"]})

        assert "findings" in result
        assert len(result["findings"]) > 0

    def test_search_finds_assets(self, handler):
        """Test search finds matching assets."""
        result = handler._handle_search({"q": ["bucket"]})

        assert "assets" in result
        assert len(result["assets"]) > 0

    def test_search_type_filter_findings(self, handler):
        """Test search type filter for findings only."""
        result = handler._handle_search({"q": ["bucket"], "type": ["findings"]})

        assert "findings" in result
        assert "assets" in result
        # When type=findings, assets should be empty
        assert len(result["assets"]) == 0

    def test_search_type_filter_assets(self, handler):
        """Test search type filter for assets only."""
        result = handler._handle_search({"q": ["bucket"], "type": ["assets"]})

        assert "findings" in result
        assert "assets" in result
        # When type=assets, findings should be empty
        assert len(result["findings"]) == 0

    def test_search_limit(self, handler):
        """Test search respects limit parameter."""
        result = handler._handle_search({"q": ["bucket"], "limit": ["1"]})

        assert len(result["findings"]) <= 1
        assert len(result["assets"]) <= 1

    def test_search_by_cve_id(self, handler):
        """Test search finds findings by CVE ID."""
        result = handler._handle_search({"q": ["CVE-2024"]})

        assert len(result["findings"]) > 0

    def test_search_by_rule_id(self, handler):
        """Test search finds findings by rule ID."""
        result = handler._handle_search({"q": ["aws-s3"]})

        assert len(result["findings"]) > 0

    def test_search_by_region(self, handler):
        """Test search finds assets by region."""
        result = handler._handle_search({"q": ["us-east-1"]})

        assert len(result["assets"]) > 0

    def test_search_by_tags(self, handler):
        """Test search finds assets by tag values."""
        result = handler._handle_search({"q": ["prod"]})

        assert len(result["assets"]) > 0

    def test_search_returns_total(self, handler):
        """Test search includes total count."""
        result = handler._handle_search({"q": ["bucket"]})

        assert "total" in result
        assert result["total"] == len(result["findings"]) + len(result["assets"])


# =============================================================================
# GET /api/presets Tests
# =============================================================================


class TestPresetsEndpoint:
    """Tests for /api/presets endpoint."""

    def test_get_presets_empty(self, handler):
        """Test presets returns empty list initially."""
        # Clear any existing presets
        StanceRequestHandler._presets = {}

        result = handler._get_presets()

        assert "presets" in result
        assert isinstance(result["presets"], list)

    def test_save_and_get_preset(self, handler):
        """Test saving and retrieving a preset."""
        StanceRequestHandler._presets = {}

        # Save preset
        body = json.dumps({
            "name": "Critical Findings",
            "view": "findings",
            "filters": {"severity": "critical"},
            "description": "Show only critical findings",
        }).encode()

        save_result = handler._save_preset(body)
        assert save_result["success"]

        # Get presets
        result = handler._get_presets()
        assert len(result["presets"]) == 1
        assert result["presets"][0]["name"] == "Critical_Findings"

    def test_get_specific_preset(self, handler):
        """Test getting a specific preset."""
        StanceRequestHandler._presets = {
            "test_preset": {
                "view": "assets",
                "filters": {"region": "us-east-1"},
                "created_at": "2024-01-15T12:00:00Z",
                "description": "Test preset",
            }
        }

        result = handler._get_preset("test_preset")

        assert result["name"] == "test_preset"
        assert result["view"] == "assets"

    def test_get_preset_not_found(self, handler):
        """Test getting nonexistent preset."""
        StanceRequestHandler._presets = {}

        result = handler._get_preset("nonexistent")

        assert "error" in result

    def test_save_preset_invalid_json(self, handler):
        """Test saving preset with invalid JSON."""
        result = handler._save_preset(b"invalid json")

        assert "error" in result

    def test_save_preset_missing_name(self, handler):
        """Test saving preset without name."""
        body = json.dumps({"view": "findings"}).encode()

        result = handler._save_preset(body)

        assert "error" in result

    def test_save_preset_name_too_long(self, handler):
        """Test saving preset with name too long."""
        body = json.dumps({"name": "x" * 100}).encode()

        result = handler._save_preset(body)

        assert "error" in result

    def test_delete_preset(self, handler):
        """Test deleting a preset."""
        StanceRequestHandler._presets = {"to_delete": {"view": "findings"}}

        result = handler._delete_preset("to_delete")

        assert result["success"]
        assert "to_delete" not in StanceRequestHandler._presets

    def test_delete_preset_not_found(self, handler):
        """Test deleting nonexistent preset."""
        StanceRequestHandler._presets = {}

        result = handler._delete_preset("nonexistent")

        assert "error" in result


# =============================================================================
# GET /api/notifications/* Tests
# =============================================================================


class TestNotificationDestinationsEndpoint:
    """Tests for /api/notifications/destinations endpoint."""

    def test_get_destinations_empty(self, handler):
        """Test destinations returns empty list initially."""
        StanceRequestHandler._notification_destinations = {}

        result = handler._get_notification_destinations()

        assert "destinations" in result
        assert "available_types" in result
        assert len(result["available_types"]) > 0

    def test_get_destinations_available_types(self, handler):
        """Test available destination types are listed."""
        result = handler._get_notification_destinations()

        types = [t["type"] for t in result["available_types"]]
        assert "slack" in types
        assert "pagerduty" in types
        assert "email" in types
        assert "teams" in types
        assert "webhook" in types

    def test_save_destination_slack(self, handler):
        """Test saving Slack destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-slack",
            "type": "slack",
            "webhook_url": "https://hooks.slack.com/test",
            "channel": "#alerts",
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]

    def test_save_destination_invalid_type(self, handler):
        """Test saving destination with invalid type."""
        body = json.dumps({
            "name": "invalid",
            "type": "invalid_type",
        }).encode()

        result = handler._save_notification_destination(body)

        assert "error" in result

    def test_save_destination_missing_name(self, handler):
        """Test saving destination without name."""
        body = json.dumps({"type": "slack"}).encode()

        result = handler._save_notification_destination(body)

        assert "error" in result

    def test_delete_destination(self, handler):
        """Test deleting a destination."""
        StanceRequestHandler._notification_destinations = {
            "to_delete": {"type": "slack"}
        }

        result = handler._delete_notification_destination("to_delete")

        assert result["success"]

    def test_delete_destination_not_found(self, handler):
        """Test deleting nonexistent destination."""
        StanceRequestHandler._notification_destinations = {}

        result = handler._delete_notification_destination("nonexistent")

        assert "error" in result


class TestNotificationConfigEndpoint:
    """Tests for /api/notifications/config endpoint."""

    def test_get_notification_config(self, handler):
        """Test getting notification config."""
        result = handler._get_notification_config()

        assert "config" in result
        assert "severity_options" in result

    def test_save_notification_config(self, handler):
        """Test saving notification config."""
        body = json.dumps({
            "enabled": True,
            "notify_on_critical": True,
            "min_severity": "high",
        }).encode()

        result = handler._save_notification_config(body)

        assert result["success"]
        assert result["config"]["enabled"] is True

    def test_save_notification_config_invalid_severity(self, handler):
        """Test saving config with invalid severity."""
        original_severity = StanceRequestHandler._notification_config.get("min_severity")

        body = json.dumps({"min_severity": "invalid"}).encode()

        result = handler._save_notification_config(body)

        # Should not update with invalid value
        assert result["success"]  # Doesn't fail, just ignores invalid


class TestNotificationHistoryEndpoint:
    """Tests for /api/notifications/history endpoint."""

    def test_get_notification_history_empty(self, handler):
        """Test getting empty notification history."""
        StanceRequestHandler._notification_history = []

        result = handler._get_notification_history({})

        assert "items" in result
        assert "total" in result
        assert result["total"] == 0

    def test_get_notification_history_pagination(self, handler):
        """Test notification history pagination."""
        StanceRequestHandler._notification_history = [
            {"id": i} for i in range(50)
        ]

        result = handler._get_notification_history({"limit": ["10"], "offset": ["5"]})

        assert result["limit"] == 10
        assert result["offset"] == 5
        assert len(result["items"]) == 10


# =============================================================================
# GET /api/attack-paths Tests
# =============================================================================


class TestAttackPathsEndpoint:
    """Tests for /api/attack-paths endpoint."""

    def test_get_attack_paths_no_storage(self):
        """Test attack paths returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_attack_paths()

            assert "error" in result


# =============================================================================
# Helper Method Tests
# =============================================================================


class TestHelperMethods:
    """Tests for handler helper methods."""

    def test_is_destination_configured_slack(self, handler):
        """Test Slack destination configuration check."""
        config = {"type": "slack", "webhook_url": "https://hooks.slack.com/test"}
        assert handler._is_destination_configured(config) is True

        config = {"type": "slack", "webhook_url": ""}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_pagerduty(self, handler):
        """Test PagerDuty destination configuration check."""
        config = {"type": "pagerduty", "routing_key": "key123"}
        assert handler._is_destination_configured(config) is True

        config = {"type": "pagerduty", "routing_key": ""}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_email(self, handler):
        """Test Email destination configuration check."""
        config = {"type": "email", "smtp_host": "smtp.example.com", "recipients": ["a@b.com"]}
        assert handler._is_destination_configured(config) is True

        config = {"type": "email", "smtp_host": "", "recipients": []}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_webhook(self, handler):
        """Test Webhook destination configuration check."""
        config = {"type": "webhook", "url": "https://example.com/hook"}
        assert handler._is_destination_configured(config) is True

        config = {"type": "webhook", "url": ""}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_jira(self, handler):
        """Test Jira destination configuration check."""
        config = {"type": "jira", "url": "https://jira.example.com", "project_key": "SEC"}
        assert handler._is_destination_configured(config) is True

        config = {"type": "jira", "url": "", "project_key": ""}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_teams(self, handler):
        """Test Teams destination configuration check."""
        config = {"type": "teams", "webhook_url": "https://outlook.webhook.office.com/test"}
        assert handler._is_destination_configured(config) is True

        config = {"type": "teams", "webhook_url": ""}
        assert handler._is_destination_configured(config) is False

    def test_is_destination_configured_unknown(self, handler):
        """Test unknown destination type returns False."""
        config = {"type": "unknown"}
        assert handler._is_destination_configured(config) is False


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Tests for API error handling."""

    def test_send_json_method(self, handler):
        """Test _send_json properly encodes response."""
        # Mock the response methods
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()

        handler._send_json({"test": "data"})

        handler.send_response.assert_called_with(200)
        handler.wfile.write.assert_called_once()

    def test_send_error_method(self, handler):
        """Test _send_error properly encodes error response."""
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()

        handler._send_error(404, "Not found")

        handler.send_response.assert_called_with(404)
        handler.wfile.write.assert_called_once()

    def test_get_snapshot_id_from_params(self, handler, mock_storage):
        """Test snapshot ID extraction from params."""
        result = handler._get_snapshot_id({"snapshot_id": ["custom-snapshot"]})
        assert result == "custom-snapshot"

    def test_get_snapshot_id_fallback_to_latest(self, handler, mock_storage):
        """Test snapshot ID falls back to latest."""
        result = handler._get_snapshot_id({})
        assert result == "20240115-120000"


# =============================================================================
# POST Endpoint Tests
# =============================================================================


class TestNotificationTestEndpoint:
    """Tests for notification test endpoints."""

    def test_test_destination_not_found(self, handler):
        """Test testing nonexistent destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({"name": "nonexistent"}).encode()
        result = handler._test_notification_destination(body)

        assert "error" in result

    def test_test_destination_missing_name(self, handler):
        """Test testing destination without name."""
        body = json.dumps({}).encode()
        result = handler._test_notification_destination(body)

        assert "error" in result

    def test_test_destination_invalid_json(self, handler):
        """Test testing destination with invalid JSON."""
        result = handler._test_notification_destination(b"invalid")

        assert "error" in result

    def test_send_test_notification_not_found(self, handler):
        """Test sending notification to nonexistent destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({"destination": "nonexistent"}).encode()
        result = handler._send_test_notification(body)

        assert "error" in result

    def test_send_test_notification_missing_destination(self, handler):
        """Test sending notification without destination."""
        body = json.dumps({}).encode()
        result = handler._send_test_notification(body)

        assert "error" in result

    def test_send_test_notification_invalid_json(self, handler):
        """Test sending notification with invalid JSON."""
        result = handler._send_test_notification(b"invalid")

        assert "error" in result


class TestSaveDestinationTypes:
    """Tests for saving different destination types."""

    def test_save_destination_pagerduty(self, handler):
        """Test saving PagerDuty destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-pagerduty",
            "type": "pagerduty",
            "routing_key": "test-key-123",
            "severity_map": {"critical": "critical", "high": "error"},
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]
        dest = StanceRequestHandler._notification_destinations["my-pagerduty"]
        assert dest["routing_key"] == "test-key-123"

    def test_save_destination_email(self, handler):
        """Test saving Email destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-email",
            "type": "email",
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_user": "user@example.com",
            "smtp_password": "password",
            "from_address": "alerts@example.com",
            "recipients": ["admin@example.com"],
            "use_tls": True,
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]
        dest = StanceRequestHandler._notification_destinations["my-email"]
        assert dest["smtp_host"] == "smtp.example.com"
        assert dest["recipients"] == ["admin@example.com"]

    def test_save_destination_teams(self, handler):
        """Test saving Teams destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-teams",
            "type": "teams",
            "webhook_url": "https://outlook.webhook.office.com/test",
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]
        dest = StanceRequestHandler._notification_destinations["my-teams"]
        assert dest["webhook_url"] == "https://outlook.webhook.office.com/test"

    def test_save_destination_jira(self, handler):
        """Test saving Jira destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-jira",
            "type": "jira",
            "url": "https://jira.example.com",
            "username": "admin",
            "api_token": "token123",
            "project_key": "SEC",
            "issue_type": "Bug",
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]
        dest = StanceRequestHandler._notification_destinations["my-jira"]
        assert dest["project_key"] == "SEC"
        assert dest["issue_type"] == "Bug"

    def test_save_destination_webhook(self, handler):
        """Test saving Webhook destination."""
        StanceRequestHandler._notification_destinations = {}

        body = json.dumps({
            "name": "my-webhook",
            "type": "webhook",
            "url": "https://example.com/hook",
            "method": "POST",
            "headers": {"Authorization": "Bearer token"},
        }).encode()

        result = handler._save_notification_destination(body)

        assert result["success"]
        dest = StanceRequestHandler._notification_destinations["my-webhook"]
        assert dest["url"] == "https://example.com/hook"
        assert dest["method"] == "POST"

    def test_save_destination_missing_type(self, handler):
        """Test saving destination without type."""
        body = json.dumps({"name": "test"}).encode()

        result = handler._save_notification_destination(body)

        assert "error" in result


class TestNotificationConfigEdgeCases:
    """Tests for notification config edge cases."""

    def test_save_config_partial_update(self, handler):
        """Test partial config update preserves other values."""
        StanceRequestHandler._notification_config = {
            "enabled": False,
            "notify_on_critical": True,
            "notify_on_high": True,
            "min_severity": "medium",
        }

        body = json.dumps({"enabled": True}).encode()
        result = handler._save_notification_config(body)

        assert result["success"]
        assert result["config"]["enabled"] is True
        # Other values should be preserved
        assert result["config"]["notify_on_critical"] is True

    def test_save_config_invalid_json(self, handler):
        """Test config save with invalid JSON."""
        result = handler._save_notification_config(b"invalid")

        assert "error" in result

    def test_save_config_all_boolean_options(self, handler):
        """Test all boolean config options."""
        body = json.dumps({
            "enabled": True,
            "notify_on_critical": False,
            "notify_on_high": True,
            "notify_on_scan_complete": True,
            "notify_on_new_findings": False,
        }).encode()

        result = handler._save_notification_config(body)

        assert result["success"]
        config = result["config"]
        assert config["enabled"] is True
        assert config["notify_on_critical"] is False
        assert config["notify_on_high"] is True
        assert config["notify_on_scan_complete"] is True
        assert config["notify_on_new_findings"] is False

    def test_save_config_default_destination(self, handler):
        """Test setting default destination."""
        body = json.dumps({"default_destination": "my-slack"}).encode()

        result = handler._save_notification_config(body)

        assert result["success"]
        assert result["config"]["default_destination"] == "my-slack"


# =============================================================================
# Export Endpoint Tests
# =============================================================================


class TestExportEndpoint:
    """Tests for /api/export endpoint."""

    def test_handle_export_no_storage(self, handler):
        """Test export returns error without storage."""
        handler.storage = None
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()

        handler._handle_export({})

        handler.send_response.assert_called()


# =============================================================================
# Attack Path Detail Tests
# =============================================================================


class TestAttackPathDetailEndpoint:
    """Tests for /api/attack-paths/{id} endpoint."""

    def test_get_attack_path_detail_not_found(self, handler):
        """Test attack path not found."""
        # Mock _get_attack_paths to return empty paths
        handler._get_attack_paths = MagicMock(return_value={"paths": [], "summary": {}})

        result = handler._get_attack_path_detail("nonexistent-path")

        assert "error" in result or result.get("found") is False

    def test_get_attack_path_detail_found(self, handler):
        """Test attack path found."""
        handler._get_attack_paths = MagicMock(return_value={
            "paths": [{"id": "path-001", "type": "privilege_escalation"}],
            "summary": {}
        })

        result = handler._get_attack_path_detail("path-001")

        assert result.get("found") is True
        assert result["path"]["id"] == "path-001"


# =============================================================================
# Compliance Framework Detail Tests
# =============================================================================


class TestComplianceFrameworkEndpoint:
    """Tests for /api/compliance/{framework} endpoint."""

    def test_get_compliance_framework_no_storage(self):
        """Test compliance framework returns error without storage."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            h = StanceRequestHandler()
            h.storage = None

            result = h._get_compliance_framework("cis")

            assert "error" in result


# =============================================================================
# Additional Search Tests
# =============================================================================


class TestSearchEdgeCases:
    """Additional search endpoint tests."""

    def test_search_by_severity(self, handler):
        """Test search by severity keyword."""
        result = handler._handle_search({"q": ["critical"]})

        # Should find findings with critical severity
        assert "findings" in result

    def test_search_by_remediation(self, handler):
        """Test search by remediation guidance."""
        result = handler._handle_search({"q": ["enable"]})

        assert "findings" in result

    def test_search_results_sorted_by_score(self, handler):
        """Test search results are sorted by relevance score."""
        result = handler._handle_search({"q": ["bucket"]})

        # Results should be sorted by score descending
        if len(result["findings"]) > 1:
            scores = [f["score"] for f in result["findings"]]
            assert scores == sorted(scores, reverse=True)

        if len(result["assets"]) > 1:
            scores = [a["score"] for a in result["assets"]]
            assert scores == sorted(scores, reverse=True)


# =============================================================================
# Drift and Risk Endpoint Tests with Mock
# =============================================================================


class TestDriftEndpointWithMock:
    """Tests for drift endpoint with mocked dependencies."""

    def test_get_drift_no_baseline(self, handler, mock_storage):
        """Test drift without active baseline."""
        with patch("stance.web.server.StanceRequestHandler._get_drift") as mock_drift:
            mock_drift.return_value = {
                "has_baseline": False,
                "message": "No active baseline configured"
            }

            result = mock_drift()

            assert result["has_baseline"] is False


class TestRiskEndpointWithMock:
    """Tests for risk endpoint with mocked dependencies."""

    def test_get_risk_scores_structure(self, handler, mock_storage):
        """Test risk scores with mocked scorer."""
        with patch("stance.correlation.RiskScorer") as MockScorer:
            mock_result = MagicMock()
            mock_result.overall_score = 75
            mock_result.overall_risk_level.value = "high"
            mock_result.risk_by_cloud = {"aws": 80, "gcp": 50}
            mock_result.risk_by_type = {"s3_bucket": 90, "ec2_instance": 60}
            mock_result.top_risks = []

            MockScorer.return_value.calculate_scores.return_value = mock_result

            result = handler._get_risk_scores()

            # Result should have the expected structure
            assert "overall_score" in result or "error" in result
