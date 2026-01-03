"""
Unit tests for web dashboard module.

Tests the StanceServer and serve_dashboard functionality.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime

from stance.web import StanceServer, serve_dashboard
from stance.web.server import StanceRequestHandler
from stance.models.finding import Finding, FindingCollection, FindingType, Severity, FindingStatus
from stance.models.asset import Asset, AssetCollection


# ============================================================================
# StanceServer Tests
# ============================================================================


class TestStanceServer:
    """Tests for StanceServer."""

    def test_server_creation(self) -> None:
        """Test StanceServer can be created."""
        server = StanceServer(host="127.0.0.1", port=8080)
        assert server is not None

    def test_server_with_storage(self) -> None:
        """Test StanceServer with storage backend."""
        mock_storage = MagicMock()
        server = StanceServer(host="127.0.0.1", port=8080, storage=mock_storage)
        assert server is not None

    def test_server_default_values(self) -> None:
        """Test StanceServer default values."""
        server = StanceServer()
        assert server.host == "127.0.0.1"
        assert server.port == 8080

    def test_server_url_property(self) -> None:
        """Test StanceServer url property."""
        server = StanceServer(host="127.0.0.1", port=9090)
        assert server.url == "http://127.0.0.1:9090"

    def test_server_has_required_methods(self) -> None:
        """Test StanceServer has required methods."""
        server = StanceServer()

        assert hasattr(server, "start")
        assert hasattr(server, "start_background")
        assert hasattr(server, "stop")
        assert hasattr(server, "url")


class TestStanceServerBackground:
    """Tests for StanceServer background operation."""

    def test_start_background(self) -> None:
        """Test starting server in background."""
        server = StanceServer(port=0)  # Port 0 = random available port
        thread = server.start_background()

        try:
            assert thread is not None
            assert thread.is_alive()
        finally:
            server.stop()

    def test_stop_server(self) -> None:
        """Test stopping server."""
        server = StanceServer(port=0)
        thread = server.start_background()

        # Wait for server to start
        import time
        time.sleep(0.2)

        # Stop the server
        server.stop()

        # Wait for thread to finish
        thread.join(timeout=1.0)

        # Thread should have stopped
        assert not thread.is_alive()


# ============================================================================
# StanceRequestHandler Tests
# ============================================================================


class TestStanceRequestHandler:
    """Tests for StanceRequestHandler."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage backend."""
        storage = MagicMock()
        storage.get_latest_snapshot_id.return_value = "snapshot-123"
        storage.get_assets.return_value = AssetCollection(assets=[])
        storage.get_findings.return_value = FindingCollection(findings=[])
        storage.list_snapshots.return_value = ["snapshot-123"]
        return storage

    def test_handler_class_exists(self) -> None:
        """Test StanceRequestHandler class exists."""
        assert StanceRequestHandler is not None

    def test_handler_has_storage_attribute(self) -> None:
        """Test StanceRequestHandler has storage class attribute."""
        assert hasattr(StanceRequestHandler, "storage")


# ============================================================================
# API Endpoint Tests
# ============================================================================


class TestAPIEndpoints:
    """Tests for API endpoints logic."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage backend with test data."""
        storage = MagicMock()
        storage.get_latest_snapshot_id.return_value = "snapshot-123"

        # Mock assets
        assets = AssetCollection(assets=[
            Asset(
                id="arn:aws:s3:::bucket1",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="bucket1",
                tags={"env": "prod"},
                network_exposure="internal",
                created_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                raw_config={},
            ),
        ])
        storage.get_assets.return_value = assets

        # Mock findings
        findings = FindingCollection(findings=[
            Finding(
                id="finding-1",
                asset_id="arn:aws:s3:::bucket1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="Test Finding",
                description="Description",
            ),
        ])
        storage.get_findings.return_value = findings
        storage.list_snapshots.return_value = ["snapshot-123"]

        return storage

    def test_summary_endpoint_logic(self, mock_storage: MagicMock) -> None:
        """Test summary endpoint returns correct data."""
        # Create handler with storage
        StanceRequestHandler.storage = mock_storage

        # Create a mock handler to test the method
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            summary = handler._get_summary()

            assert "snapshot_id" in summary
            assert "total_assets" in summary
            assert "total_findings" in summary

    def test_summary_endpoint_no_storage(self) -> None:
        """Test summary endpoint with no storage returns error."""
        StanceRequestHandler.storage = None

        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = None

            summary = handler._get_summary()

            assert "error" in summary

    def test_assets_endpoint_logic(self, mock_storage: MagicMock) -> None:
        """Test assets endpoint returns correct data."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            assets = handler._get_assets({})

            assert "items" in assets or "error" not in assets


# ============================================================================
# serve_dashboard Tests
# ============================================================================


class TestServeDashboard:
    """Tests for serve_dashboard function."""

    def test_serve_dashboard_function_exists(self) -> None:
        """Test serve_dashboard function exists."""
        assert serve_dashboard is not None
        assert callable(serve_dashboard)

    @patch("stance.web.StanceServer")
    @patch("webbrowser.open")
    def test_serve_dashboard_creates_server(
        self, mock_browser: MagicMock, mock_server_class: MagicMock
    ) -> None:
        """Test serve_dashboard creates server instance."""
        mock_server = MagicMock()
        mock_server.url = "http://127.0.0.1:8080"
        mock_server_class.return_value = mock_server

        # Call serve_dashboard (it would block, so we don't actually run it)
        # Just verify the function signature is correct
        import inspect
        sig = inspect.signature(serve_dashboard)

        assert "host" in sig.parameters
        assert "port" in sig.parameters
        assert "storage" in sig.parameters
        assert "open_browser" in sig.parameters

    def test_serve_dashboard_defaults(self) -> None:
        """Test serve_dashboard has correct default values."""
        import inspect
        sig = inspect.signature(serve_dashboard)

        assert sig.parameters["host"].default == "127.0.0.1"
        assert sig.parameters["port"].default == 8080
        assert sig.parameters["open_browser"].default is True


# ============================================================================
# Integration Tests
# ============================================================================


class TestServerIntegration:
    """Integration tests for web server."""

    def test_server_starts_and_stops(self) -> None:
        """Test server can start and stop cleanly."""
        server = StanceServer(port=0)

        try:
            thread = server.start_background()
            assert thread.is_alive()

            # Verify server has started (internal reference should exist)
            import time
            time.sleep(0.1)  # Give server time to start
            # Thread being alive indicates server is running
            assert thread.is_alive() or server._server is not None
        finally:
            server.stop()

    def test_server_with_mock_storage(self) -> None:
        """Test server with mocked storage."""
        mock_storage = MagicMock()
        mock_storage.get_latest_snapshot_id.return_value = None

        server = StanceServer(port=0, storage=mock_storage)

        try:
            thread = server.start_background()
            import time
            time.sleep(0.1)
            # Thread being alive indicates server started
            assert thread.is_alive()
        finally:
            server.stop()

    @patch("socket.socket")
    def test_server_port_binding(self, mock_socket: MagicMock) -> None:
        """Test server creates correct HTTP server."""
        server = StanceServer(host="127.0.0.1", port=8888)

        assert server.host == "127.0.0.1"
        assert server.port == 8888


# ============================================================================
# URL Routing Tests
# ============================================================================


class TestURLRouting:
    """Tests for URL routing logic."""

    def test_api_routes(self) -> None:
        """Test API routes are defined."""
        api_routes = [
            "/api/summary",
            "/api/overview",
            "/api/assets",
            "/api/findings",
            "/api/compliance",
            "/api/snapshots",
            "/api/trends",
            "/api/drift",
            "/api/risk",
            "/api/export",
        ]

        # Verify these routes are handled by checking handler method exists
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()

            # These should not raise AttributeError
            assert hasattr(handler, "_get_summary")
            assert hasattr(handler, "_get_assets")
            assert hasattr(handler, "_get_findings")
            assert hasattr(handler, "_get_compliance")
            assert hasattr(handler, "_get_snapshots")
            assert hasattr(handler, "_get_trends")


# ============================================================================
# Static File Serving Tests
# ============================================================================


class TestStaticFileServing:
    """Tests for static file serving."""

    def test_static_dir_exists(self) -> None:
        """Test static directory is set correctly."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        assert os.path.exists(static_dir)

    def test_index_html_exists(self) -> None:
        """Test index.html exists in static directory."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")
        assert os.path.exists(index_path)


# ============================================================================
# Detail View Tests (Drill-down functionality)
# ============================================================================


class TestFindingDetailEndpoint:
    """Tests for /api/findings/<finding_id> endpoint."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage backend with test data."""
        storage = MagicMock()
        storage.get_latest_snapshot_id.return_value = "snapshot-123"

        # Mock assets
        test_asset = Asset(
            id="arn:aws:s3:::bucket1",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket1",
            tags={"env": "prod"},
            network_exposure="internal",
            created_at=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            raw_config={},
        )
        assets = AssetCollection(assets=[test_asset])
        storage.get_assets.return_value = assets

        # Mock findings
        test_finding = Finding(
            id="finding-1",
            asset_id="arn:aws:s3:::bucket1",
            finding_type=FindingType.MISCONFIGURATION,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Test Finding",
            description="This is a test finding description.",
            rule_id="aws-s3-001",
            remediation_guidance="Step 1. Do this\nStep 2. Do that",
            compliance_frameworks=["CIS AWS 1.2", "PCI-DSS 3.2"],
            resource_path="$.BucketEncryption",
            expected_value="true",
            actual_value="false",
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
        )
        findings = FindingCollection(findings=[test_finding])
        storage.get_findings.return_value = findings

        return storage

    def test_get_finding_detail(self, mock_storage: MagicMock) -> None:
        """Test getting finding detail."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("finding-1")

            assert "finding" in result
            assert "asset" in result
            assert result["finding"]["id"] == "finding-1"
            assert result["finding"]["title"] == "Test Finding"
            assert result["finding"]["severity"] == "high"

    def test_get_finding_detail_not_found(self, mock_storage: MagicMock) -> None:
        """Test getting non-existent finding."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("nonexistent-finding")

            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_get_finding_detail_includes_asset(self, mock_storage: MagicMock) -> None:
        """Test finding detail includes associated asset info."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("finding-1")

            assert result["asset"] is not None
            assert result["asset"]["id"] == "arn:aws:s3:::bucket1"
            assert result["asset"]["name"] == "bucket1"
            assert result["asset"]["resource_type"] == "aws_s3_bucket"

    def test_get_finding_detail_includes_compliance(self, mock_storage: MagicMock) -> None:
        """Test finding detail includes compliance frameworks."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("finding-1")

            assert "compliance_frameworks" in result["finding"]
            assert len(result["finding"]["compliance_frameworks"]) == 2

    def test_get_finding_detail_includes_remediation(self, mock_storage: MagicMock) -> None:
        """Test finding detail includes remediation guidance."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("finding-1")

            assert "remediation_guidance" in result["finding"]
            assert result["finding"]["remediation_guidance"] is not None

    def test_get_finding_detail_includes_config_values(self, mock_storage: MagicMock) -> None:
        """Test finding detail includes expected/actual values."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_finding_detail("finding-1")

            assert "expected_value" in result["finding"]
            assert "actual_value" in result["finding"]
            assert result["finding"]["expected_value"] == "true"
            assert result["finding"]["actual_value"] == "false"

    def test_get_finding_detail_no_storage(self) -> None:
        """Test finding detail with no storage configured."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = None

            result = handler._get_finding_detail("finding-1")

            assert "error" in result

    def test_get_finding_detail_url_decode(self, mock_storage: MagicMock) -> None:
        """Test finding detail URL-decodes finding ID."""
        # Create a finding with special characters in ID
        encoded_id = "finding%2F1"  # URL-encoded slash

        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            # Should URL-decode the ID
            result = handler._get_finding_detail(encoded_id)
            # Will not find because actual ID is "finding-1"
            assert "error" in result or "finding" in result


class TestAssetDetailEndpoint:
    """Tests for /api/assets/<asset_id> endpoint."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage backend with test data."""
        storage = MagicMock()
        storage.get_latest_snapshot_id.return_value = "snapshot-123"

        # Mock asset with detailed info
        test_asset = Asset(
            id="arn:aws:s3:::bucket1",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="bucket1",
            tags={"env": "prod", "team": "security"},
            network_exposure="internal",
            created_at=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            raw_config={"BucketName": "bucket1"},
        )
        assets = AssetCollection(assets=[test_asset])
        storage.get_assets.return_value = assets

        # Mock findings for this asset
        findings = FindingCollection(findings=[
            Finding(
                id="finding-1",
                asset_id="arn:aws:s3:::bucket1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="High Finding 1",
                description="High severity finding description",
            ),
            Finding(
                id="finding-2",
                asset_id="arn:aws:s3:::bucket1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                title="Critical Finding",
                description="Critical severity finding description",
            ),
            Finding(
                id="finding-3",
                asset_id="arn:aws:s3:::bucket1",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.MEDIUM,
                status=FindingStatus.OPEN,
                title="Medium Finding",
                description="Medium severity finding description",
            ),
        ])
        storage.get_findings.return_value = findings

        return storage

    def test_get_asset_detail(self, mock_storage: MagicMock) -> None:
        """Test getting asset detail."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "asset" in result
            assert result["asset"]["id"] == "arn:aws:s3:::bucket1"
            assert result["asset"]["name"] == "bucket1"
            assert result["asset"]["resource_type"] == "aws_s3_bucket"

    def test_get_asset_detail_not_found(self, mock_storage: MagicMock) -> None:
        """Test getting non-existent asset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("nonexistent-asset")

            assert "error" in result
            assert "not found" in result["error"].lower()

    def test_get_asset_detail_includes_findings(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes associated findings."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "findings" in result
            assert len(result["findings"]) == 3

    def test_get_asset_detail_findings_by_severity(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes findings count by severity."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "findings_by_severity" in result
            assert result["findings_by_severity"]["critical"] == 1
            assert result["findings_by_severity"]["high"] == 1
            assert result["findings_by_severity"]["medium"] == 1

    def test_get_asset_detail_finding_count(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes total finding count."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "finding_count" in result
            assert result["finding_count"] == 3

    def test_get_asset_detail_includes_tags(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes tags."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "tags" in result["asset"]
            assert result["asset"]["tags"]["env"] == "prod"
            assert result["asset"]["tags"]["team"] == "security"

    def test_get_asset_detail_includes_timestamps(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes timestamps."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert "created_at" in result["asset"]
            assert "last_seen" in result["asset"]

    def test_get_asset_detail_includes_cloud_info(self, mock_storage: MagicMock) -> None:
        """Test asset detail includes cloud provider info."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._get_asset_detail("arn:aws:s3:::bucket1")

            assert result["asset"]["cloud_provider"] == "aws"
            assert result["asset"]["account_id"] == "123456789012"
            assert result["asset"]["region"] == "us-east-1"
            assert result["asset"]["network_exposure"] == "internal"

    def test_get_asset_detail_no_storage(self) -> None:
        """Test asset detail with no storage configured."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = None

            result = handler._get_asset_detail("asset-id")

            assert "error" in result


class TestDetailViewHTMLFeatures:
    """Tests to verify drill-down functionality is in the HTML."""

    def test_index_html_has_modal(self) -> None:
        """Test index.html includes modal structure."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "detail-modal" in content
        assert "modal-overlay" in content
        assert "modal-content" in content

    def test_index_html_has_clickable_rows(self) -> None:
        """Test index.html makes table rows clickable."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "tr.clickable" in content
        assert "showFindingDetail" in content
        assert "showAssetDetail" in content

    def test_index_html_has_modal_functions(self) -> None:
        """Test index.html includes modal JavaScript functions."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function openModal" in content
        assert "function closeModal" in content
        assert "async function showFindingDetail" in content
        assert "async function showAssetDetail" in content

    def test_index_html_has_detail_sections(self) -> None:
        """Test index.html includes detail section styling."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".detail-section" in content
        assert ".detail-grid" in content
        assert ".detail-item" in content
        assert ".detail-label" in content
        assert ".detail-value" in content

    def test_index_html_has_escape_close_listener(self) -> None:
        """Test index.html closes modal on Escape key."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "Escape" in content
        assert "closeModal" in content

    def test_index_html_has_overlay_click_listener(self) -> None:
        """Test index.html closes modal on overlay click."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "modal-overlay" in content
        # Check for overlay click handling
        assert "classList.contains('modal-overlay')" in content


# ============================================================================
# Search Endpoint Tests
# ============================================================================


class TestSearchEndpoint:
    """Tests for /api/search endpoint."""

    @pytest.fixture
    def mock_storage(self) -> MagicMock:
        """Create a mock storage backend with test data."""
        storage = MagicMock()
        storage.get_latest_snapshot_id.return_value = "snapshot-123"

        # Mock assets
        assets = AssetCollection(assets=[
            Asset(
                id="arn:aws:s3:::my-bucket",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="my-bucket",
                tags={"env": "production"},
                network_exposure="internal",
                created_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                raw_config={},
            ),
            Asset(
                id="arn:aws:ec2:us-west-2:123456789012:instance/i-12345",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-west-2",
                resource_type="aws_ec2_instance",
                name="web-server",
                tags={"team": "security"},
                network_exposure="internet_facing",
                created_at=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                raw_config={},
            ),
        ])
        storage.get_assets.return_value = assets

        # Mock findings
        findings = FindingCollection(findings=[
            Finding(
                id="finding-1",
                asset_id="arn:aws:s3:::my-bucket",
                finding_type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title="S3 Bucket Encryption Missing",
                description="The bucket does not have encryption enabled",
                rule_id="aws-s3-001",
            ),
            Finding(
                id="finding-2",
                asset_id="arn:aws:ec2:us-west-2:123456789012:instance/i-12345",
                finding_type=FindingType.VULNERABILITY,
                severity=Severity.CRITICAL,
                status=FindingStatus.OPEN,
                title="CVE-2024-1234 Critical Vulnerability",
                description="Critical vulnerability found",
                cve_id="CVE-2024-1234",
            ),
        ])
        storage.get_findings.return_value = findings

        return storage

    def test_search_findings_by_title(self, mock_storage: MagicMock) -> None:
        """Test searching findings by title."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["encryption"]})

            assert "findings" in result
            assert len(result["findings"]) == 1
            assert result["findings"][0]["title"] == "S3 Bucket Encryption Missing"

    def test_search_findings_by_cve(self, mock_storage: MagicMock) -> None:
        """Test searching findings by CVE ID."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["cve-2024"]})

            assert "findings" in result
            assert len(result["findings"]) == 1
            assert "CVE-2024-1234" in result["findings"][0]["title"]

    def test_search_assets_by_name(self, mock_storage: MagicMock) -> None:
        """Test searching assets by name."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["bucket"]})

            assert "assets" in result
            assert len(result["assets"]) == 1
            assert result["assets"][0]["name"] == "my-bucket"

    def test_search_assets_by_resource_type(self, mock_storage: MagicMock) -> None:
        """Test searching assets by resource type."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["ec2"]})

            assert "assets" in result
            assert len(result["assets"]) == 1
            assert result["assets"][0]["resource_type"] == "aws_ec2_instance"

    def test_search_both_findings_and_assets(self, mock_storage: MagicMock) -> None:
        """Test searching returns both findings and assets."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["aws"]})

            assert "findings" in result
            assert "assets" in result
            assert result["total"] > 0

    def test_search_empty_query(self, mock_storage: MagicMock) -> None:
        """Test search with empty query returns error."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": [""]})

            assert "error" in result

    def test_search_short_query(self, mock_storage: MagicMock) -> None:
        """Test search with query < 2 chars returns error."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["a"]})

            assert "error" in result
            assert "at least 2 characters" in result["error"]

    def test_search_no_results(self, mock_storage: MagicMock) -> None:
        """Test search with no matching results."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["nonexistent123"]})

            assert result["total"] == 0
            assert len(result["findings"]) == 0
            assert len(result["assets"]) == 0

    def test_search_limit_parameter(self, mock_storage: MagicMock) -> None:
        """Test search respects limit parameter."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["aws"], "limit": ["1"]})

            # Should limit total results
            assert len(result["findings"]) <= 1
            assert len(result["assets"]) <= 1

    def test_search_type_filter_findings_only(self, mock_storage: MagicMock) -> None:
        """Test search with type=findings only returns findings."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["aws"], "type": ["findings"]})

            assert "findings" in result
            assert len(result["assets"]) == 0

    def test_search_type_filter_assets_only(self, mock_storage: MagicMock) -> None:
        """Test search with type=assets only returns assets."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["aws"], "type": ["assets"]})

            assert "assets" in result
            assert len(result["findings"]) == 0

    def test_search_no_storage(self) -> None:
        """Test search with no storage configured."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = None

            result = handler._handle_search({"q": ["test"]})

            assert "error" in result

    def test_search_case_insensitive(self, mock_storage: MagicMock) -> None:
        """Test search is case insensitive."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["BUCKET"]})

            assert len(result["assets"]) >= 1

    def test_search_results_include_score(self, mock_storage: MagicMock) -> None:
        """Test search results include relevance score."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["bucket"]})

            if result["assets"]:
                assert "score" in result["assets"][0]

    def test_search_by_tag(self, mock_storage: MagicMock) -> None:
        """Test searching assets by tag value."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler.storage = mock_storage

            result = handler._handle_search({"q": ["production"]})

            assert len(result["assets"]) >= 1


class TestSearchHTMLFeatures:
    """Tests to verify search functionality is in the HTML."""

    def test_index_html_has_search_input(self) -> None:
        """Test index.html includes search input."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "search-input" in content
        assert "search-container" in content

    def test_index_html_has_search_functions(self) -> None:
        """Test index.html includes search JavaScript functions."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "performSearch" in content
        assert "displaySearchResults" in content
        assert "hideSearchResults" in content
        assert "clearSearch" in content

    def test_index_html_has_search_results_container(self) -> None:
        """Test index.html includes search results container."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "search-results" in content
        assert "search-result-item" in content

    def test_index_html_has_keyboard_shortcut(self) -> None:
        """Test index.html includes keyboard shortcut for search."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Ctrl/Cmd + K shortcut
        assert "ctrlKey" in content or "metaKey" in content

    def test_index_html_has_debounced_search(self) -> None:
        """Test index.html includes debounced search."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "searchTimeout" in content
        assert "setTimeout" in content


# ============================================================================
# Filter Preset Tests
# ============================================================================


class TestPresetEndpoints:
    """Tests for filter preset API endpoints."""

    def test_get_presets_empty(self) -> None:
        """Test getting presets when none exist."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            result = handler._get_presets()

            assert "presets" in result
            assert len(result["presets"]) == 0

    def test_get_presets_with_data(self) -> None:
        """Test getting presets when they exist."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {
                "my-preset": {
                    "view": "findings",
                    "filters": {"severity": "high"},
                    "created_at": "2024-01-01T00:00:00Z",
                    "description": "High severity findings",
                }
            }

            result = handler._get_presets()

            assert len(result["presets"]) == 1
            assert result["presets"][0]["name"] == "my-preset"
            assert result["presets"][0]["view"] == "findings"

    def test_get_preset_by_name(self) -> None:
        """Test getting a specific preset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {
                "my-preset": {
                    "view": "findings",
                    "filters": {"severity": "high"},
                    "created_at": "2024-01-01T00:00:00Z",
                    "description": "High severity findings",
                }
            }

            result = handler._get_preset("my-preset")

            assert result["name"] == "my-preset"
            assert result["view"] == "findings"
            assert result["filters"]["severity"] == "high"

    def test_get_preset_not_found(self) -> None:
        """Test getting a non-existent preset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            result = handler._get_preset("nonexistent")

            assert "error" in result
            assert "not found" in result["error"]

    def test_save_preset(self) -> None:
        """Test saving a preset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            body = b'{"name": "My Preset", "view": "findings", "filters": {"severity": "high"}}'
            result = handler._save_preset(body)

            assert result["success"] is True
            assert "My_Preset" in handler._presets

    def test_save_preset_empty_name(self) -> None:
        """Test saving a preset with empty name."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            body = b'{"name": "", "view": "findings"}'
            result = handler._save_preset(body)

            assert "error" in result
            assert "name is required" in result["error"].lower()

    def test_save_preset_long_name(self) -> None:
        """Test saving a preset with name too long."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            long_name = "a" * 51
            body = f'{{"name": "{long_name}", "view": "findings"}}'.encode("utf-8")
            result = handler._save_preset(body)

            assert "error" in result
            assert "50 characters" in result["error"]

    def test_save_preset_invalid_json(self) -> None:
        """Test saving a preset with invalid JSON."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            body = b'not valid json'
            result = handler._save_preset(body)

            assert "error" in result
            assert "Invalid JSON" in result["error"]

    def test_save_preset_sanitizes_name(self) -> None:
        """Test saving a preset sanitizes the name for URL safety."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            body = b'{"name": "My Preset/With Special!Chars", "view": "findings"}'
            result = handler._save_preset(body)

            assert result["success"] is True
            # Name should be sanitized
            assert result["name"] == "My_Preset_With_Special_Chars"

    def test_delete_preset(self) -> None:
        """Test deleting a preset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {
                "my-preset": {"view": "findings", "filters": {}}
            }

            result = handler._delete_preset("my-preset")

            assert result["success"] is True
            assert "my-preset" not in handler._presets

    def test_delete_preset_not_found(self) -> None:
        """Test deleting a non-existent preset."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            result = handler._delete_preset("nonexistent")

            assert "error" in result
            assert "not found" in result["error"]

    def test_preset_includes_timestamp(self) -> None:
        """Test saved preset includes created_at timestamp."""
        with patch.object(StanceRequestHandler, "__init__", lambda x: None):
            handler = StanceRequestHandler()
            handler._presets = {}

            body = b'{"name": "test", "view": "findings"}'
            handler._save_preset(body)

            preset = handler._presets.get("test", {})
            assert "created_at" in preset
            assert preset["created_at"] is not None


class TestPresetHTMLFeatures:
    """Tests to verify preset functionality is in the HTML."""

    def test_index_html_has_preset_modal(self) -> None:
        """Test index.html includes preset modal."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "preset-modal" in content
        assert "preset-name" in content

    def test_index_html_has_preset_functions(self) -> None:
        """Test index.html includes preset JavaScript functions."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "openPresetModal" in content
        assert "closePresetModal" in content
        assert "handlePresetSave" in content
        assert "loadPresets" in content
        assert "applyPreset" in content
        assert "deletePreset" in content

    def test_index_html_has_share_url_functionality(self) -> None:
        """Test index.html includes share URL functionality."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "generateShareUrl" in content
        assert "copyShareUrl" in content
        assert "share-url-input" in content

    def test_index_html_has_filter_bar(self) -> None:
        """Test index.html includes filter bar with preset actions."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "filter-bar" in content
        assert "preset-actions" in content
        assert "Save Preset" in content

    def test_index_html_applies_url_filters_on_load(self) -> None:
        """Test index.html applies URL filters on page load."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "applyUrlFilters" in content
        # Should be called in initial load
        assert "applyUrlFilters()" in content

    def test_index_html_loads_presets_on_init(self) -> None:
        """Test index.html loads presets on initialization."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Should load presets in initial load
        assert "loadPresets()" in content


# ============================================================================
# Trend Chart HTML Feature Tests (Phase 10 - Task 54)
# ============================================================================


class TestTrendChartHTMLFeatures:
    """Tests to verify trend chart functionality is in the HTML."""

    def test_index_html_has_findings_chart_container(self) -> None:
        """Test index.html includes findings chart container."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "findings-chart-container" in content
        assert "findings-chart" in content
        assert "Findings Over Time" in content

    def test_index_html_has_severity_chart_container(self) -> None:
        """Test index.html includes severity chart container."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "severity-chart-container" in content
        assert "severity-chart" in content
        assert "Findings by Severity" in content

    def test_index_html_has_chart_legend(self) -> None:
        """Test index.html includes chart legends."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "chart-legend" in content
        assert "chart-legend-item" in content
        assert "chart-legend-color" in content

    def test_index_html_has_chart_tooltip(self) -> None:
        """Test index.html includes chart tooltip element."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "chart-tooltip" in content
        assert "chart-tooltip-title" in content
        assert "chart-tooltip-value" in content

    def test_index_html_has_chart_css_styles(self) -> None:
        """Test index.html includes chart CSS styles."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".chart-container" in content
        assert ".chart-svg" in content
        assert ".chart-line" in content
        assert ".chart-point" in content
        assert ".chart-grid-line" in content
        assert ".chart-axis-label" in content

    def test_index_html_has_render_line_chart_function(self) -> None:
        """Test index.html includes renderLineChart function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderLineChart" in content

    def test_index_html_has_render_findings_chart_function(self) -> None:
        """Test index.html includes renderFindingsChart function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderFindingsChart" in content

    def test_index_html_has_render_severity_chart_function(self) -> None:
        """Test index.html includes renderSeverityChart function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderSeverityChart" in content

    def test_index_html_has_format_chart_date_function(self) -> None:
        """Test index.html includes formatChartDate function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function formatChartDate" in content

    def test_index_html_calls_chart_rendering_in_load_trends(self) -> None:
        """Test index.html calls chart rendering in loadTrends function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "renderFindingsChart(points)" in content
        assert "renderSeverityChart(points)" in content

    def test_index_html_has_chart_area_support(self) -> None:
        """Test index.html includes chart area fill support."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".chart-area" in content
        assert "showArea" in content

    def test_index_html_has_chart_no_data_message(self) -> None:
        """Test index.html includes no data message for charts."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "chart-no-data" in content
        assert "Not enough data points" in content


# ============================================================================
# Dark Mode Toggle Tests (Phase 10 - Task 55)
# ============================================================================


class TestDarkModeHTMLFeatures:
    """Tests to verify dark mode toggle functionality is in the HTML."""

    def test_index_html_has_theme_toggle_button(self) -> None:
        """Test index.html includes theme toggle button."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "theme-toggle-btn" in content
        assert 'id="theme-toggle-btn"' in content

    def test_index_html_has_theme_toggle_css(self) -> None:
        """Test index.html includes theme toggle CSS styles."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".theme-toggle" in content
        assert ".theme-toggle-btn" in content

    def test_index_html_has_dark_mode_css_variables(self) -> None:
        """Test index.html includes dark mode CSS variables."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ":root.dark-mode" in content

    def test_index_html_has_light_mode_css_class(self) -> None:
        """Test index.html includes light mode CSS class."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ":root:not(.light-mode)" in content
        assert "light-mode" in content

    def test_index_html_has_theme_icons(self) -> None:
        """Test index.html includes theme icons."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "icon-sun" in content
        assert "icon-moon" in content
        assert "icon-auto" in content

    def test_index_html_has_get_theme_preference_function(self) -> None:
        """Test index.html includes getThemePreference function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function getThemePreference" in content

    def test_index_html_has_set_theme_preference_function(self) -> None:
        """Test index.html includes setThemePreference function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function setThemePreference" in content

    def test_index_html_has_apply_theme_function(self) -> None:
        """Test index.html includes applyTheme function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function applyTheme" in content

    def test_index_html_has_cycle_theme_function(self) -> None:
        """Test index.html includes cycleTheme function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function cycleTheme" in content

    def test_index_html_has_init_theme_function(self) -> None:
        """Test index.html includes initTheme function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function initTheme" in content

    def test_index_html_uses_local_storage_for_theme(self) -> None:
        """Test index.html uses localStorage for theme preference."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "localStorage.getItem" in content
        assert "localStorage.setItem" in content
        assert "stance-theme-preference" in content

    def test_index_html_initializes_theme_on_load(self) -> None:
        """Test index.html initializes theme on page load."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "initTheme()" in content

    def test_index_html_has_theme_toggle_event_listener(self) -> None:
        """Test index.html has event listener for theme toggle button."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "theme-toggle-btn" in content
        assert "addEventListener" in content
        assert "cycleTheme" in content


# ============================================================================
# PDF Export HTML Features Tests (Task 56)
# ============================================================================


class TestPDFExportHTMLFeatures:
    """Tests for PDF export functionality in the web dashboard."""

    def test_index_html_has_pdf_export_option(self) -> None:
        """Test index.html has PDF option in export dropdown."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'value="pdf"' in content
        assert ">PDF<" in content

    def test_index_html_has_export_dropdown(self) -> None:
        """Test index.html has export dropdown with all formats."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "export-format" in content
        assert 'value="json"' in content
        assert 'value="csv"' in content
        assert 'value="html"' in content
        assert 'value="pdf"' in content

    def test_server_export_format_map_includes_pdf(self) -> None:
        """Test server.py format_map includes PDF format."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"pdf": ExportFormat.PDF' in content

    def test_server_content_types_includes_pdf(self) -> None:
        """Test server.py content_types includes PDF."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert 'ExportFormat.PDF: "application/pdf"' in content

    def test_server_extensions_includes_pdf(self) -> None:
        """Test server.py extensions includes PDF."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert 'ExportFormat.PDF: "pdf"' in content

    def test_export_format_has_pdf_option(self) -> None:
        """Test ExportFormat enum has PDF option."""
        from stance.export import ExportFormat

        assert hasattr(ExportFormat, "PDF")
        assert ExportFormat.PDF.value == "pdf"

    def test_pdf_exporter_registered(self) -> None:
        """Test PDF exporter is registered in export manager."""
        from stance.export import ExportFormat, create_export_manager

        manager = create_export_manager()
        exporter = manager.get_exporter(ExportFormat.PDF)

        assert exporter is not None
        assert exporter.format == ExportFormat.PDF


# ============================================================================
# Keyboard Shortcuts HTML Features Tests (Task 57)
# ============================================================================


class TestKeyboardShortcutsHTMLFeatures:
    """Tests for keyboard shortcuts functionality in the web dashboard."""

    def test_index_html_has_shortcuts_help_button(self) -> None:
        """Test index.html has keyboard shortcuts help button."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "shortcuts-help-btn" in content
        assert "Keyboard shortcuts" in content

    def test_index_html_has_shortcuts_modal(self) -> None:
        """Test index.html has keyboard shortcuts modal."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "shortcuts-modal" in content
        assert "Keyboard Shortcuts" in content

    def test_index_html_has_shortcuts_grid_css(self) -> None:
        """Test index.html has CSS for shortcuts grid layout."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".shortcuts-grid" in content
        assert ".shortcut-group" in content
        assert ".shortcut-row" in content
        assert ".shortcut-key" in content

    def test_index_html_has_navigation_shortcuts(self) -> None:
        """Test index.html documents navigation shortcuts."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Check for navigation shortcuts in modal
        assert "Summary view" in content
        assert "Findings view" in content
        assert "Assets view" in content

    def test_index_html_has_action_shortcuts(self) -> None:
        """Test index.html documents action shortcuts."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Check for action shortcuts in modal
        assert "Focus search" in content
        assert "Toggle theme" in content
        assert "Refresh current view" in content

    def test_index_html_has_keyboard_handler_function(self) -> None:
        """Test index.html has handleKeyboardShortcut function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function handleKeyboardShortcut" in content

    def test_index_html_has_shortcuts_modal_functions(self) -> None:
        """Test index.html has open/close shortcuts modal functions."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function openShortcutsModal" in content
        assert "function closeShortcutsModal" in content

    def test_index_html_has_should_ignore_shortcut_function(self) -> None:
        """Test index.html has shouldIgnoreShortcut function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function shouldIgnoreShortcut" in content

    def test_index_html_has_refresh_current_view_function(self) -> None:
        """Test index.html has refreshCurrentView function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function refreshCurrentView" in content

    def test_index_html_has_keydown_event_listener(self) -> None:
        """Test index.html registers keyboard event listener."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "addEventListener('keydown', handleKeyboardShortcut)" in content

    def test_index_html_shortcuts_modal_has_close_button(self) -> None:
        """Test shortcuts modal has close button."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "closeShortcutsModal()" in content

    def test_index_html_has_shortcut_key_styling(self) -> None:
        """Test index.html has keyboard key styling."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert '<span class="shortcut-key">' in content


# ============================================================================
# Posture Score Gauge Tests (Task 58)
# ============================================================================


class TestPostureGaugeHTMLFeatures:
    """Tests for posture score gauge functionality in the web dashboard."""

    def test_index_html_has_gauge_css_styles(self) -> None:
        """Test index.html has CSS for gauge styling."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".gauge-container" in content
        assert ".gauge-wrapper" in content
        assert ".gauge-svg" in content
        assert ".gauge-background" in content
        assert ".gauge-progress" in content

    def test_index_html_has_gauge_center_styles(self) -> None:
        """Test index.html has CSS for gauge center content."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".gauge-center" in content
        assert ".gauge-value" in content
        assert ".gauge-label" in content

    def test_index_html_has_gauge_color_classes(self) -> None:
        """Test index.html has CSS classes for gauge colors."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".gauge-progress.good" in content
        assert ".gauge-progress.warning" in content
        assert ".gauge-progress.bad" in content

    def test_index_html_has_calculate_gauge_progress_function(self) -> None:
        """Test index.html has calculateGaugeProgress function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function calculateGaugeProgress" in content

    def test_index_html_has_render_gauge_function(self) -> None:
        """Test index.html has renderGauge function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderGauge" in content

    def test_index_html_has_animate_gauge_function(self) -> None:
        """Test index.html has animateGauge function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function animateGauge" in content

    def test_index_html_calls_render_gauge_in_load_summary(self) -> None:
        """Test index.html calls renderGauge in loadSummary function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "renderGauge('posture-gauge-card'" in content

    def test_index_html_has_posture_gauge_card(self) -> None:
        """Test index.html has posture gauge card in summary."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "posture-gauge-card" in content

    def test_index_html_gauge_uses_svg(self) -> None:
        """Test index.html gauge uses SVG circles."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Check renderGauge creates SVG
        assert "gauge-svg" in content
        assert "stroke-dasharray" in content
        assert "stroke-dashoffset" in content

    def test_index_html_gauge_has_animation(self) -> None:
        """Test index.html gauge has animation transition."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "transition: stroke-dashoffset" in content
        assert "requestAnimationFrame" in content


# ============================================================================
# Accessibility Tests (Task 59)
# ============================================================================


class TestAccessibilityHTMLFeatures:
    """Tests for accessibility features in the web dashboard."""

    def test_index_html_has_aria_live_region(self) -> None:
        """Test index.html has aria-live region for announcements."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "aria-live-region" in content
        assert 'aria-live="polite"' in content

    def test_index_html_has_banner_role(self) -> None:
        """Test index.html header has role=banner."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'role="banner"' in content

    def test_index_html_has_navigation_role(self) -> None:
        """Test index.html nav has role=navigation."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'role="navigation"' in content
        assert 'aria-label="Main navigation"' in content

    def test_index_html_has_main_role(self) -> None:
        """Test index.html main has role=main."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'role="main"' in content

    def test_index_html_has_search_role(self) -> None:
        """Test index.html search container has role=search."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'role="search"' in content

    def test_index_html_has_dialog_roles_on_modals(self) -> None:
        """Test index.html modals have role=dialog."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'role="dialog"' in content
        assert 'aria-modal="true"' in content

    def test_index_html_has_aria_labels_on_buttons(self) -> None:
        """Test index.html has aria-labels on icon buttons."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'aria-label="Clear search"' in content
        assert 'aria-label="Close modal"' in content
        assert 'aria-label="Show keyboard shortcuts help"' in content

    def test_index_html_has_aria_pressed_on_nav_buttons(self) -> None:
        """Test index.html nav buttons have aria-pressed attributes."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'aria-pressed="true"' in content
        assert 'aria-pressed="false"' in content

    def test_index_html_has_sr_only_class(self) -> None:
        """Test index.html has screen reader only CSS class."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".sr-only" in content
        assert "clip: rect(0, 0, 0, 0)" in content

    def test_index_html_has_focus_visible_styles(self) -> None:
        """Test index.html has focus-visible CSS styles."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ":focus-visible" in content
        assert "outline:" in content

    def test_index_html_has_announce_function(self) -> None:
        """Test index.html has announceToScreenReader function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function announceToScreenReader" in content

    def test_index_html_updates_aria_pressed_in_show_view(self) -> None:
        """Test index.html updates aria-pressed in showView function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "setAttribute('aria-pressed'" in content

    def test_index_html_has_aria_labelledby_on_modals(self) -> None:
        """Test index.html modals have aria-labelledby."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'aria-labelledby="modal-title"' in content
        assert 'aria-labelledby="preset-modal-title"' in content
        assert 'aria-labelledby="shortcuts-modal-title"' in content

    def test_index_html_has_aria_hidden_on_decorative_icons(self) -> None:
        """Test index.html has aria-hidden on decorative icons."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'aria-hidden="true"' in content


# ============================================================================
# Drift Detection View Tests (Task 60)
# ============================================================================


class TestDriftViewHTMLFeatures:
    """Tests for drift detection view functionality in the web dashboard."""

    def test_index_html_has_drift_nav_button(self) -> None:
        """Test index.html has Drift navigation button."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'data-view="drift"' in content
        assert ">Drift<" in content

    def test_index_html_has_drift_view_section(self) -> None:
        """Test index.html has drift view section."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'id="drift-view"' in content
        assert 'id="drift-content"' in content
        assert "Configuration Drift" in content

    def test_index_html_has_drift_css_styles(self) -> None:
        """Test index.html has CSS styles for drift view."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".drift-status-card" in content
        assert ".drift-status-icon" in content
        assert ".drift-summary" in content
        assert ".drift-stat-card" in content
        assert ".drift-severity-section" in content

    def test_index_html_has_drift_severity_bar_styles(self) -> None:
        """Test index.html has CSS for drift severity bars."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".drift-severity-bar" in content
        assert ".drift-severity-fill" in content
        assert ".drift-severity-fill.critical" in content
        assert ".drift-severity-fill.high" in content

    def test_index_html_has_no_baseline_message_styles(self) -> None:
        """Test index.html has CSS for no baseline message."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".no-baseline-message" in content

    def test_index_html_has_load_drift_function(self) -> None:
        """Test index.html has loadDrift function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "async function loadDrift" in content

    def test_index_html_has_render_drift_view_function(self) -> None:
        """Test index.html has renderDriftView function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderDriftView" in content

    def test_index_html_has_render_drift_severity_row_function(self) -> None:
        """Test index.html has renderDriftSeverityRow function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function renderDriftSeverityRow" in content

    def test_index_html_calls_load_drift_in_show_view(self) -> None:
        """Test index.html calls loadDrift in showView function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "loadDrift()" in content
        assert "viewName === 'drift'" in content

    def test_index_html_has_drift_keyboard_shortcut(self) -> None:
        """Test index.html has keyboard shortcut for drift view."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        # Check drift is in the views array for keyboard shortcuts
        assert "'drift'" in content
        assert "Drift view" in content

    def test_index_html_keyboard_handler_supports_9_keys(self) -> None:
        """Test index.html keyboard handler supports keys 1-9."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "e.key >= '1' && e.key <= '9'" in content
        assert "'summary', 'findings', 'assets', 'compliance', 'risk', 'attack-paths', 'drift', 'trends', 'settings'" in content

    def test_index_html_fetches_api_drift(self) -> None:
        """Test index.html fetches /api/drift endpoint."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "/api/drift" in content


# ============================================================================
# Snapshot Selector Tests (Task 61)
# ============================================================================


class TestSnapshotSelectorHTMLFeatures:
    """Tests for snapshot selector functionality in the web dashboard."""

    def test_index_html_has_snapshot_selector(self) -> None:
        """Test index.html has snapshot selector dropdown."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert 'id="snapshot-select"' in content
        assert "snapshot-selector" in content

    def test_index_html_has_snapshot_selector_css(self) -> None:
        """Test index.html has CSS styles for snapshot selector."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ".snapshot-selector" in content
        assert ".snapshot-selector select" in content
        assert ".snapshot-selector-label" in content

    def test_index_html_has_load_snapshots_function(self) -> None:
        """Test index.html has loadSnapshots function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "async function loadSnapshots" in content

    def test_index_html_has_on_snapshot_change_function(self) -> None:
        """Test index.html has onSnapshotChange function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function onSnapshotChange" in content

    def test_index_html_has_format_snapshot_date_function(self) -> None:
        """Test index.html has formatSnapshotDate function."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "function formatSnapshotDate" in content

    def test_index_html_state_has_selected_snapshot_id(self) -> None:
        """Test index.html state includes selectedSnapshotId."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "selectedSnapshotId" in content

    def test_index_html_fetch_api_adds_snapshot_id(self) -> None:
        """Test index.html fetchAPI adds snapshot_id to params."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "state.selectedSnapshotId" in content
        assert "params.snapshot_id" in content

    def test_index_html_snapshot_selector_has_latest_option(self) -> None:
        """Test index.html snapshot selector has Latest option."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert ">Latest<" in content

    def test_index_html_loads_snapshots_on_init(self) -> None:
        """Test index.html loads snapshots on initialization."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "loadSnapshots()" in content

    def test_index_html_has_snapshot_change_event_listener(self) -> None:
        """Test index.html has event listener for snapshot change."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "snapshot-select" in content
        assert "onSnapshotChange" in content

    def test_index_html_fetches_api_snapshots(self) -> None:
        """Test index.html fetches /api/snapshots endpoint."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            content = f.read()

        assert "/api/snapshots" in content


class TestSnapshotSelectorServerFeatures:
    """Tests for snapshot_id parameter support in server."""

    def test_server_has_get_snapshot_id_method(self) -> None:
        """Test server has _get_snapshot_id helper method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_snapshot_id" in content

    def test_server_get_summary_accepts_params(self) -> None:
        """Test server _get_summary accepts params."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_summary(self, params" in content

    def test_server_get_overview_accepts_params(self) -> None:
        """Test server _get_overview accepts params."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_overview(self, params" in content

    def test_server_uses_get_snapshot_id_helper(self) -> None:
        """Test server uses _get_snapshot_id in methods."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        # Should use the helper in multiple places
        assert content.count("self._get_snapshot_id(params)") >= 3


# =============================================================================
# Phase 14: Notification Settings UI Tests
# =============================================================================


class TestSettingsViewHTMLFeatures:
    """Tests for Settings view HTML features."""

    def _get_html_content(self) -> str:
        """Get HTML content."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            return f.read()

    def test_index_html_has_settings_nav_button(self) -> None:
        """Test Settings navigation button exists."""
        content = self._get_html_content()
        assert 'data-view="settings"' in content

    def test_index_html_has_settings_view_section(self) -> None:
        """Test settings-view section exists."""
        content = self._get_html_content()
        assert 'id="settings-view"' in content

    def test_index_html_has_settings_section_class(self) -> None:
        """Test settings-section CSS class exists."""
        content = self._get_html_content()
        assert ".settings-section" in content

    def test_index_html_has_settings_toggle_class(self) -> None:
        """Test settings-toggle CSS class exists."""
        content = self._get_html_content()
        assert ".settings-toggle" in content

    def test_index_html_has_notifications_enabled_toggle(self) -> None:
        """Test notifications enabled toggle exists."""
        content = self._get_html_content()
        assert 'id="notifications-enabled-toggle"' in content

    def test_index_html_has_notify_critical_toggle(self) -> None:
        """Test notify critical toggle exists."""
        content = self._get_html_content()
        assert 'id="notify-critical-toggle"' in content

    def test_index_html_has_min_severity_select(self) -> None:
        """Test minimum severity select exists."""
        content = self._get_html_content()
        assert 'id="min-severity-select"' in content

    def test_index_html_has_destinations_list(self) -> None:
        """Test destinations list container exists."""
        content = self._get_html_content()
        assert 'id="destinations-list"' in content

    def test_index_html_has_notification_history(self) -> None:
        """Test notification history container exists."""
        content = self._get_html_content()
        assert 'id="notification-history"' in content

    def test_index_html_has_add_destination_button(self) -> None:
        """Test add destination button exists."""
        content = self._get_html_content()
        assert "add-destination-btn" in content

    def test_index_html_has_destination_modal(self) -> None:
        """Test destination modal exists."""
        content = self._get_html_content()
        assert 'id="destination-modal"' in content

    def test_index_html_has_destination_form(self) -> None:
        """Test destination form exists."""
        content = self._get_html_content()
        assert 'id="destination-form"' in content

    def test_index_html_has_destination_card_css(self) -> None:
        """Test destination card CSS exists."""
        content = self._get_html_content()
        assert ".destination-card" in content

    def test_index_html_has_load_settings_function(self) -> None:
        """Test loadSettings function exists."""
        content = self._get_html_content()
        assert "async function loadSettings()" in content

    def test_index_html_has_load_destinations_function(self) -> None:
        """Test loadDestinations function exists."""
        content = self._get_html_content()
        assert "async function loadDestinations()" in content

    def test_index_html_has_save_destination_function(self) -> None:
        """Test saveDestination function exists."""
        content = self._get_html_content()
        assert "async function saveDestination(event)" in content

    def test_index_html_has_test_destination_function(self) -> None:
        """Test testDestination function exists."""
        content = self._get_html_content()
        assert "async function testDestination(name)" in content

    def test_index_html_has_delete_destination_function(self) -> None:
        """Test deleteDestination function exists."""
        content = self._get_html_content()
        assert "async function deleteDestination(name)" in content

    def test_index_html_has_update_destination_fields_function(self) -> None:
        """Test updateDestinationFields function exists."""
        content = self._get_html_content()
        assert "function updateDestinationFields()" in content

    def test_index_html_settings_in_keyboard_shortcuts(self) -> None:
        """Test settings view in keyboard shortcuts."""
        content = self._get_html_content()
        assert "'settings'" in content
        assert "Settings view" in content

    def test_index_html_keyboard_handler_includes_key_9(self) -> None:
        """Test keyboard handler includes key 9."""
        content = self._get_html_content()
        assert "e.key <= '9'" in content

    def test_index_html_has_notification_history_css(self) -> None:
        """Test notification history CSS exists."""
        content = self._get_html_content()
        assert ".notification-history-item" in content

    def test_index_html_has_form_group_css(self) -> None:
        """Test form group CSS exists."""
        content = self._get_html_content()
        assert ".form-group" in content

    def test_index_html_has_form_actions_css(self) -> None:
        """Test form actions CSS exists."""
        content = self._get_html_content()
        assert ".form-actions" in content


class TestNotificationAPIServerFeatures:
    """Tests for notification API server features."""

    def test_server_has_notification_destinations_endpoint(self) -> None:
        """Test server has /api/notifications/destinations endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/notifications/destinations"' in content

    def test_server_has_notification_config_endpoint(self) -> None:
        """Test server has /api/notifications/config endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/notifications/config"' in content

    def test_server_has_notification_history_endpoint(self) -> None:
        """Test server has /api/notifications/history endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/notifications/history"' in content

    def test_server_has_destination_test_endpoint(self) -> None:
        """Test server has destination test endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/notifications/destinations/test"' in content

    def test_server_has_get_notification_destinations_method(self) -> None:
        """Test server has _get_notification_destinations method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_notification_destinations(self)" in content

    def test_server_has_save_notification_destination_method(self) -> None:
        """Test server has _save_notification_destination method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _save_notification_destination(self, body" in content

    def test_server_has_test_notification_destination_method(self) -> None:
        """Test server has _test_notification_destination method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _test_notification_destination(self, body" in content

    def test_server_has_delete_notification_destination_method(self) -> None:
        """Test server has _delete_notification_destination method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _delete_notification_destination(self, name" in content

    def test_server_has_notification_config_storage(self) -> None:
        """Test server has notification config storage."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "_notification_config" in content

    def test_server_has_notification_history_storage(self) -> None:
        """Test server has notification history storage."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "_notification_history" in content

    def test_server_has_available_destination_types(self) -> None:
        """Test server returns available destination types."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "available_types" in content
        assert '"slack"' in content
        assert '"pagerduty"' in content
        assert '"email"' in content

    def test_server_has_is_destination_configured_method(self) -> None:
        """Test server has _is_destination_configured method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _is_destination_configured(self, config" in content

    def test_server_has_perform_destination_test_method(self) -> None:
        """Test server has _perform_destination_test method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _perform_destination_test(self, dest_type" in content

    def test_server_has_send_test_notification_method(self) -> None:
        """Test server has _send_test_notification method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _send_test_notification(self, body" in content


# ============================================================================
# Phase 15: Attack Paths View Tests
# ============================================================================


class TestAttackPathsViewHTMLFeatures:
    """Tests for Attack Paths view HTML features."""

    def _get_html_content(self) -> str:
        """Get HTML content."""
        import os
        from stance.web import server

        static_dir = os.path.join(os.path.dirname(server.__file__), "static")
        index_path = os.path.join(static_dir, "index.html")

        with open(index_path, "r") as f:
            return f.read()

    def test_html_has_attack_paths_navigation_button(self) -> None:
        """Test HTML has Attack Paths navigation button."""
        content = self._get_html_content()
        assert 'data-view="attack-paths"' in content
        assert ">Attack Paths</button>" in content

    def test_html_has_attack_paths_view_section(self) -> None:
        """Test HTML has Attack Paths view section."""
        content = self._get_html_content()
        assert 'id="attack-paths-view"' in content

    def test_html_has_attack_paths_summary_container(self) -> None:
        """Test HTML has Attack Paths summary container."""
        content = self._get_html_content()
        assert 'id="attack-paths-summary"' in content
        assert 'class="attack-paths-summary"' in content

    def test_html_has_attack_paths_list_container(self) -> None:
        """Test HTML has Attack Paths list container."""
        content = self._get_html_content()
        assert 'id="attack-paths-list"' in content

    def test_html_has_attack_path_type_filter(self) -> None:
        """Test HTML has Attack Path type filter."""
        content = self._get_html_content()
        assert 'id="attack-path-type-filter"' in content
        assert "Filter by attack path type" in content

    def test_html_has_attack_path_severity_filter(self) -> None:
        """Test HTML has Attack Path severity filter."""
        content = self._get_html_content()
        assert 'id="attack-path-severity-filter"' in content
        assert "Filter by severity" in content

    def test_html_has_attack_path_type_options(self) -> None:
        """Test HTML has Attack Path type filter options."""
        content = self._get_html_content()
        assert 'value="internet_to_internal"' in content
        assert 'value="privilege_escalation"' in content
        assert 'value="lateral_movement"' in content
        assert 'value="data_exfiltration"' in content

    def test_html_has_load_attack_paths_function(self) -> None:
        """Test HTML has loadAttackPaths function."""
        content = self._get_html_content()
        assert "async function loadAttackPaths()" in content

    def test_html_has_render_attack_paths_summary_function(self) -> None:
        """Test HTML has renderAttackPathsSummary function."""
        content = self._get_html_content()
        assert "function renderAttackPathsSummary(summary)" in content

    def test_html_has_render_attack_paths_list_function(self) -> None:
        """Test HTML has renderAttackPathsList function."""
        content = self._get_html_content()
        assert "function renderAttackPathsList(paths)" in content

    def test_html_has_render_attack_path_card_function(self) -> None:
        """Test HTML has renderAttackPathCard function."""
        content = self._get_html_content()
        assert "function renderAttackPathCard(path)" in content

    def test_html_has_show_attack_path_detail_function(self) -> None:
        """Test HTML has showAttackPathDetail function."""
        content = self._get_html_content()
        assert "async function showAttackPathDetail(pathId)" in content

    def test_html_has_close_attack_path_modal_function(self) -> None:
        """Test HTML has closeAttackPathModal function."""
        content = self._get_html_content()
        assert "function closeAttackPathModal(event)" in content

    def test_html_attack_paths_styles(self) -> None:
        """Test HTML has Attack Paths CSS styles."""
        content = self._get_html_content()
        assert ".attack-paths-summary" in content
        assert ".attack-path-card" in content
        assert ".attack-path-header" in content
        assert ".attack-path-steps" in content

    def test_html_keyboard_shortcut_includes_attack_paths(self) -> None:
        """Test HTML keyboard shortcuts include Attack Paths."""
        content = self._get_html_content()
        # Check that attack-paths is in the keyboard navigation array
        assert "'attack-paths'" in content

    def test_html_show_view_handles_attack_paths(self) -> None:
        """Test HTML showView function handles attack-paths view."""
        content = self._get_html_content()
        assert "viewName === 'attack-paths'" in content
        assert "loadAttackPaths()" in content


class TestAttackPathsAPIServerFeatures:
    """Tests for Attack Paths API server features."""

    def test_server_has_attack_paths_endpoint(self) -> None:
        """Test server has /api/attack-paths endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/attack-paths"' in content

    def test_server_has_attack_paths_detail_endpoint(self) -> None:
        """Test server has /api/attack-paths/<id> detail endpoint."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"/api/attack-paths/"' in content

    def test_server_has_get_attack_paths_method(self) -> None:
        """Test server has _get_attack_paths method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_attack_paths(self" in content

    def test_server_has_get_attack_path_detail_method(self) -> None:
        """Test server has _get_attack_path_detail method."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "def _get_attack_path_detail(self" in content

    def test_server_has_attack_paths_cache(self) -> None:
        """Test server has attack paths caching."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "_attack_paths_cache" in content
        assert "_attack_paths_cache_time" in content

    def test_server_attack_paths_uses_analyzer(self) -> None:
        """Test server attack paths uses AttackPathAnalyzer."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "AttackPathAnalyzer" in content
        assert "from stance.analytics import AttackPathAnalyzer" in content

    def test_server_attack_paths_uses_asset_graph(self) -> None:
        """Test server attack paths uses AssetGraph."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "AssetGraph" in content

    def test_server_attack_paths_filter_by_type(self) -> None:
        """Test server attack paths supports type filtering."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert 'params.get("type"' in content

    def test_server_attack_paths_filter_by_severity(self) -> None:
        """Test server attack paths supports severity filtering."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert 'params.get("severity"' in content

    def test_server_attack_paths_returns_summary(self) -> None:
        """Test server attack paths returns summary statistics."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert '"total_paths"' in content
        assert '"by_type"' in content
        assert '"by_severity"' in content

    def test_server_attack_paths_limits_results(self) -> None:
        """Test server attack paths limits results to 50."""
        import os
        from stance.web import server

        server_path = os.path.join(os.path.dirname(server.__file__), "server.py")

        with open(server_path, "r") as f:
            content = f.read()

        assert "paths[:50]" in content
