"""
Unit tests for ASM storage adapter.

Tests cover:
- Database initialization
- Scan result storage and retrieval
- External asset storage and retrieval
- Asset history tracking
- Query functions
- Statistics generation
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.storage import (
    ASMStorageAdapter,
    ASMScanInfo,
    generate_scan_id,
)


# ============================================================================
# generate_scan_id Tests
# ============================================================================


class TestGenerateScanId:
    """Tests for scan ID generation."""

    def test_generate_scan_id_format(self) -> None:
        """Test scan ID has correct format."""
        scan_id = generate_scan_id()
        assert scan_id.startswith("asm-")
        parts = scan_id.split("-")
        assert len(parts) == 4

    def test_generate_scan_id_unique(self) -> None:
        """Test scan IDs are unique."""
        ids = {generate_scan_id() for _ in range(100)}
        assert len(ids) == 100


# ============================================================================
# ASMStorageAdapter Tests
# ============================================================================


class TestASMStorageAdapter:
    """Tests for ASMStorageAdapter."""

    def test_init_creates_database(self, temp_db_path: str) -> None:
        """Test storage adapter creates database file."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert os.path.exists(temp_db_path)

    def test_init_creates_tables(self, temp_db_path: str) -> None:
        """Test storage adapter creates required tables."""
        adapter = ASMStorageAdapter(temp_db_path)

        # Check tables exist by querying them
        conn = adapter._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cursor.fetchall()}
        conn.close()

        assert "asm_scans" in tables
        assert "asm_external_assets" in tables
        assert "asm_asset_history" in tables


class TestScanResultStorage:
    """Tests for scan result storage operations."""

    def test_store_scan_result(
        self, temp_db_path: str, asm_scan_result: ASMScanResult
    ) -> None:
        """Test storing a scan result."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        # Verify it was stored
        retrieved = adapter.get_scan_result(asm_scan_result.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == asm_scan_result.scan_id

    def test_store_scan_result_overwrites(
        self, temp_db_path: str, asm_scan_result: ASMScanResult
    ) -> None:
        """Test storing scan result overwrites existing."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        # Modify and store again
        asm_scan_result.findings_count = 99
        adapter.store_scan_result(asm_scan_result)

        retrieved = adapter.get_scan_result(asm_scan_result.scan_id)
        assert retrieved is not None
        assert retrieved.findings_count == 99

    def test_get_scan_result_not_found(self, temp_db_path: str) -> None:
        """Test retrieving non-existent scan result."""
        adapter = ASMStorageAdapter(temp_db_path)
        result = adapter.get_scan_result("nonexistent-scan")
        assert result is None

    def test_get_latest_scan(
        self, temp_db_path: str, asm_scan_result: ASMScanResult
    ) -> None:
        """Test getting latest scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        latest = adapter.get_latest_scan()
        assert latest is not None
        assert latest.scan_id == asm_scan_result.scan_id

    def test_get_latest_scan_empty(self, temp_db_path: str) -> None:
        """Test getting latest scan when none exist."""
        adapter = ASMStorageAdapter(temp_db_path)
        latest = adapter.get_latest_scan()
        assert latest is None

    def test_get_latest_scan_id(
        self, temp_db_path: str, asm_scan_result: ASMScanResult
    ) -> None:
        """Test getting latest scan ID."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        latest_id = adapter.get_latest_scan_id()
        assert latest_id == asm_scan_result.scan_id

    def test_get_latest_scan_id_empty(self, temp_db_path: str) -> None:
        """Test getting latest scan ID when none exist."""
        adapter = ASMStorageAdapter(temp_db_path)
        latest_id = adapter.get_latest_scan_id()
        assert latest_id is None

    def test_list_scans(self, temp_db_path: str) -> None:
        """Test listing scans."""
        adapter = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        # Create multiple scans
        for i in range(5):
            result = ASMScanResult(
                scan_id=f"scan-{i:03d}",
                started_at=now - timedelta(hours=i),
                target_domains=["example.com"],
                scan_mode=ASMScanMode.PASSIVE,
                status=ASMScanStatus.COMPLETED,
            )
            adapter.store_scan_result(result)

        scans = adapter.list_scans(limit=10)
        assert len(scans) == 5
        assert all(isinstance(s, ASMScanInfo) for s in scans)

        # Should be sorted most recent first
        assert scans[0].scan_id == "scan-000"

    def test_list_scans_limit(self, temp_db_path: str) -> None:
        """Test listing scans with limit."""
        adapter = ASMStorageAdapter(temp_db_path)
        now = datetime.now(timezone.utc)

        for i in range(10):
            result = ASMScanResult(
                scan_id=f"scan-{i:03d}",
                started_at=now - timedelta(hours=i),
                target_domains=["example.com"],
            )
            adapter.store_scan_result(result)

        scans = adapter.list_scans(limit=5)
        assert len(scans) == 5

    def test_delete_scan(
        self, temp_db_path: str, asm_scan_result: ASMScanResult
    ) -> None:
        """Test deleting a scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        deleted = adapter.delete_scan(asm_scan_result.scan_id)
        assert deleted is True

        # Verify it's gone
        result = adapter.get_scan_result(asm_scan_result.scan_id)
        assert result is None

    def test_delete_scan_not_found(self, temp_db_path: str) -> None:
        """Test deleting non-existent scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        deleted = adapter.delete_scan("nonexistent")
        assert deleted is False


class TestExternalAssetStorage:
    """Tests for external asset storage operations."""

    def test_store_external_assets(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test storing external assets."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        # Verify assets were stored
        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        assert len(retrieved) == len(external_asset_collection)

    def test_store_external_assets_overwrites(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        api_asset: ExternalAsset,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test storing assets overwrites existing for same scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)

        # Store first batch (1 asset)
        adapter.store_external_assets(
            ExternalAssetCollection([web_asset]),
            asm_scan_result.scan_id,
        )

        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        assert len(retrieved) == 1

        # Store second batch (should replace with 2 assets)
        adapter.store_external_assets(
            ExternalAssetCollection([web_asset, api_asset]),
            asm_scan_result.scan_id,
        )

        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        # Should now have both web_asset and api_asset
        assert len(retrieved) == 2

    def test_get_external_assets_by_scan_id(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test retrieving assets by scan ID."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        domains = {a.domain for a in retrieved}

        assert "www.example.com" in domains
        assert "api.example.com" in domains

    def test_get_external_assets_latest(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test retrieving assets defaults to latest scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        # Don't specify scan_id
        retrieved = adapter.get_external_assets()
        assert len(retrieved) == len(external_asset_collection)

    def test_get_external_assets_empty(self, temp_db_path: str) -> None:
        """Test retrieving assets when none exist."""
        adapter = ASMStorageAdapter(temp_db_path)
        retrieved = adapter.get_external_assets()
        assert len(retrieved) == 0

    def test_asset_with_certificate_roundtrip(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test asset with certificate survives storage roundtrip."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            ExternalAssetCollection([web_asset]),
            asm_scan_result.scan_id,
        )

        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        asset = retrieved[0]

        assert asset.certificate_info is not None
        assert asset.certificate_info.subject == "CN=api.example.com"

    def test_asset_technology_stack_roundtrip(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test asset technology stack survives storage roundtrip."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            ExternalAssetCollection([web_asset]),
            asm_scan_result.scan_id,
        )

        retrieved = adapter.get_external_assets(asm_scan_result.scan_id)
        asset = retrieved[0]

        assert asset.technology_stack == ("nginx", "React", "Node.js")


class TestAssetHistory:
    """Tests for asset history tracking."""

    def test_get_asset_history(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting asset history."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            ExternalAssetCollection([web_asset]),
            asm_scan_result.scan_id,
        )

        history = adapter.get_asset_history(web_asset.id)
        assert history is not None
        assert history["domain"] == web_asset.domain
        assert history["scan_count"] == 1

    def test_get_asset_history_not_found(self, temp_db_path: str) -> None:
        """Test getting history for non-existent asset."""
        adapter = ASMStorageAdapter(temp_db_path)
        history = adapter.get_asset_history("nonexistent")
        assert history is None

    def test_asset_history_increments_scan_count(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
    ) -> None:
        """Test asset history scan count increments across scans."""
        adapter = ASMStorageAdapter(temp_db_path)

        # Store same asset in multiple scans
        for i in range(3):
            scan = ASMScanResult(
                scan_id=f"scan-{i}",
                started_at=datetime.now(timezone.utc),
                target_domains=["example.com"],
            )
            adapter.store_scan_result(scan)
            adapter.store_external_assets(
                ExternalAssetCollection([web_asset]),
                scan.scan_id,
            )

        history = adapter.get_asset_history(web_asset.id)
        assert history is not None
        assert history["scan_count"] == 3


class TestAssetQueries:
    """Tests for asset query functions."""

    def test_get_assets_by_domain(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting assets by domain."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        assets = adapter.get_assets_by_domain("api.example.com")
        assert len(assets) == 1
        assert assets[0].domain == "api.example.com"

    def test_get_assets_by_port(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting assets by port."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        assets = adapter.get_assets_by_port(443, asm_scan_result.scan_id)
        assert len(assets) == 2  # web and api assets

    def test_get_assets_by_port_latest_scan(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting assets by port from latest scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        # Don't specify scan_id
        assets = adapter.get_assets_by_port(443)
        assert len(assets) == 2

    def test_get_high_risk_assets(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting high risk assets."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        # database_asset has risk 8.0, shadow_it_asset has 7.5
        assets = adapter.get_high_risk_assets(7.0, asm_scan_result.scan_id)
        assert len(assets) == 2

        # Verify sorted by risk descending
        risks = [a.risk_score for a in assets]
        assert risks == sorted(risks, reverse=True)

    def test_get_high_risk_assets_empty(self, temp_db_path: str) -> None:
        """Test getting high risk assets when none exist."""
        adapter = ASMStorageAdapter(temp_db_path)
        assets = adapter.get_high_risk_assets(7.0)
        assert len(assets) == 0


class TestQueryExternalAssets:
    """Tests for raw SQL query execution."""

    def test_query_external_assets_select(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test executing SELECT query."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        results = adapter.query_external_assets(
            "SELECT domain, port FROM asm_external_assets WHERE port = 443"
        )
        assert len(results) == 2
        assert all("domain" in r for r in results)
        assert all("port" in r for r in results)

    def test_query_external_assets_rejects_insert(
        self, temp_db_path: str
    ) -> None:
        """Test INSERT query is rejected."""
        adapter = ASMStorageAdapter(temp_db_path)

        with pytest.raises(ValueError, match="Only SELECT"):
            adapter.query_external_assets(
                "INSERT INTO asm_external_assets (id, domain) VALUES ('x', 'x')"
            )

    def test_query_external_assets_rejects_delete(
        self, temp_db_path: str
    ) -> None:
        """Test DELETE query is rejected."""
        adapter = ASMStorageAdapter(temp_db_path)

        with pytest.raises(ValueError, match="Only SELECT"):
            adapter.query_external_assets("DELETE FROM asm_external_assets")

    def test_query_external_assets_rejects_drop(
        self, temp_db_path: str
    ) -> None:
        """Test DROP query is rejected."""
        adapter = ASMStorageAdapter(temp_db_path)

        with pytest.raises(ValueError, match="Only SELECT"):
            adapter.query_external_assets("DROP TABLE asm_external_assets")

    def test_query_external_assets_rejects_comments(
        self, temp_db_path: str
    ) -> None:
        """Test queries with SQL comments are rejected."""
        adapter = ASMStorageAdapter(temp_db_path)

        with pytest.raises(ValueError, match="Only SELECT"):
            adapter.query_external_assets("SELECT * FROM asm_external_assets -- drop")

    def test_query_external_assets_rejects_multiple_statements(
        self, temp_db_path: str
    ) -> None:
        """Test multiple statements are rejected."""
        adapter = ASMStorageAdapter(temp_db_path)

        with pytest.raises(ValueError, match="Only SELECT"):
            adapter.query_external_assets(
                "SELECT * FROM asm_external_assets; DELETE FROM asm_external_assets"
            )


class TestScanStatistics:
    """Tests for scan statistics generation."""

    def test_get_scan_statistics(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting scan statistics."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        stats = adapter.get_scan_statistics(asm_scan_result.scan_id)

        assert stats["scan_id"] == asm_scan_result.scan_id
        assert stats["total_assets"] == 4
        assert stats["domains_discovered"] == 4
        assert stats["unique_ips"] == 4

        # Check port distribution
        assert 443 in stats["ports_detected"]
        assert stats["ports_detected"][443] == 2

        # Check cloud provider distribution
        assert "aws" in stats["cloud_providers"]

        # Check risk distribution
        assert "risk_distribution" in stats

    def test_get_scan_statistics_latest(
        self,
        temp_db_path: str,
        external_asset_collection: ExternalAssetCollection,
        asm_scan_result: ASMScanResult,
    ) -> None:
        """Test getting statistics defaults to latest scan."""
        adapter = ASMStorageAdapter(temp_db_path)
        adapter.store_scan_result(asm_scan_result)
        adapter.store_external_assets(
            external_asset_collection, asm_scan_result.scan_id
        )

        # Don't specify scan_id
        stats = adapter.get_scan_statistics()
        assert stats["scan_id"] == asm_scan_result.scan_id

    def test_get_scan_statistics_empty(self, temp_db_path: str) -> None:
        """Test getting statistics when no scans exist."""
        adapter = ASMStorageAdapter(temp_db_path)
        stats = adapter.get_scan_statistics()

        assert stats["scan_id"] is None
        assert stats["total_assets"] == 0


class TestIsSafeQuery:
    """Tests for SQL query safety validation."""

    def test_safe_select_query(self, temp_db_path: str) -> None:
        """Test valid SELECT query passes."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("SELECT * FROM asm_external_assets") is True

    def test_safe_select_with_where(self, temp_db_path: str) -> None:
        """Test SELECT with WHERE passes."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query(
            "SELECT domain FROM asm_external_assets WHERE port = 443"
        ) is True

    def test_unsafe_insert(self, temp_db_path: str) -> None:
        """Test INSERT query fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("INSERT INTO table VALUES (1)") is False

    def test_unsafe_update(self, temp_db_path: str) -> None:
        """Test UPDATE query fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("UPDATE table SET x = 1") is False

    def test_unsafe_delete(self, temp_db_path: str) -> None:
        """Test DELETE query fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("DELETE FROM table") is False

    def test_unsafe_drop(self, temp_db_path: str) -> None:
        """Test DROP query fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("DROP TABLE table") is False

    def test_unsafe_alter(self, temp_db_path: str) -> None:
        """Test ALTER query fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("ALTER TABLE table ADD column") is False

    def test_unsafe_comments(self, temp_db_path: str) -> None:
        """Test query with comments fails."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("SELECT * FROM table -- comment") is False
        assert adapter._is_safe_query("SELECT * FROM table /* comment */") is False

    def test_unsafe_multiple_statements(self, temp_db_path: str) -> None:
        """Test multiple statements fail."""
        adapter = ASMStorageAdapter(temp_db_path)
        assert adapter._is_safe_query("SELECT 1; SELECT 2") is False

    def test_case_insensitive_detection(self, temp_db_path: str) -> None:
        """Test dangerous keywords detected case-insensitively."""
        adapter = ASMStorageAdapter(temp_db_path)
        # Keywords in string literals are still flagged for safety (strict mode)
        # This prevents SQL injection via string concatenation
        assert adapter._is_safe_query("select * from table where x = 'DELETE'") is False
        # Standalone DELETE should fail
        assert adapter._is_safe_query("delete from table") is False
        # Safe queries work
        assert adapter._is_safe_query("SELECT * FROM table WHERE status = 'active'") is True
