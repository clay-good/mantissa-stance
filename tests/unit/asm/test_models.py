"""
Unit tests for ASM data models.

Tests cover:
- CertificateInfo: creation, serialization, validation properties
- ExternalAsset: creation, serialization, property checks
- ExternalAssetCollection: filtering, counting, sorting
- ASMScanResult: state transitions, serialization
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)


# ============================================================================
# CertificateInfo Tests
# ============================================================================


class TestCertificateInfo:
    """Tests for CertificateInfo model."""

    def test_create_certificate(self, valid_certificate: CertificateInfo) -> None:
        """Test basic certificate creation."""
        assert valid_certificate.subject == "CN=api.example.com"
        assert valid_certificate.issuer == "CN=DigiCert"
        assert valid_certificate.is_self_signed is False
        assert valid_certificate.key_algorithm == "RSA"
        assert valid_certificate.key_size == 2048

    def test_certificate_is_expired(self, expired_certificate: CertificateInfo) -> None:
        """Test is_expired property for expired certificate."""
        assert expired_certificate.is_expired is True

    def test_certificate_not_expired(self, valid_certificate: CertificateInfo) -> None:
        """Test is_expired property for valid certificate."""
        assert valid_certificate.is_expired is False

    def test_certificate_expiring_soon(self, expiring_certificate: CertificateInfo) -> None:
        """Test is_expiring_soon property for certificate expiring within 30 days."""
        assert expiring_certificate.is_expiring_soon is True

    def test_certificate_not_expiring_soon(self, valid_certificate: CertificateInfo) -> None:
        """Test is_expiring_soon property for certificate not expiring soon."""
        assert valid_certificate.is_expiring_soon is False

    def test_days_until_expiry_positive(self, valid_certificate: CertificateInfo) -> None:
        """Test days_until_expiry for valid certificate."""
        days = valid_certificate.days_until_expiry
        assert days > 0
        assert days <= 90  # expires in ~90 days

    def test_days_until_expiry_negative(self, expired_certificate: CertificateInfo) -> None:
        """Test days_until_expiry for expired certificate."""
        days = expired_certificate.days_until_expiry
        assert days < 0

    def test_weak_key_rsa_1024(self, expired_certificate: CertificateInfo) -> None:
        """Test is_weak_key for RSA 1024-bit key."""
        assert expired_certificate.key_size == 1024
        assert expired_certificate.is_weak_key is True

    def test_strong_key_rsa_2048(self, valid_certificate: CertificateInfo) -> None:
        """Test is_weak_key for RSA 2048-bit key."""
        assert valid_certificate.key_size == 2048
        assert valid_certificate.is_weak_key is False

    def test_weak_key_ecdsa(self) -> None:
        """Test is_weak_key for weak ECDSA key."""
        now = datetime.now(timezone.utc)
        cert = CertificateInfo(
            subject="CN=test",
            issuer="CN=test",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=30),
            key_algorithm="ECDSA",
            key_size=128,  # Too small for ECDSA
        )
        assert cert.is_weak_key is True

    def test_strong_key_ecdsa(self) -> None:
        """Test is_weak_key for strong ECDSA key."""
        now = datetime.now(timezone.utc)
        cert = CertificateInfo(
            subject="CN=test",
            issuer="CN=test",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=30),
            key_algorithm="ECDSA",
            key_size=256,
        )
        assert cert.is_weak_key is False

    def test_certificate_to_dict(self, valid_certificate: CertificateInfo) -> None:
        """Test serialization to dictionary."""
        data = valid_certificate.to_dict()

        assert data["subject"] == "CN=api.example.com"
        assert data["issuer"] == "CN=DigiCert"
        assert data["is_self_signed"] is False
        assert data["key_algorithm"] == "RSA"
        assert data["key_size"] == 2048
        assert "not_before" in data
        assert "not_after" in data
        assert data["is_expired"] is False
        assert "days_until_expiry" in data

    def test_certificate_from_dict(self) -> None:
        """Test deserialization from dictionary."""
        data = {
            "subject": "CN=test.example.com",
            "issuer": "CN=Test CA",
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",
            "san_domains": ["test.example.com", "www.test.example.com"],
            "fingerprint_sha256": "abcdef123456",
            "is_self_signed": False,
            "key_algorithm": "RSA",
            "key_size": 4096,
            "serial_number": "12345",
        }

        cert = CertificateInfo.from_dict(data)

        assert cert.subject == "CN=test.example.com"
        assert cert.issuer == "CN=Test CA"
        assert cert.san_domains == ("test.example.com", "www.test.example.com")
        assert cert.fingerprint_sha256 == "abcdef123456"
        assert cert.key_size == 4096
        assert cert.serial_number == "12345"

    def test_certificate_roundtrip(self, valid_certificate: CertificateInfo) -> None:
        """Test serialization/deserialization roundtrip."""
        data = valid_certificate.to_dict()
        restored = CertificateInfo.from_dict(data)

        assert restored.subject == valid_certificate.subject
        assert restored.issuer == valid_certificate.issuer
        assert restored.fingerprint_sha256 == valid_certificate.fingerprint_sha256
        assert restored.key_size == valid_certificate.key_size

    def test_san_domains_immutable(self, valid_certificate: CertificateInfo) -> None:
        """Test that san_domains is a tuple (immutable)."""
        assert isinstance(valid_certificate.san_domains, tuple)


# ============================================================================
# ExternalAsset Tests
# ============================================================================


class TestExternalAsset:
    """Tests for ExternalAsset model."""

    def test_create_web_asset(self, web_asset: ExternalAsset) -> None:
        """Test basic web asset creation."""
        assert web_asset.id == "ext-web-001"
        assert web_asset.domain == "www.example.com"
        assert web_asset.ip_address == "203.0.113.10"
        assert web_asset.port == 443
        assert web_asset.protocol == "https"

    def test_generate_id(self) -> None:
        """Test unique ID generation."""
        id1 = ExternalAsset.generate_id("example.com", "1.2.3.4", 443)
        id2 = ExternalAsset.generate_id("example.com", "1.2.3.4", 443)
        id3 = ExternalAsset.generate_id("example.com", "1.2.3.4", 80)

        # Same inputs should produce same ID
        assert id1 == id2
        # Different port should produce different ID
        assert id1 != id3
        # ID should be 16 chars (truncated sha256)
        assert len(id1) == 16

    def test_has_certificate(self, web_asset: ExternalAsset, database_asset: ExternalAsset) -> None:
        """Test has_certificate property."""
        assert web_asset.has_certificate is True
        assert database_asset.has_certificate is False

    def test_is_https(self, web_asset: ExternalAsset) -> None:
        """Test is_https property."""
        assert web_asset.is_https is True
        assert web_asset.port == 443

    def test_is_web_service(self, web_asset: ExternalAsset, database_asset: ExternalAsset) -> None:
        """Test is_web_service property."""
        assert web_asset.is_web_service is True
        assert database_asset.is_web_service is False

    def test_is_database_service(self, web_asset: ExternalAsset, database_asset: ExternalAsset) -> None:
        """Test is_database_service property."""
        assert database_asset.is_database_service is True
        assert web_asset.is_database_service is False

    def test_is_remote_access(self, rdp_asset: ExternalAsset, web_asset: ExternalAsset) -> None:
        """Test is_remote_access property."""
        assert rdp_asset.is_remote_access is True
        assert web_asset.is_remote_access is False

    def test_asset_to_dict(self, web_asset: ExternalAsset) -> None:
        """Test serialization to dictionary."""
        data = web_asset.to_dict()

        assert data["id"] == "ext-web-001"
        assert data["domain"] == "www.example.com"
        assert data["ip_address"] == "203.0.113.10"
        assert data["port"] == 443
        assert data["protocol"] == "https"
        assert data["cloud_provider"] == "aws"
        assert "certificate_info" in data
        assert data["certificate_info"] is not None

    def test_asset_from_dict(self) -> None:
        """Test deserialization from dictionary."""
        data = {
            "id": "test-asset-001",
            "domain": "test.example.com",
            "ip_address": "10.0.0.1",
            "port": 8080,
            "protocol": "http",
            "service": "Apache",
            "technology_stack": ["Apache", "PHP"],
            "cloud_provider": "gcp",
            "cloud_region": "us-central1",
            "first_seen": "2025-01-01T00:00:00+00:00",
            "last_seen": "2025-01-15T00:00:00+00:00",
            "risk_score": 5.5,
            "source": "port_scan",
            "is_verified": True,
        }

        asset = ExternalAsset.from_dict(data)

        assert asset.id == "test-asset-001"
        assert asset.domain == "test.example.com"
        assert asset.port == 8080
        assert asset.technology_stack == ("Apache", "PHP")
        assert asset.cloud_provider == "gcp"
        assert asset.risk_score == 5.5
        assert asset.is_verified is True

    def test_asset_roundtrip(self, web_asset: ExternalAsset) -> None:
        """Test serialization/deserialization roundtrip."""
        data = web_asset.to_dict()
        restored = ExternalAsset.from_dict(data)

        assert restored.id == web_asset.id
        assert restored.domain == web_asset.domain
        assert restored.port == web_asset.port
        assert restored.protocol == web_asset.protocol

    def test_technology_stack_immutable(self, web_asset: ExternalAsset) -> None:
        """Test that technology_stack is a tuple (immutable)."""
        assert isinstance(web_asset.technology_stack, tuple)


# ============================================================================
# ExternalAssetCollection Tests
# ============================================================================


class TestExternalAssetCollection:
    """Tests for ExternalAssetCollection."""

    def test_collection_length(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test collection length."""
        assert len(external_asset_collection) == 4

    def test_collection_iteration(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test collection iteration."""
        domains = [asset.domain for asset in external_asset_collection]
        assert len(domains) == 4

    def test_collection_indexing(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test collection indexing."""
        asset = external_asset_collection[0]
        assert isinstance(asset, ExternalAsset)

    def test_add_asset(self, web_asset: ExternalAsset) -> None:
        """Test adding asset to collection."""
        collection = ExternalAssetCollection()
        collection.add(web_asset)
        assert len(collection) == 1
        assert collection[0] == web_asset

    def test_extend_assets(
        self, web_asset: ExternalAsset, api_asset: ExternalAsset
    ) -> None:
        """Test extending collection with multiple assets."""
        collection = ExternalAssetCollection()
        collection.extend([web_asset, api_asset])
        assert len(collection) == 2

    def test_filter_by_domain(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by domain pattern."""
        filtered = external_asset_collection.filter_by_domain("*.example.com")
        assert len(filtered) == 4  # All match *.example.com

    def test_filter_by_domain_specific(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by specific domain."""
        filtered = external_asset_collection.filter_by_domain("api.example.com")
        assert len(filtered) == 1
        assert filtered[0].domain == "api.example.com"

    def test_filter_by_port(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by port number."""
        filtered = external_asset_collection.filter_by_port(443)
        assert len(filtered) == 2  # web_asset and api_asset

    def test_filter_by_ports(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by multiple ports."""
        filtered = external_asset_collection.filter_by_ports([443, 3306])
        assert len(filtered) == 3  # web, api, and database

    def test_filter_by_cloud_provider(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by cloud provider."""
        filtered = external_asset_collection.filter_by_cloud_provider("aws")
        assert len(filtered) == 3  # web, api, database

    def test_filter_by_risk_score(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by minimum risk score."""
        filtered = external_asset_collection.filter_by_risk_score(5.0)
        assert len(filtered) == 2  # database (8.0) and shadow_it (7.5)

    def test_filter_by_source(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering by discovery source."""
        filtered = external_asset_collection.filter_by_source("dns_enumeration")
        assert len(filtered) == 2  # api_asset and shadow_it_asset

    def test_filter_with_certificates(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering for assets with certificates."""
        filtered = external_asset_collection.filter_with_certificates()
        assert len(filtered) == 3  # web, api, shadow_it have certificates

    def test_filter_expiring_certificates(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering for expiring certificates."""
        # api_asset has certificate expiring in 5 days
        # expired_certificate (shadow_it) is already expired
        filtered = external_asset_collection.filter_expiring_certificates(30)
        assert len(filtered) >= 1

    def test_filter_expired_certificates(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering for expired certificates."""
        filtered = external_asset_collection.filter_expired_certificates()
        assert len(filtered) == 1  # shadow_it_asset has expired cert

    def test_filter_web_services(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering for web services."""
        filtered = external_asset_collection.filter_web_services()
        assert len(filtered) == 3  # 443 (web, api), 8080 (shadow_it)

    def test_filter_database_services(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test filtering for database services."""
        filtered = external_asset_collection.filter_database_services()
        assert len(filtered) == 1  # database_asset

    def test_get_by_id(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test getting asset by ID."""
        asset = external_asset_collection.get_by_id("ext-web-001")
        assert asset is not None
        assert asset.domain == "www.example.com"

    def test_get_by_id_not_found(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test getting non-existent asset by ID."""
        asset = external_asset_collection.get_by_id("nonexistent")
        assert asset is None

    def test_get_by_domain(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test getting assets by domain."""
        assets = external_asset_collection.get_by_domain("api.example.com")
        assert len(assets) == 1
        assert assets[0].domain == "api.example.com"

    def test_get_unique_domains(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test getting unique domains."""
        domains = external_asset_collection.get_unique_domains()
        assert len(domains) == 4

    def test_get_unique_ips(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test getting unique IP addresses."""
        ips = external_asset_collection.get_unique_ips()
        assert len(ips) == 4

    def test_count_by_cloud_provider(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test counting by cloud provider."""
        counts = external_asset_collection.count_by_cloud_provider()
        assert counts["aws"] == 3
        assert counts["gcp"] == 1

    def test_count_by_port(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test counting by port."""
        counts = external_asset_collection.count_by_port()
        assert counts[443] == 2
        assert counts[3306] == 1
        assert counts[8080] == 1

    def test_count_by_source(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test counting by source."""
        counts = external_asset_collection.count_by_source()
        assert "dns_enumeration" in counts
        assert "cert_transparency" in counts
        assert "port_scan" in counts

    def test_merge_collections(
        self,
        external_asset_collection: ExternalAssetCollection,
        rdp_asset: ExternalAsset,
    ) -> None:
        """Test merging two collections."""
        other = ExternalAssetCollection([rdp_asset])
        merged = external_asset_collection.merge(other)
        assert len(merged) == 5

    def test_deduplicate(self, web_asset: ExternalAsset) -> None:
        """Test deduplication."""
        collection = ExternalAssetCollection([web_asset, web_asset, web_asset])
        deduped = collection.deduplicate()
        assert len(deduped) == 1

    def test_sort_by_risk(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test sorting by risk score."""
        sorted_coll = external_asset_collection.sort_by_risk(descending=True)
        risks = [a.risk_score for a in sorted_coll]
        assert risks == sorted(risks, reverse=True)

    def test_sort_by_domain(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test sorting by domain."""
        sorted_coll = external_asset_collection.sort_by_domain()
        domains = [a.domain.lower() for a in sorted_coll]
        assert domains == sorted(domains)

    def test_sort_by_last_seen(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test sorting by last seen time."""
        sorted_coll = external_asset_collection.sort_by_last_seen(descending=True)
        times = [a.last_seen for a in sorted_coll]
        assert times == sorted(times, reverse=True)

    def test_to_list(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test conversion to list of dicts."""
        data = external_asset_collection.to_list()
        assert isinstance(data, list)
        assert len(data) == 4
        assert all(isinstance(item, dict) for item in data)

    def test_to_json(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test conversion to JSON string."""
        json_str = external_asset_collection.to_json()
        assert isinstance(json_str, str)
        assert "www.example.com" in json_str

    def test_from_list(self) -> None:
        """Test creation from list of dicts."""
        data = [
            {"id": "asset-1", "domain": "test1.example.com"},
            {"id": "asset-2", "domain": "test2.example.com"},
        ]
        collection = ExternalAssetCollection.from_list(data)
        assert len(collection) == 2

    def test_from_json(self) -> None:
        """Test creation from JSON string."""
        json_str = '[{"id": "asset-1", "domain": "test.example.com"}]'
        collection = ExternalAssetCollection.from_json(json_str)
        assert len(collection) == 1
        assert collection[0].domain == "test.example.com"

    def test_collection_roundtrip(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test JSON serialization/deserialization roundtrip."""
        json_str = external_asset_collection.to_json()
        restored = ExternalAssetCollection.from_json(json_str)
        assert len(restored) == len(external_asset_collection)


# ============================================================================
# ASMScanResult Tests
# ============================================================================


class TestASMScanResult:
    """Tests for ASMScanResult model."""

    def test_create_scan_result(self) -> None:
        """Test basic scan result creation."""
        result = ASMScanResult(
            scan_id="test-scan-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
            scan_mode=ASMScanMode.PASSIVE,
        )

        assert result.scan_id == "test-scan-001"
        assert result.status == ASMScanStatus.PENDING
        assert result.target_domains == ["example.com"]
        assert result.scan_mode == ASMScanMode.PASSIVE

    def test_scan_status_pending(self) -> None:
        """Test initial pending status."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        assert result.status == ASMScanStatus.PENDING
        assert result.is_complete is False
        assert result.is_success is False

    def test_scan_start(self) -> None:
        """Test starting a scan."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        result.start()

        assert result.status == ASMScanStatus.RUNNING
        assert result.is_complete is False

    def test_scan_complete(
        self, external_asset_collection: ExternalAssetCollection
    ) -> None:
        """Test completing a scan."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        result.start()
        result.complete(external_asset_collection, findings_count=5)

        assert result.status == ASMScanStatus.COMPLETED
        assert result.is_complete is True
        assert result.is_success is True
        assert result.assets_discovered == 4
        assert result.findings_count == 5
        assert result.completed_at is not None
        assert result.duration_seconds >= 0

    def test_scan_fail(self) -> None:
        """Test failing a scan."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        result.start()
        result.fail("Connection timeout")

        assert result.status == ASMScanStatus.FAILED
        assert result.is_complete is True
        assert result.is_success is False
        assert result.has_errors is True
        assert "Connection timeout" in result.errors

    def test_add_error(self) -> None:
        """Test adding errors to scan."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        result.add_error("Warning: rate limit reached")
        result.add_error("Warning: DNS timeout")

        assert len(result.errors) == 2
        assert result.has_errors is True

    def test_add_collector(self) -> None:
        """Test recording collector execution."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )
        result.add_collector("cert_transparency")
        result.add_collector("dns_enumeration")
        result.add_collector("cert_transparency")  # Duplicate

        assert len(result.collectors_run) == 2
        assert "cert_transparency" in result.collectors_run
        assert "dns_enumeration" in result.collectors_run

    def test_scan_to_dict(self, asm_scan_result: ASMScanResult) -> None:
        """Test serialization to dictionary."""
        data = asm_scan_result.to_dict()

        assert data["scan_id"] == "asm-20260108-120000-abc123"
        assert data["status"] == "completed"
        assert data["scan_mode"] == "passive"
        assert "started_at" in data
        assert "completed_at" in data
        assert "duration_seconds" in data

    def test_scan_from_dict(self) -> None:
        """Test deserialization from dictionary."""
        data = {
            "scan_id": "test-scan-001",
            "started_at": "2025-01-15T10:00:00+00:00",
            "completed_at": "2025-01-15T10:05:00+00:00",
            "status": "completed",
            "target_domains": ["example.com", "test.com"],
            "scan_mode": "active",
            "assets_discovered": 10,
            "findings_count": 3,
            "errors": [],
            "collectors_run": ["cert_transparency", "port_scan"],
            "duration_seconds": 300.0,
        }

        result = ASMScanResult.from_dict(data)

        assert result.scan_id == "test-scan-001"
        assert result.status == ASMScanStatus.COMPLETED
        assert result.scan_mode == ASMScanMode.ACTIVE
        assert result.assets_discovered == 10
        assert len(result.target_domains) == 2
        assert len(result.collectors_run) == 2

    def test_generate_scan_id(self) -> None:
        """Test scan ID generation."""
        scan_id = ASMScanResult.generate_scan_id()

        assert scan_id.startswith("asm-")
        # Format: asm-YYYYMMDD-HHMMSS-XXXXXXXX
        parts = scan_id.split("-")
        assert len(parts) == 4

    def test_scan_modes(self) -> None:
        """Test different scan modes."""
        for mode in ASMScanMode:
            result = ASMScanResult(
                scan_id="test-001",
                started_at=datetime.now(timezone.utc),
                target_domains=["example.com"],
                scan_mode=mode,
            )
            assert result.scan_mode == mode

    def test_scan_statuses(self) -> None:
        """Test all scan status values."""
        assert ASMScanStatus.PENDING.value == "pending"
        assert ASMScanStatus.RUNNING.value == "running"
        assert ASMScanStatus.COMPLETED.value == "completed"
        assert ASMScanStatus.FAILED.value == "failed"
        assert ASMScanStatus.CANCELLED.value == "cancelled"

    def test_is_complete_states(self) -> None:
        """Test is_complete for all terminal states."""
        result = ASMScanResult(
            scan_id="test-001",
            started_at=datetime.now(timezone.utc),
            target_domains=["example.com"],
        )

        result.status = ASMScanStatus.COMPLETED
        assert result.is_complete is True

        result.status = ASMScanStatus.FAILED
        assert result.is_complete is True

        result.status = ASMScanStatus.CANCELLED
        assert result.is_complete is True

        result.status = ASMScanStatus.RUNNING
        assert result.is_complete is False
