"""
Unit tests for ASM drift detection.

Tests cover:
- Change type and severity enums
- AssetChange, PortChange, CertificateChange dataclasses
- DriftReport and DriftSummary
- ASMDriftDetector detection logic
- Drift findings generation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from stance.asm.drift import (
    ASMDriftDetector,
    AssetChange,
    CertificateChange,
    ChangeType,
    DriftReport,
    DriftSeverity,
    DriftSummary,
    PortChange,
    CRITICAL_PORTS,
    HIGH_RISK_PORTS,
)
from stance.asm.models import (
    ASMScanMode,
    ASMScanResult,
    ASMScanStatus,
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)
from stance.asm.storage import ASMStorageAdapter


# ============================================================================
# Enum Tests
# ============================================================================


class TestChangeType:
    """Tests for ChangeType enum."""

    def test_change_type_values(self) -> None:
        """Test ChangeType enum values."""
        assert ChangeType.ADDED.value == "added"
        assert ChangeType.REMOVED.value == "removed"
        assert ChangeType.MODIFIED.value == "modified"


class TestDriftSeverity:
    """Tests for DriftSeverity enum."""

    def test_drift_severity_values(self) -> None:
        """Test DriftSeverity enum values."""
        assert DriftSeverity.CRITICAL.value == "critical"
        assert DriftSeverity.HIGH.value == "high"
        assert DriftSeverity.MEDIUM.value == "medium"
        assert DriftSeverity.LOW.value == "low"
        assert DriftSeverity.INFO.value == "info"


# ============================================================================
# DataClass Tests
# ============================================================================


class TestAssetChange:
    """Tests for AssetChange dataclass."""

    def test_create_asset_change(self) -> None:
        """Test creating an asset change."""
        change = AssetChange(
            asset_id="asset-001",
            domain="example.com",
            field_name="ip_address",
            old_value="1.2.3.4",
            new_value="5.6.7.8",
            change_type=ChangeType.MODIFIED,
        )

        assert change.asset_id == "asset-001"
        assert change.domain == "example.com"
        assert change.field_name == "ip_address"
        assert change.old_value == "1.2.3.4"
        assert change.new_value == "5.6.7.8"
        assert change.change_type == ChangeType.MODIFIED

    def test_asset_change_to_dict(self) -> None:
        """Test AssetChange serialization."""
        change = AssetChange(
            asset_id="asset-001",
            domain="example.com",
            field_name="service",
            old_value="nginx",
            new_value="apache",
            change_type=ChangeType.MODIFIED,
        )

        data = change.to_dict()
        assert data["asset_id"] == "asset-001"
        assert data["change_type"] == "modified"


class TestPortChange:
    """Tests for PortChange dataclass."""

    def test_create_port_change(self) -> None:
        """Test creating a port change."""
        change = PortChange(
            domain="example.com",
            ip_address="1.2.3.4",
            port=3389,
            change_type=ChangeType.ADDED,
            service="Microsoft Terminal Services",
            protocol="tcp",
        )

        assert change.domain == "example.com"
        assert change.port == 3389
        assert change.change_type == ChangeType.ADDED

    def test_port_change_to_dict(self) -> None:
        """Test PortChange serialization."""
        change = PortChange(
            domain="example.com",
            ip_address="1.2.3.4",
            port=22,
            change_type=ChangeType.REMOVED,
        )

        data = change.to_dict()
        assert data["port"] == 22
        assert data["change_type"] == "removed"


class TestCertificateChange:
    """Tests for CertificateChange dataclass."""

    def test_create_certificate_change(self) -> None:
        """Test creating a certificate change."""
        now = datetime.now(timezone.utc)
        later = now + timedelta(days=365)

        change = CertificateChange(
            domain="example.com",
            change_type=ChangeType.MODIFIED,
            old_fingerprint="abc123",
            new_fingerprint="def456",
            old_expiry=now,
            new_expiry=later,
            old_issuer="Old CA",
            new_issuer="New CA",
        )

        assert change.domain == "example.com"
        assert change.change_type == ChangeType.MODIFIED
        assert change.old_fingerprint == "abc123"
        assert change.new_fingerprint == "def456"

    def test_certificate_change_to_dict(self) -> None:
        """Test CertificateChange serialization."""
        now = datetime.now(timezone.utc)

        change = CertificateChange(
            domain="example.com",
            change_type=ChangeType.ADDED,
            new_fingerprint="abc123",
            new_expiry=now,
            new_issuer="CA",
        )

        data = change.to_dict()
        assert data["domain"] == "example.com"
        assert data["change_type"] == "added"
        assert data["new_fingerprint"] == "abc123"


# ============================================================================
# DriftSummary Tests
# ============================================================================


class TestDriftSummary:
    """Tests for DriftSummary dataclass."""

    def test_default_summary(self) -> None:
        """Test default DriftSummary values."""
        summary = DriftSummary()

        assert summary.total_changes == 0
        assert summary.new_assets_count == 0
        assert summary.removed_assets_count == 0
        assert summary.modified_assets_count == 0
        assert summary.new_ports_count == 0
        assert summary.closed_ports_count == 0
        assert summary.certificate_changes_count == 0
        assert summary.critical_changes == 0
        assert summary.high_changes == 0

    def test_summary_to_dict(self) -> None:
        """Test DriftSummary serialization."""
        summary = DriftSummary(
            total_changes=10,
            new_assets_count=3,
            removed_assets_count=2,
            critical_changes=1,
        )

        data = summary.to_dict()
        assert data["total_changes"] == 10
        assert data["new_assets_count"] == 3
        assert data["critical_changes"] == 1


# ============================================================================
# DriftReport Tests
# ============================================================================


class TestDriftReport:
    """Tests for DriftReport dataclass."""

    def test_default_report(self) -> None:
        """Test creating default DriftReport."""
        report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
        )

        assert report.baseline_scan_id == "scan-001"
        assert report.current_scan_id == "scan-002"
        assert report.new_assets == []
        assert report.removed_assets == []

    def test_has_changes(self) -> None:
        """Test has_changes method."""
        report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
        )

        assert report.has_changes() is False

        report.summary.total_changes = 5
        assert report.has_changes() is True

    def test_has_critical_changes(self) -> None:
        """Test has_critical_changes method."""
        report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
        )

        assert report.has_critical_changes() is False

        report.summary.critical_changes = 1
        assert report.has_critical_changes() is True

    def test_report_to_dict(self, web_asset: ExternalAsset) -> None:
        """Test DriftReport serialization."""
        now = datetime.now(timezone.utc)

        report = DriftReport(
            baseline_scan_id="scan-001",
            current_scan_id="scan-002",
            baseline_scan_time=now - timedelta(days=1),
            current_scan_time=now,
            new_assets=[web_asset],
        )

        data = report.to_dict()
        assert data["baseline_scan_id"] == "scan-001"
        assert data["current_scan_id"] == "scan-002"
        assert len(data["new_assets"]) == 1
        assert "summary" in data


# ============================================================================
# Port Constants Tests
# ============================================================================


class TestPortConstants:
    """Tests for port risk constants."""

    def test_critical_ports(self) -> None:
        """Test critical ports set."""
        assert 3389 in CRITICAL_PORTS  # RDP
        assert 3306 in CRITICAL_PORTS  # MySQL
        assert 5432 in CRITICAL_PORTS  # PostgreSQL
        assert 27017 in CRITICAL_PORTS  # MongoDB
        assert 6379 in CRITICAL_PORTS  # Redis

    def test_high_risk_ports(self) -> None:
        """Test high-risk ports set."""
        assert 22 in HIGH_RISK_PORTS  # SSH
        assert 23 in HIGH_RISK_PORTS  # Telnet
        assert 21 in HIGH_RISK_PORTS  # FTP
        assert 445 in HIGH_RISK_PORTS  # SMB
        assert 5900 in HIGH_RISK_PORTS  # VNC


# ============================================================================
# ASMDriftDetector Tests
# ============================================================================


class TestASMDriftDetector:
    """Tests for ASMDriftDetector."""

    def test_detect_new_assets(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        api_asset: ExternalAsset,
    ) -> None:
        """Test detecting new assets."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Create baseline scan with web_asset
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset]),
            baseline.scan_id,
        )

        # Create current scan with web_asset and api_asset
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset, api_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.new_assets) == 1
        assert report.new_assets[0].domain == "api.example.com"
        assert report.summary.new_assets_count == 1

    def test_detect_removed_assets(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        api_asset: ExternalAsset,
    ) -> None:
        """Test detecting removed assets."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Create baseline scan with both assets
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset, api_asset]),
            baseline.scan_id,
        )

        # Create current scan with only web_asset
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.removed_assets) == 1
        assert report.removed_assets[0].domain == "api.example.com"
        assert report.summary.removed_assets_count == 1

    def test_detect_ip_change(
        self,
        temp_db_path: str,
        valid_certificate: CertificateInfo,
    ) -> None:
        """Test detecting IP address change."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Create baseline asset
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        # Create current asset with changed IP
        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="5.6.7.8",  # Changed
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        # Find IP change
        ip_changes = [c for c in report.changed_assets if c.field_name == "ip_address"]
        assert len(ip_changes) == 1
        assert ip_changes[0].old_value == "1.2.3.4"
        assert ip_changes[0].new_value == "5.6.7.8"

    def test_detect_certificate_change(
        self,
        temp_db_path: str,
        valid_certificate: CertificateInfo,
        expiring_certificate: CertificateInfo,
    ) -> None:
        """Test detecting certificate change."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Create assets with different certificates
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            certificate_info=valid_certificate,
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            certificate_info=expiring_certificate,  # Different certificate
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.certificate_changes) == 1
        cert_change = report.certificate_changes[0]
        assert cert_change.change_type == ChangeType.MODIFIED
        assert cert_change.old_fingerprint == "abc123def456"
        assert cert_change.new_fingerprint == "def456abc789"

    def test_detect_new_critical_port(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        rdp_asset: ExternalAsset,
    ) -> None:
        """Test detecting new critical port exposure."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline with only web asset
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset]),
            baseline.scan_id,
        )

        # Current with RDP asset (critical port)
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset, rdp_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.new_ports) == 1
        assert report.new_ports[0].port == 3389
        assert report.summary.critical_changes >= 1

    def test_detect_certificate_added(
        self,
        temp_db_path: str,
        valid_certificate: CertificateInfo,
    ) -> None:
        """Test detecting certificate addition."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline asset without certificate
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        # Current asset with certificate
        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            certificate_info=valid_certificate,
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.certificate_changes) == 1
        assert report.certificate_changes[0].change_type == ChangeType.ADDED

    def test_detect_certificate_removed(
        self,
        temp_db_path: str,
        valid_certificate: CertificateInfo,
    ) -> None:
        """Test detecting certificate removal."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline asset with certificate
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            certificate_info=valid_certificate,
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        # Current asset without certificate
        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        assert len(report.certificate_changes) == 1
        assert report.certificate_changes[0].change_type == ChangeType.REMOVED
        assert report.summary.high_changes >= 1  # Certificate removal is high severity

    def test_detect_no_baseline(self, temp_db_path: str) -> None:
        """Test drift detection with no baseline scan."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Only create current scan
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)

        # Detect drift without baseline
        report = detector.detect_drift(current.scan_id)

        assert report.baseline_scan_id == ""
        assert report.current_scan_id == current.scan_id
        assert report.has_changes() is False

    def test_detect_technology_stack_change(
        self,
        temp_db_path: str,
    ) -> None:
        """Test detecting technology stack changes."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline asset with tech stack
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            technology_stack=("nginx", "PHP"),
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        # Current asset with changed tech stack
        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            technology_stack=("nginx", "Node.js"),  # PHP -> Node.js
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        # Detect drift
        report = detector.detect_drift(current.scan_id, baseline.scan_id)

        # Check for tech stack changes
        added = [c for c in report.changed_assets if c.field_name == "technology_stack_added"]
        removed = [c for c in report.changed_assets if c.field_name == "technology_stack_removed"]

        assert len(added) == 1
        assert "Node.js" in added[0].new_value
        assert len(removed) == 1
        assert "PHP" in removed[0].old_value


# ============================================================================
# Drift Findings Tests
# ============================================================================


class TestGetDriftFindings:
    """Tests for drift findings generation."""

    def test_generate_critical_port_finding(
        self,
        temp_db_path: str,
        web_asset: ExternalAsset,
        database_asset: ExternalAsset,
    ) -> None:
        """Test generating finding for critical port exposure."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline with web asset only
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset]),
            baseline.scan_id,
        )

        # Current with database asset (critical port 3306)
        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([web_asset, database_asset]),
            current.scan_id,
        )

        report = detector.detect_drift(current.scan_id, baseline.scan_id)
        findings = detector.get_drift_findings(report)

        critical_findings = [f for f in findings if f.get("severity") == "critical"]
        assert len(critical_findings) >= 1
        assert any(f["type"] == "drift_new_critical_port" for f in critical_findings)

    def test_generate_certificate_removed_finding(
        self,
        temp_db_path: str,
        valid_certificate: CertificateInfo,
    ) -> None:
        """Test generating finding for certificate removal."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        # Baseline asset with certificate
        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            certificate_info=valid_certificate,
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        # Current asset without certificate
        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        # Store scans
        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        report = detector.detect_drift(current.scan_id, baseline.scan_id)
        findings = detector.get_drift_findings(report)

        cert_findings = [f for f in findings if f["type"] == "drift_certificate_removed"]
        assert len(cert_findings) == 1
        assert cert_findings[0]["severity"] == "high"

    def test_generate_ip_change_finding(
        self,
        temp_db_path: str,
    ) -> None:
        """Test generating finding for IP address change."""
        storage = ASMStorageAdapter(temp_db_path)
        detector = ASMDriftDetector(storage)
        now = datetime.now(timezone.utc)

        baseline_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="1.2.3.4",
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now - timedelta(hours=2),
        )

        current_asset = ExternalAsset(
            id="asset-001",
            domain="www.example.com",
            ip_address="5.6.7.8",  # Changed
            port=443,
            protocol="https",
            first_seen=now - timedelta(days=30),
            last_seen=now,
        )

        baseline = ASMScanResult(
            scan_id="baseline-001",
            started_at=now - timedelta(hours=2),
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(baseline)
        storage.store_external_assets(
            ExternalAssetCollection([baseline_asset]),
            baseline.scan_id,
        )

        current = ASMScanResult(
            scan_id="current-001",
            started_at=now,
            target_domains=["example.com"],
            status=ASMScanStatus.COMPLETED,
        )
        storage.store_scan_result(current)
        storage.store_external_assets(
            ExternalAssetCollection([current_asset]),
            current.scan_id,
        )

        report = detector.detect_drift(current.scan_id, baseline.scan_id)
        findings = detector.get_drift_findings(report)

        ip_findings = [f for f in findings if f["type"] == "drift_ip_changed"]
        assert len(ip_findings) == 1
        assert ip_findings[0]["old_value"] == "1.2.3.4"
        assert ip_findings[0]["new_value"] == "5.6.7.8"
