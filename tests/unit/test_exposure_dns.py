"""
Unit tests for DNS inventory in exposure management.

Tests the DNSInventory, DNS models, and cloud-specific collectors.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.exposure.dns import (
    AWSRoute53Collector,
    AzureDNSCollector,
    BaseDNSCollector,
    CLOUD_SERVICE_PATTERNS,
    DNSConfig,
    DNSFinding,
    DNSFindingType,
    DNSInventory,
    DNSInventoryResult,
    DNSRecord,
    DNSRecordType,
    DNSSeverity,
    DNSSummary,
    DNSZone,
    GCPCloudDNSCollector,
    scan_dns_inventory,
)


class TestDNSRecordType:
    """Tests for DNSRecordType enum."""

    def test_common_types_exist(self) -> None:
        """Test common DNS record types are defined."""
        assert DNSRecordType.A.value == "A"
        assert DNSRecordType.AAAA.value == "AAAA"
        assert DNSRecordType.CNAME.value == "CNAME"
        assert DNSRecordType.MX.value == "MX"
        assert DNSRecordType.TXT.value == "TXT"
        assert DNSRecordType.NS.value == "NS"

    def test_alias_type(self) -> None:
        """Test ALIAS record type for cloud-specific aliases."""
        assert DNSRecordType.ALIAS.value == "ALIAS"


class TestDNSFindingType:
    """Tests for DNSFindingType enum."""

    def test_dangling_types(self) -> None:
        """Test dangling DNS finding types."""
        assert DNSFindingType.DANGLING_CNAME.value == "dangling_cname"
        assert DNSFindingType.DANGLING_A_RECORD.value == "dangling_a_record"
        assert DNSFindingType.DANGLING_ALIAS.value == "dangling_alias"

    def test_exposure_types(self) -> None:
        """Test exposure finding types."""
        assert DNSFindingType.DNS_TO_PUBLIC_RESOURCE.value == "dns_to_public_resource"
        assert DNSFindingType.WILDCARD_EXPOSURE.value == "wildcard_exposure"

    def test_takeover_types(self) -> None:
        """Test takeover risk finding types."""
        assert DNSFindingType.AZURE_TAKEOVER_RISK.value == "azure_takeover_risk"
        assert DNSFindingType.AWS_TAKEOVER_RISK.value == "aws_takeover_risk"
        assert DNSFindingType.GCP_TAKEOVER_RISK.value == "gcp_takeover_risk"


class TestDNSSeverity:
    """Tests for DNSSeverity enum."""

    def test_severity_ranking(self) -> None:
        """Test severity comparison operators."""
        assert DNSSeverity.CRITICAL > DNSSeverity.HIGH
        assert DNSSeverity.HIGH > DNSSeverity.MEDIUM
        assert DNSSeverity.MEDIUM > DNSSeverity.LOW
        assert DNSSeverity.LOW > DNSSeverity.INFO

    def test_severity_ranks(self) -> None:
        """Test severity rank values."""
        assert DNSSeverity.CRITICAL.rank == 5
        assert DNSSeverity.HIGH.rank == 4
        assert DNSSeverity.MEDIUM.rank == 3


class TestDNSConfig:
    """Tests for DNSConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = DNSConfig()
        assert config.check_dangling is True
        assert config.check_caa is True
        assert config.check_wildcards is True
        assert config.resolve_records is True
        assert "A" in config.include_record_types
        assert "CNAME" in config.include_record_types

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = DNSConfig(
            check_dangling=False,
            include_record_types=["A", "AAAA"],
        )
        assert config.check_dangling is False
        assert config.include_record_types == ["A", "AAAA"]


class TestDNSZone:
    """Tests for DNSZone dataclass."""

    def test_zone_creation(self) -> None:
        """Test basic zone creation."""
        zone = DNSZone(
            zone_id="Z123456",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
        )
        assert zone.zone_id == "Z123456"
        assert zone.name == "example.com"
        assert zone.is_private is False

    def test_private_zone(self) -> None:
        """Test private zone."""
        zone = DNSZone(
            zone_id="Z789",
            name="internal.example.com",
            cloud_provider="aws",
            account_id="123456789",
            is_private=True,
        )
        assert zone.is_private is True

    def test_zone_to_dict(self) -> None:
        """Test zone to_dict method."""
        zone = DNSZone(
            zone_id="Z123",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
            nameservers=["ns1.example.com", "ns2.example.com"],
        )
        result = zone.to_dict()
        assert result["zone_id"] == "Z123"
        assert len(result["nameservers"]) == 2


class TestDNSRecord:
    """Tests for DNSRecord dataclass."""

    def test_record_creation(self) -> None:
        """Test basic record creation."""
        record = DNSRecord(
            record_id="rec-123",
            zone_id="Z123",
            zone_name="example.com",
            name="www.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
        )
        assert record.name == "www.example.com"
        assert record.values == ["1.2.3.4"]

    def test_is_wildcard(self) -> None:
        """Test wildcard detection."""
        wildcard = DNSRecord(
            record_id="rec-w1",
            zone_id="Z123",
            zone_name="example.com",
            name="*.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
        )
        assert wildcard.is_wildcard is True

        regular = DNSRecord(
            record_id="rec-r1",
            zone_id="Z123",
            zone_name="example.com",
            name="www.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
        )
        assert regular.is_wildcard is False

    def test_subdomain_extraction(self) -> None:
        """Test subdomain property."""
        record = DNSRecord(
            record_id="rec-1",
            zone_id="Z123",
            zone_name="example.com",
            name="api.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
        )
        assert record.subdomain == "api"

    def test_cname_record(self) -> None:
        """Test CNAME record."""
        record = DNSRecord(
            record_id="rec-c1",
            zone_id="Z123",
            zone_name="example.com",
            name="www.example.com",
            record_type=DNSRecordType.CNAME,
            values=["example.com"],
        )
        assert record.record_type == DNSRecordType.CNAME

    def test_alias_record(self) -> None:
        """Test alias record."""
        record = DNSRecord(
            record_id="rec-a1",
            zone_id="Z123",
            zone_name="example.com",
            name="cdn.example.com",
            record_type=DNSRecordType.A,
            values=["d123.cloudfront.net"],
            is_alias=True,
            alias_target="d123.cloudfront.net",
        )
        assert record.is_alias is True
        assert record.alias_target == "d123.cloudfront.net"

    def test_record_to_dict(self) -> None:
        """Test record to_dict method."""
        record = DNSRecord(
            record_id="rec-1",
            zone_id="Z123",
            zone_name="example.com",
            name="www.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
        )
        result = record.to_dict()
        assert result["record_type"] == "A"
        assert result["values"] == ["1.2.3.4"]


class TestDNSFinding:
    """Tests for DNSFinding dataclass."""

    def test_finding_creation(self) -> None:
        """Test DNS finding creation."""
        finding = DNSFinding(
            finding_id=str(uuid.uuid4()),
            finding_type=DNSFindingType.DANGLING_CNAME,
            severity=DNSSeverity.CRITICAL,
            title="Dangling CNAME detected",
            description="CNAME points to non-existent resource.",
            record_name="old.example.com",
            record_type="CNAME",
            record_values=["deleted.azurewebsites.net"],
            zone_name="example.com",
            cloud_provider="aws",
            takeover_risk=True,
        )
        assert finding.severity == DNSSeverity.CRITICAL
        assert finding.takeover_risk is True

    def test_finding_to_dict(self) -> None:
        """Test finding to_dict method."""
        finding = DNSFinding(
            finding_id="find-1",
            finding_type=DNSFindingType.DANGLING_CNAME,
            severity=DNSSeverity.HIGH,
            title="Dangling CNAME",
            description="Test",
            record_name="test.example.com",
            record_type="CNAME",
            record_values=["target.net"],
            zone_name="example.com",
            cloud_provider="aws",
        )
        result = finding.to_dict()
        assert result["finding_type"] == "dangling_cname"
        assert result["severity"] == "high"


class TestDNSSummary:
    """Tests for DNSSummary dataclass."""

    def test_summary_defaults(self) -> None:
        """Test summary default values."""
        summary = DNSSummary()
        assert summary.total_zones == 0
        assert summary.total_records == 0
        assert summary.dangling_records == 0
        assert summary.takeover_risks == 0

    def test_summary_to_dict(self) -> None:
        """Test summary to_dict method."""
        summary = DNSSummary(
            total_zones=5,
            total_records=100,
            public_zones=4,
            private_zones=1,
        )
        result = summary.to_dict()
        assert result["total_zones"] == 5
        assert result["public_zones"] == 4


class TestDNSInventoryResult:
    """Tests for DNSInventoryResult dataclass."""

    def test_result_creation(self) -> None:
        """Test result creation."""
        result = DNSInventoryResult(
            result_id=str(uuid.uuid4()),
            config=DNSConfig(),
            started_at=datetime.now(timezone.utc),
        )
        assert result.has_findings is False
        assert len(result.zones) == 0

    def test_result_properties(self) -> None:
        """Test result property methods."""
        finding1 = DNSFinding(
            finding_id="f1",
            finding_type=DNSFindingType.DANGLING_CNAME,
            severity=DNSSeverity.CRITICAL,
            title="Critical",
            description="Test",
            record_name="test.com",
            record_type="CNAME",
            record_values=[],
            zone_name="test.com",
            cloud_provider="aws",
            takeover_risk=True,
        )
        finding2 = DNSFinding(
            finding_id="f2",
            finding_type=DNSFindingType.NO_CAA_RECORD,
            severity=DNSSeverity.LOW,
            title="Low",
            description="Test",
            record_name="test.com",
            record_type="CAA",
            record_values=[],
            zone_name="test.com",
            cloud_provider="aws",
        )

        result = DNSInventoryResult(
            result_id="r1",
            config=DNSConfig(),
            started_at=datetime.now(timezone.utc),
            findings=[finding1, finding2],
        )

        assert result.has_findings is True
        assert len(result.critical_findings) == 1
        assert len(result.dangling_records) == 1
        assert len(result.takeover_risks) == 1


class TestCloudServicePatterns:
    """Tests for cloud service pattern matching."""

    def test_aws_patterns(self) -> None:
        """Test AWS service patterns."""
        assert "aws" in CLOUD_SERVICE_PATTERNS
        patterns = CLOUD_SERVICE_PATTERNS["aws"]
        assert any("s3" in p for p in patterns)
        assert any("cloudfront" in p for p in patterns)
        assert any("elasticbeanstalk" in p for p in patterns)

    def test_azure_patterns(self) -> None:
        """Test Azure service patterns."""
        assert "azure" in CLOUD_SERVICE_PATTERNS
        patterns = CLOUD_SERVICE_PATTERNS["azure"]
        assert any("azurewebsites" in p for p in patterns)
        assert any("cloudapp" in p for p in patterns)

    def test_gcp_patterns(self) -> None:
        """Test GCP service patterns."""
        assert "gcp" in CLOUD_SERVICE_PATTERNS
        patterns = CLOUD_SERVICE_PATTERNS["gcp"]
        assert any("appspot" in p for p in patterns)
        assert any("cloudfunctions" in p for p in patterns)


class TestDNSInventory:
    """Tests for DNSInventory class."""

    def _create_zone(
        self,
        name: str = "example.com",
        cloud_provider: str = "aws",
        is_private: bool = False,
    ) -> DNSZone:
        """Create a test DNS zone."""
        return DNSZone(
            zone_id=f"zone-{uuid.uuid4().hex[:8]}",
            name=name,
            cloud_provider=cloud_provider,
            account_id="123456789",
            is_private=is_private,
        )

    def _create_record(
        self,
        zone: DNSZone,
        name: str = "www",
        record_type: DNSRecordType = DNSRecordType.A,
        values: list[str] | None = None,
        is_alias: bool = False,
        alias_target: str | None = None,
    ) -> DNSRecord:
        """Create a test DNS record."""
        full_name = f"{name}.{zone.name}" if not name.endswith(zone.name) else name
        return DNSRecord(
            record_id=f"rec-{uuid.uuid4().hex[:8]}",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=full_name,
            record_type=record_type,
            values=values or ["1.2.3.4"],
            cloud_provider=zone.cloud_provider,
            account_id=zone.account_id,
            is_alias=is_alias,
            alias_target=alias_target,
        )

    def test_inventory_initialization(self) -> None:
        """Test inventory initialization."""
        inventory = DNSInventory()
        assert len(inventory.zones) == 0
        assert len(inventory.records) == 0

    def test_add_zones(self) -> None:
        """Test adding zones to inventory."""
        inventory = DNSInventory()
        zones = [self._create_zone() for _ in range(3)]
        inventory.add_zones(zones)
        assert len(inventory.zones) == 3

    def test_add_records(self) -> None:
        """Test adding records to inventory."""
        zone = self._create_zone()
        inventory = DNSInventory(zones=[zone])
        records = [self._create_record(zone) for _ in range(5)]
        inventory.add_records(records)
        assert len(inventory.records) == 5

    def test_analyze_healthy_records(self) -> None:
        """Test analyzing healthy DNS records (no findings)."""
        zone = self._create_zone()
        record = self._create_record(zone, values=["1.2.3.4"])

        inventory = DNSInventory(zones=[zone], records=[record])
        inventory.add_known_assets(["1.2.3.4"])  # Mark as known
        result = inventory.analyze()

        # Should only have CAA finding (not dangling)
        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 0

    def test_detect_dangling_cname_to_azure(self) -> None:
        """Test detecting dangling CNAME to Azure service."""
        zone = self._create_zone()
        record = self._create_record(
            zone,
            name="app",
            record_type=DNSRecordType.CNAME,
            values=["deleted-app.azurewebsites.net"],
        )

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 1
        assert dangling[0].takeover_risk is True
        assert dangling[0].severity == DNSSeverity.CRITICAL

    def test_detect_dangling_cname_to_aws(self) -> None:
        """Test detecting dangling CNAME to AWS service."""
        zone = self._create_zone()
        record = self._create_record(
            zone,
            name="old-app",
            record_type=DNSRecordType.CNAME,
            values=["old-app.elasticbeanstalk.com"],
        )

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 1
        assert dangling[0].takeover_risk is True

    def test_detect_dangling_alias(self) -> None:
        """Test detecting dangling alias record."""
        zone = self._create_zone()
        record = self._create_record(
            zone,
            name="cdn",
            record_type=DNSRecordType.A,
            values=["d123456.cloudfront.net"],
            is_alias=True,
            alias_target="d123456.cloudfront.net",
        )

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_ALIAS
        ]
        assert len(dangling) == 1

    def test_no_dangling_for_known_assets(self) -> None:
        """Test that known assets are not flagged as dangling."""
        zone = self._create_zone()
        record = self._create_record(
            zone,
            name="app",
            record_type=DNSRecordType.CNAME,
            values=["my-app.azurewebsites.net"],
        )

        inventory = DNSInventory(zones=[zone], records=[record])
        inventory.add_known_assets(["my-app.azurewebsites.net"])
        result = inventory.analyze()

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 0

    def test_detect_wildcard_exposure(self) -> None:
        """Test detecting wildcard DNS exposure."""
        zone = self._create_zone()
        record = DNSRecord(
            record_id="rec-w1",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=f"*.{zone.name}",
            record_type=DNSRecordType.CNAME,
            values=["wildcard.cloudfront.net"],
            cloud_provider="aws",
            account_id="123",
        )

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        wildcard = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.WILDCARD_EXPOSURE
        ]
        assert len(wildcard) == 1
        assert wildcard[0].severity == DNSSeverity.MEDIUM

    def test_detect_missing_caa_record(self) -> None:
        """Test detecting missing CAA record."""
        zone = self._create_zone()
        record = self._create_record(zone, values=["1.2.3.4"])

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        caa = [
            f for f in result.findings if f.finding_type == DNSFindingType.NO_CAA_RECORD
        ]
        assert len(caa) == 1
        assert caa[0].severity == DNSSeverity.LOW

    def test_no_caa_finding_when_caa_exists(self) -> None:
        """Test no CAA finding when CAA record exists."""
        zone = self._create_zone()
        caa_record = DNSRecord(
            record_id="rec-caa",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=zone.name,
            record_type=DNSRecordType.CAA,
            values=['0 issue "letsencrypt.org"'],
            cloud_provider="aws",
            account_id="123",
        )

        inventory = DNSInventory(zones=[zone], records=[caa_record])
        result = inventory.analyze()

        caa = [
            f for f in result.findings if f.finding_type == DNSFindingType.NO_CAA_RECORD
        ]
        assert len(caa) == 0

    def test_no_caa_finding_for_private_zones(self) -> None:
        """Test no CAA finding for private zones."""
        zone = self._create_zone(is_private=True)
        record = self._create_record(zone)

        inventory = DNSInventory(zones=[zone], records=[record])
        result = inventory.analyze()

        caa = [
            f for f in result.findings if f.finding_type == DNSFindingType.NO_CAA_RECORD
        ]
        assert len(caa) == 0

    def test_disable_dangling_check(self) -> None:
        """Test disabling dangling DNS check."""
        config = DNSConfig(check_dangling=False)
        zone = self._create_zone()
        record = self._create_record(
            zone,
            name="app",
            record_type=DNSRecordType.CNAME,
            values=["deleted.azurewebsites.net"],
        )

        inventory = DNSInventory(zones=[zone], records=[record], config=config)
        result = inventory.analyze()

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 0

    def test_disable_wildcard_check(self) -> None:
        """Test disabling wildcard check."""
        config = DNSConfig(check_wildcards=False)
        zone = self._create_zone()
        record = DNSRecord(
            record_id="rec-w1",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=f"*.{zone.name}",
            record_type=DNSRecordType.CNAME,
            values=["wildcard.cloudfront.net"],
            cloud_provider="aws",
            account_id="123",
        )

        inventory = DNSInventory(zones=[zone], records=[record], config=config)
        result = inventory.analyze()

        wildcard = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.WILDCARD_EXPOSURE
        ]
        assert len(wildcard) == 0

    def test_get_records_by_zone(self) -> None:
        """Test getting records by zone."""
        zone1 = self._create_zone(name="zone1.com")
        zone2 = self._create_zone(name="zone2.com")
        records = [
            self._create_record(zone1),
            self._create_record(zone1),
            self._create_record(zone2),
        ]

        inventory = DNSInventory(zones=[zone1, zone2], records=records)
        zone1_records = inventory.get_records_by_zone("zone1.com")
        assert len(zone1_records) == 2

    def test_get_records_by_type(self) -> None:
        """Test getting records by type."""
        zone = self._create_zone()
        records = [
            self._create_record(zone, record_type=DNSRecordType.A),
            self._create_record(zone, record_type=DNSRecordType.A),
            self._create_record(zone, record_type=DNSRecordType.CNAME, values=["target.com"]),
        ]

        inventory = DNSInventory(zones=[zone], records=records)
        a_records = inventory.get_records_by_type(DNSRecordType.A)
        assert len(a_records) == 2

    def test_get_zones_by_cloud(self) -> None:
        """Test getting zones by cloud provider."""
        aws_zone = self._create_zone(cloud_provider="aws")
        gcp_zone = self._create_zone(cloud_provider="gcp", name="gcp.example.com")

        inventory = DNSInventory(zones=[aws_zone, gcp_zone])
        aws_zones = inventory.get_zones_by_cloud("aws")
        assert len(aws_zones) == 1
        assert aws_zones[0].cloud_provider == "aws"

    def test_summary_statistics(self) -> None:
        """Test summary statistics are calculated correctly."""
        zone1 = self._create_zone(name="public.com")
        zone2 = self._create_zone(name="private.internal", is_private=True)
        records = [
            self._create_record(zone1, record_type=DNSRecordType.A),
            self._create_record(zone1, record_type=DNSRecordType.CNAME, values=["target.com"]),
            DNSRecord(
                record_id="rec-w",
                zone_id=zone1.zone_id,
                zone_name=zone1.name,
                name=f"*.{zone1.name}",
                record_type=DNSRecordType.A,
                values=["1.2.3.4"],
                cloud_provider="aws",
                account_id="123",
            ),
        ]

        inventory = DNSInventory(zones=[zone1, zone2], records=records)
        result = inventory.analyze()

        assert result.summary.total_zones == 2
        assert result.summary.public_zones == 1
        assert result.summary.private_zones == 1
        assert result.summary.total_records == 3
        assert result.summary.wildcard_records == 1


class TestScanDNSInventoryFunction:
    """Tests for scan_dns_inventory convenience function."""

    def test_scan_dns_inventory(self) -> None:
        """Test scan_dns_inventory function."""
        zone = DNSZone(
            zone_id="Z1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
        )
        record = DNSRecord(
            record_id="r1",
            zone_id="Z1",
            zone_name="example.com",
            name="app.example.com",
            record_type=DNSRecordType.CNAME,
            values=["old.azurewebsites.net"],
            cloud_provider="aws",
            account_id="123",
        )

        result = scan_dns_inventory([zone], [record])

        assert result.summary.total_zones == 1
        assert result.summary.total_records == 1
        assert len(result.findings) >= 1  # At least dangling or CAA

    def test_scan_with_known_assets(self) -> None:
        """Test scan with known assets."""
        zone = DNSZone(
            zone_id="Z1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
        )
        record = DNSRecord(
            record_id="r1",
            zone_id="Z1",
            zone_name="example.com",
            name="app.example.com",
            record_type=DNSRecordType.CNAME,
            values=["my-app.azurewebsites.net"],
            cloud_provider="aws",
            account_id="123",
        )

        result = scan_dns_inventory(
            [zone], [record], known_assets=["my-app.azurewebsites.net"]
        )

        dangling = [
            f
            for f in result.findings
            if f.finding_type == DNSFindingType.DANGLING_CNAME
        ]
        assert len(dangling) == 0


class TestAWSRoute53Collector:
    """Tests for AWS Route53 collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        mock_session = MagicMock()
        collector = AWSRoute53Collector(session=mock_session)
        assert collector._session == mock_session

    def test_parse_zone(self) -> None:
        """Test parsing Route53 hosted zone."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789"
        }
        collector = AWSRoute53Collector(session=mock_session)

        zone_data = {
            "Id": "/hostedzone/Z123456",
            "Name": "example.com.",
            "Config": {"PrivateZone": False, "Comment": "Test zone"},
            "ResourceRecordSetCount": 10,
        }
        zone = collector._parse_zone(zone_data)

        assert zone.zone_id == "Z123456"
        assert zone.name == "example.com"
        assert zone.is_private is False

    def test_parse_private_zone(self) -> None:
        """Test parsing private hosted zone."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789"
        }
        collector = AWSRoute53Collector(session=mock_session)

        zone_data = {
            "Id": "/hostedzone/Z789",
            "Name": "internal.example.com.",
            "Config": {"PrivateZone": True},
            "ResourceRecordSetCount": 5,
        }
        zone = collector._parse_zone(zone_data)

        assert zone.is_private is True

    def test_parse_a_record(self) -> None:
        """Test parsing A record."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789"
        }
        collector = AWSRoute53Collector(session=mock_session)

        zone = DNSZone(
            zone_id="Z123",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
        )
        record_data = {
            "Name": "www.example.com.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [{"Value": "1.2.3.4"}],
        }
        record = collector._parse_record(record_data, zone)

        assert record is not None
        assert record.name == "www.example.com"
        assert record.record_type == DNSRecordType.A
        assert record.values == ["1.2.3.4"]

    def test_parse_alias_record(self) -> None:
        """Test parsing alias record."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789"
        }
        collector = AWSRoute53Collector(session=mock_session)

        zone = DNSZone(
            zone_id="Z123",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
        )
        record_data = {
            "Name": "cdn.example.com.",
            "Type": "A",
            "AliasTarget": {
                "DNSName": "d123.cloudfront.net.",
                "HostedZoneId": "Z2FDTNDATAQYW2",
                "EvaluateTargetHealth": False,
            },
        }
        record = collector._parse_record(record_data, zone)

        assert record is not None
        assert record.is_alias is True
        assert record.alias_target == "d123.cloudfront.net"

    def test_parse_cname_record(self) -> None:
        """Test parsing CNAME record."""
        mock_session = MagicMock()
        mock_session.client.return_value.get_caller_identity.return_value = {
            "Account": "123456789"
        }
        collector = AWSRoute53Collector(session=mock_session)

        zone = DNSZone(
            zone_id="Z123",
            name="example.com",
            cloud_provider="aws",
            account_id="123456789",
        )
        record_data = {
            "Name": "app.example.com.",
            "Type": "CNAME",
            "TTL": 300,
            "ResourceRecords": [{"Value": "app.azurewebsites.net"}],
        }
        record = collector._parse_record(record_data, zone)

        assert record is not None
        assert record.record_type == DNSRecordType.CNAME
        assert record.values == ["app.azurewebsites.net"]


class TestGCPCloudDNSCollector:
    """Tests for GCP Cloud DNS collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        collector = GCPCloudDNSCollector(project_id="my-project")
        assert collector.project_id == "my-project"

    def test_project_id_required(self) -> None:
        """Test project_id is required."""
        collector = GCPCloudDNSCollector()
        with pytest.raises(ValueError, match="project_id is required"):
            _ = collector.project_id


class TestAzureDNSCollector:
    """Tests for Azure DNS collector."""

    def test_collector_initialization(self) -> None:
        """Test collector initialization."""
        collector = AzureDNSCollector(subscription_id="sub-123")
        assert collector.subscription_id == "sub-123"

    def test_subscription_id_required(self) -> None:
        """Test subscription_id is required."""
        collector = AzureDNSCollector()
        with pytest.raises(ValueError, match="subscription_id is required"):
            _ = collector.subscription_id


class TestDNSInventoryIntegration:
    """Integration tests for DNS inventory."""

    def test_full_inventory_workflow(self) -> None:
        """Test complete inventory workflow."""
        # Create multi-cloud zones
        zones = [
            DNSZone(
                zone_id="Z-aws",
                name="aws.example.com",
                cloud_provider="aws",
                account_id="123",
            ),
            DNSZone(
                zone_id="Z-gcp",
                name="gcp.example.com",
                cloud_provider="gcp",
                account_id="proj-1",
            ),
        ]

        # Create various records
        records = [
            # Healthy A record
            DNSRecord(
                record_id="r1",
                zone_id="Z-aws",
                zone_name="aws.example.com",
                name="www.aws.example.com",
                record_type=DNSRecordType.A,
                values=["1.2.3.4"],
                cloud_provider="aws",
                account_id="123",
            ),
            # Dangling CNAME
            DNSRecord(
                record_id="r2",
                zone_id="Z-aws",
                zone_name="aws.example.com",
                name="old.aws.example.com",
                record_type=DNSRecordType.CNAME,
                values=["deleted.azurewebsites.net"],
                cloud_provider="aws",
                account_id="123",
            ),
            # Wildcard
            DNSRecord(
                record_id="r3",
                zone_id="Z-gcp",
                zone_name="gcp.example.com",
                name="*.gcp.example.com",
                record_type=DNSRecordType.CNAME,
                values=["wildcard.appspot.com"],
                cloud_provider="gcp",
                account_id="proj-1",
            ),
        ]

        result = scan_dns_inventory(zones, records)

        # Verify results
        assert result.summary.total_zones == 2
        assert result.summary.total_records == 3
        assert result.summary.wildcard_records == 1

        # Should have findings for dangling and wildcard
        assert len(result.findings) >= 2
        assert len(result.takeover_risks) >= 1

    def test_result_serialization(self) -> None:
        """Test result can be serialized to dict."""
        zone = DNSZone(
            zone_id="Z1",
            name="example.com",
            cloud_provider="aws",
            account_id="123",
        )
        record = DNSRecord(
            record_id="r1",
            zone_id="Z1",
            zone_name="example.com",
            name="www.example.com",
            record_type=DNSRecordType.A,
            values=["1.2.3.4"],
            cloud_provider="aws",
            account_id="123",
        )

        result = scan_dns_inventory([zone], [record])
        result_dict = result.to_dict()

        assert "result_id" in result_dict
        assert "zones" in result_dict
        assert "records" in result_dict
        assert "findings" in result_dict
        assert "summary" in result_dict
