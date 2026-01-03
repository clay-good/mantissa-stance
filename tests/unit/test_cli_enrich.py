"""
Unit tests for CLI Enrichment commands.

Tests the enrichment CLI including:
- Finding enrichment with threat intelligence and CVE details
- Asset enrichment with context and IP information
- IP lookup
- CVE lookup
- KEV lookup
- Enrichment status
"""

from __future__ import annotations

import argparse
import json
import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, PropertyMock

from stance.cli_enrich import (
    cmd_enrich,
    _cmd_enrich_findings,
    _cmd_enrich_assets,
    _cmd_enrich_ip,
    _cmd_enrich_cve,
    _cmd_enrich_kev,
    _cmd_enrich_status,
)
from stance.models.asset import Asset, AssetCollection
from stance.models.finding import Finding, FindingType, Severity
from stance.enrichment.base import (
    EnrichedFinding,
    EnrichedAsset,
    EnrichmentData,
    EnrichmentType,
)


class TestCmdEnrich:
    """Tests for the main enrich command router."""

    def test_enrich_no_action_shows_help(self, capsys):
        """Test enrich with no action shows usage."""
        args = argparse.Namespace(enrich_action=None)
        result = cmd_enrich(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Usage: stance enrich <command>" in captured.out
        assert "findings" in captured.out
        assert "assets" in captured.out
        assert "ip" in captured.out
        assert "cve" in captured.out
        assert "kev" in captured.out
        assert "status" in captured.out

    def test_enrich_unknown_action(self, capsys):
        """Test enrich with unknown action returns error."""
        args = argparse.Namespace(enrich_action="unknown")
        result = cmd_enrich(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Unknown enrich command: unknown" in captured.out


class TestEnrichFindings:
    """Tests for finding enrichment command."""

    @pytest.fixture
    def mock_finding(self):
        """Create mock finding."""
        return Finding(
            id="finding-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            finding_type=FindingType.VULNERABILITY,
            cve_id="CVE-2021-44228",
            asset_id="asset-001",
        )

    @pytest.fixture
    def mock_findings_data(self, mock_finding):
        """Create mock findings data."""
        mock_data = MagicMock()
        mock_data.findings = [mock_finding]
        return mock_data

    def test_enrich_findings_no_findings(self, capsys):
        """Test enrich findings with no findings available."""
        args = argparse.Namespace(
            enrich_action="findings",
            format="table",
            types=None,
            finding_id=None,
            limit=50,
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = None
            result = _cmd_enrich_findings(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No findings found" in captured.out

    def test_enrich_findings_success_table(self, capsys, mock_findings_data, mock_finding):
        """Test successful finding enrichment with table output."""
        args = argparse.Namespace(
            enrich_action="findings",
            format="table",
            types=None,
            finding_id=None,
            limit=50,
        )

        # Create mock enriched finding
        enriched_finding = EnrichedFinding(
            finding=mock_finding,
            enrichments=[
                EnrichmentData(
                    enrichment_type=EnrichmentType.CVE_DETAILS,
                    source="nvd",
                    data={"cvss_v3": {"score": 9.8}},
                    confidence=1.0,
                )
            ],
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.cli_enrich.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                result = _cmd_enrich_findings(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Finding Enrichment Results" in captured.out
        assert "Findings processed: 1" in captured.out

    def test_enrich_findings_success_json(self, capsys, mock_findings_data, mock_finding):
        """Test successful finding enrichment with JSON output."""
        args = argparse.Namespace(
            enrich_action="findings",
            format="json",
            types=None,
            finding_id=None,
            limit=50,
        )

        enriched_finding = EnrichedFinding(
            finding=mock_finding,
            enrichments=[
                EnrichmentData(
                    enrichment_type=EnrichmentType.CVE_DETAILS,
                    source="nvd",
                    data={"cvss_v3": {"score": 9.8}},
                    confidence=1.0,
                )
            ],
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.cli_enrich.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                result = _cmd_enrich_findings(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["total_findings"] == 1
        assert output["findings_enriched"] == 1

    def test_enrich_findings_specific_types(self, capsys, mock_findings_data, mock_finding):
        """Test finding enrichment with specific types."""
        args = argparse.Namespace(
            enrich_action="findings",
            format="table",
            types="cve,kev",
            finding_id=None,
            limit=50,
        )

        enriched_finding = EnrichedFinding(finding=mock_finding, enrichments=[])

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            with patch("stance.cli_enrich.CVEEnricher"):
                with patch("stance.cli_enrich.KEVEnricher"):
                    with patch("stance.cli_enrich.EnrichmentPipeline") as mock_pipeline:
                        mock_pipeline.return_value.enrich_findings.return_value = [enriched_finding]

                        result = _cmd_enrich_findings(args)

        assert result == 0

    def test_enrich_findings_invalid_types(self, capsys, mock_findings_data):
        """Test finding enrichment with invalid types."""
        args = argparse.Namespace(
            enrich_action="findings",
            format="table",
            types="invalid",
            finding_id=None,
            limit=50,
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_findings.return_value = mock_findings_data

            result = _cmd_enrich_findings(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No valid enrichment types" in captured.out


class TestEnrichAssets:
    """Tests for asset enrichment command."""

    @pytest.fixture
    def mock_asset(self):
        """Create mock asset."""
        return Asset(
            id="asset-001",
            name="test-bucket",
            resource_type="aws_s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            tags={"environment": "production"},
        )

    @pytest.fixture
    def mock_assets_data(self, mock_asset):
        """Create mock assets data."""
        mock_data = MagicMock()
        mock_data.assets = [mock_asset]
        return mock_data

    def test_enrich_assets_no_assets(self, capsys):
        """Test enrich assets with no assets available."""
        args = argparse.Namespace(
            enrich_action="assets",
            format="table",
            types=None,
            asset_id=None,
            cloud=None,
            limit=50,
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = None
            result = _cmd_enrich_assets(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No assets found" in captured.out

    def test_enrich_assets_success(self, capsys, mock_assets_data, mock_asset):
        """Test successful asset enrichment."""
        args = argparse.Namespace(
            enrich_action="assets",
            format="table",
            types=None,
            asset_id=None,
            cloud=None,
            limit=50,
        )

        enriched_asset = EnrichedAsset(
            asset=mock_asset,
            enrichments=[
                EnrichmentData(
                    enrichment_type=EnrichmentType.CRITICALITY,
                    source="criticality_rules",
                    data={"level": "critical"},
                    confidence=0.9,
                )
            ],
        )

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets_data

            with patch("stance.cli_enrich.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_assets.return_value = [enriched_asset]

                result = _cmd_enrich_assets(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Asset Enrichment Results" in captured.out

    def test_enrich_assets_filter_by_cloud(self, capsys, mock_assets_data, mock_asset):
        """Test asset enrichment filtered by cloud provider."""
        args = argparse.Namespace(
            enrich_action="assets",
            format="table",
            types=None,
            asset_id=None,
            cloud="aws",
            limit=50,
        )

        enriched_asset = EnrichedAsset(asset=mock_asset, enrichments=[])

        with patch("stance.cli_enrich.get_storage") as mock_storage:
            mock_storage.return_value.load_assets.return_value = mock_assets_data

            with patch("stance.cli_enrich.create_default_pipeline") as mock_pipeline:
                mock_pipeline.return_value.enrich_assets.return_value = [enriched_asset]

                result = _cmd_enrich_assets(args)

        assert result == 0


class TestEnrichIP:
    """Tests for IP lookup command."""

    def test_enrich_ip_no_ip(self, capsys):
        """Test IP lookup without IP address."""
        args = argparse.Namespace(
            enrich_action="ip",
            ip=None,
            no_geoip=False,
            format="table",
        )

        result = _cmd_enrich_ip(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "IP address is required" in captured.out

    def test_enrich_ip_success_table(self, capsys):
        """Test successful IP lookup with table output."""
        args = argparse.Namespace(
            enrich_action="ip",
            ip="8.8.8.8",
            no_geoip=True,
            format="table",
        )

        mock_result = {
            "ip": "8.8.8.8",
            "is_public": True,
            "is_private": False,
            "version": 4,
            "cloud_provider": None,
            "geolocation": None,
        }

        with patch("stance.cli_enrich.IPEnricher") as mock_enricher:
            mock_enricher.return_value.lookup_ip.return_value = mock_result
            result = _cmd_enrich_ip(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "IP Information: 8.8.8.8" in captured.out
        assert "Public: True" in captured.out

    def test_enrich_ip_success_json(self, capsys):
        """Test successful IP lookup with JSON output."""
        args = argparse.Namespace(
            enrich_action="ip",
            ip="52.1.2.3",
            no_geoip=True,
            format="json",
        )

        mock_result = {
            "ip": "52.1.2.3",
            "is_public": True,
            "is_private": False,
            "version": 4,
            "cloud_provider": "aws",
            "geolocation": None,
        }

        with patch("stance.cli_enrich.IPEnricher") as mock_enricher:
            mock_enricher.return_value.lookup_ip.return_value = mock_result
            result = _cmd_enrich_ip(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["is_public"] is True
        assert output["cloud_provider"] == "aws"


class TestEnrichCVE:
    """Tests for CVE lookup command."""

    def test_enrich_cve_no_cve(self, capsys):
        """Test CVE lookup without CVE ID."""
        args = argparse.Namespace(
            enrich_action="cve",
            cve=None,
            format="table",
        )

        result = _cmd_enrich_cve(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "CVE ID is required" in captured.out

    def test_enrich_cve_not_found(self, capsys):
        """Test CVE lookup for non-existent CVE."""
        args = argparse.Namespace(
            enrich_action="cve",
            cve="CVE-9999-99999",
            format="table",
        )

        with patch("stance.cli_enrich.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = None
            result = _cmd_enrich_cve(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "CVE not found" in captured.out

    def test_enrich_cve_success_table(self, capsys):
        """Test successful CVE lookup with table output."""
        args = argparse.Namespace(
            enrich_action="cve",
            cve="CVE-2021-44228",
            format="table",
        )

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 vulnerability",
            "published": "2021-12-10",
            "cvss_v3": {
                "score": 10.0,
                "severity": "CRITICAL",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "affected_products": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
            "weaknesses": ["CWE-502"],
        }

        with patch("stance.cli_enrich.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = mock_result
            result = _cmd_enrich_cve(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CVE Details: CVE-2021-44228" in captured.out
        assert "CRITICAL" in captured.out

    def test_enrich_cve_success_json(self, capsys):
        """Test successful CVE lookup with JSON output."""
        args = argparse.Namespace(
            enrich_action="cve",
            cve="2021-44228",  # Without CVE- prefix
            format="json",
        )

        mock_result = {
            "cve_id": "CVE-2021-44228",
            "description": "Apache Log4j2 vulnerability",
        }

        with patch("stance.cli_enrich.CVEEnricher") as mock_enricher:
            mock_enricher.return_value._lookup_cve.return_value = mock_result
            result = _cmd_enrich_cve(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["cve_id"] == "CVE-2021-44228"


class TestEnrichKEV:
    """Tests for KEV lookup command."""

    def test_enrich_kev_no_cve_no_list(self, capsys):
        """Test KEV lookup without CVE ID or list flag."""
        args = argparse.Namespace(
            enrich_action="kev",
            cve=None,
            list=False,
            format="table",
        )

        with patch("stance.cli_enrich.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {}
            result = _cmd_enrich_kev(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "CVE ID is required" in captured.out

    def test_enrich_kev_list(self, capsys):
        """Test KEV list all entries."""
        args = argparse.Namespace(
            enrich_action="kev",
            cve=None,
            list=True,
            format="table",
        )

        mock_kev_data = {
            "CVE-2021-44228": {
                "vendorProject": "Apache",
                "product": "Log4j",
                "dateAdded": "2021-12-10",
            },
        }

        with patch("stance.cli_enrich.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = mock_kev_data
            result = _cmd_enrich_kev(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CISA KEV Catalog" in captured.out

    def test_enrich_kev_not_in_catalog(self, capsys):
        """Test KEV lookup for CVE not in catalog."""
        args = argparse.Namespace(
            enrich_action="kev",
            cve="CVE-9999-99999",
            list=False,
            format="table",
        )

        with patch("stance.cli_enrich.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {}
            mock_enricher.return_value.is_known_exploited.return_value = False
            result = _cmd_enrich_kev(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "NOT in the CISA KEV catalog" in captured.out

    def test_enrich_kev_in_catalog(self, capsys):
        """Test KEV lookup for CVE in catalog."""
        args = argparse.Namespace(
            enrich_action="kev",
            cve="CVE-2021-44228",
            list=False,
            format="table",
        )

        mock_kev_entry = {
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "shortDescription": "Remote code execution vulnerability",
            "requiredAction": "Apply updates per vendor instructions",
        }

        with patch("stance.cli_enrich.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {"CVE-2021-44228": mock_kev_entry}
            mock_enricher.return_value.is_known_exploited.return_value = True
            result = _cmd_enrich_kev(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "CISA KEV Entry: CVE-2021-44228" in captured.out
        assert "KNOWN EXPLOITED VULNERABILITY" in captured.out

    def test_enrich_kev_json_format(self, capsys):
        """Test KEV lookup with JSON output."""
        args = argparse.Namespace(
            enrich_action="kev",
            cve="CVE-2021-44228",
            list=False,
            format="json",
        )

        mock_kev_entry = {
            "vendorProject": "Apache",
            "product": "Log4j",
        }

        with patch("stance.cli_enrich.KEVEnricher") as mock_enricher:
            mock_enricher.return_value._kev_data = {"CVE-2021-44228": mock_kev_entry}
            mock_enricher.return_value.is_known_exploited.return_value = True
            result = _cmd_enrich_kev(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output["cve_id"] == "CVE-2021-44228"
        assert output["is_known_exploited"] is True


class TestEnrichStatus:
    """Tests for enrichment status command."""

    def test_enrich_status_table(self, capsys):
        """Test enrichment status with table output."""
        args = argparse.Namespace(
            enrich_action="status",
            format="table",
        )

        result = _cmd_enrich_status(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Enrichment Capabilities" in captured.out
        assert "Finding Enrichers:" in captured.out
        assert "Asset Enrichers:" in captured.out
        assert "CVE Enricher" in captured.out
        assert "IP Enricher" in captured.out

    def test_enrich_status_json(self, capsys):
        """Test enrichment status with JSON output."""
        args = argparse.Namespace(
            enrich_action="status",
            format="json",
        )

        result = _cmd_enrich_status(args)

        assert result == 0
        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert "enrichers" in output
        assert "finding_enrichers" in output
        assert "asset_enrichers" in output


class TestCLIIntegration:
    """Integration tests for CLI argument parsing."""

    def test_parser_enrich_findings(self):
        """Test enrich findings parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "findings",
            "--types", "cve,kev",
            "--limit", "25",
            "--format", "json",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "findings"
        assert args.types == "cve,kev"
        assert args.limit == 25
        assert args.format == "json"

    def test_parser_enrich_assets(self):
        """Test enrich assets parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "assets",
            "--types", "ip,context",
            "--cloud", "aws",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "assets"
        assert args.types == "ip,context"
        assert args.cloud == "aws"

    def test_parser_enrich_ip(self):
        """Test enrich ip parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "ip", "8.8.8.8",
            "--no-geoip",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "ip"
        assert args.ip == "8.8.8.8"
        assert args.no_geoip is True

    def test_parser_enrich_cve(self):
        """Test enrich cve parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "cve", "CVE-2021-44228",
            "--format", "json",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "cve"
        assert args.cve == "CVE-2021-44228"
        assert args.format == "json"

    def test_parser_enrich_kev(self):
        """Test enrich kev parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "kev", "CVE-2021-44228",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "kev"
        assert args.cve == "CVE-2021-44228"

    def test_parser_enrich_kev_list(self):
        """Test enrich kev list parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "kev",
            "--list",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "kev"
        assert args.list is True

    def test_parser_enrich_status(self):
        """Test enrich status parser arguments."""
        from stance.cli import create_parser

        parser = create_parser()
        args = parser.parse_args([
            "enrich", "status",
        ])

        assert args.command == "enrich"
        assert args.enrich_action == "status"
