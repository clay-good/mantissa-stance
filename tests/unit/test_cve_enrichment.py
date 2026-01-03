"""
Tests for the CVE enrichment module.
"""

import json
import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile

from stance.scanner.cve_enrichment import (
    EPSSScore,
    KEVEntry,
    EnrichedVulnerability,
    CVEEnricher,
    prioritize_vulnerabilities,
)
from stance.scanner.base import (
    Vulnerability,
    VulnerabilitySeverity,
    ScanResult,
)


class TestEPSSScore:
    """Tests for EPSSScore dataclass."""

    def test_basic_epss_score(self):
        """Test creating basic EPSS score."""
        score = EPSSScore(
            cve_id="CVE-2023-12345",
            epss=0.15,
            percentile=0.85,
            date="2023-12-01",
        )

        assert score.cve_id == "CVE-2023-12345"
        assert score.epss == 0.15
        assert score.percentile == 0.85


class TestKEVEntry:
    """Tests for KEVEntry dataclass."""

    def test_basic_kev_entry(self):
        """Test creating basic KEV entry."""
        entry = KEVEntry(
            cve_id="CVE-2023-12345",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Log4Shell",
            date_added="2021-12-10",
            short_description="Remote code execution in Log4j",
            required_action="Apply updates",
            due_date="2021-12-24",
            known_ransomware_campaign_use=True,
        )

        assert entry.cve_id == "CVE-2023-12345"
        assert entry.known_ransomware_campaign_use is True


class TestEnrichedVulnerability:
    """Tests for EnrichedVulnerability dataclass."""

    def test_basic_enriched_vulnerability(self):
        """Test creating enriched vulnerability."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            package_type="deb",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.HIGH,
        )

        enriched = EnrichedVulnerability(vulnerability=vuln)
        assert enriched.vulnerability == vuln
        assert enriched.epss_score is None
        assert enriched.kev_entry is None

    def test_calculate_priority_severity_only(self):
        """Test priority calculation based on severity only."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            package_type="deb",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.CRITICAL,
        )

        enriched = EnrichedVulnerability(vulnerability=vuln)
        score = enriched.calculate_priority()

        assert score >= 40  # Critical severity base score
        assert "Severity CRITICAL" in enriched.priority_factors[0]

    def test_calculate_priority_with_cvss(self):
        """Test priority calculation with CVSS score."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            package_type="deb",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=8.5,
        )

        enriched = EnrichedVulnerability(vulnerability=vuln)
        score = enriched.calculate_priority()

        # Should include CVSS contribution
        assert any("CVSS" in f for f in enriched.priority_factors)

    def test_calculate_priority_with_epss(self):
        """Test priority calculation with EPSS score."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            package_type="deb",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.MEDIUM,
        )

        epss = EPSSScore(
            cve_id="CVE-2023-12345",
            epss=0.5,  # 50% exploitation probability
            percentile=0.95,
            date="2023-12-01",
        )

        enriched = EnrichedVulnerability(vulnerability=vuln, epss_score=epss)
        score = enriched.calculate_priority()

        # Should include EPSS contribution
        assert any("EPSS" in f for f in enriched.priority_factors)

    def test_calculate_priority_with_kev(self):
        """Test priority calculation with KEV entry."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="log4j",
            package_type="java",
            installed_version="2.14.0",
            severity=VulnerabilitySeverity.CRITICAL,
        )

        kev = KEVEntry(
            cve_id="CVE-2023-12345",
            vendor_project="Apache",
            product="Log4j",
            vulnerability_name="Log4Shell",
            date_added="2021-12-10",
            short_description="RCE in Log4j",
            required_action="Apply updates",
            due_date="2021-12-24",
            known_ransomware_campaign_use=True,
        )

        enriched = EnrichedVulnerability(vulnerability=vuln, kev_entry=kev)
        score = enriched.calculate_priority()

        # Should include KEV and ransomware contributions
        assert any("KEV" in f for f in enriched.priority_factors)
        assert any("Ransomware" in f for f in enriched.priority_factors)

    def test_calculate_priority_with_fix_available(self):
        """Test priority calculation with fix available."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            package_type="deb",
            installed_version="1.1.1k",
            fixed_version="1.1.1n",
            severity=VulnerabilitySeverity.HIGH,
        )

        enriched = EnrichedVulnerability(vulnerability=vuln)
        score = enriched.calculate_priority()

        # Should include fix available contribution
        assert any("Fix available" in f for f in enriched.priority_factors)


class TestCVEEnricher:
    """Tests for CVEEnricher class."""

    def test_init_default(self):
        """Test default initialization."""
        enricher = CVEEnricher()
        assert enricher.cache_dir.name == "cve"

    def test_init_custom_cache_dir(self):
        """Test initialization with custom cache directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir) / "custom_cache"
            enricher = CVEEnricher(cache_dir=cache_dir)
            assert enricher.cache_dir == cache_dir
            assert cache_dir.exists()

    def test_enrich_non_cve_vulnerability(self):
        """Test enriching non-CVE vulnerability."""
        vuln = Vulnerability(
            vulnerability_id="GHSA-xxxx-yyyy-zzzz",
            package_name="requests",
            installed_version="2.20.0",
            severity=VulnerabilitySeverity.HIGH,
        )

        enricher = CVEEnricher()
        enriched = enricher.enrich_vulnerability(vuln, fetch_epss=False, fetch_kev=False)

        # Non-CVE should still be enriched but without EPSS/KEV
        assert enriched.vulnerability == vuln
        assert enriched.epss_score is None
        assert enriched.kev_entry is None

    def test_enrich_cve_vulnerability(self):
        """Test enriching CVE vulnerability."""
        vuln = Vulnerability(
            vulnerability_id="CVE-2023-12345",
            package_name="openssl",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.HIGH,
        )

        enricher = CVEEnricher()
        enriched = enricher.enrich_vulnerability(vuln, fetch_epss=False, fetch_kev=False)

        assert enriched.vulnerability == vuln
        assert enriched.priority_score > 0

    @patch.object(CVEEnricher, "_load_kev_catalog")
    def test_enrich_scan_result(self, mock_load_kev):
        """Test enriching scan result."""
        vulns = [
            Vulnerability(
                vulnerability_id="CVE-2023-0001",
                package_name="pkg1",
                installed_version="1.0",
                severity=VulnerabilitySeverity.CRITICAL,
            ),
            Vulnerability(
                vulnerability_id="CVE-2023-0002",
                package_name="pkg2",
                installed_version="2.0",
                severity=VulnerabilitySeverity.LOW,
            ),
        ]

        result = ScanResult(
            image_reference="test:latest",
            scanner_name="trivy",
            vulnerabilities=vulns,
        )

        enricher = CVEEnricher()
        enriched = enricher.enrich_scan_result(result, fetch_epss=False, fetch_kev=True)

        assert len(enriched) == 2
        # Should be sorted by priority (critical first)
        assert enriched[0].vulnerability.severity == VulnerabilitySeverity.CRITICAL

    def test_correlate_vulnerabilities(self):
        """Test correlating vulnerabilities across images."""
        shared_vuln = Vulnerability(
            vulnerability_id="CVE-2023-0001",
            package_name="openssl",
            installed_version="1.1.1k",
            severity=VulnerabilitySeverity.HIGH,
        )

        result1 = ScanResult(
            image_reference="app1:latest",
            scanner_name="trivy",
            vulnerabilities=[shared_vuln],
        )

        result2 = ScanResult(
            image_reference="app2:latest",
            scanner_name="trivy",
            vulnerabilities=[shared_vuln],
        )

        enricher = CVEEnricher()
        correlation = enricher.correlate_vulnerabilities([result1, result2])

        assert "CVE-2023-0001" in correlation
        assert len(correlation["CVE-2023-0001"]) == 2
        assert correlation["CVE-2023-0001"][0][0] == "app1:latest"
        assert correlation["CVE-2023-0001"][1][0] == "app2:latest"

    def test_get_vulnerability_summary(self):
        """Test generating vulnerability summary."""
        vulns = [
            Vulnerability(
                vulnerability_id="CVE-2023-0001",
                package_name="pkg1",
                installed_version="1.0",
                fixed_version="1.1",
                is_fixable=True,
                severity=VulnerabilitySeverity.CRITICAL,
            ),
            Vulnerability(
                vulnerability_id="CVE-2023-0002",
                package_name="pkg2",
                installed_version="2.0",
                severity=VulnerabilitySeverity.HIGH,
            ),
        ]

        enricher = CVEEnricher()
        enriched = [
            enricher.enrich_vulnerability(v, fetch_epss=False, fetch_kev=False)
            for v in vulns
        ]

        summary = enricher.get_vulnerability_summary(enriched)

        assert summary["total"] == 2
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["fixable"] == 1

    def test_get_vulnerability_summary_empty(self):
        """Test generating summary for empty list."""
        enricher = CVEEnricher()
        summary = enricher.get_vulnerability_summary([])

        assert summary["total"] == 0
        assert summary["by_severity"] == {}

    @patch("urllib.request.urlopen")
    def test_fetch_epss_batch(self, mock_urlopen):
        """Test batch fetching EPSS scores."""
        epss_response = {
            "data": [
                {
                    "cve": "CVE-2023-0001",
                    "epss": 0.15,
                    "percentile": 0.85,
                    "date": "2023-12-01",
                },
                {
                    "cve": "CVE-2023-0002",
                    "epss": 0.02,
                    "percentile": 0.40,
                    "date": "2023-12-01",
                },
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(epss_response).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            enricher = CVEEnricher(cache_dir=Path(tmpdir))
            enricher._fetch_epss_batch(["CVE-2023-0001", "CVE-2023-0002"])

            assert "CVE-2023-0001" in enricher._epss_cache
            assert enricher._epss_cache["CVE-2023-0001"].epss == 0.15

    @patch("urllib.request.urlopen")
    def test_load_kev_catalog(self, mock_urlopen):
        """Test loading KEV catalog."""
        kev_response = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "vendorProject": "Apache",
                    "product": "Log4j",
                    "vulnerabilityName": "Log4Shell",
                    "dateAdded": "2021-12-10",
                    "shortDescription": "RCE in Log4j",
                    "requiredAction": "Apply updates",
                    "dueDate": "2021-12-24",
                    "knownRansomwareCampaignUse": "Known",
                },
            ]
        }

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(kev_response).encode()
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        with tempfile.TemporaryDirectory() as tmpdir:
            enricher = CVEEnricher(cache_dir=Path(tmpdir))
            enricher._load_kev_catalog()

            assert "CVE-2021-44228" in enricher._kev_cache
            assert enricher._kev_cache["CVE-2021-44228"].known_ransomware_campaign_use is True


class TestPrioritizeVulnerabilities:
    """Tests for prioritize_vulnerabilities convenience function."""

    def test_prioritize_vulnerabilities(self):
        """Test prioritizing a list of vulnerabilities."""
        vulns = [
            Vulnerability(
                vulnerability_id="CVE-2023-0001",
                package_name="pkg1",
                package_type="deb",
                installed_version="1.0",
                severity=VulnerabilitySeverity.LOW,
            ),
            Vulnerability(
                vulnerability_id="CVE-2023-0002",
                package_name="pkg2",
                package_type="deb",
                installed_version="2.0",
                severity=VulnerabilitySeverity.CRITICAL,
            ),
        ]

        enriched = prioritize_vulnerabilities(vulns)

        assert len(enriched) == 2
        # Critical should be first (higher priority)
        assert enriched[0].vulnerability.severity == VulnerabilitySeverity.CRITICAL
        assert enriched[0].priority_score > enriched[1].priority_score
