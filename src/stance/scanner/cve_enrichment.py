"""
CVE correlation and enrichment for vulnerability data.

This module provides enrichment of vulnerability data with:
- EPSS (Exploit Prediction Scoring System) scores
- CISA KEV (Known Exploited Vulnerabilities) catalog data
- NVD (National Vulnerability Database) details
- CVE correlation across multiple images/resources
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Any
from pathlib import Path

from stance.scanner.base import Vulnerability, VulnerabilitySeverity, ScanResult

logger = logging.getLogger(__name__)


@dataclass
class EPSSScore:
    """EPSS (Exploit Prediction Scoring System) score for a CVE."""

    cve_id: str
    epss: float  # Probability of exploitation (0-1)
    percentile: float  # Percentile ranking (0-1)
    date: str  # Date of the score


@dataclass
class KEVEntry:
    """CISA Known Exploited Vulnerabilities catalog entry."""

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_campaign_use: bool = False


@dataclass
class EnrichedVulnerability:
    """Vulnerability with enrichment data."""

    vulnerability: Vulnerability
    epss_score: Optional[EPSSScore] = None
    kev_entry: Optional[KEVEntry] = None
    nvd_data: Optional[dict] = None
    priority_score: float = 0.0  # Calculated priority (0-100)
    priority_factors: list[str] = field(default_factory=list)

    def calculate_priority(self) -> float:
        """Calculate priority score based on multiple factors."""
        score = 0.0
        factors = []

        # Base score from severity (0-40 points)
        severity_scores = {
            VulnerabilitySeverity.CRITICAL: 40,
            VulnerabilitySeverity.HIGH: 30,
            VulnerabilitySeverity.MEDIUM: 20,
            VulnerabilitySeverity.LOW: 10,
            VulnerabilitySeverity.UNKNOWN: 5,
        }
        severity_score = severity_scores.get(self.vulnerability.severity, 5)
        score += severity_score
        factors.append(f"Severity {self.vulnerability.severity.value}: +{severity_score}")

        # CVSS score contribution (0-20 points)
        if self.vulnerability.cvss_score:
            cvss_contribution = min(20, self.vulnerability.cvss_score * 2)
            score += cvss_contribution
            factors.append(f"CVSS {self.vulnerability.cvss_score}: +{cvss_contribution:.1f}")

        # EPSS score contribution (0-20 points)
        if self.epss_score:
            epss_contribution = self.epss_score.epss * 20
            score += epss_contribution
            factors.append(f"EPSS {self.epss_score.epss:.2%}: +{epss_contribution:.1f}")

        # KEV catalog (high priority, +20 points)
        if self.kev_entry:
            score += 20
            factors.append("In CISA KEV catalog: +20")

            if self.kev_entry.known_ransomware_campaign_use:
                score += 10
                factors.append("Ransomware campaign use: +10")

        # Fixable vulnerability (+5 points for priority)
        if self.vulnerability.fixed_version:
            score += 5
            factors.append("Fix available: +5")

        self.priority_score = min(100, score)
        self.priority_factors = factors
        return self.priority_score


class CVEEnricher:
    """Enriches vulnerability data with additional context."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        cache_ttl_hours: int = 24,
    ):
        """Initialize CVE enricher.

        Args:
            cache_dir: Directory for caching enrichment data
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.cache_dir = cache_dir or Path.home() / ".stance" / "cache" / "cve"
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory caches
        self._epss_cache: dict[str, EPSSScore] = {}
        self._kev_cache: dict[str, KEVEntry] = {}
        self._kev_loaded = False

    def enrich_vulnerability(
        self,
        vuln: Vulnerability,
        fetch_epss: bool = True,
        fetch_kev: bool = True,
    ) -> EnrichedVulnerability:
        """Enrich a single vulnerability with additional data.

        Args:
            vuln: Vulnerability to enrich
            fetch_epss: Whether to fetch EPSS scores
            fetch_kev: Whether to check KEV catalog

        Returns:
            EnrichedVulnerability with additional context
        """
        enriched = EnrichedVulnerability(vulnerability=vuln)

        cve_id = vuln.vulnerability_id
        if not cve_id.upper().startswith("CVE-"):
            # Only enrich CVE IDs
            enriched.calculate_priority()
            return enriched

        if fetch_epss:
            enriched.epss_score = self._get_epss_score(cve_id)

        if fetch_kev:
            enriched.kev_entry = self._get_kev_entry(cve_id)

        enriched.calculate_priority()
        return enriched

    def enrich_scan_result(
        self,
        result: ScanResult,
        fetch_epss: bool = True,
        fetch_kev: bool = True,
    ) -> list[EnrichedVulnerability]:
        """Enrich all vulnerabilities in a scan result.

        Args:
            result: Scan result to enrich
            fetch_epss: Whether to fetch EPSS scores
            fetch_kev: Whether to check KEV catalog

        Returns:
            List of enriched vulnerabilities
        """
        enriched = []

        # Pre-load KEV catalog if needed
        if fetch_kev and not self._kev_loaded:
            self._load_kev_catalog()

        # Batch fetch EPSS scores for efficiency
        if fetch_epss:
            cve_ids = [
                v.vulnerability_id
                for v in result.vulnerabilities
                if v.vulnerability_id.upper().startswith("CVE-")
            ]
            self._batch_fetch_epss(cve_ids)

        for vuln in result.vulnerabilities:
            enriched.append(
                self.enrich_vulnerability(
                    vuln,
                    fetch_epss=fetch_epss,
                    fetch_kev=fetch_kev,
                )
            )

        # Sort by priority score (highest first)
        enriched.sort(key=lambda e: e.priority_score, reverse=True)
        return enriched

    def correlate_vulnerabilities(
        self,
        results: list[ScanResult],
    ) -> dict[str, list[tuple[str, Vulnerability]]]:
        """Correlate vulnerabilities across multiple scan results.

        Args:
            results: List of scan results

        Returns:
            Dict mapping CVE IDs to list of (image_ref, vulnerability) tuples
        """
        correlation: dict[str, list[tuple[str, Vulnerability]]] = {}

        for result in results:
            for vuln in result.vulnerabilities:
                cve_id = vuln.vulnerability_id
                if cve_id not in correlation:
                    correlation[cve_id] = []
                correlation[cve_id].append((result.image_reference, vuln))

        return correlation

    def get_vulnerability_summary(
        self,
        enriched_vulns: list[EnrichedVulnerability],
    ) -> dict[str, Any]:
        """Generate summary statistics for enriched vulnerabilities.

        Args:
            enriched_vulns: List of enriched vulnerabilities

        Returns:
            Summary statistics dict
        """
        total = len(enriched_vulns)
        if total == 0:
            return {
                "total": 0,
                "by_severity": {},
                "in_kev": 0,
                "high_epss": 0,
                "fixable": 0,
                "priority_critical": 0,
                "priority_high": 0,
            }

        by_severity = {}
        in_kev = 0
        high_epss = 0
        fixable = 0
        priority_critical = 0
        priority_high = 0

        for ev in enriched_vulns:
            sev = ev.vulnerability.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            if ev.kev_entry:
                in_kev += 1

            if ev.epss_score and ev.epss_score.epss >= 0.1:
                high_epss += 1

            if ev.vulnerability.fixed_version:
                fixable += 1

            if ev.priority_score >= 80:
                priority_critical += 1
            elif ev.priority_score >= 60:
                priority_high += 1

        return {
            "total": total,
            "by_severity": by_severity,
            "in_kev": in_kev,
            "in_kev_percent": round(in_kev / total * 100, 1),
            "high_epss": high_epss,
            "high_epss_percent": round(high_epss / total * 100, 1),
            "fixable": fixable,
            "fixable_percent": round(fixable / total * 100, 1),
            "priority_critical": priority_critical,
            "priority_high": priority_high,
        }

    def _get_epss_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a CVE from cache or API."""
        cve_id = cve_id.upper()

        if cve_id in self._epss_cache:
            return self._epss_cache[cve_id]

        # Try to fetch from cache file
        cache_file = self.cache_dir / f"epss_{cve_id}.json"
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if datetime.now() - mtime < self.cache_ttl:
                try:
                    data = json.loads(cache_file.read_text())
                    score = EPSSScore(**data)
                    self._epss_cache[cve_id] = score
                    return score
                except Exception:
                    pass

        # Would need to fetch from EPSS API
        # For now, return None if not in cache
        return None

    def _batch_fetch_epss(self, cve_ids: list[str]) -> None:
        """Batch fetch EPSS scores for multiple CVEs.

        Uses the FIRST.org EPSS API to fetch scores.
        """
        if not cve_ids:
            return

        # Filter out already cached
        to_fetch = [
            cve_id.upper()
            for cve_id in cve_ids
            if cve_id.upper() not in self._epss_cache
        ]

        if not to_fetch:
            return

        # Batch in groups of 100
        batch_size = 100
        for i in range(0, len(to_fetch), batch_size):
            batch = to_fetch[i:i + batch_size]
            self._fetch_epss_batch(batch)

    def _fetch_epss_batch(self, cve_ids: list[str]) -> None:
        """Fetch EPSS scores for a batch of CVEs."""
        if not cve_ids:
            return

        try:
            url = f"https://api.first.org/data/v1/epss?cve={','.join(cve_ids)}"
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json"},
            )

            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode())

            for item in data.get("data", []):
                cve_id = item.get("cve", "").upper()
                if cve_id:
                    score = EPSSScore(
                        cve_id=cve_id,
                        epss=float(item.get("epss", 0)),
                        percentile=float(item.get("percentile", 0)),
                        date=item.get("date", ""),
                    )
                    self._epss_cache[cve_id] = score

                    # Write to cache file
                    cache_file = self.cache_dir / f"epss_{cve_id}.json"
                    cache_file.write_text(json.dumps({
                        "cve_id": score.cve_id,
                        "epss": score.epss,
                        "percentile": score.percentile,
                        "date": score.date,
                    }))
        except urllib.error.URLError as e:
            logger.warning(f"Failed to fetch EPSS scores: {e}")
        except Exception as e:
            logger.warning(f"Error processing EPSS response: {e}")

    def _get_kev_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """Get KEV catalog entry for a CVE."""
        cve_id = cve_id.upper()

        if not self._kev_loaded:
            self._load_kev_catalog()

        return self._kev_cache.get(cve_id)

    def _load_kev_catalog(self) -> None:
        """Load CISA KEV catalog from cache or API."""
        self._kev_loaded = True

        cache_file = self.cache_dir / "kev_catalog.json"

        # Check if cache is fresh
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if datetime.now() - mtime < self.cache_ttl:
                try:
                    data = json.loads(cache_file.read_text())
                    self._parse_kev_catalog(data)
                    return
                except Exception:
                    pass

        # Fetch from CISA
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            request = urllib.request.Request(
                url,
                headers={"Accept": "application/json"},
            )

            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode())

            # Cache the response
            cache_file.write_text(json.dumps(data))
            self._parse_kev_catalog(data)

        except urllib.error.URLError as e:
            logger.warning(f"Failed to fetch KEV catalog: {e}")
        except Exception as e:
            logger.warning(f"Error processing KEV catalog: {e}")

    def _parse_kev_catalog(self, data: dict) -> None:
        """Parse KEV catalog JSON into cache."""
        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID", "").upper()
            if cve_id:
                entry = KEVEntry(
                    cve_id=cve_id,
                    vendor_project=item.get("vendorProject", ""),
                    product=item.get("product", ""),
                    vulnerability_name=item.get("vulnerabilityName", ""),
                    date_added=item.get("dateAdded", ""),
                    short_description=item.get("shortDescription", ""),
                    required_action=item.get("requiredAction", ""),
                    due_date=item.get("dueDate", ""),
                    known_ransomware_campaign_use=item.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                )
                self._kev_cache[cve_id] = entry


def prioritize_vulnerabilities(
    vulnerabilities: list[Vulnerability],
    enricher: Optional[CVEEnricher] = None,
) -> list[EnrichedVulnerability]:
    """Convenience function to enrich and prioritize vulnerabilities.

    Args:
        vulnerabilities: List of vulnerabilities to prioritize
        enricher: Optional CVEEnricher instance

    Returns:
        List of enriched vulnerabilities sorted by priority
    """
    if enricher is None:
        enricher = CVEEnricher()

    enriched = []
    for vuln in vulnerabilities:
        enriched.append(enricher.enrich_vulnerability(vuln))

    enriched.sort(key=lambda e: e.priority_score, reverse=True)
    return enriched
