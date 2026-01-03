"""
Threat intelligence enrichment for Mantissa Stance.

Provides threat intelligence enrichment including known malicious IPs,
vulnerable software identification, and CVE severity enrichment.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from stance.enrichment.base import (
    EnrichmentData,
    EnrichmentType,
    FindingEnricher,
)
from stance.models.finding import Finding, FindingType, Severity


@dataclass
class ThreatIndicator:
    """
    Threat intelligence indicator.

    Attributes:
        indicator_type: Type of indicator (ip, domain, hash, cve)
        value: Indicator value
        threat_type: Type of threat
        severity: Severity level
        source: Source of intelligence
        confidence: Confidence score
        first_seen: When first observed
        last_seen: When last observed
        tags: Associated tags
        references: Reference URLs
    """

    indicator_type: str
    value: str
    threat_type: str
    severity: str
    source: str
    confidence: float = 0.8
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# Known vulnerable software patterns (simplified example)
KNOWN_VULNERABLE_SOFTWARE = {
    "log4j": {
        "pattern": r"log4j.*2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)(\..*)?$",
        "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
        "severity": "critical",
        "description": "Apache Log4j Remote Code Execution vulnerability",
    },
    "spring4shell": {
        "pattern": r"spring-.*5\.(3\.[0-9]|3\.1[0-7])$",
        "cves": ["CVE-2022-22965"],
        "severity": "critical",
        "description": "Spring Framework RCE vulnerability",
    },
    "openssl_heartbleed": {
        "pattern": r"openssl.*1\.0\.1[a-f]$",
        "cves": ["CVE-2014-0160"],
        "severity": "high",
        "description": "OpenSSL Heartbleed vulnerability",
    },
    "struts2_rce": {
        "pattern": r"struts2?-core-2\.(3\.(5|[6-9]|[12][0-9]|3[01])|5\.[0-9]|5\.1[0-2])\.jar$",
        "cves": ["CVE-2017-5638", "CVE-2018-11776"],
        "severity": "critical",
        "description": "Apache Struts 2 Remote Code Execution",
    },
}


class CVEEnricher(FindingEnricher):
    """
    Enriches findings with CVE details.

    Fetches additional CVE information from NVD and other sources.
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(
        self,
        nvd_api_key: str | None = None,
        cache_ttl_hours: int = 24,
    ):
        """
        Initialize CVE enricher.

        Args:
            nvd_api_key: NVD API key for higher rate limits
            cache_ttl_hours: Cache TTL in hours
        """
        self.nvd_api_key = nvd_api_key or os.getenv("NVD_API_KEY")
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self._cache: dict[str, tuple[datetime, dict]] = {}

    @property
    def enricher_name(self) -> str:
        return "cve_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.CVE_DETAILS]

    def enrich(self, finding: Finding) -> list[EnrichmentData]:
        """
        Enrich finding with CVE details.

        Args:
            finding: Finding to enrich

        Returns:
            List of enrichment data
        """
        if not finding.cve_id:
            return []

        cve_data = self._lookup_cve(finding.cve_id)
        if not cve_data:
            return []

        return [
            EnrichmentData(
                enrichment_type=EnrichmentType.CVE_DETAILS,
                source="nvd",
                data=cve_data,
                cached=self._is_cached(finding.cve_id),
                expires_at=datetime.utcnow() + self.cache_ttl,
            )
        ]

    def _lookup_cve(self, cve_id: str) -> dict[str, Any] | None:
        """Look up CVE details from NVD."""
        # Validate CVE ID format
        if not re.match(r"CVE-\d{4}-\d+", cve_id):
            return None

        # Check cache
        if cve_id in self._cache:
            cached_time, cached_data = self._cache[cve_id]
            if datetime.utcnow() - cached_time < self.cache_ttl:
                return cached_data

        try:
            url = f"{self.NVD_API_BASE}?cveId={cve_id}"
            headers = {"User-Agent": "mantissa-stance/1.0"}

            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            request = Request(url, headers=headers)

            with urlopen(request, timeout=10) as response:
                data = json.loads(response.read().decode())

            if not data.get("vulnerabilities"):
                return None

            vuln = data["vulnerabilities"][0]["cve"]

            # Extract CVSS score
            cvss_v3 = None
            cvss_v2 = None
            metrics = vuln.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricV30" in metrics:
                cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]

            if "cvssMetricV2" in metrics:
                cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]

            # Extract description
            descriptions = vuln.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d["lang"] == "en"),
                ""
            )

            # Extract references
            references = [
                ref["url"] for ref in vuln.get("references", [])
            ]

            # Extract affected products (CPE)
            affected_products = []
            for config in vuln.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            affected_products.append(cpe.get("criteria", ""))

            result = {
                "cve_id": cve_id,
                "description": description,
                "published": vuln.get("published"),
                "last_modified": vuln.get("lastModified"),
                "cvss_v3": {
                    "score": cvss_v3.get("baseScore") if cvss_v3 else None,
                    "severity": cvss_v3.get("baseSeverity") if cvss_v3 else None,
                    "vector": cvss_v3.get("vectorString") if cvss_v3 else None,
                } if cvss_v3 else None,
                "cvss_v2": {
                    "score": cvss_v2.get("baseScore") if cvss_v2 else None,
                    "severity": self._cvss2_severity(cvss_v2.get("baseScore")) if cvss_v2 else None,
                    "vector": cvss_v2.get("vectorString") if cvss_v2 else None,
                } if cvss_v2 else None,
                "references": references[:10],  # Limit to 10
                "affected_products": affected_products[:20],  # Limit to 20
                "weaknesses": [
                    w["description"][0]["value"]
                    for w in vuln.get("weaknesses", [])
                    if w.get("description")
                ],
            }

            # Cache result
            self._cache[cve_id] = (datetime.utcnow(), result)

            return result

        except (URLError, json.JSONDecodeError, TimeoutError, KeyError):
            return None

    def _cvss2_severity(self, score: float | None) -> str | None:
        """Map CVSS v2 score to severity."""
        if score is None:
            return None
        if score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"

    def _is_cached(self, cve_id: str) -> bool:
        """Check if CVE data is cached."""
        return cve_id in self._cache


class VulnerableSoftwareEnricher(FindingEnricher):
    """
    Enriches findings with known vulnerable software information.

    Identifies if a finding relates to known vulnerable software patterns.
    """

    def __init__(
        self,
        vulnerability_patterns: dict[str, dict] | None = None,
    ):
        """
        Initialize vulnerable software enricher.

        Args:
            vulnerability_patterns: Custom vulnerability patterns
        """
        self.patterns = vulnerability_patterns or KNOWN_VULNERABLE_SOFTWARE

    @property
    def enricher_name(self) -> str:
        return "vulnerable_software_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.THREAT_INTEL]

    def enrich(self, finding: Finding) -> list[EnrichmentData]:
        """
        Enrich finding with vulnerable software information.

        Args:
            finding: Finding to enrich

        Returns:
            List of enrichment data
        """
        if finding.finding_type != FindingType.VULNERABILITY:
            return []

        enrichments = []

        # Check package name against known patterns
        if finding.package_name:
            for vuln_name, vuln_info in self.patterns.items():
                pattern = vuln_info["pattern"]
                if re.match(pattern, finding.package_name, re.IGNORECASE):
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.THREAT_INTEL,
                        source="vulnerability_database",
                        data={
                            "vulnerability_name": vuln_name,
                            "description": vuln_info["description"],
                            "related_cves": vuln_info["cves"],
                            "severity": vuln_info["severity"],
                            "matched_package": finding.package_name,
                            "is_known_exploited": True,
                        },
                        confidence=0.95,
                    ))
                    break

        return enrichments

    def add_pattern(
        self,
        name: str,
        pattern: str,
        cves: list[str],
        severity: str,
        description: str,
    ) -> None:
        """Add a custom vulnerability pattern."""
        self.patterns[name] = {
            "pattern": pattern,
            "cves": cves,
            "severity": severity,
            "description": description,
        }


class ThreatIntelEnricher(FindingEnricher):
    """
    Enriches findings with threat intelligence data.

    Checks indicators against threat intelligence feeds.
    """

    def __init__(
        self,
        indicators: list[ThreatIndicator] | None = None,
        enable_external_lookup: bool = False,
    ):
        """
        Initialize threat intelligence enricher.

        Args:
            indicators: Pre-loaded threat indicators
            enable_external_lookup: Whether to query external feeds
        """
        self.indicators = indicators or []
        self.enable_external_lookup = enable_external_lookup
        self._indicator_index: dict[str, list[ThreatIndicator]] = {}
        self._build_index()

    @property
    def enricher_name(self) -> str:
        return "threat_intel_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.THREAT_INTEL]

    def _build_index(self) -> None:
        """Build index for fast indicator lookup."""
        for indicator in self.indicators:
            key = f"{indicator.indicator_type}:{indicator.value}"
            if key not in self._indicator_index:
                self._indicator_index[key] = []
            self._indicator_index[key].append(indicator)

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add a threat indicator."""
        self.indicators.append(indicator)
        key = f"{indicator.indicator_type}:{indicator.value}"
        if key not in self._indicator_index:
            self._indicator_index[key] = []
        self._indicator_index[key].append(indicator)

    def add_indicators_from_file(self, file_path: str) -> None:
        """
        Load indicators from a JSON file.

        Expected format:
        [
            {
                "indicator_type": "ip",
                "value": "1.2.3.4",
                "threat_type": "malware",
                "severity": "high",
                "source": "feed_name"
            },
            ...
        ]
        """
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            for item in data:
                indicator = ThreatIndicator(
                    indicator_type=item["indicator_type"],
                    value=item["value"],
                    threat_type=item.get("threat_type", "unknown"),
                    severity=item.get("severity", "medium"),
                    source=item.get("source", "file"),
                    confidence=item.get("confidence", 0.8),
                    tags=item.get("tags", []),
                    references=item.get("references", []),
                )
                self.add_indicator(indicator)
        except (OSError, json.JSONDecodeError):
            pass

    def enrich(self, finding: Finding) -> list[EnrichmentData]:
        """
        Enrich finding with threat intelligence.

        Args:
            finding: Finding to enrich

        Returns:
            List of enrichment data
        """
        enrichments = []

        # Check CVE against threat intel
        if finding.cve_id:
            cve_indicators = self._lookup_indicator("cve", finding.cve_id)
            if cve_indicators:
                enrichments.append(self._create_enrichment(cve_indicators))

        # Extract and check IPs from finding description
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        ips = re.findall(ip_pattern, finding.description)
        for ip in ips:
            ip_indicators = self._lookup_indicator("ip", ip)
            if ip_indicators:
                enrichments.append(self._create_enrichment(ip_indicators))

        # Check package name for known threats
        if finding.package_name:
            pkg_indicators = self._lookup_indicator("package", finding.package_name)
            if pkg_indicators:
                enrichments.append(self._create_enrichment(pkg_indicators))

        return enrichments

    def _lookup_indicator(
        self,
        indicator_type: str,
        value: str,
    ) -> list[ThreatIndicator]:
        """Look up indicators by type and value."""
        key = f"{indicator_type}:{value}"
        return self._indicator_index.get(key, [])

    def _create_enrichment(
        self,
        indicators: list[ThreatIndicator],
    ) -> EnrichmentData:
        """Create enrichment data from indicators."""
        # Use highest severity indicator
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        indicators.sort(
            key=lambda i: severity_order.get(i.severity.lower(), 4)
        )
        primary = indicators[0]

        return EnrichmentData(
            enrichment_type=EnrichmentType.THREAT_INTEL,
            source=primary.source,
            data={
                "indicator_type": primary.indicator_type,
                "indicator_value": primary.value,
                "threat_type": primary.threat_type,
                "severity": primary.severity,
                "sources": list(set(i.source for i in indicators)),
                "tags": list(set(tag for i in indicators for tag in i.tags)),
                "references": list(set(ref for i in indicators for ref in i.references))[:5],
                "indicator_count": len(indicators),
            },
            confidence=max(i.confidence for i in indicators),
        )


class KEVEnricher(FindingEnricher):
    """
    Enriches findings with CISA Known Exploited Vulnerabilities data.

    Checks CVEs against the CISA KEV catalog.
    """

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        kev_data: dict[str, dict] | None = None,
        auto_fetch: bool = True,
    ):
        """
        Initialize KEV enricher.

        Args:
            kev_data: Pre-loaded KEV data
            auto_fetch: Whether to fetch KEV data automatically
        """
        self._kev_data = kev_data or {}
        self._last_fetch: datetime | None = None
        self._auto_fetch = auto_fetch

    @property
    def enricher_name(self) -> str:
        return "kev_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.THREAT_INTEL]

    def enrich(self, finding: Finding) -> list[EnrichmentData]:
        """
        Enrich finding with KEV data.

        Args:
            finding: Finding to enrich

        Returns:
            List of enrichment data
        """
        if not finding.cve_id:
            return []

        # Fetch KEV data if needed
        if self._auto_fetch and not self._kev_data:
            self._fetch_kev_data()

        kev_entry = self._kev_data.get(finding.cve_id)
        if not kev_entry:
            return []

        return [
            EnrichmentData(
                enrichment_type=EnrichmentType.THREAT_INTEL,
                source="cisa_kev",
                data={
                    "cve_id": finding.cve_id,
                    "is_known_exploited": True,
                    "vendor_project": kev_entry.get("vendorProject"),
                    "product": kev_entry.get("product"),
                    "vulnerability_name": kev_entry.get("vulnerabilityName"),
                    "date_added": kev_entry.get("dateAdded"),
                    "short_description": kev_entry.get("shortDescription"),
                    "required_action": kev_entry.get("requiredAction"),
                    "due_date": kev_entry.get("dueDate"),
                    "notes": kev_entry.get("notes"),
                },
                confidence=1.0,  # CISA KEV is authoritative
            )
        ]

    def _fetch_kev_data(self) -> None:
        """Fetch KEV data from CISA."""
        # Only fetch once per day
        if self._last_fetch and (datetime.utcnow() - self._last_fetch) < timedelta(days=1):
            return

        try:
            request = Request(
                self.KEV_URL,
                headers={"User-Agent": "mantissa-stance/1.0"}
            )

            with urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode())

            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    self._kev_data[cve_id] = vuln

            self._last_fetch = datetime.utcnow()

        except (URLError, json.JSONDecodeError, TimeoutError):
            pass

    def is_known_exploited(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        if self._auto_fetch and not self._kev_data:
            self._fetch_kev_data()
        return cve_id in self._kev_data
