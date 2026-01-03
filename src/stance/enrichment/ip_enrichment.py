"""
IP enrichment for Mantissa Stance.

Provides IP address enrichment including geolocation,
ASN information, and cloud provider identification.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from stance.enrichment.base import (
    AssetEnricher,
    EnrichmentData,
    EnrichmentType,
)
from stance.models.asset import Asset


@dataclass
class IPInfo:
    """
    IP address information.

    Attributes:
        ip: IP address
        is_public: Whether IP is public
        is_private: Whether IP is private (RFC 1918)
        version: IP version (4 or 6)
    """

    ip: str
    is_public: bool
    is_private: bool
    version: int

    @classmethod
    def from_string(cls, ip_str: str) -> IPInfo | None:
        """Parse IP address string."""
        try:
            ip = ipaddress.ip_address(ip_str)
            return cls(
                ip=ip_str,
                is_public=ip.is_global,
                is_private=ip.is_private,
                version=ip.version,
            )
        except ValueError:
            return None


# Known cloud provider IP ranges (simplified - real implementation would
# fetch from cloud provider IP range APIs)
CLOUD_PROVIDER_RANGES = {
    "aws": [
        ("3.0.0.0", "3.255.255.255"),
        ("13.32.0.0", "13.35.255.255"),
        ("15.177.0.0", "15.177.255.255"),
        ("18.0.0.0", "18.255.255.255"),
        ("34.192.0.0", "34.255.255.255"),
        ("35.80.0.0", "35.191.255.255"),
        ("52.0.0.0", "52.255.255.255"),
        ("54.0.0.0", "54.255.255.255"),
    ],
    "gcp": [
        ("34.64.0.0", "34.79.255.255"),
        ("34.80.0.0", "34.95.255.255"),
        ("34.96.0.0", "34.111.255.255"),
        ("35.184.0.0", "35.199.255.255"),
        ("35.200.0.0", "35.215.255.255"),
        ("35.216.0.0", "35.231.255.255"),
        ("35.232.0.0", "35.247.255.255"),
    ],
    "azure": [
        ("13.64.0.0", "13.107.255.255"),
        ("20.0.0.0", "20.255.255.255"),
        ("40.64.0.0", "40.127.255.255"),
        ("52.0.0.0", "52.255.255.255"),
        ("104.40.0.0", "104.47.255.255"),
        ("137.116.0.0", "137.135.255.255"),
        ("168.61.0.0", "168.63.255.255"),
    ],
}


def _ip_in_range(ip_str: str, start: str, end: str) -> bool:
    """Check if IP is within range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        return start_ip <= ip <= end_ip
    except ValueError:
        return False


def _identify_cloud_provider(ip_str: str) -> str | None:
    """Identify cloud provider from IP address."""
    for provider, ranges in CLOUD_PROVIDER_RANGES.items():
        for start, end in ranges:
            if _ip_in_range(ip_str, start, end):
                return provider
    return None


class IPEnricher(AssetEnricher):
    """
    Enriches assets with IP-related information.

    Provides:
    - GeoIP lookup (country, city, coordinates)
    - ASN information (organization, network)
    - Cloud provider identification
    """

    # IP extraction pattern
    IP_PATTERN = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    def __init__(
        self,
        geoip_api_key: str | None = None,
        cache_ttl_hours: int = 24,
        enable_geoip: bool = True,
    ):
        """
        Initialize IP enricher.

        Args:
            geoip_api_key: API key for GeoIP service (optional)
            cache_ttl_hours: Cache TTL in hours
            enable_geoip: Whether to enable GeoIP lookups
        """
        self.geoip_api_key = geoip_api_key or os.getenv("GEOIP_API_KEY")
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.enable_geoip = enable_geoip
        self._cache: dict[str, tuple[datetime, dict]] = {}

    @property
    def enricher_name(self) -> str:
        return "ip_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [
            EnrichmentType.IP_GEOLOCATION,
            EnrichmentType.IP_ASN,
            EnrichmentType.IP_CLOUD_PROVIDER,
        ]

    def enrich(self, asset: Asset) -> list[EnrichmentData]:
        """
        Enrich asset with IP information.

        Args:
            asset: Asset to enrich

        Returns:
            List of enrichment data
        """
        enrichments = []

        # Extract IP addresses from asset
        ips = self._extract_ips(asset)

        for ip_str in ips:
            ip_info = IPInfo.from_string(ip_str)
            if not ip_info or not ip_info.is_public:
                continue

            # Cloud provider identification
            cloud_provider = _identify_cloud_provider(ip_str)
            if cloud_provider:
                enrichments.append(EnrichmentData(
                    enrichment_type=EnrichmentType.IP_CLOUD_PROVIDER,
                    source="ip_ranges",
                    data={
                        "ip": ip_str,
                        "cloud_provider": cloud_provider,
                    },
                    confidence=0.9,
                    expires_at=datetime.utcnow() + timedelta(days=7),
                ))

            # GeoIP lookup
            if self.enable_geoip:
                geo_data = self._lookup_geoip(ip_str)
                if geo_data:
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.IP_GEOLOCATION,
                        source="geoip",
                        data=geo_data,
                        cached=self._is_cached(ip_str),
                        expires_at=datetime.utcnow() + self.cache_ttl,
                    ))

                # ASN from GeoIP response
                if "asn" in geo_data:
                    enrichments.append(EnrichmentData(
                        enrichment_type=EnrichmentType.IP_ASN,
                        source="geoip",
                        data={
                            "ip": ip_str,
                            "asn": geo_data.get("asn"),
                            "asn_org": geo_data.get("asn_org"),
                            "asn_network": geo_data.get("asn_network"),
                        },
                        cached=self._is_cached(ip_str),
                        expires_at=datetime.utcnow() + self.cache_ttl,
                    ))

        return enrichments

    def _extract_ips(self, asset: Asset) -> list[str]:
        """Extract IP addresses from asset."""
        ips = set()

        # Check common fields in raw_config
        config = asset.raw_config or {}

        # EC2 instances
        if "PublicIpAddress" in config:
            ips.add(config["PublicIpAddress"])
        if "PrivateIpAddress" in config:
            ips.add(config["PrivateIpAddress"])

        # Network interfaces
        for iface in config.get("NetworkInterfaces", []):
            if "PrivateIpAddress" in iface:
                ips.add(iface["PrivateIpAddress"])
            for assoc in iface.get("Association", []):
                if isinstance(assoc, dict) and "PublicIp" in assoc:
                    ips.add(assoc["PublicIp"])

        # GCP compute instances
        for iface in config.get("networkInterfaces", []):
            for access in iface.get("accessConfigs", []):
                if "natIP" in access:
                    ips.add(access["natIP"])

        # Azure VMs
        for ip_config in config.get("ipConfigurations", []):
            if "publicIPAddress" in ip_config:
                pub_ip = ip_config["publicIPAddress"]
                if isinstance(pub_ip, dict) and "ipAddress" in pub_ip:
                    ips.add(pub_ip["ipAddress"])

        # Also search in raw config string for IPs
        config_str = json.dumps(config)
        found_ips = self.IP_PATTERN.findall(config_str)
        ips.update(found_ips)

        return list(ips)

    def _lookup_geoip(self, ip: str) -> dict[str, Any] | None:
        """Look up GeoIP information."""
        # Check cache
        if ip in self._cache:
            cached_time, cached_data = self._cache[ip]
            if datetime.utcnow() - cached_time < self.cache_ttl:
                return cached_data

        # Use ip-api.com (free tier, no API key needed)
        # In production, use a proper GeoIP service
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
            request = Request(url, headers={"User-Agent": "mantissa-stance/1.0"})

            with urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode())

            if data.get("status") != "success":
                return None

            result = {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "postal_code": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as"),
                "asn_org": data.get("asname"),
            }

            # Cache result
            self._cache[ip] = (datetime.utcnow(), result)

            return result

        except (URLError, json.JSONDecodeError, TimeoutError):
            return None

    def _is_cached(self, ip: str) -> bool:
        """Check if IP data is cached."""
        return ip in self._cache

    def is_available(self) -> bool:
        """Check if enricher is available."""
        # Always available for cloud provider identification
        # GeoIP requires network access but is optional
        return True

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """
        Look up information for a single IP.

        Public method for direct IP lookups.

        Args:
            ip: IP address to look up

        Returns:
            Dictionary with IP information
        """
        result = {
            "ip": ip,
            "is_public": False,
            "is_private": False,
            "cloud_provider": None,
            "geolocation": None,
        }

        ip_info = IPInfo.from_string(ip)
        if not ip_info:
            return result

        result["is_public"] = ip_info.is_public
        result["is_private"] = ip_info.is_private
        result["version"] = ip_info.version

        if ip_info.is_public:
            result["cloud_provider"] = _identify_cloud_provider(ip)

            if self.enable_geoip:
                result["geolocation"] = self._lookup_geoip(ip)

        return result


class CloudProviderRangeEnricher(AssetEnricher):
    """
    Enriches assets with cloud provider range information.

    Identifies which cloud provider an IP belongs to based on
    known IP ranges.
    """

    def __init__(self):
        """Initialize cloud provider range enricher."""
        self._ranges = CLOUD_PROVIDER_RANGES.copy()

    @property
    def enricher_name(self) -> str:
        return "cloud_provider_range_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.IP_CLOUD_PROVIDER]

    def enrich(self, asset: Asset) -> list[EnrichmentData]:
        """
        Enrich asset with cloud provider information.

        Args:
            asset: Asset to enrich

        Returns:
            List of enrichment data
        """
        enrichments = []

        # Get the asset's cloud provider from the asset itself
        # This is useful for cross-referencing
        if asset.cloud_provider:
            enrichments.append(EnrichmentData(
                enrichment_type=EnrichmentType.IP_CLOUD_PROVIDER,
                source="asset_metadata",
                data={
                    "cloud_provider": asset.cloud_provider,
                    "region": asset.region,
                    "account_id": asset.account_id,
                },
                confidence=1.0,
            ))

        return enrichments

    def add_custom_range(
        self,
        provider: str,
        start: str,
        end: str,
    ) -> None:
        """
        Add a custom IP range for a provider.

        Args:
            provider: Provider name
            start: Range start IP
            end: Range end IP
        """
        if provider not in self._ranges:
            self._ranges[provider] = []
        self._ranges[provider].append((start, end))

    def identify_provider(self, ip: str) -> str | None:
        """
        Identify cloud provider for an IP.

        Args:
            ip: IP address

        Returns:
            Provider name or None
        """
        for provider, ranges in self._ranges.items():
            for start, end in ranges:
                if _ip_in_range(ip, start, end):
                    return provider
        return None
