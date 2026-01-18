"""
Cloud IP Range collector for ASM.

This module fetches and caches public IP ranges from major cloud providers
and CDNs, then uses them to identify which cloud provider hosts a given IP.

Supported providers:
- AWS (ip-ranges.amazonaws.com)
- GCP (gstatic.com/ipranges)
- Azure (download.microsoft.com)
- Cloudflare (cloudflare.com/ips)

This information helps:
- Identify which cloud provider hosts discovered assets
- Detect assets in unexpected cloud providers (shadow IT)
- Correlate external assets with internal CSPM inventory
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from stance.asm.config import ASMConfiguration
from stance.asm.models import ExternalAsset, ExternalAssetCollection

logger = logging.getLogger(__name__)

# Cloud provider IP range sources
IP_RANGE_SOURCES = {
    "aws": {
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "parser": "_parse_aws_ranges",
    },
    "gcp": {
        "url": "https://www.gstatic.com/ipranges/cloud.json",
        "parser": "_parse_gcp_ranges",
    },
    "cloudflare": {
        "urls": [
            "https://www.cloudflare.com/ips-v4",
            "https://www.cloudflare.com/ips-v6",
        ],
        "parser": "_parse_cloudflare_ranges",
    },
}

# Azure requires downloading a file from a download page, which is complex
# For simplicity, we'll include a subset of well-known Azure ranges
# In production, this would be periodically updated from Microsoft's JSON files
AZURE_KNOWN_PREFIXES = [
    # Azure Public Cloud (subset of common ranges)
    "13.64.0.0/11",
    "13.96.0.0/13",
    "13.104.0.0/14",
    "20.0.0.0/11",
    "20.32.0.0/11",
    "20.64.0.0/10",
    "20.128.0.0/16",
    "23.96.0.0/13",
    "40.64.0.0/10",
    "51.104.0.0/15",
    "51.120.0.0/16",
    "52.96.0.0/12",
    "52.112.0.0/14",
    "52.120.0.0/14",
    "52.224.0.0/11",
    "65.52.0.0/14",
    "70.37.0.0/17",
    "70.37.128.0/18",
    "104.40.0.0/13",
    "104.208.0.0/13",
    "137.116.0.0/15",
    "137.135.0.0/16",
    "138.91.0.0/16",
    "157.55.0.0/16",
    "168.61.0.0/16",
    "168.62.0.0/15",
    "191.232.0.0/13",
    "204.79.180.0/24",
]

# Default cache TTL
DEFAULT_CACHE_TTL_HOURS = 24


@dataclass
class IPRange:
    """Represents a cloud provider IP range."""

    cidr: str
    provider: str
    region: str | None = None
    service: str | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = field(
        default=None, repr=False
    )

    def __post_init__(self) -> None:
        """Parse CIDR into network object."""
        if self.network is None:
            try:
                self.network = ipaddress.ip_network(self.cidr, strict=False)
            except ValueError:
                logger.warning(f"Invalid CIDR: {self.cidr}")


@dataclass
class IPLookupResult:
    """Result of an IP address lookup."""

    ip: str
    provider: str | None = None
    region: str | None = None
    service: str | None = None
    cidr: str | None = None


class CloudIPRangeCollector:
    """
    Collector that identifies cloud providers from IP addresses.

    Downloads and caches IP ranges from major cloud providers,
    then provides fast lookups to identify which provider hosts an IP.

    Attributes:
        config: ASM configuration
    """

    collector_name = "cloud_ip_ranges"

    def __init__(self, config: ASMConfiguration | None = None) -> None:
        """
        Initialize the Cloud IP Range collector.

        Args:
            config: Optional ASM configuration
        """
        self._config = config or ASMConfiguration()
        self._cache_dir = Path(self._config.ip_ranges_cache_path)
        self._ranges: list[IPRange] = []
        self._loaded = False
        self._last_load_time: datetime | None = None

    @property
    def config(self) -> ASMConfiguration:
        """Get the ASM configuration."""
        return self._config

    @property
    def is_loaded(self) -> bool:
        """Check if IP ranges have been loaded."""
        return self._loaded

    def load_ip_ranges(self, force_refresh: bool = False) -> None:
        """
        Load IP ranges from cache or fetch from providers.

        Args:
            force_refresh: If True, fetch fresh data even if cache exists
        """
        if self._loaded and not force_refresh:
            return

        self._ranges = []

        # Try to load from cache first
        if not force_refresh:
            cached_ranges = self._load_from_cache()
            if cached_ranges:
                self._ranges = cached_ranges
                self._loaded = True
                logger.info(f"Loaded {len(self._ranges)} IP ranges from cache")
                return

        # Fetch from providers
        logger.info("Fetching IP ranges from cloud providers...")

        # AWS
        try:
            aws_ranges = self._fetch_aws_ranges()
            self._ranges.extend(aws_ranges)
            logger.info(f"Loaded {len(aws_ranges)} AWS IP ranges")
        except Exception as e:
            logger.warning(f"Failed to fetch AWS IP ranges: {e}")

        # GCP
        try:
            gcp_ranges = self._fetch_gcp_ranges()
            self._ranges.extend(gcp_ranges)
            logger.info(f"Loaded {len(gcp_ranges)} GCP IP ranges")
        except Exception as e:
            logger.warning(f"Failed to fetch GCP IP ranges: {e}")

        # Azure (using known prefixes)
        try:
            azure_ranges = self._load_azure_ranges()
            self._ranges.extend(azure_ranges)
            logger.info(f"Loaded {len(azure_ranges)} Azure IP ranges")
        except Exception as e:
            logger.warning(f"Failed to load Azure IP ranges: {e}")

        # Cloudflare
        try:
            cf_ranges = self._fetch_cloudflare_ranges()
            self._ranges.extend(cf_ranges)
            logger.info(f"Loaded {len(cf_ranges)} Cloudflare IP ranges")
        except Exception as e:
            logger.warning(f"Failed to fetch Cloudflare IP ranges: {e}")

        self._loaded = True
        self._last_load_time = datetime.now(timezone.utc)

        # Save to cache
        self._save_to_cache()

        logger.info(f"Total IP ranges loaded: {len(self._ranges)}")

    def identify_cloud_provider(self, ip: str) -> IPLookupResult:
        """
        Identify which cloud provider hosts an IP address.

        Args:
            ip: IP address to look up

        Returns:
            IPLookupResult with provider information
        """
        if not self._loaded:
            self.load_ip_ranges()

        result = IPLookupResult(ip=ip)

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return result

        # Search for matching range
        # For efficiency, we could build a prefix tree, but for now linear search
        for ip_range in self._ranges:
            if ip_range.network and ip_obj in ip_range.network:
                result.provider = ip_range.provider
                result.region = ip_range.region
                result.service = ip_range.service
                result.cidr = ip_range.cidr
                return result

        return result

    def enrich_assets(
        self,
        assets: ExternalAssetCollection,
    ) -> ExternalAssetCollection:
        """
        Enrich assets with cloud provider information.

        Args:
            assets: Collection of assets to enrich

        Returns:
            New collection with cloud provider data added
        """
        if not self._loaded:
            self.load_ip_ranges()

        enriched: list[ExternalAsset] = []

        for asset in assets:
            if not asset.ip_address:
                enriched.append(asset)
                continue

            lookup = self.identify_cloud_provider(asset.ip_address)

            if lookup.provider and lookup.provider != asset.cloud_provider:
                # Create updated asset with cloud provider info
                new_raw_data = dict(asset.raw_data)
                new_raw_data["ip_lookup"] = {
                    "provider": lookup.provider,
                    "region": lookup.region,
                    "service": lookup.service,
                    "cidr": lookup.cidr,
                }

                enriched_asset = ExternalAsset(
                    id=asset.id,
                    domain=asset.domain,
                    ip_address=asset.ip_address,
                    port=asset.port,
                    protocol=asset.protocol,
                    service=asset.service,
                    technology_stack=asset.technology_stack,
                    cloud_provider=lookup.provider,
                    cloud_region=lookup.region or asset.cloud_region,
                    first_seen=asset.first_seen,
                    last_seen=datetime.now(timezone.utc),
                    certificate_info=asset.certificate_info,
                    risk_score=asset.risk_score,
                    raw_data=new_raw_data,
                    source=asset.source,
                    is_verified=asset.is_verified,
                )
                enriched.append(enriched_asset)
            else:
                enriched.append(asset)

        return ExternalAssetCollection(enriched)

    def _fetch_with_retry(
        self,
        url: str,
        max_retries: int = 3,
        base_delay: float = 1.0,
    ) -> bytes:
        """
        Fetch URL with exponential backoff retry.

        Args:
            url: URL to fetch
            max_retries: Maximum retry attempts
            base_delay: Base delay in seconds

        Returns:
            Response content as bytes
        """
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                request = Request(
                    url,
                    headers={
                        "User-Agent": self._config.user_agent,
                    },
                )

                with urlopen(
                    request, timeout=self._config.request_timeout_seconds
                ) as response:
                    return response.read()

            except (HTTPError, URLError) as e:
                last_error = e
                if attempt < max_retries:
                    delay = base_delay * (2**attempt)
                    logger.warning(f"Retry {attempt + 1} for {url}: {e}")
                    time.sleep(delay)

            except Exception as e:
                last_error = e
                if attempt < max_retries:
                    time.sleep(base_delay * (2**attempt))

        raise last_error or Exception(f"Failed to fetch {url}")

    def _fetch_aws_ranges(self) -> list[IPRange]:
        """Fetch and parse AWS IP ranges."""
        url = IP_RANGE_SOURCES["aws"]["url"]
        data = self._fetch_with_retry(url)
        ranges_data = json.loads(data.decode("utf-8"))

        ranges: list[IPRange] = []

        # Parse IPv4 prefixes
        for prefix in ranges_data.get("prefixes", []):
            cidr = prefix.get("ip_prefix")
            if cidr:
                ranges.append(
                    IPRange(
                        cidr=cidr,
                        provider="aws",
                        region=prefix.get("region"),
                        service=prefix.get("service"),
                    )
                )

        # Parse IPv6 prefixes
        for prefix in ranges_data.get("ipv6_prefixes", []):
            cidr = prefix.get("ipv6_prefix")
            if cidr:
                ranges.append(
                    IPRange(
                        cidr=cidr,
                        provider="aws",
                        region=prefix.get("region"),
                        service=prefix.get("service"),
                    )
                )

        return ranges

    def _fetch_gcp_ranges(self) -> list[IPRange]:
        """Fetch and parse GCP IP ranges."""
        url = IP_RANGE_SOURCES["gcp"]["url"]
        data = self._fetch_with_retry(url)
        ranges_data = json.loads(data.decode("utf-8"))

        ranges: list[IPRange] = []

        for prefix in ranges_data.get("prefixes", []):
            # GCP uses either ipv4Prefix or ipv6Prefix
            cidr = prefix.get("ipv4Prefix") or prefix.get("ipv6Prefix")
            if cidr:
                ranges.append(
                    IPRange(
                        cidr=cidr,
                        provider="gcp",
                        region=prefix.get("scope"),
                        service=prefix.get("service"),
                    )
                )

        return ranges

    def _load_azure_ranges(self) -> list[IPRange]:
        """Load Azure IP ranges from known prefixes."""
        ranges: list[IPRange] = []

        for cidr in AZURE_KNOWN_PREFIXES:
            ranges.append(
                IPRange(
                    cidr=cidr,
                    provider="azure",
                    region=None,
                    service=None,
                )
            )

        return ranges

    def _fetch_cloudflare_ranges(self) -> list[IPRange]:
        """Fetch and parse Cloudflare IP ranges."""
        ranges: list[IPRange] = []

        for url in IP_RANGE_SOURCES["cloudflare"]["urls"]:
            try:
                data = self._fetch_with_retry(url)
                cidrs = data.decode("utf-8").strip().split("\n")

                for cidr in cidrs:
                    cidr = cidr.strip()
                    if cidr:
                        ranges.append(
                            IPRange(
                                cidr=cidr,
                                provider="cloudflare",
                                region=None,
                                service="cdn",
                            )
                        )
            except Exception as e:
                logger.warning(f"Failed to fetch Cloudflare ranges from {url}: {e}")

        return ranges

    def _get_cache_path(self) -> Path:
        """Get the cache file path."""
        return self._cache_dir / "ip_ranges.json"

    def _load_from_cache(self) -> list[IPRange] | None:
        """
        Load IP ranges from cache.

        Returns:
            List of IPRange or None if cache is invalid/expired
        """
        cache_path = self._get_cache_path()

        if not cache_path.exists():
            return None

        try:
            # Check cache age
            cache_age = time.time() - cache_path.stat().st_mtime
            cache_ttl_seconds = self._config.cache_ttl_hours * 3600

            if cache_age > cache_ttl_seconds:
                logger.debug("IP ranges cache expired")
                return None

            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            ranges: list[IPRange] = []
            for item in data.get("ranges", []):
                ranges.append(
                    IPRange(
                        cidr=item["cidr"],
                        provider=item["provider"],
                        region=item.get("region"),
                        service=item.get("service"),
                    )
                )

            return ranges

        except Exception as e:
            logger.warning(f"Failed to load IP ranges cache: {e}")
            return None

    def _save_to_cache(self) -> None:
        """Save IP ranges to cache."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = self._get_cache_path()

            data = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "ranges": [
                    {
                        "cidr": r.cidr,
                        "provider": r.provider,
                        "region": r.region,
                        "service": r.service,
                    }
                    for r in self._ranges
                ],
            }

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            logger.debug(f"Cached {len(self._ranges)} IP ranges")

        except Exception as e:
            logger.warning(f"Failed to cache IP ranges: {e}")

    def clear_cache(self) -> bool:
        """
        Clear the IP ranges cache.

        Returns:
            True if cache was cleared
        """
        cache_path = self._get_cache_path()
        if cache_path.exists():
            cache_path.unlink()
            self._loaded = False
            self._ranges = []
            return True
        return False

    def get_statistics(self) -> dict[str, Any]:
        """
        Get statistics about loaded IP ranges.

        Returns:
            Dictionary with range counts by provider
        """
        if not self._loaded:
            self.load_ip_ranges()

        stats: dict[str, int] = {}
        for ip_range in self._ranges:
            provider = ip_range.provider
            stats[provider] = stats.get(provider, 0) + 1

        return {
            "total_ranges": len(self._ranges),
            "by_provider": stats,
            "loaded_at": self._last_load_time.isoformat()
            if self._last_load_time
            else None,
        }
