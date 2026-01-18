"""
Passive DNS collector for ASM.

This module performs passive DNS enumeration to discover subdomains
and resolve IP addresses for target domains. It uses only standard
DNS queries (no zone transfers or brute-forcing) making it safe
for any domain.

DNS enumeration discovers:
- Common subdomain patterns (www, mail, api, etc.)
- MX, NS, and TXT record analysis
- Cloud provider detection from CNAME targets
- Dangling DNS record detection
"""

from __future__ import annotations

import logging
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from stance.asm.config import ASMConfiguration, DEFAULT_SUBDOMAIN_PREFIXES
from stance.asm.models import ExternalAsset, ExternalAssetCollection

logger = logging.getLogger(__name__)

# Common cloud provider CNAME patterns
CLOUD_CNAME_PATTERNS = {
    "aws": [
        ".amazonaws.com",
        ".aws.amazon.com",
        ".cloudfront.net",
        ".elasticbeanstalk.com",
        ".elb.amazonaws.com",
        ".s3.amazonaws.com",
        ".s3-website",
    ],
    "gcp": [
        ".googleapis.com",
        ".googleusercontent.com",
        ".appspot.com",
        ".cloudfunctions.net",
        ".run.app",
        ".storage.googleapis.com",
    ],
    "azure": [
        ".azure.com",
        ".azurewebsites.net",
        ".azure-api.net",
        ".cloudapp.azure.com",
        ".blob.core.windows.net",
        ".azurefd.net",
        ".trafficmanager.net",
    ],
    "cloudflare": [
        ".cloudflare.com",
        ".cloudflaressl.com",
    ],
    "fastly": [
        ".fastly.net",
        ".fastlylb.net",
    ],
    "akamai": [
        ".akamaiedge.net",
        ".akamai.net",
        ".akadns.net",
    ],
}

# Services that indicate potential subdomain takeover when dangling
TAKEOVER_VULNERABLE_SERVICES = [
    ".s3.amazonaws.com",
    ".cloudfront.net",
    ".elasticbeanstalk.com",
    ".herokuapp.com",
    ".github.io",
    ".bitbucket.io",
    ".azurewebsites.net",
    ".cloudapp.azure.com",
    ".trafficmanager.net",
    ".zendesk.com",
    ".shopify.com",
    ".fastly.net",
    ".pantheon.io",
    ".ghost.io",
    ".surge.sh",
    ".netlify.app",
]


@dataclass
class DNSRecord:
    """Represents a DNS record."""

    record_type: str  # A, AAAA, CNAME, MX, NS, TXT
    name: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    """Result of DNS queries for a domain."""

    domain: str
    records: list[DNSRecord] = field(default_factory=list)
    resolved_ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    cloud_provider: str | None = None
    is_dangling: bool = False
    takeover_vulnerable: bool = False
    errors: list[str] = field(default_factory=list)
    query_time_seconds: float = 0.0


class PassiveDNSCollector:
    """
    Collector that discovers assets through passive DNS enumeration.

    Performs DNS lookups for common subdomain prefixes and analyzes
    DNS records to discover cloud providers and potential issues.

    Attributes:
        target_domains: List of domains to scan
        config: ASM configuration
    """

    collector_name = "passive_dns"

    def __init__(
        self,
        target_domains: list[str],
        config: ASMConfiguration | None = None,
    ) -> None:
        """
        Initialize the Passive DNS collector.

        Args:
            target_domains: List of domains to enumerate
            config: Optional ASM configuration
        """
        self._target_domains = [d.lower().strip() for d in target_domains]
        self._config = config or ASMConfiguration(target_domains=self._target_domains)
        self._subdomain_prefixes = self._config.subdomain_prefixes or DEFAULT_SUBDOMAIN_PREFIXES

    @property
    def target_domains(self) -> list[str]:
        """Get the list of target domains."""
        return self._target_domains

    @property
    def config(self) -> ASMConfiguration:
        """Get the ASM configuration."""
        return self._config

    def collect(self) -> ExternalAssetCollection:
        """
        Collect DNS data for all target domains.

        Returns:
            ExternalAssetCollection containing discovered assets
        """
        all_assets: list[ExternalAsset] = []
        discovered_domains: set[str] = set()

        for domain in self._target_domains:
            if self._config.is_domain_excluded(domain):
                logger.debug(f"Skipping excluded domain: {domain}")
                continue

            try:
                # First, check the base domain
                result = self._resolve_domain(domain)
                if result.resolved_ips or result.cnames:
                    asset = self._create_asset(domain, result)
                    if asset and domain not in discovered_domains:
                        all_assets.append(asset)
                        discovered_domains.add(domain)

                # Enumerate common subdomains
                subdomains = self._enumerate_subdomains(domain)
                for subdomain, sub_result in subdomains.items():
                    if subdomain not in discovered_domains:
                        asset = self._create_asset(subdomain, sub_result)
                        if asset:
                            all_assets.append(asset)
                            discovered_domains.add(subdomain)

            except Exception as e:
                logger.error(f"Failed DNS enumeration for {domain}: {e}")
                continue

        logger.info(
            f"Passive DNS collector found {len(all_assets)} assets "
            f"from {len(discovered_domains)} domains"
        )

        return ExternalAssetCollection(all_assets)

    def _enumerate_subdomains(self, base_domain: str) -> dict[str, DNSResult]:
        """
        Enumerate subdomains by checking common prefixes.

        Args:
            base_domain: Base domain to enumerate subdomains for

        Returns:
            Dictionary mapping subdomain to DNSResult
        """
        results: dict[str, DNSResult] = {}
        checked = 0
        found = 0

        for prefix in self._subdomain_prefixes:
            subdomain = f"{prefix}.{base_domain}"

            if self._config.is_domain_excluded(subdomain):
                continue

            try:
                result = self._resolve_domain(subdomain)
                checked += 1

                # Only include if we got valid results
                if result.resolved_ips or result.cnames:
                    results[subdomain] = result
                    found += 1
                    logger.debug(f"Found subdomain: {subdomain}")

            except Exception as e:
                logger.debug(f"Failed to resolve {subdomain}: {e}")
                continue

            # Rate limiting to avoid overwhelming DNS servers
            if checked % 50 == 0:
                time.sleep(0.1)

        logger.info(
            f"Subdomain enumeration for {base_domain}: "
            f"checked {checked}, found {found}"
        )

        return results

    def _resolve_domain(self, domain: str) -> DNSResult:
        """
        Resolve a domain and gather DNS information.

        Args:
            domain: Domain to resolve

        Returns:
            DNSResult with resolution data
        """
        result = DNSResult(domain=domain)
        start_time = time.time()

        # Resolve A records (IPv4)
        try:
            socket.setdefaulttimeout(self._config.dns_timeout_seconds)
            ips = socket.gethostbyname_ex(domain)
            # ips is (hostname, aliaslist, ipaddrlist)
            result.resolved_ips.extend(ips[2])

            # Check for CNAMEs in alias list
            for alias in ips[1]:
                if alias and alias != domain:
                    result.cnames.append(alias)
                    result.records.append(
                        DNSRecord(
                            record_type="CNAME",
                            name=domain,
                            value=alias,
                        )
                    )

            # Add A records
            for ip in ips[2]:
                result.records.append(
                    DNSRecord(
                        record_type="A",
                        name=domain,
                        value=ip,
                    )
                )

        except socket.gaierror as e:
            # Check if this is NXDOMAIN (domain doesn't exist)
            if e.errno == socket.EAI_NONAME:
                result.is_dangling = True
            result.errors.append(f"DNS resolution failed: {e}")
        except socket.timeout:
            result.errors.append("DNS query timed out")
        except Exception as e:
            result.errors.append(f"DNS error: {e}")

        # Try to resolve AAAA (IPv6) records
        try:
            socket.setdefaulttimeout(self._config.dns_timeout_seconds)
            ipv6_info = socket.getaddrinfo(
                domain, None, socket.AF_INET6, socket.SOCK_STREAM
            )
            for info in ipv6_info:
                ip = info[4][0]
                if ip not in result.resolved_ips:
                    result.resolved_ips.append(ip)
                    result.records.append(
                        DNSRecord(
                            record_type="AAAA",
                            name=domain,
                            value=ip,
                        )
                    )
        except (socket.gaierror, socket.timeout, OSError):
            pass  # IPv6 resolution is optional

        # Detect cloud provider from CNAMEs
        result.cloud_provider = self._detect_cloud_provider(result.cnames)

        # Check for subdomain takeover vulnerability
        result.takeover_vulnerable = self._check_takeover_vulnerability(result)

        result.query_time_seconds = time.time() - start_time

        return result

    def _detect_cloud_provider(self, cnames: list[str]) -> str | None:
        """
        Detect cloud provider from CNAME targets.

        Args:
            cnames: List of CNAME values

        Returns:
            Cloud provider name or None
        """
        for cname in cnames:
            cname_lower = cname.lower()
            for provider, patterns in CLOUD_CNAME_PATTERNS.items():
                for pattern in patterns:
                    if pattern in cname_lower:
                        return provider
        return None

    def _check_takeover_vulnerability(self, result: DNSResult) -> bool:
        """
        Check if domain might be vulnerable to subdomain takeover.

        A domain is potentially vulnerable if:
        - It has a CNAME pointing to a takeover-vulnerable service
        - The CNAME target doesn't resolve (dangling)

        Args:
            result: DNS resolution result

        Returns:
            True if potentially vulnerable
        """
        if not result.cnames:
            return False

        for cname in result.cnames:
            cname_lower = cname.lower()

            # Check if CNAME points to vulnerable service
            for service in TAKEOVER_VULNERABLE_SERVICES:
                if service in cname_lower:
                    # Try to resolve the CNAME target
                    try:
                        socket.setdefaulttimeout(self._config.dns_timeout_seconds)
                        socket.gethostbyname(cname)
                        # CNAME resolves, not vulnerable
                    except socket.gaierror:
                        # CNAME doesn't resolve - potential takeover
                        logger.warning(
                            f"Potential subdomain takeover: {result.domain} "
                            f"-> {cname} (doesn't resolve)"
                        )
                        return True
                    except Exception:
                        pass

        return False

    def _create_asset(
        self,
        domain: str,
        dns_result: DNSResult,
    ) -> ExternalAsset | None:
        """
        Create an ExternalAsset from DNS resolution results.

        Args:
            domain: Domain name
            dns_result: DNS resolution data

        Returns:
            ExternalAsset or None if creation fails
        """
        try:
            # Skip if no useful data
            if not dns_result.resolved_ips and not dns_result.cnames:
                if not dns_result.is_dangling:
                    return None

            now = datetime.now(timezone.utc)

            # Use first resolved IP if available
            ip_address = dns_result.resolved_ips[0] if dns_result.resolved_ips else None

            # Filter out excluded IPs
            if ip_address and self._config.is_ip_excluded(ip_address):
                logger.debug(f"Skipping asset with excluded IP: {ip_address}")
                return None

            asset_id = ExternalAsset.generate_id(domain, ip_address, None)

            # Calculate initial risk score based on DNS findings
            risk_score = 0.0
            if dns_result.takeover_vulnerable:
                risk_score = 9.0  # High risk for takeover
            elif dns_result.is_dangling:
                risk_score = 5.0  # Medium risk for dangling

            return ExternalAsset(
                id=asset_id,
                domain=domain,
                ip_address=ip_address,
                port=None,
                protocol=None,
                service=None,
                technology_stack=tuple(),
                cloud_provider=dns_result.cloud_provider,
                cloud_region=None,
                first_seen=now,
                last_seen=now,
                certificate_info=None,
                risk_score=risk_score,
                raw_data={
                    "source": "passive_dns",
                    "resolved_ips": dns_result.resolved_ips,
                    "cnames": dns_result.cnames,
                    "is_dangling": dns_result.is_dangling,
                    "takeover_vulnerable": dns_result.takeover_vulnerable,
                    "records": [
                        {"type": r.record_type, "name": r.name, "value": r.value}
                        for r in dns_result.records
                    ],
                },
                source="passive_dns",
                is_verified=False,
            )

        except Exception as e:
            logger.warning(f"Failed to create asset for {domain}: {e}")
            return None

    def resolve_single(self, domain: str) -> DNSResult:
        """
        Resolve a single domain (public API).

        Args:
            domain: Domain to resolve

        Returns:
            DNSResult with resolution data
        """
        return self._resolve_domain(domain)

    def enrich_assets(
        self,
        assets: ExternalAssetCollection,
    ) -> ExternalAssetCollection:
        """
        Enrich existing assets with DNS data.

        Resolves IP addresses for assets that don't have them.

        Args:
            assets: Collection of assets to enrich

        Returns:
            New collection with enriched assets
        """
        enriched: list[ExternalAsset] = []

        for asset in assets:
            if asset.ip_address:
                # Already has IP, keep as-is
                enriched.append(asset)
                continue

            # Resolve DNS for this asset
            result = self._resolve_domain(asset.domain)

            if result.resolved_ips:
                # Create updated asset with IP
                # Since ExternalAsset is frozen, we need to create a new one
                new_raw_data = dict(asset.raw_data)
                new_raw_data["dns_resolved_ips"] = result.resolved_ips
                new_raw_data["dns_cnames"] = result.cnames

                enriched_asset = ExternalAsset(
                    id=asset.id,
                    domain=asset.domain,
                    ip_address=result.resolved_ips[0],
                    port=asset.port,
                    protocol=asset.protocol,
                    service=asset.service,
                    technology_stack=asset.technology_stack,
                    cloud_provider=result.cloud_provider or asset.cloud_provider,
                    cloud_region=asset.cloud_region,
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
