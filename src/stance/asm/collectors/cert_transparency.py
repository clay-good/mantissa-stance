"""
Certificate Transparency collector for ASM.

This module queries Certificate Transparency logs via crt.sh to discover
subdomains and certificate information for target domains.

Certificate Transparency (CT) is a framework for monitoring and auditing
SSL/TLS certificates. By querying CT logs, we can discover:
- All certificates issued for a domain and its subdomains
- Historical certificates (useful for discovering forgotten subdomains)
- Certificate metadata (issuer, validity, SANs)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from stance.asm.config import ASMConfiguration
from stance.asm.models import (
    CertificateInfo,
    ExternalAsset,
    ExternalAssetCollection,
)

logger = logging.getLogger(__name__)

# crt.sh API endpoint
CRTSH_API_URL = "https://crt.sh/"

# Rate limiting: crt.sh requests max 1 per second
CRTSH_RATE_LIMIT_SECONDS = 1.0

# Cache TTL for crt.sh results
DEFAULT_CACHE_TTL_HOURS = 1


@dataclass
class CertTransparencyResult:
    """Result from a single certificate transparency query."""

    domain: str
    certificates: list[dict[str, Any]] = field(default_factory=list)
    subdomains: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    cached: bool = False
    query_time_seconds: float = 0.0


class CertTransparencyCollector:
    """
    Collector that discovers subdomains via Certificate Transparency logs.

    Uses the crt.sh public API to query CT logs for certificates issued
    to target domains and their subdomains.

    Attributes:
        target_domains: List of domains to scan
        config: ASM configuration
    """

    collector_name = "cert_transparency"

    def __init__(
        self,
        target_domains: list[str],
        config: ASMConfiguration | None = None,
    ) -> None:
        """
        Initialize the Certificate Transparency collector.

        Args:
            target_domains: List of domains to discover certificates for
            config: Optional ASM configuration (uses defaults if not provided)
        """
        self._target_domains = [d.lower().strip() for d in target_domains]
        self._config = config or ASMConfiguration(target_domains=self._target_domains)
        self._last_request_time: float = 0.0
        self._cache_dir = Path(self._config.cert_transparency_cache_path)

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
        Collect certificate transparency data for all target domains.

        Returns:
            ExternalAssetCollection containing discovered assets
        """
        all_assets: list[ExternalAsset] = []
        all_subdomains: set[str] = set()

        for domain in self._target_domains:
            if self._config.is_domain_excluded(domain):
                logger.debug(f"Skipping excluded domain: {domain}")
                continue

            try:
                result = self._query_domain(domain)

                # Process discovered subdomains
                for subdomain in result.subdomains:
                    if subdomain not in all_subdomains:
                        all_subdomains.add(subdomain)
                        asset = self._create_asset_from_subdomain(
                            subdomain, domain, result.certificates
                        )
                        if asset:
                            all_assets.append(asset)

                if result.errors:
                    for error in result.errors:
                        logger.warning(f"CT query error for {domain}: {error}")

            except Exception as e:
                logger.error(f"Failed to query CT logs for {domain}: {e}")
                continue

        logger.info(
            f"Certificate Transparency collector found {len(all_assets)} assets "
            f"from {len(all_subdomains)} unique subdomains"
        )

        return ExternalAssetCollection(all_assets)

    def _query_domain(self, domain: str) -> CertTransparencyResult:
        """
        Query crt.sh for certificates issued to a domain.

        Args:
            domain: Domain to query (e.g., "example.com")

        Returns:
            CertTransparencyResult with discovered data
        """
        result = CertTransparencyResult(domain=domain)

        # Check cache first
        cached_result = self._load_from_cache(domain)
        if cached_result:
            logger.debug(f"Using cached CT data for {domain}")
            return cached_result

        # Rate limiting
        self._rate_limit()

        start_time = time.time()

        try:
            # Query crt.sh API
            # The wildcard % matches any subdomain
            url = f"{CRTSH_API_URL}?q=%.{domain}&output=json"
            logger.debug(f"Querying crt.sh: {url}")

            certificates = self._fetch_with_retry(url)
            result.certificates = certificates

            # Extract unique subdomains from certificates
            result.subdomains = self._extract_subdomains(certificates, domain)

            result.query_time_seconds = time.time() - start_time

            # Cache the result
            self._save_to_cache(domain, result)

            logger.info(
                f"CT query for {domain}: found {len(certificates)} certificates, "
                f"{len(result.subdomains)} unique subdomains in {result.query_time_seconds:.2f}s"
            )

        except Exception as e:
            result.errors.append(str(e))
            result.query_time_seconds = time.time() - start_time
            logger.error(f"CT query failed for {domain}: {e}")

        return result

    def _fetch_with_retry(
        self,
        url: str,
        max_retries: int = 3,
        base_delay: float = 1.0,
    ) -> list[dict[str, Any]]:
        """
        Fetch URL with exponential backoff retry.

        Args:
            url: URL to fetch
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds (doubles each retry)

        Returns:
            Parsed JSON response as list of dictionaries

        Raises:
            Exception: If all retries fail
        """
        last_error: Exception | None = None

        for attempt in range(max_retries + 1):
            try:
                request = Request(
                    url,
                    headers={
                        "User-Agent": self._config.user_agent,
                        "Accept": "application/json",
                    },
                )

                with urlopen(
                    request, timeout=self._config.request_timeout_seconds
                ) as response:
                    data = response.read().decode("utf-8")

                    # Handle empty response
                    if not data or data.strip() == "":
                        return []

                    return json.loads(data)

            except HTTPError as e:
                last_error = e
                if e.code == 429:  # Rate limited
                    delay = base_delay * (2**attempt)
                    logger.warning(f"Rate limited by crt.sh, waiting {delay}s")
                    time.sleep(delay)
                elif e.code == 404:
                    # No certificates found - not an error
                    return []
                else:
                    logger.warning(f"HTTP error {e.code} from crt.sh: {e.reason}")
                    if attempt < max_retries:
                        time.sleep(base_delay * (2**attempt))

            except URLError as e:
                last_error = e
                logger.warning(f"URL error querying crt.sh: {e.reason}")
                if attempt < max_retries:
                    time.sleep(base_delay * (2**attempt))

            except json.JSONDecodeError as e:
                last_error = e
                logger.warning(f"Invalid JSON from crt.sh: {e}")
                if attempt < max_retries:
                    time.sleep(base_delay * (2**attempt))

            except Exception as e:
                last_error = e
                logger.warning(f"Error fetching from crt.sh: {e}")
                if attempt < max_retries:
                    time.sleep(base_delay * (2**attempt))

        raise last_error or Exception("Failed to fetch from crt.sh after retries")

    def _extract_subdomains(
        self,
        certificates: list[dict[str, Any]],
        base_domain: str,
    ) -> set[str]:
        """
        Extract unique subdomains from certificate data.

        Args:
            certificates: List of certificate records from crt.sh
            base_domain: The base domain to filter against

        Returns:
            Set of unique subdomain names
        """
        subdomains: set[str] = set()
        base_domain_lower = base_domain.lower()

        for cert in certificates:
            # crt.sh returns 'name_value' which contains the CN and SANs
            name_value = cert.get("name_value", "")

            # name_value can contain multiple domains separated by newlines
            for name in name_value.split("\n"):
                name = name.strip().lower()

                if not name:
                    continue

                # Skip wildcard entries but track the base
                if name.startswith("*."):
                    # Convert *.example.com to example.com
                    name = name[2:]

                # Validate this is a subdomain of our target
                if self._is_valid_subdomain(name, base_domain_lower):
                    # Skip if excluded
                    if not self._config.is_domain_excluded(name):
                        subdomains.add(name)

        return subdomains

    def _is_valid_subdomain(self, name: str, base_domain: str) -> bool:
        """
        Check if a name is a valid subdomain of the base domain.

        Args:
            name: Domain name to check
            base_domain: Base domain

        Returns:
            True if name is a valid subdomain of base_domain
        """
        # Must end with the base domain
        if not (name == base_domain or name.endswith(f".{base_domain}")):
            return False

        # Basic domain name validation
        # Allow alphanumeric, hyphens, and dots
        if not re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", name):
            return False

        # Check for consecutive dots or leading/trailing hyphens
        if ".." in name:
            return False

        return True

    def _create_asset_from_subdomain(
        self,
        subdomain: str,
        base_domain: str,
        certificates: list[dict[str, Any]],
    ) -> ExternalAsset | None:
        """
        Create an ExternalAsset from a discovered subdomain.

        Args:
            subdomain: The discovered subdomain
            base_domain: The base domain it belongs to
            certificates: Certificate data (for extracting cert info)

        Returns:
            ExternalAsset or None if creation fails
        """
        try:
            # Find the most recent certificate for this subdomain
            cert_info = self._find_certificate_for_domain(subdomain, certificates)

            now = datetime.now(timezone.utc)
            asset_id = ExternalAsset.generate_id(subdomain, None, None)

            return ExternalAsset(
                id=asset_id,
                domain=subdomain,
                ip_address=None,  # Will be resolved by DNS collector
                port=None,  # Will be discovered by port scanner
                protocol=None,
                service=None,
                technology_stack=tuple(),
                cloud_provider=None,
                cloud_region=None,
                first_seen=now,
                last_seen=now,
                certificate_info=cert_info,
                risk_score=0.0,  # Will be calculated later
                raw_data={
                    "base_domain": base_domain,
                    "source": "cert_transparency",
                    "discovery_method": "crt.sh",
                },
                source="cert_transparency",
                is_verified=False,
            )

        except Exception as e:
            logger.warning(f"Failed to create asset for {subdomain}: {e}")
            return None

    def _find_certificate_for_domain(
        self,
        domain: str,
        certificates: list[dict[str, Any]],
    ) -> CertificateInfo | None:
        """
        Find the most recent valid certificate for a domain.

        Args:
            domain: Domain to find certificate for
            certificates: List of certificate records

        Returns:
            CertificateInfo if found, None otherwise
        """
        domain_lower = domain.lower()
        matching_certs: list[dict[str, Any]] = []

        for cert in certificates:
            name_value = cert.get("name_value", "").lower()

            # Check if this certificate covers our domain
            for name in name_value.split("\n"):
                name = name.strip()
                if name.startswith("*."):
                    # Wildcard: *.example.com covers sub.example.com
                    wildcard_base = name[2:]
                    if domain_lower == wildcard_base or domain_lower.endswith(
                        f".{wildcard_base}"
                    ):
                        matching_certs.append(cert)
                        break
                elif name == domain_lower:
                    matching_certs.append(cert)
                    break

        if not matching_certs:
            return None

        # Sort by not_after (most recent expiry first) to get the current cert
        def get_not_after(cert: dict) -> datetime:
            try:
                # crt.sh returns dates in ISO format
                not_after_str = cert.get("not_after", "")
                if not_after_str:
                    return datetime.fromisoformat(
                        not_after_str.replace("Z", "+00:00")
                    )
            except (ValueError, TypeError):
                pass
            return datetime.min.replace(tzinfo=timezone.utc)

        matching_certs.sort(key=get_not_after, reverse=True)
        best_cert = matching_certs[0]

        return self._parse_certificate(best_cert)

    def _parse_certificate(self, cert: dict[str, Any]) -> CertificateInfo:
        """
        Parse crt.sh certificate data into CertificateInfo.

        Args:
            cert: Certificate record from crt.sh

        Returns:
            CertificateInfo object
        """
        # Parse dates
        not_before = self._parse_date(cert.get("not_before"))
        not_after = self._parse_date(cert.get("not_after"))

        # Parse SANs from name_value
        san_domains: list[str] = []
        name_value = cert.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip()
            if name and name not in san_domains:
                san_domains.append(name)

        # Extract issuer info
        issuer_name = cert.get("issuer_name", "")
        issuer_cn = self._extract_cn(issuer_name)

        # Extract subject
        common_name = cert.get("common_name", "")
        if not common_name and san_domains:
            common_name = san_domains[0]

        # Check if self-signed
        is_self_signed = issuer_cn == common_name if issuer_cn and common_name else False

        # Serial number
        serial_number = str(cert.get("serial_number", ""))

        return CertificateInfo(
            subject=common_name,
            issuer=issuer_cn or issuer_name,
            not_before=not_before,
            not_after=not_after,
            san_domains=tuple(san_domains),
            fingerprint_sha256="",  # crt.sh doesn't provide this directly
            is_self_signed=is_self_signed,
            key_algorithm="RSA",  # Default, crt.sh doesn't always provide this
            key_size=2048,  # Default
            serial_number=serial_number,
        )

    def _parse_date(self, date_str: str | None) -> datetime:
        """
        Parse a date string from crt.sh.

        Args:
            date_str: Date string in ISO format

        Returns:
            datetime object (defaults to now if parsing fails)
        """
        if not date_str:
            return datetime.now(timezone.utc)

        try:
            # Handle various ISO formats
            date_str = date_str.replace("Z", "+00:00")
            return datetime.fromisoformat(date_str)
        except (ValueError, TypeError):
            try:
                # Try parsing without timezone
                dt = datetime.fromisoformat(date_str.replace("Z", ""))
                return dt.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                return datetime.now(timezone.utc)

    def _extract_cn(self, issuer_name: str) -> str:
        """
        Extract Common Name (CN) from an issuer/subject string.

        Args:
            issuer_name: X.509 name string (e.g., "CN=Let's Encrypt, O=...")

        Returns:
            Common Name value or empty string
        """
        if not issuer_name:
            return ""

        # Look for CN= pattern
        match = re.search(r"CN=([^,]+)", issuer_name)
        if match:
            return match.group(1).strip()

        return issuer_name

    def _rate_limit(self) -> None:
        """Apply rate limiting between crt.sh requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < CRTSH_RATE_LIMIT_SECONDS:
            sleep_time = CRTSH_RATE_LIMIT_SECONDS - elapsed
            logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self._last_request_time = time.time()

    def _get_cache_path(self, domain: str) -> Path:
        """Get the cache file path for a domain."""
        # Create a safe filename from domain
        safe_name = domain.replace(".", "_").replace("/", "_")
        cache_hash = hashlib.md5(domain.encode()).hexdigest()[:8]
        return self._cache_dir / f"{safe_name}_{cache_hash}.json"

    def _load_from_cache(self, domain: str) -> CertTransparencyResult | None:
        """
        Load cached CT results for a domain.

        Args:
            domain: Domain to load cache for

        Returns:
            CertTransparencyResult if valid cache exists, None otherwise
        """
        cache_path = self._get_cache_path(domain)

        if not cache_path.exists():
            return None

        try:
            # Check cache age
            cache_age = time.time() - cache_path.stat().st_mtime
            cache_ttl_seconds = self._config.cache_ttl_hours * 3600

            if cache_age > cache_ttl_seconds:
                logger.debug(f"Cache expired for {domain}")
                return None

            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            result = CertTransparencyResult(
                domain=domain,
                certificates=data.get("certificates", []),
                subdomains=set(data.get("subdomains", [])),
                cached=True,
            )

            return result

        except Exception as e:
            logger.warning(f"Failed to load cache for {domain}: {e}")
            return None

    def _save_to_cache(self, domain: str, result: CertTransparencyResult) -> None:
        """
        Save CT results to cache.

        Args:
            domain: Domain to cache results for
            result: Results to cache
        """
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = self._get_cache_path(domain)

            data = {
                "domain": domain,
                "certificates": result.certificates,
                "subdomains": list(result.subdomains),
                "cached_at": datetime.now(timezone.utc).isoformat(),
            }

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f)

            logger.debug(f"Cached CT results for {domain}")

        except Exception as e:
            logger.warning(f"Failed to cache results for {domain}: {e}")

    def clear_cache(self, domain: str | None = None) -> int:
        """
        Clear cached CT results.

        Args:
            domain: Specific domain to clear, or None for all

        Returns:
            Number of cache files removed
        """
        removed = 0

        if domain:
            cache_path = self._get_cache_path(domain)
            if cache_path.exists():
                cache_path.unlink()
                removed = 1
        else:
            if self._cache_dir.exists():
                for cache_file in self._cache_dir.glob("*.json"):
                    try:
                        cache_file.unlink()
                        removed += 1
                    except Exception:
                        pass

        logger.info(f"Cleared {removed} cache files")
        return removed
