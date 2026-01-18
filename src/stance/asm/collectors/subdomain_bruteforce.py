"""
Subdomain Brute Force collector for ASM.

This module provides opt-in subdomain enumeration via DNS brute-forcing
for verified domains only. Active scanning requires explicit ownership
verification before any probing is performed.

IMPORTANT: This collector will NEVER brute-force without verified ownership.
This is a safety and legal requirement.

Features:
- Wordlist-based subdomain enumeration
- Wildcard DNS detection
- Permutation generation
- Rate limiting
- Parallel DNS resolution
"""

from __future__ import annotations

import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from stance.asm.config import ASMConfiguration, ASMOwnershipVerification
from stance.asm.models import ExternalAsset, ExternalAssetCollection

logger = logging.getLogger(__name__)


# Default subdomain wordlist (top 1000 common subdomains)
# This is a subset; the full list would be in a separate file
DEFAULT_SUBDOMAINS = [
    # Common subdomains
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns", "mx", "mx1", "mx2", "blog", "dev", "www2", "ns3", "pop3", "forum",
    "admin", "mail2", "test", "vpn", "api", "server", "m", "mobile", "www1",
    "secure", "portal", "shop", "www3", "host", "support", "cloud", "demo",
    "static", "mysql", "web", "old", "news", "cp", "dns", "dns1", "dns2",
    "beta", "stage", "staging", "live", "app", "apps", "images", "img",
    "search", "files", "download", "downloads", "help", "cdn", "cpanel",
    "whm", "email", "webdisk", "autoconfig", "autodiscover", "imap",
    "calendar", "docs", "drive", "video", "videos", "media", "store",
    "backup", "backups", "db", "sql", "database", "data", "logs", "log",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "build", "jira",
    "confluence", "wiki", "internal", "intranet", "extranet", "corp",
    "corporate", "office", "exchange", "owa", "remote", "rdp", "citrix",
    "gateway", "gw", "router", "firewall", "proxy", "cache", "wap",
    "monitor", "monitoring", "status", "stats", "analytics", "track",
    "tracking", "sso", "auth", "login", "accounts", "account", "billing",
    "pay", "payment", "payments", "checkout", "cart", "orders", "order",
    "crm", "erp", "hr", "finance", "legal", "sales", "marketing",
    "partners", "partner", "reseller", "affiliate", "affiliates",
    "assets", "static1", "static2", "img1", "img2", "images1", "images2",
    "cdn1", "cdn2", "origin", "edge", "lb", "loadbalancer", "balancer",
    "web1", "web2", "web3", "app1", "app2", "app3", "api1", "api2",
    "api-dev", "api-staging", "api-prod", "dev-api", "staging-api",
    "v1", "v2", "v3", "legacy", "archive", "archives", "temp", "tmp",
    "sandbox", "qa", "uat", "preprod", "pre-prod", "pre-production",
    "grafana", "prometheus", "kibana", "elastic", "elasticsearch",
    "logstash", "redis", "memcache", "memcached", "mongo", "mongodb",
    "postgres", "postgresql", "mssql", "oracle", "rabbitmq", "kafka",
    "zookeeper", "consul", "vault", "nomad", "terraform", "ansible",
    "puppet", "chef", "docker", "kubernetes", "k8s", "rancher", "swarm",
    "aws", "azure", "gcp", "cloud", "s3", "storage", "bucket", "buckets",
]

# Permutation patterns for subdomain variations
PERMUTATION_PATTERNS = [
    "{word}-dev",
    "{word}-staging",
    "{word}-prod",
    "{word}-api",
    "dev-{word}",
    "staging-{word}",
    "prod-{word}",
    "api-{word}",
    "{word}1",
    "{word}2",
    "{word}01",
    "{word}02",
]

# Rate limiting: max DNS queries per second
MAX_DNS_QUERIES_PER_SECOND = 100


class OwnershipVerificationRequired(Exception):
    """Raised when ownership verification is required but not present."""

    pass


class OwnershipVerificationFailed(Exception):
    """Raised when ownership verification check fails."""

    pass


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration for a domain."""

    domain: str
    discovered_subdomains: list[str] = field(default_factory=list)
    resolved_ips: dict[str, list[str]] = field(default_factory=dict)
    wildcard_detected: bool = False
    wildcard_ip: str | None = None
    words_checked: int = 0
    errors: list[str] = field(default_factory=list)
    scan_started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_completed: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "discovered_subdomains": self.discovered_subdomains,
            "resolved_ips": self.resolved_ips,
            "wildcard_detected": self.wildcard_detected,
            "wildcard_ip": self.wildcard_ip,
            "words_checked": self.words_checked,
            "errors": self.errors,
            "scan_started": self.scan_started.isoformat(),
            "scan_completed": self.scan_completed.isoformat() if self.scan_completed else None,
        }


@dataclass
class BruteforceAuditEntry:
    """Audit log entry for subdomain brute-forcing."""

    timestamp: datetime
    domain: str
    wordlist_size: int
    verification_token: str
    verification_method: str
    scan_initiated_by: str = "stance-asm"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "wordlist_size": self.wordlist_size,
            "verification_token": self.verification_token,
            "verification_method": self.verification_method,
            "scan_initiated_by": self.scan_initiated_by,
        }


class SubdomainBruteforcer:
    """
    Subdomain brute-forcer for verified domains only.

    This collector performs DNS brute-forcing against targets that have
    been verified as owned by the user. It will NEVER enumerate without
    valid ownership verification.

    Attributes:
        config: ASM configuration
    """

    collector_name = "subdomain_bruteforce"

    def __init__(self, config: ASMConfiguration) -> None:
        """
        Initialize the Subdomain Bruteforcer.

        Args:
            config: ASM configuration with ownership verifications
        """
        self._config = config
        self._audit_log: list[BruteforceAuditEntry] = []
        self._wordlist: list[str] = []
        self._wordlist_loaded = False

    @property
    def config(self) -> ASMConfiguration:
        """Get the ASM configuration."""
        return self._config

    @property
    def audit_log(self) -> list[BruteforceAuditEntry]:
        """Get the audit log of all enumerations."""
        return self._audit_log

    def load_wordlist(self, path: str | None = None) -> list[str]:
        """
        Load subdomain wordlist.

        Args:
            path: Custom wordlist path (None = use default)

        Returns:
            List of subdomain words
        """
        wordlist: list[str] = []

        # Try custom wordlist first
        custom_path = path or self._config.subdomain_wordlist_path
        if custom_path:
            try:
                wordlist_path = Path(custom_path).expanduser()
                if wordlist_path.exists():
                    with open(wordlist_path, "r", encoding="utf-8") as f:
                        for line in f:
                            word = line.strip().lower()
                            if word and not word.startswith("#"):
                                wordlist.append(word)
                    logger.info(f"Loaded {len(wordlist)} words from {custom_path}")
            except Exception as e:
                logger.warning(f"Failed to load custom wordlist: {e}")

        # Fall back to default if no custom wordlist loaded
        if not wordlist:
            wordlist = DEFAULT_SUBDOMAINS.copy()
            logger.debug(f"Using default wordlist with {len(wordlist)} words")

        # Add permutations if enabled
        if self._config.enable_subdomain_bruteforce:
            base_words = ["api", "dev", "staging", "app", "web", "mail"]
            for word in base_words:
                for pattern in PERMUTATION_PATTERNS:
                    variant = pattern.format(word=word)
                    if variant not in wordlist:
                        wordlist.append(variant)

        self._wordlist = wordlist
        self._wordlist_loaded = True

        return wordlist

    def enumerate(self, domain: str) -> SubdomainResult:
        """
        Enumerate subdomains for a domain.

        REQUIRES valid ownership verification before enumeration.

        Args:
            domain: Domain to enumerate subdomains for

        Returns:
            SubdomainResult with discovered subdomains

        Raises:
            OwnershipVerificationRequired: If no verification exists
            OwnershipVerificationFailed: If verification is invalid/expired
        """
        # SAFETY CHECK: Never enumerate without verification
        if self._config.ownership_verification_required:
            if not self._config.can_active_scan(domain):
                raise OwnershipVerificationRequired(
                    f"Ownership verification required for subdomain brute-forcing of {domain}. "
                    f"Use 'stance asm verify --domain {domain}' to configure verification."
                )

        # Get verification details for audit
        verification = self._config.get_verification_for_domain(domain)
        if verification is None:
            raise OwnershipVerificationRequired(
                f"No ownership verification configured for {domain}"
            )

        if not verification.is_valid:
            raise OwnershipVerificationFailed(
                f"Ownership verification for {domain} is expired or invalid. "
                f"Please re-verify ownership."
            )

        # Load wordlist if not already loaded
        if not self._wordlist_loaded:
            self.load_wordlist()

        # Create audit entry
        audit_entry = BruteforceAuditEntry(
            timestamp=datetime.now(timezone.utc),
            domain=domain,
            wordlist_size=len(self._wordlist),
            verification_token=verification.verification_token,
            verification_method=verification.verification_method,
        )
        self._audit_log.append(audit_entry)

        logger.info(
            f"Starting subdomain enumeration for {domain} "
            f"({len(self._wordlist)} words) - "
            f"Ownership verified via {verification.verification_method}"
        )

        result = SubdomainResult(domain=domain)

        # Check for wildcard DNS
        wildcard_result = self._check_wildcard(domain)
        if wildcard_result:
            result.wildcard_detected = True
            result.wildcard_ip = wildcard_result
            logger.info(
                f"Wildcard DNS detected for {domain}: {wildcard_result}"
            )

        # Enumerate subdomains
        discovered = self._enumerate_parallel(domain, result)
        result.discovered_subdomains = discovered
        result.scan_completed = datetime.now(timezone.utc)

        logger.info(
            f"Subdomain enumeration complete for {domain}: "
            f"found {len(result.discovered_subdomains)} subdomains"
        )

        return result

    def _check_wildcard(self, domain: str) -> str | None:
        """
        Check if domain has wildcard DNS configured.

        Args:
            domain: Base domain to check

        Returns:
            Wildcard IP if detected, None otherwise
        """
        # Generate random subdomain that shouldn't exist
        import secrets

        random_sub = f"random-nonexistent-{secrets.token_hex(8)}"
        test_domain = f"{random_sub}.{domain}"

        try:
            socket.setdefaulttimeout(self._config.dns_timeout_seconds)
            ips = socket.gethostbyname_ex(test_domain)
            if ips[2]:
                # Wildcard detected - random subdomain resolves
                return ips[2][0]
        except socket.gaierror:
            # Expected - random subdomain should not resolve
            pass
        except Exception as e:
            logger.debug(f"Error checking wildcard for {domain}: {e}")

        return None

    def _enumerate_parallel(
        self,
        domain: str,
        result: SubdomainResult,
    ) -> list[str]:
        """
        Enumerate subdomains using parallel DNS resolution.

        Args:
            domain: Base domain
            result: Result object to update

        Returns:
            List of discovered subdomains
        """
        discovered: list[str] = []
        checked = 0
        rate_limit_start = time.time()
        queries_in_window = 0

        # Use thread pool for parallel resolution
        max_workers = min(self._config.max_concurrent_requests, 20)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit resolution tasks in batches for rate limiting
            batch_size = MAX_DNS_QUERIES_PER_SECOND

            for i in range(0, len(self._wordlist), batch_size):
                batch = self._wordlist[i : i + batch_size]

                # Rate limiting
                elapsed = time.time() - rate_limit_start
                if queries_in_window >= MAX_DNS_QUERIES_PER_SECOND and elapsed < 1.0:
                    sleep_time = 1.0 - elapsed
                    time.sleep(sleep_time)
                    rate_limit_start = time.time()
                    queries_in_window = 0

                futures = {
                    executor.submit(
                        self._resolve_subdomain,
                        word,
                        domain,
                        result.wildcard_ip,
                    ): word
                    for word in batch
                }

                for future in as_completed(futures):
                    word = futures[future]
                    checked += 1
                    queries_in_window += 1

                    try:
                        subdomain, ips = future.result()
                        if subdomain and ips:
                            discovered.append(subdomain)
                            result.resolved_ips[subdomain] = ips
                            logger.debug(f"Found: {subdomain} -> {ips}")
                    except Exception as e:
                        logger.debug(f"Error resolving {word}.{domain}: {e}")

        result.words_checked = checked
        return discovered

    def _resolve_subdomain(
        self,
        word: str,
        domain: str,
        wildcard_ip: str | None,
    ) -> tuple[str | None, list[str] | None]:
        """
        Resolve a single subdomain candidate.

        Args:
            word: Subdomain word to test
            domain: Base domain
            wildcard_ip: Wildcard IP to filter (if any)

        Returns:
            Tuple of (subdomain, ips) or (None, None) if not found
        """
        subdomain = f"{word}.{domain}"

        try:
            socket.setdefaulttimeout(self._config.dns_timeout_seconds)
            result = socket.gethostbyname_ex(subdomain)
            ips = result[2]

            if not ips:
                return None, None

            # Filter out wildcard matches
            if wildcard_ip:
                ips = [ip for ip in ips if ip != wildcard_ip]
                if not ips:
                    return None, None

            return subdomain, ips

        except socket.gaierror:
            # Domain doesn't exist
            return None, None
        except socket.timeout:
            # Timeout - treat as not found
            return None, None
        except Exception:
            return None, None

    def enumerate_assets(
        self,
        domains: list[str],
    ) -> ExternalAssetCollection:
        """
        Enumerate subdomains for multiple domains and create assets.

        Only enumerates domains with verified ownership.

        Args:
            domains: List of domains to enumerate

        Returns:
            ExternalAssetCollection with discovered subdomains
        """
        assets: list[ExternalAsset] = []

        for domain in domains:
            # Skip excluded domains
            if self._config.is_domain_excluded(domain):
                logger.debug(f"Skipping excluded domain: {domain}")
                continue

            # Check if we can enumerate this domain
            if not self._config.can_active_scan(domain):
                logger.debug(
                    f"Skipping subdomain enumeration for {domain}: "
                    f"ownership not verified"
                )
                continue

            try:
                result = self.enumerate(domain)

                # Create assets for each discovered subdomain
                for subdomain in result.discovered_subdomains:
                    ips = result.resolved_ips.get(subdomain, [])
                    ip_address = ips[0] if ips else None

                    # Skip excluded IPs
                    if ip_address and self._config.is_ip_excluded(ip_address):
                        continue

                    asset = ExternalAsset(
                        id=ExternalAsset.generate_id(subdomain, ip_address, None),
                        domain=subdomain,
                        ip_address=ip_address,
                        port=None,
                        protocol=None,
                        service=None,
                        technology_stack=tuple(),
                        cloud_provider=None,
                        cloud_region=None,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        certificate_info=None,
                        risk_score=0.0,
                        raw_data={
                            "source": "subdomain_bruteforce",
                            "resolved_ips": ips,
                            "wildcard_detected": result.wildcard_detected,
                        },
                        source="subdomain_bruteforce",
                        is_verified=True,  # We own this domain
                    )
                    assets.append(asset)

            except OwnershipVerificationRequired as e:
                logger.warning(str(e))
            except OwnershipVerificationFailed as e:
                logger.warning(str(e))
            except Exception as e:
                logger.error(f"Subdomain enumeration failed for {domain}: {e}")

        logger.info(
            f"Subdomain enumeration complete: "
            f"found {len(assets)} subdomains across {len(domains)} domains"
        )

        return ExternalAssetCollection(assets)

    def get_audit_summary(self) -> dict[str, Any]:
        """
        Get summary of all enumeration operations performed.

        Returns:
            Dictionary with audit summary
        """
        return {
            "total_enumerations": len(self._audit_log),
            "domains_enumerated": list(
                set(entry.domain for entry in self._audit_log)
            ),
            "entries": [entry.to_dict() for entry in self._audit_log],
        }
