"""
ASM configuration for Mantissa Stance.

This module provides configuration management for Attack Surface Management,
including scan settings, collector options, and ownership verification.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from stance.asm.models import ASMScanMode


# Default ports for common services
DEFAULT_SCAN_PORTS = [
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    80,     # HTTP
    110,    # POP3
    143,    # IMAP
    443,    # HTTPS
    445,    # SMB
    993,    # IMAPS
    995,    # POP3S
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    6379,   # Redis
    8080,   # HTTP Alternate
    8443,   # HTTPS Alternate
    9200,   # Elasticsearch
    27017,  # MongoDB
]

# Common subdomain prefixes for enumeration
DEFAULT_SUBDOMAIN_PREFIXES = [
    "www", "mail", "ftp", "vpn", "remote", "dev", "staging", "api",
    "cdn", "assets", "static", "admin", "portal", "app", "dashboard",
    "login", "auth", "sso", "m", "mobile", "beta", "test", "uat",
    "prod", "production", "stage", "demo", "docs", "help", "support",
    "shop", "store", "blog", "news", "media", "images", "img", "video",
    "download", "downloads", "files", "secure", "gateway", "proxy",
    "ns1", "ns2", "dns", "mx", "smtp", "pop", "imap", "webmail",
    "autodiscover", "exchange", "owa", "cpanel", "whm", "plesk",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence",
    "grafana", "prometheus", "kibana", "elastic", "redis", "mongo",
    "mysql", "postgres", "db", "database", "sql", "backup", "backups",
]


@dataclass
class ASMOwnershipVerification:
    """
    Ownership verification for a domain.

    Before active scanning (port scanning, etc.), ownership must be verified
    to ensure the scanner has authorization to probe the target.

    Attributes:
        domain: The domain being verified
        verification_method: Method used (dns_txt, http_file)
        verification_token: Token to verify
        verified: Whether verification has been confirmed
        verified_at: When verification was confirmed
        expires_at: When verification expires (must re-verify)
        created_at: When verification was initiated
    """

    domain: str
    verification_method: str = "dns_txt"  # dns_txt, http_file
    verification_token: str = ""
    verified: bool = False
    verified_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Generate token if not provided."""
        if not self.verification_token:
            self.verification_token = self._generate_token()
        if self.expires_at is None and self.verified:
            # Default expiration: 30 days from verification
            self.expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    @staticmethod
    def _generate_token() -> str:
        """Generate a secure verification token."""
        return f"stance-verify-{secrets.token_hex(16)}"

    @property
    def is_valid(self) -> bool:
        """Check if verification is currently valid."""
        if not self.verified:
            return False
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) < self.expires_at

    @property
    def dns_record_name(self) -> str:
        """Get the DNS TXT record name for verification."""
        return f"_stance-verify.{self.domain}"

    @property
    def dns_record_value(self) -> str:
        """Get the expected DNS TXT record value."""
        return self.verification_token

    @property
    def http_file_path(self) -> str:
        """Get the HTTP file path for verification."""
        return f"/.well-known/stance-verify.txt"

    @property
    def http_file_url(self) -> str:
        """Get the full URL for HTTP verification."""
        return f"https://{self.domain}{self.http_file_path}"

    @property
    def http_file_content(self) -> str:
        """Get the expected HTTP file content."""
        return self.verification_token

    def verify(self) -> None:
        """Mark this domain as verified."""
        self.verified = True
        self.verified_at = datetime.now(timezone.utc)
        self.expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "domain": self.domain,
            "verification_method": self.verification_method,
            "verification_token": self.verification_token,
            "verified": self.verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ASMOwnershipVerification:
        """Create from dictionary."""
        verified_at = data.get("verified_at")
        if isinstance(verified_at, str):
            verified_at = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))

        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

        created_at = data.get("created_at")
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        elif created_at is None:
            created_at = datetime.now(timezone.utc)

        return cls(
            domain=data.get("domain", ""),
            verification_method=data.get("verification_method", "dns_txt"),
            verification_token=data.get("verification_token", ""),
            verified=data.get("verified", False),
            verified_at=verified_at,
            expires_at=expires_at,
            created_at=created_at,
        )


@dataclass
class ASMConfiguration:
    """
    Configuration for ASM operations.

    Controls which collectors run, scan parameters, rate limiting,
    and security settings.

    Attributes:
        target_domains: Primary domains to scan
        scan_mode: Scanning mode (passive, active, full)
        enable_cert_transparency: Enable certificate transparency log collection
        enable_dns_enumeration: Enable passive DNS enumeration
        enable_cloud_ip_detection: Enable cloud provider IP range detection
        enable_port_scanning: Enable port scanning (requires ownership verification)
        enable_technology_fingerprinting: Enable technology stack detection
        enable_subdomain_bruteforce: Enable subdomain brute-forcing (active)
        port_scan_ports: List of ports to scan if enabled
        subdomain_wordlist_path: Custom wordlist path (None = use default)
        subdomain_prefixes: Custom subdomain prefixes for enumeration
        max_concurrent_requests: Maximum concurrent requests for rate limiting
        request_timeout_seconds: Timeout for individual requests
        dns_timeout_seconds: Timeout for DNS queries
        scan_interval_hours: Interval for continuous monitoring
        ownership_verification_required: Require verification for active scanning
        ownership_verifications: List of verified domain ownerships
        excluded_domains: Domains to skip during scanning
        excluded_ips: IP addresses to skip
        excluded_ports: Ports to skip during scanning
        user_agent: User-Agent string for HTTP requests
        respect_robots_txt: Whether to respect robots.txt
        cache_ttl_hours: Cache TTL for external data (cert transparency, IP ranges)
        data_dir: Directory for caching and data storage
    """

    target_domains: list[str] = field(default_factory=list)
    scan_mode: ASMScanMode = ASMScanMode.PASSIVE

    # Collector toggles
    enable_cert_transparency: bool = True
    enable_dns_enumeration: bool = True
    enable_cloud_ip_detection: bool = True
    enable_port_scanning: bool = False  # Opt-in only
    enable_technology_fingerprinting: bool = True
    enable_subdomain_bruteforce: bool = False  # Opt-in only

    # Port scanning configuration
    port_scan_ports: list[int] = field(default_factory=lambda: DEFAULT_SCAN_PORTS.copy())

    # Subdomain enumeration configuration
    subdomain_wordlist_path: str | None = None
    subdomain_prefixes: list[str] = field(
        default_factory=lambda: DEFAULT_SUBDOMAIN_PREFIXES.copy()
    )

    # Rate limiting and timeouts
    max_concurrent_requests: int = 10
    request_timeout_seconds: int = 10
    dns_timeout_seconds: int = 5
    http_timeout_seconds: int = 10

    # Scheduling
    scan_interval_hours: int = 24

    # Security settings
    ownership_verification_required: bool = True
    ownership_verifications: list[ASMOwnershipVerification] = field(default_factory=list)

    # Exclusions
    excluded_domains: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)
    excluded_ports: list[int] = field(default_factory=list)

    # HTTP settings
    user_agent: str = "Stance-ASM/1.0 (Security Scanner; https://github.com/mantissa/stance)"
    respect_robots_txt: bool = True

    # Caching
    cache_ttl_hours: int = 24
    data_dir: str = "~/.stance/asm"

    def __post_init__(self) -> None:
        """Expand paths and validate."""
        self.data_dir = os.path.expanduser(self.data_dir)

    @property
    def cache_dir(self) -> str:
        """Get the cache directory path."""
        return os.path.join(self.data_dir, "cache")

    @property
    def ip_ranges_cache_path(self) -> str:
        """Get path for cached IP ranges."""
        return os.path.join(self.cache_dir, "ip_ranges")

    @property
    def cert_transparency_cache_path(self) -> str:
        """Get path for cached cert transparency data."""
        return os.path.join(self.cache_dir, "cert_transparency")

    def is_domain_excluded(self, domain: str) -> bool:
        """Check if a domain is in the exclusion list."""
        domain_lower = domain.lower()
        for excluded in self.excluded_domains:
            if domain_lower == excluded.lower():
                return True
            # Support wildcard exclusions
            if excluded.startswith("*."):
                suffix = excluded[2:].lower()
                if domain_lower.endswith(suffix):
                    return True
        return False

    def is_ip_excluded(self, ip: str) -> bool:
        """Check if an IP is in the exclusion list."""
        return ip in self.excluded_ips

    def is_port_excluded(self, port: int) -> bool:
        """Check if a port is in the exclusion list."""
        return port in self.excluded_ports

    def get_verification_for_domain(self, domain: str) -> ASMOwnershipVerification | None:
        """Get ownership verification for a domain."""
        domain_lower = domain.lower()
        for verification in self.ownership_verifications:
            if verification.domain.lower() == domain_lower:
                return verification
        return None

    def is_domain_verified(self, domain: str) -> bool:
        """Check if a domain has valid ownership verification."""
        verification = self.get_verification_for_domain(domain)
        return verification is not None and verification.is_valid

    def add_verification(self, domain: str, method: str = "dns_txt") -> ASMOwnershipVerification:
        """
        Add a new ownership verification for a domain.

        Args:
            domain: Domain to verify
            method: Verification method (dns_txt, http_file)

        Returns:
            New ASMOwnershipVerification object
        """
        # Check if verification already exists
        existing = self.get_verification_for_domain(domain)
        if existing:
            return existing

        verification = ASMOwnershipVerification(
            domain=domain.lower(),
            verification_method=method,
        )
        self.ownership_verifications.append(verification)
        return verification

    def can_active_scan(self, domain: str) -> bool:
        """
        Check if active scanning is permitted for a domain.

        Args:
            domain: Domain to check

        Returns:
            True if active scanning is allowed
        """
        if not self.ownership_verification_required:
            return True
        return self.is_domain_verified(domain)

    def get_enabled_collectors(self) -> list[str]:
        """Get list of enabled collector names."""
        collectors = []
        if self.enable_cert_transparency:
            collectors.append("cert_transparency")
        if self.enable_dns_enumeration:
            collectors.append("passive_dns")
        if self.enable_cloud_ip_detection:
            collectors.append("cloud_ip_ranges")
        if self.enable_technology_fingerprinting:
            collectors.append("technology")
        if self.enable_port_scanning:
            collectors.append("port_scanner")
        if self.enable_subdomain_bruteforce:
            collectors.append("subdomain_bruteforce")
        return collectors

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target_domains": self.target_domains,
            "scan_mode": self.scan_mode.value,
            "enable_cert_transparency": self.enable_cert_transparency,
            "enable_dns_enumeration": self.enable_dns_enumeration,
            "enable_cloud_ip_detection": self.enable_cloud_ip_detection,
            "enable_port_scanning": self.enable_port_scanning,
            "enable_technology_fingerprinting": self.enable_technology_fingerprinting,
            "enable_subdomain_bruteforce": self.enable_subdomain_bruteforce,
            "port_scan_ports": self.port_scan_ports,
            "subdomain_wordlist_path": self.subdomain_wordlist_path,
            "subdomain_prefixes": self.subdomain_prefixes,
            "max_concurrent_requests": self.max_concurrent_requests,
            "request_timeout_seconds": self.request_timeout_seconds,
            "dns_timeout_seconds": self.dns_timeout_seconds,
            "http_timeout_seconds": self.http_timeout_seconds,
            "scan_interval_hours": self.scan_interval_hours,
            "ownership_verification_required": self.ownership_verification_required,
            "ownership_verifications": [v.to_dict() for v in self.ownership_verifications],
            "excluded_domains": self.excluded_domains,
            "excluded_ips": self.excluded_ips,
            "excluded_ports": self.excluded_ports,
            "user_agent": self.user_agent,
            "respect_robots_txt": self.respect_robots_txt,
            "cache_ttl_hours": self.cache_ttl_hours,
            "data_dir": self.data_dir,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ASMConfiguration:
        """Create from dictionary."""
        scan_mode = data.get("scan_mode", "passive")
        if isinstance(scan_mode, str):
            scan_mode = ASMScanMode(scan_mode)

        verifications = [
            ASMOwnershipVerification.from_dict(v)
            for v in data.get("ownership_verifications", [])
        ]

        return cls(
            target_domains=data.get("target_domains", []),
            scan_mode=scan_mode,
            enable_cert_transparency=data.get("enable_cert_transparency", True),
            enable_dns_enumeration=data.get("enable_dns_enumeration", True),
            enable_cloud_ip_detection=data.get("enable_cloud_ip_detection", True),
            enable_port_scanning=data.get("enable_port_scanning", False),
            enable_technology_fingerprinting=data.get("enable_technology_fingerprinting", True),
            enable_subdomain_bruteforce=data.get("enable_subdomain_bruteforce", False),
            port_scan_ports=data.get("port_scan_ports", DEFAULT_SCAN_PORTS.copy()),
            subdomain_wordlist_path=data.get("subdomain_wordlist_path"),
            subdomain_prefixes=data.get("subdomain_prefixes", DEFAULT_SUBDOMAIN_PREFIXES.copy()),
            max_concurrent_requests=data.get("max_concurrent_requests", 10),
            request_timeout_seconds=data.get("request_timeout_seconds", 10),
            dns_timeout_seconds=data.get("dns_timeout_seconds", 5),
            http_timeout_seconds=data.get("http_timeout_seconds", 10),
            scan_interval_hours=data.get("scan_interval_hours", 24),
            ownership_verification_required=data.get("ownership_verification_required", True),
            ownership_verifications=verifications,
            excluded_domains=data.get("excluded_domains", []),
            excluded_ips=data.get("excluded_ips", []),
            excluded_ports=data.get("excluded_ports", []),
            user_agent=data.get("user_agent", "Stance-ASM/1.0 (Security Scanner)"),
            respect_robots_txt=data.get("respect_robots_txt", True),
            cache_ttl_hours=data.get("cache_ttl_hours", 24),
            data_dir=data.get("data_dir", "~/.stance/asm"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ASMConfiguration:
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_file(cls, path: str) -> ASMConfiguration:
        """Load configuration from file."""
        path = os.path.expanduser(path)
        with open(path, "r", encoding="utf-8") as f:
            if path.endswith(".json"):
                return cls.from_dict(json.load(f))
            else:
                # Try YAML if available
                try:
                    import yaml
                    return cls.from_dict(yaml.safe_load(f))
                except ImportError:
                    raise ValueError(
                        "YAML support requires PyYAML. Use JSON format instead."
                    )

    def save(self, path: str) -> None:
        """Save configuration to file."""
        path = os.path.expanduser(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            if path.endswith(".json"):
                json.dump(self.to_dict(), f, indent=2)
            else:
                try:
                    import yaml
                    yaml.safe_dump(self.to_dict(), f, default_flow_style=False)
                except ImportError:
                    raise ValueError(
                        "YAML support requires PyYAML. Use JSON format instead."
                    )


class ASMConfigurationError(Exception):
    """Raised when ASM configuration is invalid."""
    pass


def validate_asm_config(config: ASMConfiguration) -> list[str]:
    """
    Validate ASM configuration.

    Args:
        config: Configuration to validate

    Returns:
        List of validation error messages (empty if valid)
    """
    errors: list[str] = []

    # Check target domains
    if not config.target_domains:
        errors.append("At least one target domain must be specified")

    # Validate domain format
    for domain in config.target_domains:
        if not _is_valid_domain(domain):
            errors.append(f"Invalid domain format: {domain}")

    # Check active scanning requirements
    if config.scan_mode in (ASMScanMode.ACTIVE, ASMScanMode.FULL):
        if config.ownership_verification_required:
            # Check that all target domains have verification
            for domain in config.target_domains:
                if not config.is_domain_verified(domain):
                    errors.append(
                        f"Active scanning requires ownership verification for: {domain}"
                    )

    # Validate port scanning configuration
    if config.enable_port_scanning:
        if not config.port_scan_ports:
            errors.append("Port scanning is enabled but no ports are specified")

        for port in config.port_scan_ports:
            if not 1 <= port <= 65535:
                errors.append(f"Invalid port number: {port}")

    # Validate rate limiting
    if config.max_concurrent_requests < 1:
        errors.append("max_concurrent_requests must be at least 1")

    if config.max_concurrent_requests > 100:
        errors.append("max_concurrent_requests should not exceed 100")

    # Validate timeouts
    if config.request_timeout_seconds < 1:
        errors.append("request_timeout_seconds must be at least 1")

    if config.dns_timeout_seconds < 1:
        errors.append("dns_timeout_seconds must be at least 1")

    # Validate excluded domains
    for domain in config.excluded_domains:
        # Allow wildcards like *.example.com
        if domain.startswith("*."):
            domain = domain[2:]
        if domain and not _is_valid_domain(domain):
            errors.append(f"Invalid excluded domain format: {domain}")

    return errors


def _is_valid_domain(domain: str) -> bool:
    """Check if a domain name is valid."""
    import re

    # Basic domain validation
    # Allows: example.com, sub.example.com, etc.
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    return bool(re.match(pattern, domain)) and len(domain) <= 253


def load_asm_config(
    config_file: str | None = None,
    target_domains: list[str] | None = None,
) -> ASMConfiguration:
    """
    Load ASM configuration from environment and/or file.

    Priority (highest to lowest):
    1. Explicit parameters
    2. Environment variables
    3. Config file
    4. Defaults

    Args:
        config_file: Path to configuration file
        target_domains: Override target domains

    Returns:
        ASMConfiguration instance
    """
    # Start with defaults
    config = ASMConfiguration()

    # Load from file if specified
    config_path = config_file or os.getenv("STANCE_ASM_CONFIG")
    if config_path and os.path.exists(os.path.expanduser(config_path)):
        config = ASMConfiguration.from_file(config_path)

    # Override from environment variables
    env_domains = os.getenv("STANCE_ASM_DOMAINS")
    if env_domains:
        config.target_domains = [d.strip() for d in env_domains.split(",")]

    env_mode = os.getenv("STANCE_ASM_MODE")
    if env_mode:
        config.scan_mode = ASMScanMode(env_mode.lower())

    env_port_scan = os.getenv("STANCE_ASM_PORT_SCAN")
    if env_port_scan:
        config.enable_port_scanning = env_port_scan.lower() in ("true", "1", "yes")

    env_subdomain_brute = os.getenv("STANCE_ASM_SUBDOMAIN_BRUTEFORCE")
    if env_subdomain_brute:
        config.enable_subdomain_bruteforce = env_subdomain_brute.lower() in ("true", "1", "yes")

    env_max_requests = os.getenv("STANCE_ASM_MAX_REQUESTS")
    if env_max_requests:
        config.max_concurrent_requests = int(env_max_requests)

    env_data_dir = os.getenv("STANCE_ASM_DATA_DIR")
    if env_data_dir:
        config.data_dir = env_data_dir

    # Override with explicit parameters
    if target_domains:
        config.target_domains = target_domains

    return config


def create_default_asm_config(target_domains: list[str]) -> ASMConfiguration:
    """
    Create a default ASM configuration for the specified domains.

    Uses passive-only settings suitable for initial discovery.

    Args:
        target_domains: Domains to scan

    Returns:
        ASMConfiguration with sensible defaults
    """
    return ASMConfiguration(
        target_domains=target_domains,
        scan_mode=ASMScanMode.PASSIVE,
        enable_cert_transparency=True,
        enable_dns_enumeration=True,
        enable_cloud_ip_detection=True,
        enable_port_scanning=False,
        enable_technology_fingerprinting=True,
        enable_subdomain_bruteforce=False,
        max_concurrent_requests=10,
        request_timeout_seconds=10,
        ownership_verification_required=True,
    )
