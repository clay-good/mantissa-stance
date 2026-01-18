"""
ASM data models for Mantissa Stance.

This module defines data models for Attack Surface Management:
- ExternalAsset: Externally-discovered assets (domains, IPs, services)
- CertificateInfo: SSL/TLS certificate metadata
- ExternalAssetCollection: Container for managing external assets
- ASMScanResult: Scan execution metadata and results
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator


class ASMScanMode(Enum):
    """
    Scanning mode for ASM operations.

    Passive mode uses only public data sources (cert transparency, DNS).
    Active mode includes port scanning and requires ownership verification.
    Full mode combines all techniques.
    """

    PASSIVE = "passive"  # Cert transparency, DNS, public data only
    ACTIVE = "active"  # Includes port scanning (requires ownership verification)
    FULL = "full"  # All techniques enabled


class ASMScanStatus(Enum):
    """Status of an ASM scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class CertificateInfo:
    """
    SSL/TLS certificate metadata.

    Attributes:
        subject: Certificate subject (CN)
        issuer: Certificate issuer
        not_before: Certificate validity start date
        not_after: Certificate validity end date
        san_domains: Subject Alternative Names (additional domains)
        fingerprint_sha256: SHA-256 fingerprint of the certificate
        is_self_signed: Whether the certificate is self-signed
        key_algorithm: Key algorithm (RSA, ECDSA, etc.)
        key_size: Key size in bits
        serial_number: Certificate serial number
    """

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san_domains: tuple[str, ...] = field(default_factory=tuple)
    fingerprint_sha256: str = ""
    is_self_signed: bool = False
    key_algorithm: str = "RSA"
    key_size: int = 2048
    serial_number: str = ""

    @property
    def is_expired(self) -> bool:
        """Check if the certificate is expired."""
        return datetime.now(timezone.utc) > self.not_after

    @property
    def is_expiring_soon(self) -> bool:
        """Check if the certificate expires within 30 days."""
        from datetime import timedelta

        threshold = datetime.now(timezone.utc) + timedelta(days=30)
        return self.not_after <= threshold

    @property
    def days_until_expiry(self) -> int:
        """Get days until certificate expiry (negative if expired)."""
        delta = self.not_after - datetime.now(timezone.utc)
        return delta.days

    @property
    def is_weak_key(self) -> bool:
        """Check if the key size is considered weak."""
        if self.key_algorithm.upper() == "RSA":
            return self.key_size < 2048
        if self.key_algorithm.upper() in ("ECDSA", "EC"):
            return self.key_size < 256
        return False

    @property
    def is_weak_algorithm(self) -> bool:
        """Check if certificate uses weak algorithms (SHA1, MD5)."""
        # This would need to be determined from the signature algorithm
        # which isn't captured here, but we can check key algorithm
        return False  # Placeholder - would need signature_algorithm field

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before.isoformat(),
            "not_after": self.not_after.isoformat(),
            "san_domains": list(self.san_domains),
            "fingerprint_sha256": self.fingerprint_sha256,
            "is_self_signed": self.is_self_signed,
            "key_algorithm": self.key_algorithm,
            "key_size": self.key_size,
            "serial_number": self.serial_number,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon,
            "days_until_expiry": self.days_until_expiry,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificateInfo:
        """Create from dictionary."""
        not_before = data.get("not_before")
        if isinstance(not_before, str):
            not_before = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
        elif not_before is None:
            not_before = datetime.now(timezone.utc)

        not_after = data.get("not_after")
        if isinstance(not_after, str):
            not_after = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        elif not_after is None:
            not_after = datetime.now(timezone.utc)

        san_domains = data.get("san_domains", [])
        if isinstance(san_domains, list):
            san_domains = tuple(san_domains)

        return cls(
            subject=data.get("subject", ""),
            issuer=data.get("issuer", ""),
            not_before=not_before,
            not_after=not_after,
            san_domains=san_domains,
            fingerprint_sha256=data.get("fingerprint_sha256", ""),
            is_self_signed=data.get("is_self_signed", False),
            key_algorithm=data.get("key_algorithm", "RSA"),
            key_size=data.get("key_size", 2048),
            serial_number=data.get("serial_number", ""),
        )


@dataclass(frozen=True)
class ExternalAsset:
    """
    Represents an externally-discovered asset.

    External assets are discovered through outside-in reconnaissance:
    certificate transparency logs, DNS enumeration, port scanning, etc.

    Attributes:
        id: Unique identifier (hash of domain+ip+port)
        domain: The discovered domain/subdomain
        ip_address: Resolved IP address (if known)
        port: Open port number (if scanned)
        protocol: Protocol (http, https, ssh, etc.)
        service: Detected service/banner
        technology_stack: List of detected technologies
        cloud_provider: Detected cloud provider (aws, gcp, azure)
        cloud_region: Inferred region from IP ranges
        first_seen: When first discovered
        last_seen: When last scanned/verified
        certificate_info: SSL/TLS certificate details (if applicable)
        risk_score: Calculated risk score (0.0-10.0)
        raw_data: Raw discovery data for reference
        source: How this asset was discovered (cert_transparency, dns, port_scan)
        is_verified: Whether ownership has been verified
    """

    id: str
    domain: str
    ip_address: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    technology_stack: tuple[str, ...] = field(default_factory=tuple)
    cloud_provider: str | None = None
    cloud_region: str | None = None
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    certificate_info: CertificateInfo | None = None
    risk_score: float = 0.0
    raw_data: dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"
    is_verified: bool = False

    @staticmethod
    def generate_id(domain: str, ip_address: str | None, port: int | None) -> str:
        """
        Generate a unique ID for an external asset.

        Args:
            domain: The domain name
            ip_address: IP address (optional)
            port: Port number (optional)

        Returns:
            SHA-256 hash of the combined values
        """
        components = [domain.lower()]
        if ip_address:
            components.append(ip_address)
        if port is not None:
            components.append(str(port))
        combined = ":".join(components)
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    @property
    def has_certificate(self) -> bool:
        """Check if this asset has certificate information."""
        return self.certificate_info is not None

    @property
    def is_https(self) -> bool:
        """Check if this asset uses HTTPS."""
        return self.protocol == "https" or self.port == 443

    @property
    def is_web_service(self) -> bool:
        """Check if this appears to be a web service."""
        web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        return self.port in web_ports if self.port else False

    @property
    def is_database_service(self) -> bool:
        """Check if this appears to be a database service."""
        db_ports = {3306, 5432, 27017, 6379, 9200, 1433, 1521, 5984}
        return self.port in db_ports if self.port else False

    @property
    def is_remote_access(self) -> bool:
        """Check if this is a remote access service (SSH, RDP)."""
        remote_ports = {22, 3389, 23, 5900}
        return self.port in remote_ports if self.port else False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "domain": self.domain,
            "ip_address": self.ip_address,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "technology_stack": list(self.technology_stack),
            "cloud_provider": self.cloud_provider,
            "cloud_region": self.cloud_region,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "certificate_info": self.certificate_info.to_dict()
            if self.certificate_info
            else None,
            "risk_score": self.risk_score,
            "raw_data": self.raw_data,
            "source": self.source,
            "is_verified": self.is_verified,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExternalAsset:
        """Create from dictionary."""
        first_seen = data.get("first_seen")
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        elif first_seen is None:
            first_seen = datetime.now(timezone.utc)

        last_seen = data.get("last_seen")
        if isinstance(last_seen, str):
            last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        elif last_seen is None:
            last_seen = datetime.now(timezone.utc)

        cert_data = data.get("certificate_info")
        certificate_info = CertificateInfo.from_dict(cert_data) if cert_data else None

        tech_stack = data.get("technology_stack", [])
        if isinstance(tech_stack, list):
            tech_stack = tuple(tech_stack)

        return cls(
            id=data.get("id", ""),
            domain=data.get("domain", ""),
            ip_address=data.get("ip_address"),
            port=data.get("port"),
            protocol=data.get("protocol"),
            service=data.get("service"),
            technology_stack=tech_stack,
            cloud_provider=data.get("cloud_provider"),
            cloud_region=data.get("cloud_region"),
            first_seen=first_seen,
            last_seen=last_seen,
            certificate_info=certificate_info,
            risk_score=data.get("risk_score", 0.0),
            raw_data=data.get("raw_data", {}),
            source=data.get("source", "unknown"),
            is_verified=data.get("is_verified", False),
        )


class ExternalAssetCollection:
    """
    A collection of ExternalAsset objects with filtering capabilities.

    Provides methods to filter assets by various criteria and
    convert the collection to different formats.
    """

    def __init__(self, assets: list[ExternalAsset] | None = None) -> None:
        """
        Initialize collection with optional list of assets.

        Args:
            assets: Initial list of assets (defaults to empty list)
        """
        self._assets: list[ExternalAsset] = assets if assets is not None else []

    @property
    def assets(self) -> list[ExternalAsset]:
        """Get the list of assets."""
        return self._assets

    def __len__(self) -> int:
        """Return number of assets in collection."""
        return len(self._assets)

    def __iter__(self) -> Iterator[ExternalAsset]:
        """Iterate over assets in collection."""
        return iter(self._assets)

    def __getitem__(self, index: int) -> ExternalAsset:
        """Get asset by index."""
        return self._assets[index]

    def add(self, asset: ExternalAsset) -> None:
        """
        Add an asset to the collection.

        Args:
            asset: Asset to add
        """
        self._assets.append(asset)

    def extend(self, assets: list[ExternalAsset]) -> None:
        """
        Add multiple assets to the collection.

        Args:
            assets: List of assets to add
        """
        self._assets.extend(assets)

    def filter_by_domain(self, pattern: str) -> ExternalAssetCollection:
        """
        Filter assets by domain pattern.

        Args:
            pattern: Domain pattern to match (supports * wildcard)

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        import fnmatch

        filtered = [
            a for a in self._assets if fnmatch.fnmatch(a.domain.lower(), pattern.lower())
        ]
        return ExternalAssetCollection(filtered)

    def filter_by_port(self, port: int) -> ExternalAssetCollection:
        """
        Filter assets by port number.

        Args:
            port: Port number to filter by

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.port == port]
        return ExternalAssetCollection(filtered)

    def filter_by_ports(self, ports: list[int]) -> ExternalAssetCollection:
        """
        Filter assets by multiple port numbers.

        Args:
            ports: List of port numbers to filter by

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        port_set = set(ports)
        filtered = [a for a in self._assets if a.port in port_set]
        return ExternalAssetCollection(filtered)

    def filter_by_cloud_provider(self, provider: str) -> ExternalAssetCollection:
        """
        Filter assets by cloud provider.

        Args:
            provider: Cloud provider to filter by (aws, gcp, azure)

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        filtered = [
            a for a in self._assets if a.cloud_provider and a.cloud_provider.lower() == provider.lower()
        ]
        return ExternalAssetCollection(filtered)

    def filter_by_risk_score(self, min_score: float) -> ExternalAssetCollection:
        """
        Filter assets by minimum risk score.

        Args:
            min_score: Minimum risk score (0.0-10.0)

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.risk_score >= min_score]
        return ExternalAssetCollection(filtered)

    def filter_by_source(self, source: str) -> ExternalAssetCollection:
        """
        Filter assets by discovery source.

        Args:
            source: Discovery source (cert_transparency, dns, port_scan)

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        filtered = [a for a in self._assets if a.source == source]
        return ExternalAssetCollection(filtered)

    def filter_with_certificates(self) -> ExternalAssetCollection:
        """
        Filter to only assets with certificate information.

        Returns:
            New ExternalAssetCollection containing only assets with certificates
        """
        filtered = [a for a in self._assets if a.has_certificate]
        return ExternalAssetCollection(filtered)

    def filter_expiring_certificates(self, days: int = 30) -> ExternalAssetCollection:
        """
        Filter to assets with certificates expiring within given days.

        Args:
            days: Number of days threshold (default 30)

        Returns:
            New ExternalAssetCollection containing only matching assets
        """
        from datetime import timedelta

        threshold = datetime.now(timezone.utc) + timedelta(days=days)
        filtered = [
            a
            for a in self._assets
            if a.certificate_info and a.certificate_info.not_after <= threshold
        ]
        return ExternalAssetCollection(filtered)

    def filter_expired_certificates(self) -> ExternalAssetCollection:
        """
        Filter to assets with expired certificates.

        Returns:
            New ExternalAssetCollection containing only assets with expired certs
        """
        filtered = [
            a for a in self._assets if a.certificate_info and a.certificate_info.is_expired
        ]
        return ExternalAssetCollection(filtered)

    def filter_web_services(self) -> ExternalAssetCollection:
        """
        Filter to web services (HTTP/HTTPS).

        Returns:
            New ExternalAssetCollection containing only web services
        """
        filtered = [a for a in self._assets if a.is_web_service]
        return ExternalAssetCollection(filtered)

    def filter_database_services(self) -> ExternalAssetCollection:
        """
        Filter to database services.

        Returns:
            New ExternalAssetCollection containing only database services
        """
        filtered = [a for a in self._assets if a.is_database_service]
        return ExternalAssetCollection(filtered)

    def filter_remote_access(self) -> ExternalAssetCollection:
        """
        Filter to remote access services (SSH, RDP, etc.).

        Returns:
            New ExternalAssetCollection containing only remote access services
        """
        filtered = [a for a in self._assets if a.is_remote_access]
        return ExternalAssetCollection(filtered)

    def get_by_id(self, asset_id: str) -> ExternalAsset | None:
        """
        Get an asset by its ID.

        Args:
            asset_id: Asset ID to find

        Returns:
            Asset if found, None otherwise
        """
        for asset in self._assets:
            if asset.id == asset_id:
                return asset
        return None

    def get_by_domain(self, domain: str) -> list[ExternalAsset]:
        """
        Get all assets for a specific domain.

        Args:
            domain: Domain to search for

        Returns:
            List of matching assets
        """
        return [a for a in self._assets if a.domain.lower() == domain.lower()]

    def get_unique_domains(self) -> set[str]:
        """
        Get set of unique domains in the collection.

        Returns:
            Set of unique domain names
        """
        return {a.domain.lower() for a in self._assets}

    def get_unique_ips(self) -> set[str]:
        """
        Get set of unique IP addresses in the collection.

        Returns:
            Set of unique IP addresses
        """
        return {a.ip_address for a in self._assets if a.ip_address}

    def count_by_cloud_provider(self) -> dict[str, int]:
        """
        Count assets grouped by cloud provider.

        Returns:
            Dictionary mapping provider to count
        """
        counts: dict[str, int] = {}
        for asset in self._assets:
            provider = asset.cloud_provider or "unknown"
            counts[provider] = counts.get(provider, 0) + 1
        return counts

    def count_by_port(self) -> dict[int, int]:
        """
        Count assets grouped by port.

        Returns:
            Dictionary mapping port to count
        """
        counts: dict[int, int] = {}
        for asset in self._assets:
            if asset.port is not None:
                counts[asset.port] = counts.get(asset.port, 0) + 1
        return counts

    def count_by_source(self) -> dict[str, int]:
        """
        Count assets grouped by discovery source.

        Returns:
            Dictionary mapping source to count
        """
        counts: dict[str, int] = {}
        for asset in self._assets:
            counts[asset.source] = counts.get(asset.source, 0) + 1
        return counts

    def merge(self, other: ExternalAssetCollection) -> ExternalAssetCollection:
        """
        Merge with another collection.

        Args:
            other: Another ExternalAssetCollection to merge

        Returns:
            New ExternalAssetCollection with assets from both collections
        """
        return ExternalAssetCollection(self._assets + other._assets)

    def deduplicate(self) -> ExternalAssetCollection:
        """
        Remove duplicate assets (by ID).

        Returns:
            New ExternalAssetCollection with duplicates removed
        """
        seen: set[str] = set()
        unique: list[ExternalAsset] = []
        for asset in self._assets:
            if asset.id not in seen:
                seen.add(asset.id)
                unique.append(asset)
        return ExternalAssetCollection(unique)

    def sort_by_risk(self, descending: bool = True) -> ExternalAssetCollection:
        """
        Sort assets by risk score.

        Args:
            descending: If True, highest risk first (default)

        Returns:
            New sorted ExternalAssetCollection
        """
        sorted_assets = sorted(
            self._assets, key=lambda a: a.risk_score, reverse=descending
        )
        return ExternalAssetCollection(sorted_assets)

    def sort_by_domain(self) -> ExternalAssetCollection:
        """
        Sort assets alphabetically by domain.

        Returns:
            New sorted ExternalAssetCollection
        """
        sorted_assets = sorted(self._assets, key=lambda a: a.domain.lower())
        return ExternalAssetCollection(sorted_assets)

    def sort_by_last_seen(self, descending: bool = True) -> ExternalAssetCollection:
        """
        Sort assets by last seen time.

        Args:
            descending: If True, most recent first (default)

        Returns:
            New sorted ExternalAssetCollection
        """
        sorted_assets = sorted(
            self._assets, key=lambda a: a.last_seen, reverse=descending
        )
        return ExternalAssetCollection(sorted_assets)

    def to_list(self) -> list[dict[str, Any]]:
        """
        Convert collection to list of dictionaries.

        Returns:
            List of asset dictionaries
        """
        return [asset.to_dict() for asset in self._assets]

    def to_json(self, indent: int = 2) -> str:
        """
        Convert collection to JSON string.

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_list(), indent=indent, default=str)

    @classmethod
    def from_list(cls, data: list[dict[str, Any]]) -> ExternalAssetCollection:
        """
        Create collection from list of dictionaries.

        Args:
            data: List of asset dictionaries

        Returns:
            New ExternalAssetCollection
        """
        assets = [ExternalAsset.from_dict(item) for item in data]
        return cls(assets)

    @classmethod
    def from_json(cls, json_str: str) -> ExternalAssetCollection:
        """
        Create collection from JSON string.

        Args:
            json_str: JSON string of asset list

        Returns:
            New ExternalAssetCollection
        """
        data = json.loads(json_str)
        return cls.from_list(data)


@dataclass
class ASMScanResult:
    """
    Result of an ASM scan operation.

    Tracks scan execution metadata and provides access to discovered assets.

    Attributes:
        scan_id: Unique identifier for this scan
        started_at: When the scan started
        completed_at: When the scan completed (None if still running)
        status: Current scan status
        target_domains: List of domains that were scanned
        scan_mode: Scanning mode used (passive, active, full)
        assets_discovered: Count of assets found
        assets: Collection of discovered external assets
        findings_count: Number of findings generated
        errors: List of errors encountered during scan
        collectors_run: List of collectors that were executed
        duration_seconds: Total scan duration in seconds
    """

    scan_id: str
    started_at: datetime
    target_domains: list[str]
    scan_mode: ASMScanMode = ASMScanMode.PASSIVE
    status: ASMScanStatus = ASMScanStatus.PENDING
    completed_at: datetime | None = None
    assets_discovered: int = 0
    assets: ExternalAssetCollection = field(default_factory=ExternalAssetCollection)
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    collectors_run: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def is_complete(self) -> bool:
        """Check if scan has completed."""
        return self.status in (ASMScanStatus.COMPLETED, ASMScanStatus.FAILED, ASMScanStatus.CANCELLED)

    @property
    def is_success(self) -> bool:
        """Check if scan completed successfully."""
        return self.status == ASMScanStatus.COMPLETED

    @property
    def has_errors(self) -> bool:
        """Check if scan encountered errors."""
        return len(self.errors) > 0

    def start(self) -> None:
        """Mark scan as started."""
        self.status = ASMScanStatus.RUNNING
        self.started_at = datetime.now(timezone.utc)

    def complete(self, assets: ExternalAssetCollection, findings_count: int = 0) -> None:
        """
        Mark scan as completed.

        Args:
            assets: Collection of discovered assets
            findings_count: Number of findings generated
        """
        self.status = ASMScanStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.assets = assets
        self.assets_discovered = len(assets)
        self.findings_count = findings_count
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def fail(self, error: str) -> None:
        """
        Mark scan as failed.

        Args:
            error: Error message describing the failure
        """
        self.status = ASMScanStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.errors.append(error)
        self.duration_seconds = (self.completed_at - self.started_at).total_seconds()

    def add_error(self, error: str) -> None:
        """
        Add an error to the scan results.

        Args:
            error: Error message
        """
        self.errors.append(error)

    def add_collector(self, collector_name: str) -> None:
        """
        Record that a collector was run.

        Args:
            collector_name: Name of the collector
        """
        if collector_name not in self.collectors_run:
            self.collectors_run.append(collector_name)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status.value,
            "target_domains": self.target_domains,
            "scan_mode": self.scan_mode.value,
            "assets_discovered": self.assets_discovered,
            "findings_count": self.findings_count,
            "errors": self.errors,
            "collectors_run": self.collectors_run,
            "duration_seconds": self.duration_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ASMScanResult:
        """Create from dictionary."""
        started_at = data.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        elif started_at is None:
            started_at = datetime.now(timezone.utc)

        completed_at = data.get("completed_at")
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))

        return cls(
            scan_id=data.get("scan_id", ""),
            started_at=started_at,
            completed_at=completed_at,
            status=ASMScanStatus(data.get("status", "pending")),
            target_domains=data.get("target_domains", []),
            scan_mode=ASMScanMode(data.get("scan_mode", "passive")),
            assets_discovered=data.get("assets_discovered", 0),
            findings_count=data.get("findings_count", 0),
            errors=data.get("errors", []),
            collectors_run=data.get("collectors_run", []),
            duration_seconds=data.get("duration_seconds", 0.0),
        )

    @staticmethod
    def generate_scan_id() -> str:
        """Generate a unique scan ID."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        import secrets
        suffix = secrets.token_hex(4)
        return f"asm-{timestamp}-{suffix}"
