"""
Port Scanner collector for ASM.

This module provides opt-in port scanning for verified domains only.
Active scanning requires explicit ownership verification before any
probing is performed.

IMPORTANT: This collector will NEVER scan without verified ownership.
This is a safety and legal requirement.

Features:
- TCP connect scanning only (no SYN/stealth)
- Banner grabbing with timeout
- TLS detection
- Rate limiting
- Comprehensive audit logging
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from stance.asm.config import ASMConfiguration, ASMOwnershipVerification
from stance.asm.models import ExternalAsset, ExternalAssetCollection

logger = logging.getLogger(__name__)


# Service identification patterns
SERVICE_BANNERS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Ports that typically use TLS directly (not STARTTLS)
TLS_PORTS = {443, 993, 995, 8443, 636}

# Rate limiting: max ports per minute per target
MAX_PORTS_PER_MINUTE = 100


class OwnershipVerificationRequired(Exception):
    """Raised when ownership verification is required but not present."""

    pass


class OwnershipVerificationFailed(Exception):
    """Raised when ownership verification check fails."""

    pass


@dataclass
class OpenPort:
    """Represents a detected open port."""

    port: int
    protocol: str = "tcp"
    state: str = "open"  # open, filtered, closed
    service: str | None = None
    banner: str | None = None
    tls_enabled: bool = False
    tls_version: str | None = None
    certificate_subject: str | None = None
    response_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "tls_enabled": self.tls_enabled,
            "tls_version": self.tls_version,
            "certificate_subject": self.certificate_subject,
            "response_time_ms": self.response_time_ms,
        }


@dataclass
class PortScanResult:
    """Result of a port scan for a single target."""

    target: str
    open_ports: list[OpenPort] = field(default_factory=list)
    filtered_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)
    scan_started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_completed: datetime | None = None
    total_ports_scanned: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "filtered_ports": self.filtered_ports,
            "closed_ports": self.closed_ports,
            "scan_started": self.scan_started.isoformat(),
            "scan_completed": self.scan_completed.isoformat() if self.scan_completed else None,
            "total_ports_scanned": self.total_ports_scanned,
            "errors": self.errors,
        }


@dataclass
class PortScanAuditEntry:
    """Audit log entry for port scanning."""

    timestamp: datetime
    domain: str
    ports_scanned: list[int]
    verification_token: str
    verification_method: str
    scan_initiated_by: str = "stance-asm"
    source_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "ports_scanned": self.ports_scanned,
            "verification_token": self.verification_token,
            "verification_method": self.verification_method,
            "scan_initiated_by": self.scan_initiated_by,
            "source_ip": self.source_ip,
        }


class PortScanner:
    """
    Port scanner for verified domains only.

    This collector performs TCP connect scans against targets that have
    been verified as owned by the user. It will NEVER scan without
    valid ownership verification.

    Attributes:
        config: ASM configuration
    """

    collector_name = "port_scanner"

    def __init__(self, config: ASMConfiguration) -> None:
        """
        Initialize the Port Scanner.

        Args:
            config: ASM configuration with ownership verifications
        """
        self._config = config
        self._audit_log: list[PortScanAuditEntry] = []
        self._scan_count_per_target: dict[str, int] = {}
        self._last_scan_time: dict[str, float] = {}

    @property
    def config(self) -> ASMConfiguration:
        """Get the ASM configuration."""
        return self._config

    @property
    def audit_log(self) -> list[PortScanAuditEntry]:
        """Get the audit log of all scans."""
        return self._audit_log

    def verify_ownership(self, domain: str) -> bool:
        """
        Verify ownership of a domain before scanning.

        Checks DNS TXT record or HTTP file based on verification method.

        Args:
            domain: Domain to verify

        Returns:
            True if ownership is verified
        """
        verification = self._config.get_verification_for_domain(domain)
        if verification is None:
            logger.warning(f"No ownership verification configured for {domain}")
            return False

        if verification.is_valid:
            logger.debug(f"Ownership already verified for {domain}")
            return True

        # Attempt verification based on method
        if verification.verification_method == "dns_txt":
            return self._verify_via_dns(domain, verification)
        elif verification.verification_method == "http_file":
            return self._verify_via_http(domain, verification)
        else:
            logger.error(f"Unknown verification method: {verification.verification_method}")
            return False

    def _verify_via_dns(
        self,
        domain: str,
        verification: ASMOwnershipVerification,
    ) -> bool:
        """
        Verify ownership via DNS TXT record.

        Args:
            domain: Domain being verified
            verification: Verification object with token

        Returns:
            True if verification succeeds
        """
        try:
            import socket

            dns_name = verification.dns_record_name
            expected_value = verification.dns_record_value

            logger.info(f"Checking DNS TXT record: {dns_name}")

            # Use socket to query TXT records
            # In production, would use dnspython for proper TXT record queries
            # For now, use a simple approach
            try:
                # Try to resolve the record
                socket.setdefaulttimeout(self._config.dns_timeout_seconds)
                # Note: socket.gethostbyname doesn't return TXT records
                # This is a simplified check - production would use dnspython
                socket.gethostbyname(dns_name)
                # If we get here, the record exists but we can't verify content
                # without dnspython
                logger.warning(
                    f"DNS record exists for {dns_name}, but TXT content verification "
                    f"requires dnspython library"
                )
                return False
            except socket.gaierror:
                # Record doesn't exist
                logger.info(
                    f"DNS TXT record not found. Please add:\n"
                    f"  Name: {dns_name}\n"
                    f"  Type: TXT\n"
                    f"  Value: {expected_value}"
                )
                return False

        except Exception as e:
            logger.error(f"DNS verification failed for {domain}: {e}")
            return False

    def _verify_via_http(
        self,
        domain: str,
        verification: ASMOwnershipVerification,
    ) -> bool:
        """
        Verify ownership via HTTP file.

        Args:
            domain: Domain being verified
            verification: Verification object with token

        Returns:
            True if verification succeeds
        """
        try:
            from urllib.request import Request, urlopen
            from urllib.error import HTTPError, URLError

            url = verification.http_file_url
            expected_content = verification.http_file_content

            logger.info(f"Checking HTTP verification file: {url}")

            request = Request(
                url,
                headers={"User-Agent": self._config.user_agent},
            )

            try:
                with urlopen(
                    request, timeout=self._config.http_timeout_seconds
                ) as response:
                    content = response.read().decode("utf-8").strip()

                    if content == expected_content:
                        logger.info(f"HTTP verification successful for {domain}")
                        verification.verify()
                        return True
                    else:
                        logger.warning(
                            f"HTTP verification content mismatch for {domain}. "
                            f"Expected: {expected_content}, Got: {content}"
                        )
                        return False

            except HTTPError as e:
                if e.code == 404:
                    logger.info(
                        f"Verification file not found. Please create:\n"
                        f"  URL: {url}\n"
                        f"  Content: {expected_content}"
                    )
                else:
                    logger.warning(f"HTTP error during verification: {e}")
                return False

            except URLError as e:
                logger.warning(f"URL error during verification: {e}")
                return False

        except Exception as e:
            logger.error(f"HTTP verification failed for {domain}: {e}")
            return False

    def scan(
        self,
        target: str,
        ports: list[int] | None = None,
    ) -> PortScanResult:
        """
        Scan a target for open ports.

        REQUIRES valid ownership verification before scanning.

        Args:
            target: Domain name to scan (NOT IP address)
            ports: Ports to scan (default: use config.port_scan_ports)

        Returns:
            PortScanResult with open/closed/filtered ports

        Raises:
            OwnershipVerificationRequired: If no verification exists
            OwnershipVerificationFailed: If verification is invalid/expired
        """
        # SAFETY CHECK: Never scan without verification
        if self._config.ownership_verification_required:
            if not self._config.can_active_scan(target):
                raise OwnershipVerificationRequired(
                    f"Ownership verification required for active scanning of {target}. "
                    f"Use 'stance asm verify --domain {target}' to configure verification."
                )

        # Get verification details for audit
        verification = self._config.get_verification_for_domain(target)
        if verification is None:
            raise OwnershipVerificationRequired(
                f"No ownership verification configured for {target}"
            )

        if not verification.is_valid:
            raise OwnershipVerificationFailed(
                f"Ownership verification for {target} is expired or invalid. "
                f"Please re-verify ownership."
            )

        # Use configured ports if not specified
        if ports is None:
            ports = self._config.port_scan_ports

        # Filter excluded ports
        ports = [p for p in ports if not self._config.is_port_excluded(p)]

        if not ports:
            logger.warning(f"No ports to scan for {target} after exclusions")
            return PortScanResult(target=target)

        # Create audit entry
        audit_entry = PortScanAuditEntry(
            timestamp=datetime.now(timezone.utc),
            domain=target,
            ports_scanned=ports,
            verification_token=verification.verification_token,
            verification_method=verification.verification_method,
        )
        self._audit_log.append(audit_entry)

        logger.info(
            f"Starting port scan of {target} ({len(ports)} ports) - "
            f"Ownership verified via {verification.verification_method}"
        )

        result = PortScanResult(target=target)

        # Resolve target to IP
        try:
            socket.setdefaulttimeout(self._config.dns_timeout_seconds)
            ip_address = socket.gethostbyname(target)
        except socket.gaierror as e:
            result.errors.append(f"Failed to resolve {target}: {e}")
            logger.error(f"DNS resolution failed for {target}: {e}")
            return result

        # Rate limiting
        ports_scanned = 0
        scan_start = time.time()

        for port in ports:
            # Check rate limiting
            if ports_scanned >= MAX_PORTS_PER_MINUTE:
                elapsed = time.time() - scan_start
                if elapsed < 60:
                    sleep_time = 60 - elapsed
                    logger.debug(f"Rate limiting: sleeping {sleep_time:.1f}s")
                    time.sleep(sleep_time)
                    scan_start = time.time()
                    ports_scanned = 0

            try:
                port_result = self._scan_port(ip_address, port, target)
                if port_result.state == "open":
                    result.open_ports.append(port_result)
                elif port_result.state == "filtered":
                    result.filtered_ports.append(port)
                else:
                    result.closed_ports.append(port)

                ports_scanned += 1
                result.total_ports_scanned += 1

            except Exception as e:
                result.errors.append(f"Error scanning port {port}: {e}")
                logger.debug(f"Error scanning {target}:{port}: {e}")

        result.scan_completed = datetime.now(timezone.utc)

        logger.info(
            f"Port scan complete for {target}: "
            f"{len(result.open_ports)} open, "
            f"{len(result.filtered_ports)} filtered, "
            f"{len(result.closed_ports)} closed"
        )

        return result

    def _scan_port(
        self,
        ip_address: str,
        port: int,
        domain: str,
    ) -> OpenPort:
        """
        Scan a single port.

        Args:
            ip_address: IP address to connect to
            port: Port number to scan
            domain: Domain name for TLS SNI

        Returns:
            OpenPort with scan results
        """
        result = OpenPort(port=port)
        start_time = time.time()

        # TCP connect scan
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)  # 5 second timeout for connection

        try:
            sock.connect((ip_address, port))
            result.state = "open"
            result.response_time_ms = (time.time() - start_time) * 1000

            # Try to identify service
            result.service = SERVICE_BANNERS.get(port)

            # Try banner grabbing
            result.banner = self._grab_banner(sock, port)

            # Check for TLS
            if port in TLS_PORTS:
                tls_result = self._check_tls(ip_address, port, domain)
                if tls_result:
                    result.tls_enabled = True
                    result.tls_version = tls_result.get("version")
                    result.certificate_subject = tls_result.get("subject")

        except socket.timeout:
            result.state = "filtered"
        except ConnectionRefusedError:
            result.state = "closed"
        except OSError as e:
            # Various network errors
            if e.errno == 113:  # No route to host
                result.state = "filtered"
            elif e.errno == 111:  # Connection refused
                result.state = "closed"
            else:
                result.state = "filtered"
        finally:
            sock.close()

        return result

    def _grab_banner(self, sock: socket.socket, port: int) -> str | None:
        """
        Attempt to grab service banner.

        Args:
            sock: Connected socket
            port: Port number

        Returns:
            Banner string or None
        """
        try:
            # Set short timeout for banner grab
            sock.settimeout(2)

            # Some services send banner immediately, others need a prompt
            if port in (21, 22, 25, 110, 143):
                # These typically send banner on connect
                data = sock.recv(1024)
            elif port in (80, 8080):
                # HTTP needs a request
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(1024)
            else:
                # Try receiving first
                data = sock.recv(1024)

            if data:
                # Decode and clean up
                try:
                    banner = data.decode("utf-8", errors="replace").strip()
                    # Limit banner length
                    if len(banner) > 256:
                        banner = banner[:256] + "..."
                    return banner
                except Exception:
                    return None

        except (socket.timeout, Exception):
            pass

        return None

    def _check_tls(
        self,
        ip_address: str,
        port: int,
        domain: str,
    ) -> dict[str, str] | None:
        """
        Check if port supports TLS and get certificate info.

        Args:
            ip_address: IP address to connect to
            port: Port number
            domain: Domain name for SNI

        Returns:
            Dictionary with TLS info or None
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (ip_address, port), timeout=5
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=domain
                ) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    version = ssock.version()

                    # Get subject from certificate
                    try:
                        import ssl as ssl_module

                        cert_dict = ssl_module._ssl._test_decode_cert(cert)  # type: ignore
                        subject = dict(x[0] for x in cert_dict.get("subject", []))
                        subject_cn = subject.get("commonName", "")
                    except Exception:
                        subject_cn = ""

                    return {
                        "version": version,
                        "subject": subject_cn,
                    }

        except (ssl.SSLError, socket.timeout, OSError):
            pass

        return None

    def scan_assets(
        self,
        assets: ExternalAssetCollection,
    ) -> ExternalAssetCollection:
        """
        Scan ports for a collection of external assets.

        Only scans assets with verified domain ownership.

        Args:
            assets: Collection of external assets

        Returns:
            New collection with port scan data added
        """
        enriched: list[ExternalAsset] = []
        scanned_domains: set[str] = set()

        for asset in assets:
            domain = asset.domain

            # Skip if already scanned this domain
            if domain in scanned_domains:
                enriched.append(asset)
                continue

            # Check if we can scan this domain
            if not self._config.can_active_scan(domain):
                logger.debug(
                    f"Skipping port scan for {domain}: ownership not verified"
                )
                enriched.append(asset)
                continue

            try:
                scan_result = self.scan(domain)
                scanned_domains.add(domain)

                # Update asset with port scan data
                new_raw_data = dict(asset.raw_data)
                new_raw_data["port_scan"] = scan_result.to_dict()

                # Create assets for each open port
                for open_port in scan_result.open_ports:
                    port_asset = ExternalAsset(
                        id=ExternalAsset.generate_id(
                            domain, asset.ip_address, open_port.port
                        ),
                        domain=domain,
                        ip_address=asset.ip_address,
                        port=open_port.port,
                        protocol="https" if open_port.tls_enabled else "http"
                        if open_port.port in (80, 8080)
                        else open_port.protocol,
                        service=open_port.service,
                        technology_stack=asset.technology_stack,
                        cloud_provider=asset.cloud_provider,
                        cloud_region=asset.cloud_region,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        certificate_info=asset.certificate_info,
                        risk_score=asset.risk_score,
                        raw_data={
                            "source": "port_scanner",
                            "port_info": open_port.to_dict(),
                        },
                        source="port_scanner",
                        is_verified=True,  # We own this domain
                    )
                    enriched.append(port_asset)

            except OwnershipVerificationRequired as e:
                logger.warning(str(e))
                enriched.append(asset)
            except OwnershipVerificationFailed as e:
                logger.warning(str(e))
                enriched.append(asset)
            except Exception as e:
                logger.error(f"Port scan failed for {domain}: {e}")
                enriched.append(asset)

        return ExternalAssetCollection(enriched)

    def get_audit_summary(self) -> dict[str, Any]:
        """
        Get summary of all port scans performed.

        Returns:
            Dictionary with audit summary
        """
        return {
            "total_scans": len(self._audit_log),
            "domains_scanned": list(
                set(entry.domain for entry in self._audit_log)
            ),
            "entries": [entry.to_dict() for entry in self._audit_log],
        }
