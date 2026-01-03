"""
DNS inventory and subdomain monitoring for Exposure Management.

Discovers DNS records from cloud DNS services (Route53, Cloud DNS, Azure DNS)
and detects dangling DNS records that could lead to subdomain takeover.
"""

from __future__ import annotations

import logging
import re
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class DNSRecordType(Enum):
    """Types of DNS records."""

    A = "A"  # IPv4 address
    AAAA = "AAAA"  # IPv6 address
    CNAME = "CNAME"  # Canonical name (alias)
    MX = "MX"  # Mail exchange
    TXT = "TXT"  # Text record
    NS = "NS"  # Name server
    SOA = "SOA"  # Start of authority
    SRV = "SRV"  # Service record
    PTR = "PTR"  # Pointer record
    CAA = "CAA"  # Certificate authority authorization
    ALIAS = "ALIAS"  # Alias record (Route53 specific)


class DNSFindingType(Enum):
    """Types of DNS-related findings."""

    # Dangling DNS (subdomain takeover risk)
    DANGLING_CNAME = "dangling_cname"  # CNAME points to non-existent resource
    DANGLING_A_RECORD = "dangling_a_record"  # A record points to unallocated IP
    DANGLING_ALIAS = "dangling_alias"  # Alias to deleted resource

    # Exposure findings
    DNS_TO_PUBLIC_RESOURCE = "dns_to_public_resource"  # DNS exposes public cloud resource
    DNS_TO_SENSITIVE_RESOURCE = "dns_to_sensitive_resource"  # DNS to resource with sensitive data

    # Configuration issues
    UNMANAGED_SUBDOMAIN = "unmanaged_subdomain"  # Subdomain not in asset inventory
    WILDCARD_EXPOSURE = "wildcard_exposure"  # Wildcard DNS exposing resources
    NO_CAA_RECORD = "no_caa_record"  # Missing CAA record for certificate control
    INSECURE_DELEGATION = "insecure_delegation"  # NS delegation to untrusted zone

    # Takeover indicators
    AZURE_TAKEOVER_RISK = "azure_takeover_risk"  # Azure service with takeover indicators
    AWS_TAKEOVER_RISK = "aws_takeover_risk"  # AWS service with takeover indicators
    GCP_TAKEOVER_RISK = "gcp_takeover_risk"  # GCP service with takeover indicators


class DNSSeverity(Enum):
    """Severity levels for DNS findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison."""
        ranks = {
            DNSSeverity.CRITICAL: 5,
            DNSSeverity.HIGH: 4,
            DNSSeverity.MEDIUM: 3,
            DNSSeverity.LOW: 2,
            DNSSeverity.INFO: 1,
        }
        return ranks.get(self, 0)

    def __gt__(self, other: "DNSSeverity") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "DNSSeverity") -> bool:
        return self.rank >= other.rank

    def __lt__(self, other: "DNSSeverity") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "DNSSeverity") -> bool:
        return self.rank <= other.rank


# Known cloud service patterns for dangling DNS detection
CLOUD_SERVICE_PATTERNS = {
    # AWS services
    "aws": [
        r"\.s3\.amazonaws\.com$",
        r"\.s3-website[.-].*\.amazonaws\.com$",
        r"\.cloudfront\.net$",
        r"\.elasticbeanstalk\.com$",
        r"\.elb\.amazonaws\.com$",
        r"\.amazonaws\.com$",
    ],
    # Azure services
    "azure": [
        r"\.azurewebsites\.net$",
        r"\.cloudapp\.azure\.com$",
        r"\.azure-api\.net$",
        r"\.azureedge\.net$",
        r"\.blob\.core\.windows\.net$",
        r"\.trafficmanager\.net$",
        r"\.azurefd\.net$",
    ],
    # GCP services
    "gcp": [
        r"\.appspot\.com$",
        r"\.cloudfunctions\.net$",
        r"\.run\.app$",
        r"\.storage\.googleapis\.com$",
        r"\.web\.app$",
        r"\.firebaseapp\.com$",
    ],
    # Third-party services commonly vulnerable
    "third_party": [
        r"\.github\.io$",
        r"\.herokuapp\.com$",
        r"\.pantheonsite\.io$",
        r"\.shopify\.com$",
        r"\.zendesk\.com$",
        r"\.ghost\.io$",
        r"\.surge\.sh$",
        r"\.bitbucket\.io$",
    ],
}


@dataclass
class DNSConfig:
    """
    Configuration for DNS inventory and monitoring.

    Attributes:
        check_dangling: Whether to check for dangling DNS records
        check_caa: Whether to check for CAA records
        check_wildcards: Whether to check wildcard records
        resolve_records: Whether to resolve DNS records
        include_record_types: Record types to include
        exclude_zones: Zones to exclude from scanning
        cloud_providers: Cloud providers to check
        known_assets: Known cloud asset endpoints for correlation
    """

    check_dangling: bool = True
    check_caa: bool = True
    check_wildcards: bool = True
    resolve_records: bool = True
    include_record_types: list[str] = field(
        default_factory=lambda: ["A", "AAAA", "CNAME", "ALIAS"]
    )
    exclude_zones: list[str] = field(default_factory=list)
    cloud_providers: list[str] = field(default_factory=lambda: ["aws", "gcp", "azure"])
    known_assets: list[str] = field(default_factory=list)


@dataclass
class DNSZone:
    """
    Represents a DNS zone (hosted zone).

    Attributes:
        zone_id: Unique identifier for the zone
        name: Domain name of the zone
        cloud_provider: Cloud provider hosting the zone
        account_id: Account/project ID
        is_private: Whether this is a private zone
        record_count: Number of records in the zone
        nameservers: Nameservers for the zone
        metadata: Additional metadata
    """

    zone_id: str
    name: str
    cloud_provider: str
    account_id: str
    is_private: bool = False
    record_count: int = 0
    nameservers: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "zone_id": self.zone_id,
            "name": self.name,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "is_private": self.is_private,
            "record_count": self.record_count,
            "nameservers": self.nameservers,
            "metadata": self.metadata,
        }


@dataclass
class DNSRecord:
    """
    Represents a DNS record.

    Attributes:
        record_id: Unique identifier
        zone_id: Parent zone ID
        zone_name: Parent zone name
        name: Full record name (FQDN)
        record_type: Type of DNS record
        values: Record values (IP addresses, CNAMEs, etc.)
        ttl: Time to live in seconds
        cloud_provider: Cloud provider
        account_id: Account/project ID
        is_alias: Whether this is an alias record
        alias_target: Alias target if applicable
        health_check_id: Associated health check if any
        detected_at: When record was discovered
        metadata: Additional metadata
    """

    record_id: str
    zone_id: str
    zone_name: str
    name: str
    record_type: DNSRecordType
    values: list[str]
    ttl: int = 300
    cloud_provider: str = ""
    account_id: str = ""
    is_alias: bool = False
    alias_target: str | None = None
    health_check_id: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_wildcard(self) -> bool:
        """Check if this is a wildcard record."""
        return self.name.startswith("*.")

    @property
    def subdomain(self) -> str:
        """Get subdomain portion of the name."""
        if self.name.endswith("." + self.zone_name):
            return self.name[: -(len(self.zone_name) + 1)]
        return self.name

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "record_id": self.record_id,
            "zone_id": self.zone_id,
            "zone_name": self.zone_name,
            "name": self.name,
            "record_type": self.record_type.value,
            "values": self.values,
            "ttl": self.ttl,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "is_alias": self.is_alias,
            "alias_target": self.alias_target,
            "health_check_id": self.health_check_id,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class DNSFinding:
    """
    A finding about a DNS issue.

    Attributes:
        finding_id: Unique identifier
        finding_type: Type of finding
        severity: Severity level
        title: Short title
        description: Detailed description
        record_name: Affected DNS record name
        record_type: Type of DNS record
        record_values: Record values
        zone_name: Zone containing the record
        cloud_provider: Cloud provider
        target_status: Status of the target (resolved, not_found, etc.)
        takeover_risk: Whether subdomain takeover is possible
        recommended_action: Suggested remediation
        detected_at: When finding was generated
        metadata: Additional context
    """

    finding_id: str
    finding_type: DNSFindingType
    severity: DNSSeverity
    title: str
    description: str
    record_name: str
    record_type: str
    record_values: list[str]
    zone_name: str
    cloud_provider: str
    target_status: str = "unknown"
    takeover_risk: bool = False
    recommended_action: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "record_name": self.record_name,
            "record_type": self.record_type,
            "record_values": self.record_values,
            "zone_name": self.zone_name,
            "cloud_provider": self.cloud_provider,
            "target_status": self.target_status,
            "takeover_risk": self.takeover_risk,
            "recommended_action": self.recommended_action,
            "detected_at": self.detected_at.isoformat(),
            "metadata": self.metadata,
        }


@dataclass
class DNSSummary:
    """
    Summary statistics for DNS inventory.

    Attributes:
        total_zones: Total number of DNS zones
        total_records: Total number of DNS records
        records_by_type: Count by record type
        records_by_zone: Count by zone
        public_zones: Number of public zones
        private_zones: Number of private zones
        dangling_records: Number of dangling records
        wildcard_records: Number of wildcard records
        findings_by_severity: Count of findings by severity
        takeover_risks: Number of subdomain takeover risks
    """

    total_zones: int = 0
    total_records: int = 0
    records_by_type: dict[str, int] = field(default_factory=dict)
    records_by_zone: dict[str, int] = field(default_factory=dict)
    public_zones: int = 0
    private_zones: int = 0
    dangling_records: int = 0
    wildcard_records: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    takeover_risks: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_zones": self.total_zones,
            "total_records": self.total_records,
            "records_by_type": self.records_by_type,
            "records_by_zone": self.records_by_zone,
            "public_zones": self.public_zones,
            "private_zones": self.private_zones,
            "dangling_records": self.dangling_records,
            "wildcard_records": self.wildcard_records,
            "findings_by_severity": self.findings_by_severity,
            "takeover_risks": self.takeover_risks,
        }


@dataclass
class DNSInventoryResult:
    """
    Result of DNS inventory scan.

    Attributes:
        result_id: Unique identifier
        config: Configuration used
        started_at: Scan start time
        completed_at: Scan completion time
        zones: List of DNS zones discovered
        records: List of DNS records discovered
        findings: List of DNS findings
        summary: Summary statistics
        errors: Errors encountered
    """

    result_id: str
    config: DNSConfig
    started_at: datetime
    completed_at: datetime | None = None
    zones: list[DNSZone] = field(default_factory=list)
    records: list[DNSRecord] = field(default_factory=list)
    findings: list[DNSFinding] = field(default_factory=list)
    summary: DNSSummary = field(default_factory=DNSSummary)
    errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Check if inventory has any findings."""
        return len(self.findings) > 0

    @property
    def critical_findings(self) -> list[DNSFinding]:
        """Get critical severity findings."""
        return [f for f in self.findings if f.severity == DNSSeverity.CRITICAL]

    @property
    def high_findings(self) -> list[DNSFinding]:
        """Get high severity findings."""
        return [f for f in self.findings if f.severity == DNSSeverity.HIGH]

    @property
    def dangling_records(self) -> list[DNSFinding]:
        """Get dangling DNS findings."""
        dangling_types = {
            DNSFindingType.DANGLING_CNAME,
            DNSFindingType.DANGLING_A_RECORD,
            DNSFindingType.DANGLING_ALIAS,
        }
        return [f for f in self.findings if f.finding_type in dangling_types]

    @property
    def takeover_risks(self) -> list[DNSFinding]:
        """Get findings with subdomain takeover risk."""
        return [f for f in self.findings if f.takeover_risk]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "result_id": self.result_id,
            "config": {
                "check_dangling": self.config.check_dangling,
                "check_caa": self.config.check_caa,
                "check_wildcards": self.config.check_wildcards,
            },
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "total_zones": len(self.zones),
            "zones": [z.to_dict() for z in self.zones],
            "total_records": len(self.records),
            "records": [r.to_dict() for r in self.records],
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary.to_dict(),
            "errors": self.errors,
        }


class BaseDNSCollector(ABC):
    """
    Abstract base class for DNS collectors.

    Subclasses implement cloud-specific logic for discovering DNS zones and records.
    """

    collector_name = "base"

    def __init__(self, config: DNSConfig | None = None):
        """
        Initialize the DNS collector.

        Args:
            config: Optional configuration for collection
        """
        self._config = config or DNSConfig()

    @property
    def config(self) -> DNSConfig:
        """Get the collection configuration."""
        return self._config

    @abstractmethod
    def collect_zones(self) -> Iterator[DNSZone]:
        """
        Collect DNS zones from the cloud provider.

        Yields:
            DNS zones discovered
        """
        pass

    @abstractmethod
    def collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]:
        """
        Collect DNS records from a zone.

        Args:
            zone: DNS zone to collect records from

        Yields:
            DNS records discovered
        """
        pass


class DNSInventory:
    """
    Manages DNS inventory across cloud providers.

    Aggregates DNS zones and records from multiple collectors and
    analyzes them for dangling records and other security issues.
    """

    def __init__(
        self,
        zones: list[DNSZone] | None = None,
        records: list[DNSRecord] | None = None,
        config: DNSConfig | None = None,
    ):
        """
        Initialize the DNS inventory.

        Args:
            zones: List of DNS zones
            records: List of DNS records
            config: Optional configuration
        """
        self._zones = zones or []
        self._records = records or []
        self._config = config or DNSConfig()
        self._known_assets = set(self._config.known_assets)

    @property
    def zones(self) -> list[DNSZone]:
        """Get the list of DNS zones."""
        return self._zones

    @property
    def records(self) -> list[DNSRecord]:
        """Get the list of DNS records."""
        return self._records

    @property
    def config(self) -> DNSConfig:
        """Get the configuration."""
        return self._config

    def add_zones(self, zones: list[DNSZone]) -> None:
        """Add zones to inventory."""
        self._zones.extend(zones)

    def add_records(self, records: list[DNSRecord]) -> None:
        """Add records to inventory."""
        self._records.extend(records)

    def add_known_assets(self, assets: list[str]) -> None:
        """Add known cloud asset endpoints for correlation."""
        self._known_assets.update(assets)

    def analyze(self) -> DNSInventoryResult:
        """
        Analyze DNS inventory and generate findings.

        Returns:
            DNS inventory result with findings
        """
        started_at = datetime.now(timezone.utc)
        findings: list[DNSFinding] = []

        # Analyze each record
        for record in self._records:
            record_findings = self._analyze_record(record)
            findings.extend(record_findings)

        # Check for missing CAA records per zone
        if self._config.check_caa:
            for zone in self._zones:
                if not zone.is_private:
                    caa_finding = self._check_caa_record(zone)
                    if caa_finding:
                        findings.append(caa_finding)

        # Build summary
        summary = self._build_summary(self._zones, self._records, findings)
        completed_at = datetime.now(timezone.utc)

        return DNSInventoryResult(
            result_id=str(uuid.uuid4()),
            config=self._config,
            started_at=started_at,
            completed_at=completed_at,
            zones=self._zones,
            records=self._records,
            findings=findings,
            summary=summary,
        )

    def _analyze_record(self, record: DNSRecord) -> list[DNSFinding]:
        """Analyze a single DNS record for issues."""
        findings: list[DNSFinding] = []

        # Check for dangling DNS
        if self._config.check_dangling:
            dangling_finding = self._check_dangling(record)
            if dangling_finding:
                findings.append(dangling_finding)

        # Check for wildcard exposure
        if self._config.check_wildcards and record.is_wildcard:
            wildcard_finding = self._check_wildcard(record)
            if wildcard_finding:
                findings.append(wildcard_finding)

        return findings

    def _check_dangling(self, record: DNSRecord) -> DNSFinding | None:
        """Check if a DNS record is dangling (points to non-existent resource)."""
        if record.record_type not in (DNSRecordType.CNAME, DNSRecordType.A, DNSRecordType.AAAA):
            if not record.is_alias:
                return None

        # Check CNAME and alias records
        if record.record_type == DNSRecordType.CNAME or record.is_alias:
            target = record.alias_target or (record.values[0] if record.values else "")
            if target:
                cloud_provider, is_cloud_service = self._identify_cloud_service(target)

                if is_cloud_service:
                    # Check if target is in known assets
                    if target not in self._known_assets:
                        takeover_risk = self._assess_takeover_risk(target, cloud_provider)

                        return DNSFinding(
                            finding_id=str(uuid.uuid4()),
                            finding_type=DNSFindingType.DANGLING_CNAME
                            if record.record_type == DNSRecordType.CNAME
                            else DNSFindingType.DANGLING_ALIAS,
                            severity=DNSSeverity.CRITICAL if takeover_risk else DNSSeverity.HIGH,
                            title=f"Potential dangling DNS: {record.name}",
                            description=(
                                f"DNS record {record.name} points to {target} which may not exist. "
                                f"This could indicate a subdomain takeover vulnerability."
                            ),
                            record_name=record.name,
                            record_type=record.record_type.value,
                            record_values=record.values,
                            zone_name=record.zone_name,
                            cloud_provider=record.cloud_provider,
                            target_status="not_verified",
                            takeover_risk=takeover_risk,
                            recommended_action=(
                                "Verify the target resource exists. If deleted, remove this DNS record "
                                "to prevent subdomain takeover attacks."
                            ),
                            metadata={
                                "target": target,
                                "target_cloud_provider": cloud_provider,
                            },
                        )

        return None

    def _check_wildcard(self, record: DNSRecord) -> DNSFinding | None:
        """Check for risky wildcard DNS records."""
        if not record.is_wildcard:
            return None

        # Wildcards pointing to cloud services can be risky
        for value in record.values:
            cloud_provider, is_cloud_service = self._identify_cloud_service(value)
            if is_cloud_service:
                return DNSFinding(
                    finding_id=str(uuid.uuid4()),
                    finding_type=DNSFindingType.WILDCARD_EXPOSURE,
                    severity=DNSSeverity.MEDIUM,
                    title=f"Wildcard DNS pointing to cloud service: {record.name}",
                    description=(
                        f"Wildcard record {record.name} points to {value}. "
                        f"Wildcard records can expose unintended subdomains."
                    ),
                    record_name=record.name,
                    record_type=record.record_type.value,
                    record_values=record.values,
                    zone_name=record.zone_name,
                    cloud_provider=record.cloud_provider,
                    recommended_action=(
                        "Review if wildcard DNS is necessary. Consider using explicit "
                        "subdomain records instead to limit exposure."
                    ),
                    metadata={
                        "target_cloud_provider": cloud_provider,
                    },
                )

        return None

    def _check_caa_record(self, zone: DNSZone) -> DNSFinding | None:
        """Check if zone has CAA records for certificate control."""
        zone_records = [r for r in self._records if r.zone_id == zone.zone_id]
        has_caa = any(r.record_type == DNSRecordType.CAA for r in zone_records)

        if not has_caa:
            return DNSFinding(
                finding_id=str(uuid.uuid4()),
                finding_type=DNSFindingType.NO_CAA_RECORD,
                severity=DNSSeverity.LOW,
                title=f"No CAA record for zone: {zone.name}",
                description=(
                    f"Zone {zone.name} does not have CAA (Certificate Authority Authorization) "
                    f"records. CAA records help prevent unauthorized certificate issuance."
                ),
                record_name=zone.name,
                record_type="CAA",
                record_values=[],
                zone_name=zone.name,
                cloud_provider=zone.cloud_provider,
                recommended_action=(
                    "Add CAA records to specify which Certificate Authorities are "
                    "authorized to issue certificates for this domain."
                ),
            )

        return None

    def _identify_cloud_service(self, target: str) -> tuple[str, bool]:
        """
        Identify if a target is a cloud service endpoint.

        Args:
            target: The CNAME or alias target

        Returns:
            Tuple of (cloud_provider, is_cloud_service)
        """
        target_lower = target.lower()

        for provider, patterns in CLOUD_SERVICE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, target_lower):
                    return provider, True

        return "", False

    def _assess_takeover_risk(self, target: str, cloud_provider: str) -> bool:
        """
        Assess if a dangling DNS record poses a subdomain takeover risk.

        Known vulnerable services:
        - Azure: azurewebsites.net, cloudapp.azure.com, trafficmanager.net
        - AWS: elasticbeanstalk.com, s3.amazonaws.com (when bucket doesn't exist)
        - GCP: appspot.com, cloudfunctions.net
        """
        target_lower = target.lower()

        # High-risk patterns known to be vulnerable to takeover
        high_risk_patterns = [
            r"\.azurewebsites\.net$",
            r"\.cloudapp\.azure\.com$",
            r"\.trafficmanager\.net$",
            r"\.elasticbeanstalk\.com$",
            r"\.s3\.amazonaws\.com$",
            r"\.appspot\.com$",
            r"\.herokuapp\.com$",
            r"\.github\.io$",
            r"\.pantheonsite\.io$",
        ]

        for pattern in high_risk_patterns:
            if re.search(pattern, target_lower):
                return True

        return False

    def _build_summary(
        self,
        zones: list[DNSZone],
        records: list[DNSRecord],
        findings: list[DNSFinding],
    ) -> DNSSummary:
        """Build summary statistics."""
        summary = DNSSummary(
            total_zones=len(zones),
            total_records=len(records),
        )

        # Zone counts
        for zone in zones:
            if zone.is_private:
                summary.private_zones += 1
            else:
                summary.public_zones += 1

        # Record counts
        for record in records:
            # By type
            record_type = record.record_type.value
            summary.records_by_type[record_type] = (
                summary.records_by_type.get(record_type, 0) + 1
            )

            # By zone
            summary.records_by_zone[record.zone_name] = (
                summary.records_by_zone.get(record.zone_name, 0) + 1
            )

            # Wildcards
            if record.is_wildcard:
                summary.wildcard_records += 1

        # Finding counts
        for finding in findings:
            severity = finding.severity.value
            summary.findings_by_severity[severity] = (
                summary.findings_by_severity.get(severity, 0) + 1
            )

            if finding.takeover_risk:
                summary.takeover_risks += 1

            if finding.finding_type in (
                DNSFindingType.DANGLING_CNAME,
                DNSFindingType.DANGLING_A_RECORD,
                DNSFindingType.DANGLING_ALIAS,
            ):
                summary.dangling_records += 1

        return summary

    def get_records_by_zone(self, zone_name: str) -> list[DNSRecord]:
        """Get records for a specific zone."""
        return [r for r in self._records if r.zone_name == zone_name]

    def get_records_by_type(self, record_type: DNSRecordType) -> list[DNSRecord]:
        """Get records of a specific type."""
        return [r for r in self._records if r.record_type == record_type]

    def get_zones_by_cloud(self, cloud_provider: str) -> list[DNSZone]:
        """Get zones for a specific cloud provider."""
        return [z for z in self._zones if z.cloud_provider == cloud_provider]


class AWSRoute53Collector(BaseDNSCollector):
    """
    Collects DNS zones and records from AWS Route53.
    """

    collector_name = "aws_route53"

    def __init__(
        self,
        session: Any = None,
        config: DNSConfig | None = None,
    ):
        """
        Initialize the Route53 collector.

        Args:
            session: Optional boto3 session
            config: Optional configuration
        """
        super().__init__(config)
        self._session = session
        self._account_id: str | None = None
        self._client: Any = None

    def _get_client(self) -> Any:
        """Get the Route53 client."""
        if self._client is None:
            if self._session is None:
                try:
                    import boto3

                    self._session = boto3.Session()
                except ImportError:
                    raise ImportError("boto3 is required for AWS Route53 collection")
            self._client = self._session.client("route53")
        return self._client

    @property
    def account_id(self) -> str:
        """Get the AWS account ID."""
        if self._account_id is None:
            if self._session is None:
                try:
                    import boto3

                    self._session = boto3.Session()
                except ImportError:
                    raise ImportError("boto3 is required")
            sts = self._session.client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
        return self._account_id

    def collect_zones(self) -> Iterator[DNSZone]:
        """Collect DNS zones from Route53."""
        client = self._get_client()

        try:
            paginator = client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page.get("HostedZones", []):
                    yield self._parse_zone(zone)
        except Exception as e:
            logger.error(f"Failed to list Route53 hosted zones: {e}")

    def collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]:
        """Collect DNS records from a Route53 zone."""
        client = self._get_client()

        try:
            paginator = client.get_paginator("list_resource_record_sets")
            for page in paginator.paginate(HostedZoneId=zone.zone_id):
                for record_set in page.get("ResourceRecordSets", []):
                    record = self._parse_record(record_set, zone)
                    if record:
                        yield record
        except Exception as e:
            logger.error(f"Failed to list records for zone {zone.name}: {e}")

    def _parse_zone(self, zone: dict[str, Any]) -> DNSZone:
        """Parse Route53 hosted zone."""
        zone_id = zone.get("Id", "").replace("/hostedzone/", "")
        name = zone.get("Name", "").rstrip(".")
        is_private = zone.get("Config", {}).get("PrivateZone", False)
        record_count = zone.get("ResourceRecordSetCount", 0)

        return DNSZone(
            zone_id=zone_id,
            name=name,
            cloud_provider="aws",
            account_id=self.account_id,
            is_private=is_private,
            record_count=record_count,
            metadata={
                "comment": zone.get("Config", {}).get("Comment", ""),
            },
        )

    def _parse_record(
        self, record_set: dict[str, Any], zone: DNSZone
    ) -> DNSRecord | None:
        """Parse Route53 resource record set."""
        name = record_set.get("Name", "").rstrip(".")
        type_str = record_set.get("Type", "")

        # Map to DNSRecordType
        try:
            record_type = DNSRecordType(type_str)
        except ValueError:
            # Skip unsupported record types
            return None

        # Check if it's in the include list
        if type_str not in self._config.include_record_types:
            # Still process if it's an alias
            if not record_set.get("AliasTarget"):
                return None

        # Get values
        values = []
        is_alias = False
        alias_target = None

        if record_set.get("AliasTarget"):
            is_alias = True
            alias_target = record_set["AliasTarget"].get("DNSName", "").rstrip(".")
            values = [alias_target] if alias_target else []
        else:
            values = [
                rr.get("Value", "") for rr in record_set.get("ResourceRecords", [])
            ]

        ttl = record_set.get("TTL", 0)

        return DNSRecord(
            record_id=f"{zone.zone_id}:{name}:{type_str}",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=name,
            record_type=record_type,
            values=values,
            ttl=ttl,
            cloud_provider="aws",
            account_id=zone.account_id,
            is_alias=is_alias,
            alias_target=alias_target,
            health_check_id=record_set.get("HealthCheckId"),
            metadata={
                "set_identifier": record_set.get("SetIdentifier"),
                "weight": record_set.get("Weight"),
                "region": record_set.get("Region"),
                "failover": record_set.get("Failover"),
            },
        )


class GCPCloudDNSCollector(BaseDNSCollector):
    """
    Collects DNS zones and records from GCP Cloud DNS.
    """

    collector_name = "gcp_cloud_dns"

    def __init__(
        self,
        project_id: str | None = None,
        credentials: Any = None,
        config: DNSConfig | None = None,
    ):
        """
        Initialize the Cloud DNS collector.

        Args:
            project_id: GCP project ID
            credentials: Optional GCP credentials
            config: Optional configuration
        """
        super().__init__(config)
        self._project_id = project_id
        self._credentials = credentials
        self._dns_client: Any = None

    @property
    def project_id(self) -> str:
        """Get the GCP project ID."""
        if self._project_id is None:
            raise ValueError("project_id is required for GCP Cloud DNS collection")
        return self._project_id

    def _get_dns_client(self) -> Any:
        """Get Cloud DNS client."""
        if self._dns_client is None:
            try:
                from google.cloud import dns

                self._dns_client = dns.Client(
                    project=self.project_id, credentials=self._credentials
                )
            except ImportError:
                raise ImportError(
                    "google-cloud-dns is required for GCP Cloud DNS collection"
                )
        return self._dns_client

    def collect_zones(self) -> Iterator[DNSZone]:
        """Collect DNS zones from Cloud DNS."""
        try:
            client = self._get_dns_client()
            for zone in client.list_zones():
                yield self._parse_zone(zone)
        except Exception as e:
            logger.error(f"Failed to list Cloud DNS zones: {e}")

    def collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]:
        """Collect DNS records from a Cloud DNS zone."""
        try:
            client = self._get_dns_client()
            gcp_zone = client.zone(zone.zone_id)

            for record_set in gcp_zone.list_resource_record_sets():
                record = self._parse_record(record_set, zone)
                if record:
                    yield record
        except Exception as e:
            logger.error(f"Failed to list records for zone {zone.name}: {e}")

    def _parse_zone(self, zone: Any) -> DNSZone:
        """Parse Cloud DNS managed zone."""
        return DNSZone(
            zone_id=zone.name,
            name=zone.dns_name.rstrip("."),
            cloud_provider="gcp",
            account_id=self.project_id,
            is_private=zone.visibility == "private",
            nameservers=list(zone.name_servers or []),
            metadata={
                "description": zone.description,
                "visibility": zone.visibility,
            },
        )

    def _parse_record(self, record_set: Any, zone: DNSZone) -> DNSRecord | None:
        """Parse Cloud DNS resource record set."""
        name = record_set.name.rstrip(".")
        type_str = record_set.record_type

        try:
            record_type = DNSRecordType(type_str)
        except ValueError:
            return None

        if type_str not in self._config.include_record_types:
            return None

        values = list(record_set.rrdatas or [])
        # Strip trailing dots from values
        values = [v.rstrip(".") for v in values]

        return DNSRecord(
            record_id=f"{zone.zone_id}:{name}:{type_str}",
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=name,
            record_type=record_type,
            values=values,
            ttl=record_set.ttl or 300,
            cloud_provider="gcp",
            account_id=self.project_id,
        )


class AzureDNSCollector(BaseDNSCollector):
    """
    Collects DNS zones and records from Azure DNS.
    """

    collector_name = "azure_dns"

    def __init__(
        self,
        subscription_id: str | None = None,
        credential: Any = None,
        config: DNSConfig | None = None,
    ):
        """
        Initialize the Azure DNS collector.

        Args:
            subscription_id: Azure subscription ID
            credential: Optional Azure credential
            config: Optional configuration
        """
        super().__init__(config)
        self._subscription_id = subscription_id
        self._credential = credential
        self._dns_client: Any = None

    @property
    def subscription_id(self) -> str:
        """Get the Azure subscription ID."""
        if self._subscription_id is None:
            raise ValueError("subscription_id is required for Azure DNS collection")
        return self._subscription_id

    def _get_dns_client(self) -> Any:
        """Get Azure DNS Management client."""
        if self._dns_client is None:
            try:
                from azure.mgmt.dns import DnsManagementClient

                if self._credential is None:
                    from azure.identity import DefaultAzureCredential

                    self._credential = DefaultAzureCredential()
                self._dns_client = DnsManagementClient(
                    self._credential, self._subscription_id
                )
            except ImportError:
                raise ImportError("azure-mgmt-dns is required for Azure DNS collection")
        return self._dns_client

    def collect_zones(self) -> Iterator[DNSZone]:
        """Collect DNS zones from Azure DNS."""
        try:
            client = self._get_dns_client()
            for zone in client.zones.list():
                yield self._parse_zone(zone)
        except Exception as e:
            logger.error(f"Failed to list Azure DNS zones: {e}")

    def collect_records(self, zone: DNSZone) -> Iterator[DNSRecord]:
        """Collect DNS records from an Azure DNS zone."""
        try:
            client = self._get_dns_client()
            # Extract resource group from zone metadata
            resource_group = zone.metadata.get("resource_group", "")
            if not resource_group:
                logger.warning(f"No resource group for zone {zone.name}")
                return

            for record_set in client.record_sets.list_all_by_dns_zone(
                resource_group, zone.name
            ):
                record = self._parse_record(record_set, zone)
                if record:
                    yield record
        except Exception as e:
            logger.error(f"Failed to list records for zone {zone.name}: {e}")

    def _parse_zone(self, zone: Any) -> DNSZone:
        """Parse Azure DNS zone."""
        # Extract resource group from zone ID
        resource_group = ""
        zone_id = getattr(zone, "id", "")
        if "/resourceGroups/" in zone_id:
            parts = zone_id.split("/resourceGroups/")
            if len(parts) > 1:
                resource_group = parts[1].split("/")[0]

        return DNSZone(
            zone_id=getattr(zone, "name", ""),
            name=getattr(zone, "name", ""),
            cloud_provider="azure",
            account_id=self._subscription_id,
            is_private=getattr(zone, "zone_type", "") == "Private",
            record_count=getattr(zone, "number_of_record_sets", 0),
            nameservers=list(getattr(zone, "name_servers", []) or []),
            metadata={
                "resource_group": resource_group,
                "location": getattr(zone, "location", ""),
                "zone_type": getattr(zone, "zone_type", ""),
            },
        )

    def _parse_record(self, record_set: Any, zone: DNSZone) -> DNSRecord | None:
        """Parse Azure DNS record set."""
        name = getattr(record_set, "name", "")
        if name == "@":
            name = zone.name
        else:
            name = f"{name}.{zone.name}"

        type_str = getattr(record_set, "type", "").split("/")[-1].upper()

        try:
            record_type = DNSRecordType(type_str)
        except ValueError:
            return None

        if type_str not in self._config.include_record_types:
            return None

        # Get values based on record type
        values = []
        is_alias = False
        alias_target = None

        if hasattr(record_set, "a_records") and record_set.a_records:
            values = [r.ipv4_address for r in record_set.a_records]
        elif hasattr(record_set, "aaaa_records") and record_set.aaaa_records:
            values = [r.ipv6_address for r in record_set.aaaa_records]
        elif hasattr(record_set, "cname_record") and record_set.cname_record:
            values = [record_set.cname_record.cname.rstrip(".")]
        elif hasattr(record_set, "target_resource") and record_set.target_resource:
            is_alias = True
            alias_target = getattr(record_set.target_resource, "id", "")
            values = [alias_target] if alias_target else []

        ttl = getattr(record_set, "ttl", 300)

        return DNSRecord(
            record_id=getattr(record_set, "id", f"{zone.zone_id}:{name}:{type_str}"),
            zone_id=zone.zone_id,
            zone_name=zone.name,
            name=name,
            record_type=record_type,
            values=values,
            ttl=ttl or 300,
            cloud_provider="azure",
            account_id=self._subscription_id,
            is_alias=is_alias,
            alias_target=alias_target,
        )


def scan_dns_inventory(
    zones: list[DNSZone],
    records: list[DNSRecord],
    config: DNSConfig | None = None,
    known_assets: list[str] | None = None,
) -> DNSInventoryResult:
    """
    Scan DNS inventory for security issues.

    Convenience function for DNS inventory analysis.

    Args:
        zones: List of DNS zones
        records: List of DNS records
        config: Optional configuration
        known_assets: Known cloud asset endpoints

    Returns:
        DNS inventory result
    """
    inventory = DNSInventory(zones=zones, records=records, config=config)
    if known_assets:
        inventory.add_known_assets(known_assets)
    return inventory.analyze()
