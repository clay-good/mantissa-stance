"""
CSPM-ASM Correlation Engine for Mantissa Stance.

This module correlates external ASM findings with internal CSPM inventory
to provide a unified view of the attack surface and detect shadow IT.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from stance.asm.models import ExternalAsset, ExternalAssetCollection
from stance.models.asset import Asset, AssetCollection

logger = logging.getLogger(__name__)


class MatchMethod(Enum):
    """Method used to match external and internal assets."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    TAG = "tag"
    LOAD_BALANCER = "load_balancer"
    API_GATEWAY = "api_gateway"
    DNS_RECORD = "dns_record"
    CLOUD_RUN = "cloud_run"


@dataclass
class MatchedAsset:
    """
    Represents a match between an external ASM asset and internal CSPM asset.

    Attributes:
        external_asset: The externally-discovered asset
        internal_asset: The matched CSPM asset
        match_confidence: Confidence score (0.0-1.0)
        match_method: How the match was determined
        match_details: Additional details about the match
    """

    external_asset: ExternalAsset
    internal_asset: Asset
    match_confidence: float
    match_method: MatchMethod
    match_details: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "external_asset": self.external_asset.to_dict(),
            "internal_asset": self.internal_asset.to_dict(),
            "match_confidence": self.match_confidence,
            "match_method": self.match_method.value,
            "match_details": self.match_details,
        }


@dataclass
class CorrelationResult:
    """
    Result of CSPM-ASM correlation.

    Attributes:
        matched_assets: External assets matched to CSPM inventory
        shadow_it: External assets NOT in CSPM inventory (potential shadow IT)
        internal_only: CSPM assets without external presence
        correlation_score: Overall correlation percentage
        correlation_time: When correlation was performed
        total_external: Total external assets analyzed
        total_internal: Total internal assets analyzed
    """

    matched_assets: list[MatchedAsset] = field(default_factory=list)
    shadow_it: list[ExternalAsset] = field(default_factory=list)
    internal_only: list[Asset] = field(default_factory=list)
    correlation_score: float = 0.0
    correlation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_external: int = 0
    total_internal: int = 0

    @property
    def matched_count(self) -> int:
        """Number of matched assets."""
        return len(self.matched_assets)

    @property
    def shadow_it_count(self) -> int:
        """Number of potential shadow IT assets."""
        return len(self.shadow_it)

    @property
    def internal_only_count(self) -> int:
        """Number of internal-only assets."""
        return len(self.internal_only)

    @property
    def high_risk_shadow_it(self) -> list[ExternalAsset]:
        """Shadow IT assets with high risk scores (>= 7.0)."""
        return [a for a in self.shadow_it if a.risk_score >= 7.0]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "matched_assets": [m.to_dict() for m in self.matched_assets],
            "shadow_it": [a.to_dict() for a in self.shadow_it],
            "internal_only": [a.to_dict() for a in self.internal_only],
            "correlation_score": self.correlation_score,
            "correlation_time": self.correlation_time.isoformat(),
            "total_external": self.total_external,
            "total_internal": self.total_internal,
            "summary": {
                "matched_count": self.matched_count,
                "shadow_it_count": self.shadow_it_count,
                "internal_only_count": self.internal_only_count,
                "high_risk_shadow_it_count": len(self.high_risk_shadow_it),
            },
        }

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of correlation results."""
        return {
            "correlation_score": f"{self.correlation_score:.1f}%",
            "matched_assets": self.matched_count,
            "shadow_it_detected": self.shadow_it_count,
            "high_risk_shadow_it": len(self.high_risk_shadow_it),
            "internal_only": self.internal_only_count,
            "total_external": self.total_external,
            "total_internal": self.total_internal,
        }


class ASMCSPMCorrelator:
    """
    Correlates external ASM assets with internal CSPM inventory.

    Uses multiple matching strategies to find correspondences between
    externally-discovered assets and internal cloud resource inventory.
    """

    def __init__(
        self,
        asm_assets: ExternalAssetCollection,
        cspm_assets: AssetCollection,
    ) -> None:
        """
        Initialize the correlator.

        Args:
            asm_assets: Collection of externally-discovered ASM assets
            cspm_assets: Collection of internal CSPM assets
        """
        self.asm_assets = asm_assets
        self.cspm_assets = cspm_assets

        # Build lookup indexes for efficient correlation
        self._ip_index: dict[str, list[Asset]] = {}
        self._domain_index: dict[str, list[Asset]] = {}
        self._dns_index: dict[str, list[Asset]] = {}
        self._cert_fingerprint_index: dict[str, list[Asset]] = {}
        self._tag_domain_index: dict[str, list[Asset]] = {}

        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build lookup indexes from CSPM assets for efficient matching."""
        for asset in self.cspm_assets:
            raw = asset.raw_config

            # Index by public IP address
            public_ip = self._extract_public_ip(asset)
            if public_ip:
                self._ip_index.setdefault(public_ip, []).append(asset)

            # Index by public DNS name
            public_dns = self._extract_public_dns(asset)
            if public_dns:
                dns_lower = public_dns.lower().rstrip(".")
                self._domain_index.setdefault(dns_lower, []).append(asset)

            # Index by DNS record values (for Route53, Cloud DNS)
            if asset.resource_type in ("aws_route53_record", "gcp_dns_record", "azure_dns_record"):
                dns_values = raw.get("values", [])
                record_name = raw.get("name", "").lower().rstrip(".")
                if record_name:
                    self._dns_index.setdefault(record_name, []).append(asset)
                for val in dns_values:
                    if val:
                        self._dns_index.setdefault(val.lower().rstrip("."), []).append(asset)

            # Index by certificate fingerprint
            cert_fingerprint = raw.get("fingerprint_sha256") or raw.get("certificate_fingerprint")
            if cert_fingerprint:
                self._cert_fingerprint_index.setdefault(cert_fingerprint.lower(), []).append(asset)

            # Index by domain tags
            for tag_key in ("Domain", "domain", "DOMAIN", "hostname", "Hostname"):
                tag_value = asset.tags.get(tag_key)
                if tag_value:
                    self._tag_domain_index.setdefault(tag_value.lower(), []).append(asset)

    def _extract_public_ip(self, asset: Asset) -> str | None:
        """Extract public IP address from a CSPM asset."""
        raw = asset.raw_config

        # EC2 instances
        if raw.get("public_ip_address"):
            return raw["public_ip_address"]

        # Generic public_ip field
        if raw.get("public_ip"):
            return raw["public_ip"]

        # Azure VMs
        if raw.get("public_ip_address_id"):
            # Would need to resolve the IP from the ID
            pass

        # Check for IP in endpoint field
        endpoint = raw.get("endpoint", {})
        if isinstance(endpoint, dict):
            addr = endpoint.get("address")
            if addr and self._is_ip_address(addr):
                return addr

        return None

    def _extract_public_dns(self, asset: Asset) -> str | None:
        """Extract public DNS name from a CSPM asset."""
        raw = asset.raw_config

        # EC2 public DNS
        if raw.get("public_dns_name"):
            return raw["public_dns_name"]

        # Load balancer DNS
        if raw.get("dns_name"):
            return raw["dns_name"]

        # API Gateway endpoint
        if raw.get("api_endpoint"):
            return self._extract_hostname(raw["api_endpoint"])

        # CloudFront distribution
        if raw.get("domain_name"):
            return raw["domain_name"]

        # S3 website endpoint
        if raw.get("website_endpoint"):
            return self._extract_hostname(raw["website_endpoint"])

        # Lambda function URL
        if raw.get("function_url"):
            return self._extract_hostname(raw["function_url"])

        # Cloud Run URL
        if raw.get("url"):
            return self._extract_hostname(raw["url"])

        # RDS endpoint
        endpoint = raw.get("endpoint", {})
        if isinstance(endpoint, dict):
            addr = endpoint.get("address")
            if addr and not self._is_ip_address(addr):
                return addr

        return None

    @staticmethod
    def _extract_hostname(url: str) -> str | None:
        """Extract hostname from a URL."""
        if not url:
            return None
        # Remove protocol prefix
        url = re.sub(r"^https?://", "", url)
        # Remove path and port
        hostname = url.split("/")[0].split(":")[0]
        return hostname.lower() if hostname else None

    @staticmethod
    def _is_ip_address(value: str) -> bool:
        """Check if a string is an IP address."""
        # Simple IPv4 check
        parts = value.split(".")
        if len(parts) == 4:
            return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        return False

    def correlate(self) -> CorrelationResult:
        """
        Perform correlation between ASM and CSPM assets.

        Returns:
            CorrelationResult with matched assets, shadow IT, and statistics
        """
        result = CorrelationResult(
            total_external=len(self.asm_assets),
            total_internal=len(self.cspm_assets),
        )

        # Track which assets have been matched
        matched_external_ids: set[str] = set()
        matched_internal_ids: set[str] = set()

        # Attempt to match each external asset
        for external in self.asm_assets:
            match = self._find_best_match(external)
            if match:
                result.matched_assets.append(match)
                matched_external_ids.add(external.id)
                matched_internal_ids.add(match.internal_asset.id)
            else:
                result.shadow_it.append(external)

        # Find internal assets without external presence
        for internal in self.cspm_assets:
            if internal.id not in matched_internal_ids:
                # Only include internet-facing assets
                if internal.is_internet_facing():
                    result.internal_only.append(internal)

        # Calculate correlation score
        if result.total_external > 0:
            result.correlation_score = (
                result.matched_count / result.total_external
            ) * 100

        logger.info(
            f"Correlation complete: {result.matched_count} matched, "
            f"{result.shadow_it_count} shadow IT, "
            f"{result.internal_only_count} internal-only"
        )

        return result

    def _find_best_match(self, external: ExternalAsset) -> MatchedAsset | None:
        """
        Find the best matching internal asset for an external asset.

        Tries multiple matching strategies in order of confidence.

        Args:
            external: External asset to match

        Returns:
            MatchedAsset if found, None otherwise
        """
        matches: list[MatchedAsset] = []

        # Strategy 1: IP address match (highest confidence)
        if external.ip_address:
            internal_matches = self._ip_index.get(external.ip_address, [])
            for internal in internal_matches:
                matches.append(
                    MatchedAsset(
                        external_asset=external,
                        internal_asset=internal,
                        match_confidence=1.0,
                        match_method=MatchMethod.IP_ADDRESS,
                        match_details=f"IP: {external.ip_address}",
                    )
                )

        # Strategy 2: Domain name match
        if external.domain:
            domain_lower = external.domain.lower().rstrip(".")

            # Direct domain match
            internal_matches = self._domain_index.get(domain_lower, [])
            for internal in internal_matches:
                matches.append(
                    MatchedAsset(
                        external_asset=external,
                        internal_asset=internal,
                        match_confidence=0.95,
                        match_method=MatchMethod.DOMAIN,
                        match_details=f"Domain: {external.domain}",
                    )
                )

            # DNS record match
            internal_matches = self._dns_index.get(domain_lower, [])
            for internal in internal_matches:
                matches.append(
                    MatchedAsset(
                        external_asset=external,
                        internal_asset=internal,
                        match_confidence=0.9,
                        match_method=MatchMethod.DNS_RECORD,
                        match_details=f"DNS record: {external.domain}",
                    )
                )

            # Tag-based domain match
            internal_matches = self._tag_domain_index.get(domain_lower, [])
            for internal in internal_matches:
                matches.append(
                    MatchedAsset(
                        external_asset=external,
                        internal_asset=internal,
                        match_confidence=0.7,
                        match_method=MatchMethod.TAG,
                        match_details=f"Tag domain: {external.domain}",
                    )
                )

        # Strategy 3: Certificate fingerprint match
        if external.certificate_info and external.certificate_info.fingerprint_sha256:
            fingerprint = external.certificate_info.fingerprint_sha256.lower()
            internal_matches = self._cert_fingerprint_index.get(fingerprint, [])
            for internal in internal_matches:
                matches.append(
                    MatchedAsset(
                        external_asset=external,
                        internal_asset=internal,
                        match_confidence=0.85,
                        match_method=MatchMethod.CERTIFICATE,
                        match_details=f"Cert: {fingerprint[:16]}...",
                    )
                )

        # Return the match with highest confidence
        if matches:
            return max(matches, key=lambda m: m.match_confidence)

        return None


def create_unified_inventory(
    correlation: CorrelationResult,
    include_shadow_it: bool = True,
) -> AssetCollection:
    """
    Create a unified asset inventory from correlation results.

    Adds external exposure information to matched assets and optionally
    creates Asset entries for shadow IT discoveries.

    Args:
        correlation: Correlation result to process
        include_shadow_it: Whether to include shadow IT as assets

    Returns:
        AssetCollection with unified view
    """
    assets: list[Asset] = []

    # Add matched assets with external exposure data
    for match in correlation.matched_assets:
        internal = match.internal_asset
        external = match.external_asset

        # Create enriched raw_config
        enriched_config = dict(internal.raw_config)
        enriched_config["asm_correlation"] = {
            "external_domain": external.domain,
            "external_ip": external.ip_address,
            "external_port": external.port,
            "external_service": external.service,
            "external_risk_score": external.risk_score,
            "match_confidence": match.match_confidence,
            "match_method": match.match_method.value,
            "first_seen_external": external.first_seen.isoformat(),
            "last_seen_external": external.last_seen.isoformat(),
            "technology_stack": list(external.technology_stack),
        }

        if external.certificate_info:
            enriched_config["asm_correlation"]["certificate"] = {
                "subject": external.certificate_info.subject,
                "issuer": external.certificate_info.issuer,
                "not_after": external.certificate_info.not_after.isoformat(),
                "is_expired": external.certificate_info.is_expired,
                "is_expiring_soon": external.certificate_info.is_expiring_soon,
            }

        # Create new asset with enriched config
        enriched_asset = Asset(
            id=internal.id,
            cloud_provider=internal.cloud_provider,
            account_id=internal.account_id,
            region=internal.region,
            resource_type=internal.resource_type,
            name=internal.name,
            tags=internal.tags,
            network_exposure="internet_facing",  # Confirmed by ASM
            created_at=internal.created_at,
            last_seen=internal.last_seen,
            raw_config=enriched_config,
        )
        assets.append(enriched_asset)

    # Add shadow IT as special asset type
    if include_shadow_it:
        for external in correlation.shadow_it:
            shadow_config = {
                "domain": external.domain,
                "ip_address": external.ip_address,
                "port": external.port,
                "protocol": external.protocol,
                "service": external.service,
                "technology_stack": list(external.technology_stack),
                "risk_score": external.risk_score,
                "source": external.source,
                "first_seen": external.first_seen.isoformat(),
                "last_seen": external.last_seen.isoformat(),
                "is_shadow_it": True,
            }

            if external.certificate_info:
                shadow_config["certificate"] = external.certificate_info.to_dict()

            shadow_asset = Asset(
                id=f"shadow-it:{external.id}",
                cloud_provider=external.cloud_provider or "unknown",
                account_id="unknown",
                region=external.cloud_region or "unknown",
                resource_type="shadow_it_asset",
                name=external.domain,
                tags={"source": "asm", "shadow_it": "true"},
                network_exposure="internet_facing",
                created_at=external.first_seen,
                last_seen=external.last_seen,
                raw_config=shadow_config,
            )
            assets.append(shadow_asset)

    return AssetCollection(assets)


def detect_shadow_it(
    asm_assets: ExternalAssetCollection,
    cspm_assets: AssetCollection,
    cloud_provider_filter: str | None = None,
) -> list[ExternalAsset]:
    """
    Convenience function to detect shadow IT assets.

    Args:
        asm_assets: Collection of externally-discovered assets
        cspm_assets: Collection of internal CSPM assets
        cloud_provider_filter: Optional filter by cloud provider

    Returns:
        List of shadow IT (unmatched external) assets
    """
    correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
    result = correlator.correlate()

    shadow_it = result.shadow_it

    if cloud_provider_filter:
        shadow_it = [
            a for a in shadow_it
            if a.cloud_provider and a.cloud_provider.lower() == cloud_provider_filter.lower()
        ]

    # Sort by risk score (highest first)
    shadow_it.sort(key=lambda a: a.risk_score, reverse=True)

    return shadow_it


def get_attack_surface(
    asm_assets: ExternalAssetCollection,
    cspm_assets: AssetCollection,
) -> list[dict[str, Any]]:
    """
    Get a unified view of the external attack surface.

    Combines matched and shadow IT assets into a single attack surface view.

    Args:
        asm_assets: Collection of externally-discovered assets
        cspm_assets: Collection of internal CSPM assets

    Returns:
        List of attack surface entries with external and internal context
    """
    correlator = ASMCSPMCorrelator(asm_assets, cspm_assets)
    result = correlator.correlate()

    attack_surface: list[dict[str, Any]] = []

    # Add matched assets
    for match in result.matched_assets:
        entry = {
            "domain": match.external_asset.domain,
            "ip_address": match.external_asset.ip_address,
            "port": match.external_asset.port,
            "service": match.external_asset.service,
            "protocol": match.external_asset.protocol,
            "risk_score": match.external_asset.risk_score,
            "cloud_provider": match.external_asset.cloud_provider,
            "is_shadow_it": False,
            "is_matched": True,
            "match_confidence": match.match_confidence,
            "internal_asset_id": match.internal_asset.id,
            "internal_resource_type": match.internal_asset.resource_type,
            "internal_name": match.internal_asset.name,
            "technology_stack": list(match.external_asset.technology_stack),
            "first_seen": match.external_asset.first_seen.isoformat(),
            "last_seen": match.external_asset.last_seen.isoformat(),
        }

        if match.external_asset.certificate_info:
            entry["certificate_expiry"] = match.external_asset.certificate_info.not_after.isoformat()
            entry["certificate_expired"] = match.external_asset.certificate_info.is_expired

        attack_surface.append(entry)

    # Add shadow IT
    for external in result.shadow_it:
        entry = {
            "domain": external.domain,
            "ip_address": external.ip_address,
            "port": external.port,
            "service": external.service,
            "protocol": external.protocol,
            "risk_score": external.risk_score,
            "cloud_provider": external.cloud_provider,
            "is_shadow_it": True,
            "is_matched": False,
            "match_confidence": 0.0,
            "internal_asset_id": None,
            "internal_resource_type": None,
            "internal_name": None,
            "technology_stack": list(external.technology_stack),
            "first_seen": external.first_seen.isoformat(),
            "last_seen": external.last_seen.isoformat(),
        }

        if external.certificate_info:
            entry["certificate_expiry"] = external.certificate_info.not_after.isoformat()
            entry["certificate_expired"] = external.certificate_info.is_expired

        attack_surface.append(entry)

    # Sort by risk score
    attack_surface.sort(key=lambda e: e["risk_score"], reverse=True)

    return attack_surface
