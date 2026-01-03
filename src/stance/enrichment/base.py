"""
Base enricher for Mantissa Stance.

Provides abstract interface for finding and asset enrichment.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from stance.models.asset import Asset
from stance.models.finding import Finding


class EnrichmentType(Enum):
    """Types of enrichment data."""

    IP_GEOLOCATION = "ip_geolocation"
    IP_ASN = "ip_asn"
    IP_CLOUD_PROVIDER = "ip_cloud_provider"
    THREAT_INTEL = "threat_intel"
    CVE_DETAILS = "cve_details"
    ASSET_CONTEXT = "asset_context"
    BUSINESS_UNIT = "business_unit"
    CRITICALITY = "criticality"
    OWNER = "owner"


@dataclass
class EnrichmentData:
    """
    Container for enrichment data.

    Attributes:
        enrichment_type: Type of enrichment
        source: Source of the enrichment data
        data: Enrichment data dictionary
        confidence: Confidence score (0.0 to 1.0)
        cached: Whether this data was from cache
        fetched_at: When the data was fetched
        expires_at: When the data expires
    """

    enrichment_type: EnrichmentType
    source: str
    data: dict[str, Any]
    confidence: float = 1.0
    cached: bool = False
    fetched_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None

    def is_expired(self) -> bool:
        """Check if enrichment data has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "enrichment_type": self.enrichment_type.value,
            "source": self.source,
            "data": self.data,
            "confidence": self.confidence,
            "cached": self.cached,
            "fetched_at": self.fetched_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class EnrichedFinding:
    """
    Finding with enrichment data attached.

    Attributes:
        finding: Original finding
        enrichments: List of enrichment data
    """

    finding: Finding
    enrichments: list[EnrichmentData] = field(default_factory=list)

    def get_enrichment(
        self,
        enrichment_type: EnrichmentType,
    ) -> EnrichmentData | None:
        """Get enrichment data by type."""
        for enrichment in self.enrichments:
            if enrichment.enrichment_type == enrichment_type:
                return enrichment
        return None

    def has_enrichment(self, enrichment_type: EnrichmentType) -> bool:
        """Check if enrichment type exists."""
        return self.get_enrichment(enrichment_type) is not None

    def add_enrichment(self, enrichment: EnrichmentData) -> None:
        """Add enrichment data."""
        # Replace existing enrichment of same type
        self.enrichments = [
            e for e in self.enrichments
            if e.enrichment_type != enrichment.enrichment_type
        ]
        self.enrichments.append(enrichment)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "finding": self.finding.to_dict(),
            "enrichments": [e.to_dict() for e in self.enrichments],
        }


@dataclass
class EnrichedAsset:
    """
    Asset with enrichment data attached.

    Attributes:
        asset: Original asset
        enrichments: List of enrichment data
    """

    asset: Asset
    enrichments: list[EnrichmentData] = field(default_factory=list)

    def get_enrichment(
        self,
        enrichment_type: EnrichmentType,
    ) -> EnrichmentData | None:
        """Get enrichment data by type."""
        for enrichment in self.enrichments:
            if enrichment.enrichment_type == enrichment_type:
                return enrichment
        return None

    def has_enrichment(self, enrichment_type: EnrichmentType) -> bool:
        """Check if enrichment type exists."""
        return self.get_enrichment(enrichment_type) is not None

    def add_enrichment(self, enrichment: EnrichmentData) -> None:
        """Add enrichment data."""
        self.enrichments = [
            e for e in self.enrichments
            if e.enrichment_type != enrichment.enrichment_type
        ]
        self.enrichments.append(enrichment)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "asset": self.asset.to_dict(),
            "enrichments": [e.to_dict() for e in self.enrichments],
        }


T = TypeVar("T", Finding, Asset)


class BaseEnricher(ABC, Generic[T]):
    """
    Abstract base class for enrichers.

    Enrichers add contextual information to findings or assets
    from external data sources.
    """

    @property
    @abstractmethod
    def enricher_name(self) -> str:
        """Return the enricher name."""
        ...

    @property
    @abstractmethod
    def enrichment_types(self) -> list[EnrichmentType]:
        """Return the types of enrichment this enricher provides."""
        ...

    @abstractmethod
    def enrich(self, item: T) -> list[EnrichmentData]:
        """
        Enrich a single finding or asset.

        Args:
            item: Finding or Asset to enrich

        Returns:
            List of enrichment data
        """
        ...

    def enrich_batch(self, items: list[T]) -> dict[str, list[EnrichmentData]]:
        """
        Enrich multiple items.

        Default implementation calls enrich() for each item.
        Subclasses may override for batch optimization.

        Args:
            items: List of findings or assets to enrich

        Returns:
            Dictionary mapping item ID to enrichment data
        """
        result = {}
        for item in items:
            item_id = item.id if hasattr(item, "id") else str(item)
            result[item_id] = self.enrich(item)
        return result

    def is_available(self) -> bool:
        """
        Check if enricher is available and configured.

        Returns:
            True if enricher can be used
        """
        return True


class FindingEnricher(BaseEnricher[Finding]):
    """Base class for finding enrichers."""
    pass


class AssetEnricher(BaseEnricher[Asset]):
    """Base class for asset enrichers."""
    pass


@dataclass
class EnrichmentResult:
    """
    Result of an enrichment operation.

    Attributes:
        enriched_findings: Findings with enrichment data
        enriched_assets: Assets with enrichment data
        enrichers_used: Names of enrichers that were used
        errors: Errors encountered during enrichment
        duration_seconds: Time taken for enrichment
    """

    enriched_findings: list[EnrichedFinding] = field(default_factory=list)
    enriched_assets: list[EnrichedAsset] = field(default_factory=list)
    enrichers_used: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "enriched_findings": [f.to_dict() for f in self.enriched_findings],
            "enriched_assets": [a.to_dict() for a in self.enriched_assets],
            "enrichers_used": self.enrichers_used,
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
        }


class EnrichmentPipeline:
    """
    Pipeline for running multiple enrichers.

    Runs enrichers in sequence, accumulating enrichment data.
    """

    def __init__(
        self,
        finding_enrichers: list[FindingEnricher] | None = None,
        asset_enrichers: list[AssetEnricher] | None = None,
    ):
        """
        Initialize enrichment pipeline.

        Args:
            finding_enrichers: Enrichers for findings
            asset_enrichers: Enrichers for assets
        """
        self.finding_enrichers = finding_enrichers or []
        self.asset_enrichers = asset_enrichers or []

    def enrich_findings(
        self,
        findings: list[Finding],
    ) -> list[EnrichedFinding]:
        """
        Enrich a list of findings.

        Args:
            findings: Findings to enrich

        Returns:
            Enriched findings
        """
        enriched = [EnrichedFinding(finding=f) for f in findings]

        for enricher in self.finding_enrichers:
            if not enricher.is_available():
                continue

            for ef in enriched:
                try:
                    enrichments = enricher.enrich(ef.finding)
                    for enrichment in enrichments:
                        ef.add_enrichment(enrichment)
                except Exception:
                    # Log error but continue with other enrichments
                    pass

        return enriched

    def enrich_assets(
        self,
        assets: list[Asset],
    ) -> list[EnrichedAsset]:
        """
        Enrich a list of assets.

        Args:
            assets: Assets to enrich

        Returns:
            Enriched assets
        """
        enriched = [EnrichedAsset(asset=a) for a in assets]

        for enricher in self.asset_enrichers:
            if not enricher.is_available():
                continue

            for ea in enriched:
                try:
                    enrichments = enricher.enrich(ea.asset)
                    for enrichment in enrichments:
                        ea.add_enrichment(enrichment)
                except Exception:
                    # Log error but continue with other enrichments
                    pass

        return enriched

    def add_finding_enricher(self, enricher: FindingEnricher) -> None:
        """Add a finding enricher to the pipeline."""
        self.finding_enrichers.append(enricher)

    def add_asset_enricher(self, enricher: AssetEnricher) -> None:
        """Add an asset enricher to the pipeline."""
        self.asset_enrichers.append(enricher)
