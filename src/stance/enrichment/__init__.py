"""
Finding and asset enrichment for Mantissa Stance.

Provides enrichment capabilities including IP geolocation,
threat intelligence, CVE details, and asset context.
"""

from stance.enrichment.base import (
    AssetEnricher,
    BaseEnricher,
    EnrichedAsset,
    EnrichedFinding,
    EnrichmentData,
    EnrichmentPipeline,
    EnrichmentResult,
    EnrichmentType,
    FindingEnricher,
)
from stance.enrichment.ip_enrichment import (
    CloudProviderRangeEnricher,
    IPEnricher,
    IPInfo,
)
from stance.enrichment.asset_enrichment import (
    AssetContextEnricher,
    BusinessUnitMapping,
    CriticalityRule,
    TagEnricher,
)
from stance.enrichment.threat_intel import (
    CVEEnricher,
    KEVEnricher,
    ThreatIndicator,
    ThreatIntelEnricher,
    VulnerableSoftwareEnricher,
)

__all__ = [
    # Base
    "AssetEnricher",
    "BaseEnricher",
    "EnrichedAsset",
    "EnrichedFinding",
    "EnrichmentData",
    "EnrichmentPipeline",
    "EnrichmentResult",
    "EnrichmentType",
    "FindingEnricher",
    # IP enrichment
    "CloudProviderRangeEnricher",
    "IPEnricher",
    "IPInfo",
    # Asset enrichment
    "AssetContextEnricher",
    "BusinessUnitMapping",
    "CriticalityRule",
    "TagEnricher",
    # Threat intelligence
    "CVEEnricher",
    "KEVEnricher",
    "ThreatIndicator",
    "ThreatIntelEnricher",
    "VulnerableSoftwareEnricher",
]


def create_default_pipeline() -> EnrichmentPipeline:
    """
    Create a default enrichment pipeline with all enrichers.

    Returns:
        Configured EnrichmentPipeline
    """
    return EnrichmentPipeline(
        finding_enrichers=[
            CVEEnricher(),
            VulnerableSoftwareEnricher(),
            ThreatIntelEnricher(),
            KEVEnricher(),
        ],
        asset_enrichers=[
            IPEnricher(),
            CloudProviderRangeEnricher(),
            AssetContextEnricher(),
            TagEnricher(),
        ],
    )


def enrich_findings(
    findings: list,
    pipeline: EnrichmentPipeline | None = None,
) -> list[EnrichedFinding]:
    """
    Enrich a list of findings.

    Args:
        findings: Findings to enrich
        pipeline: Optional custom pipeline

    Returns:
        List of enriched findings
    """
    if pipeline is None:
        pipeline = create_default_pipeline()
    return pipeline.enrich_findings(findings)


def enrich_assets(
    assets: list,
    pipeline: EnrichmentPipeline | None = None,
) -> list[EnrichedAsset]:
    """
    Enrich a list of assets.

    Args:
        assets: Assets to enrich
        pipeline: Optional custom pipeline

    Returns:
        List of enriched assets
    """
    if pipeline is None:
        pipeline = create_default_pipeline()
    return pipeline.enrich_assets(assets)
