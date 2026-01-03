"""
Asset enrichment for Mantissa Stance.

Provides asset context enrichment including tag-based context,
business unit mapping, and criticality assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from stance.enrichment.base import (
    AssetEnricher as BaseAssetEnricher,
    EnrichmentData,
    EnrichmentType,
)
from stance.models.asset import Asset


@dataclass
class BusinessUnitMapping:
    """
    Mapping configuration for business units.

    Attributes:
        name: Business unit name
        patterns: Tag patterns to match (regex)
        tag_key: Tag key to match
        tag_values: Tag values to match
        owners: Default owners for this business unit
        contacts: Contact information
    """

    name: str
    patterns: list[str] = field(default_factory=list)
    tag_key: str = "business_unit"
    tag_values: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    contacts: dict[str, str] = field(default_factory=dict)


@dataclass
class CriticalityRule:
    """
    Rule for determining asset criticality.

    Attributes:
        level: Criticality level (critical, high, medium, low)
        resource_types: Resource types this rule applies to
        tag_patterns: Tag patterns that indicate this criticality
        name_patterns: Name patterns that indicate this criticality
        conditions: Additional conditions (key-value pairs)
    """

    level: str
    resource_types: list[str] = field(default_factory=list)
    tag_patterns: dict[str, str] = field(default_factory=dict)
    name_patterns: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)


# Default business unit mappings
DEFAULT_BUSINESS_UNITS = [
    BusinessUnitMapping(
        name="Engineering",
        tag_key="team",
        tag_values=["engineering", "eng", "development", "dev"],
        patterns=[r".*-eng-.*", r".*-dev-.*"],
    ),
    BusinessUnitMapping(
        name="Platform",
        tag_key="team",
        tag_values=["platform", "infrastructure", "infra", "devops", "sre"],
        patterns=[r".*-platform-.*", r".*-infra-.*"],
    ),
    BusinessUnitMapping(
        name="Data",
        tag_key="team",
        tag_values=["data", "analytics", "ml", "ai", "data-science"],
        patterns=[r".*-data-.*", r".*-analytics-.*", r".*-ml-.*"],
    ),
    BusinessUnitMapping(
        name="Security",
        tag_key="team",
        tag_values=["security", "infosec", "secops"],
        patterns=[r".*-security-.*", r".*-sec-.*"],
    ),
    BusinessUnitMapping(
        name="Finance",
        tag_key="team",
        tag_values=["finance", "billing", "payments"],
        patterns=[r".*-finance-.*", r".*-billing-.*"],
    ),
]

# Default criticality rules
DEFAULT_CRITICALITY_RULES = [
    # Critical by resource type
    CriticalityRule(
        level="critical",
        resource_types=[
            "aws_iam_user",
            "aws_iam_role",
            "aws_kms_key",
            "aws_secretsmanager_secret",
            "gcp_iam_service_account",
            "gcp_kms_key",
            "azure_key_vault",
            "azure_ad_user",
        ],
    ),
    # Critical by environment tag
    CriticalityRule(
        level="critical",
        tag_patterns={
            "environment": r"^(production|prod|prd)$",
            "env": r"^(production|prod|prd)$",
        },
    ),
    # Critical by criticality tag
    CriticalityRule(
        level="critical",
        tag_patterns={
            "criticality": r"^(critical|tier-0|tier0)$",
            "tier": r"^(0|tier-0)$",
        },
    ),
    # High criticality
    CriticalityRule(
        level="high",
        resource_types=[
            "aws_rds_instance",
            "aws_s3_bucket",
            "aws_dynamodb_table",
            "gcp_sql_instance",
            "gcp_storage_bucket",
            "azure_sql_database",
            "azure_storage_account",
        ],
    ),
    CriticalityRule(
        level="high",
        tag_patterns={
            "criticality": r"^(high|tier-1|tier1)$",
            "tier": r"^(1|tier-1)$",
        },
    ),
    # Medium criticality
    CriticalityRule(
        level="medium",
        tag_patterns={
            "environment": r"^(staging|stage|stg|uat)$",
            "criticality": r"^(medium|tier-2|tier2)$",
        },
    ),
    # Low criticality
    CriticalityRule(
        level="low",
        tag_patterns={
            "environment": r"^(development|dev|sandbox|test)$",
            "criticality": r"^(low|tier-3|tier3)$",
        },
    ),
]


class AssetContextEnricher(BaseAssetEnricher):
    """
    Enriches assets with contextual information.

    Provides:
    - Business unit identification
    - Owner identification
    - Criticality assessment
    - Environment classification
    """

    def __init__(
        self,
        business_units: list[BusinessUnitMapping] | None = None,
        criticality_rules: list[CriticalityRule] | None = None,
    ):
        """
        Initialize asset context enricher.

        Args:
            business_units: Custom business unit mappings
            criticality_rules: Custom criticality rules
        """
        self.business_units = business_units or DEFAULT_BUSINESS_UNITS
        self.criticality_rules = criticality_rules or DEFAULT_CRITICALITY_RULES

    @property
    def enricher_name(self) -> str:
        return "asset_context_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [
            EnrichmentType.ASSET_CONTEXT,
            EnrichmentType.BUSINESS_UNIT,
            EnrichmentType.CRITICALITY,
            EnrichmentType.OWNER,
        ]

    def enrich(self, asset: Asset) -> list[EnrichmentData]:
        """
        Enrich asset with contextual information.

        Args:
            asset: Asset to enrich

        Returns:
            List of enrichment data
        """
        enrichments = []

        # Determine business unit
        business_unit = self._determine_business_unit(asset)
        if business_unit:
            enrichments.append(EnrichmentData(
                enrichment_type=EnrichmentType.BUSINESS_UNIT,
                source="tag_mapping",
                data={
                    "business_unit": business_unit.name,
                    "owners": business_unit.owners,
                    "contacts": business_unit.contacts,
                },
                confidence=0.8,
            ))

        # Determine criticality
        criticality = self._determine_criticality(asset)
        enrichments.append(EnrichmentData(
            enrichment_type=EnrichmentType.CRITICALITY,
            source="criticality_rules",
            data={
                "level": criticality["level"],
                "reason": criticality["reason"],
                "factors": criticality["factors"],
            },
            confidence=criticality["confidence"],
        ))

        # Determine owner
        owner_info = self._determine_owner(asset, business_unit)
        if owner_info:
            enrichments.append(EnrichmentData(
                enrichment_type=EnrichmentType.OWNER,
                source="tag_mapping",
                data=owner_info,
                confidence=owner_info.get("confidence", 0.7),
            ))

        # General asset context
        context = self._build_asset_context(asset)
        enrichments.append(EnrichmentData(
            enrichment_type=EnrichmentType.ASSET_CONTEXT,
            source="asset_analysis",
            data=context,
            confidence=0.9,
        ))

        return enrichments

    def _determine_business_unit(
        self,
        asset: Asset,
    ) -> BusinessUnitMapping | None:
        """Determine business unit from asset tags and name."""
        tags = asset.tags or {}

        for bu in self.business_units:
            # Check tag values
            tag_value = tags.get(bu.tag_key, "").lower()
            if tag_value in [v.lower() for v in bu.tag_values]:
                return bu

            # Check name patterns
            for pattern in bu.patterns:
                if re.match(pattern, asset.name, re.IGNORECASE):
                    return bu

        return None

    def _determine_criticality(self, asset: Asset) -> dict[str, Any]:
        """Determine asset criticality level."""
        tags = asset.tags or {}
        factors = []
        matched_level = "low"  # Default

        for rule in self.criticality_rules:
            matched = False
            reason = ""

            # Check resource type
            if rule.resource_types and asset.resource_type in rule.resource_types:
                matched = True
                reason = f"Resource type: {asset.resource_type}"

            # Check tag patterns
            for tag_key, pattern in rule.tag_patterns.items():
                tag_value = tags.get(tag_key, "")
                if tag_value and re.match(pattern, tag_value, re.IGNORECASE):
                    matched = True
                    reason = f"Tag {tag_key}={tag_value}"
                    break

            # Check name patterns
            for pattern in rule.name_patterns:
                if re.match(pattern, asset.name, re.IGNORECASE):
                    matched = True
                    reason = f"Name pattern: {pattern}"
                    break

            if matched:
                factors.append({
                    "level": rule.level,
                    "reason": reason,
                })
                # Keep highest criticality level
                level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                if level_order.get(rule.level, 4) < level_order.get(matched_level, 4):
                    matched_level = rule.level

        # Check for explicit criticality tag
        explicit_criticality = tags.get("criticality", tags.get("Criticality", ""))
        if explicit_criticality:
            factors.append({
                "level": explicit_criticality.lower(),
                "reason": "Explicit criticality tag",
            })

        return {
            "level": matched_level,
            "reason": factors[0]["reason"] if factors else "Default classification",
            "factors": factors,
            "confidence": 0.9 if factors else 0.5,
        }

    def _determine_owner(
        self,
        asset: Asset,
        business_unit: BusinessUnitMapping | None,
    ) -> dict[str, Any] | None:
        """Determine asset owner from tags and business unit."""
        tags = asset.tags or {}

        owner_info: dict[str, Any] = {}

        # Check common owner tags
        owner_tags = ["owner", "Owner", "team", "Team", "created_by", "CreatedBy"]
        for tag in owner_tags:
            if tag in tags:
                owner_info["owner"] = tags[tag]
                owner_info["source"] = f"tag:{tag}"
                break

        # Check email tags
        email_tags = ["owner_email", "OwnerEmail", "contact", "Contact"]
        for tag in email_tags:
            if tag in tags:
                owner_info["email"] = tags[tag]
                break

        # Fall back to business unit owners
        if not owner_info and business_unit and business_unit.owners:
            owner_info["owner"] = business_unit.owners[0]
            owner_info["source"] = "business_unit_default"
            owner_info["all_owners"] = business_unit.owners
            owner_info["confidence"] = 0.6

        if owner_info:
            owner_info["confidence"] = owner_info.get("confidence", 0.8)
            return owner_info

        return None

    def _build_asset_context(self, asset: Asset) -> dict[str, Any]:
        """Build comprehensive asset context."""
        tags = asset.tags or {}

        # Determine environment
        env = tags.get("environment", tags.get("Environment", tags.get("env", "")))
        if not env:
            # Try to infer from name
            name_lower = asset.name.lower()
            if any(p in name_lower for p in ["prod", "prd", "production"]):
                env = "production"
            elif any(p in name_lower for p in ["stag", "stg", "staging"]):
                env = "staging"
            elif any(p in name_lower for p in ["dev", "development"]):
                env = "development"
            elif any(p in name_lower for p in ["test", "qa"]):
                env = "test"

        # Determine project/application
        project = tags.get("project", tags.get("Project", tags.get("application", "")))
        application = tags.get("application", tags.get("Application", tags.get("app", "")))

        # Determine cost center
        cost_center = tags.get("cost_center", tags.get("CostCenter", ""))

        return {
            "environment": env or "unknown",
            "project": project,
            "application": application,
            "cost_center": cost_center,
            "tags_count": len(tags),
            "has_standard_tags": bool(env or project or application),
            "created_at": asset.created_at.isoformat() if asset.created_at else None,
            "age_days": self._calculate_age_days(asset.created_at),
        }

    def _calculate_age_days(self, created_at: datetime | None) -> int | None:
        """Calculate age in days handling timezone-aware and naive datetimes."""
        if created_at is None:
            return None
        now = datetime.utcnow()
        # Handle timezone-aware datetimes by making them naive (UTC)
        if created_at.tzinfo is not None:
            created_at = created_at.replace(tzinfo=None)
        return (now - created_at).days

    def add_business_unit(self, mapping: BusinessUnitMapping) -> None:
        """Add a custom business unit mapping."""
        self.business_units.append(mapping)

    def add_criticality_rule(self, rule: CriticalityRule) -> None:
        """Add a custom criticality rule."""
        self.criticality_rules.insert(0, rule)  # Insert at beginning for priority


class TagEnricher(BaseAssetEnricher):
    """
    Enriches assets based on tag analysis.

    Provides tag-based insights and compliance checking.
    """

    # Required tags for different compliance frameworks
    REQUIRED_TAGS = {
        "aws_tagging_policy": ["Name", "Environment", "Owner", "Project"],
        "cost_allocation": ["CostCenter", "Project", "Environment"],
        "security_baseline": ["DataClassification", "Owner", "Environment"],
    }

    def __init__(
        self,
        required_tags: dict[str, list[str]] | None = None,
    ):
        """
        Initialize tag enricher.

        Args:
            required_tags: Custom required tag definitions
        """
        self.required_tags = required_tags or self.REQUIRED_TAGS

    @property
    def enricher_name(self) -> str:
        return "tag_enricher"

    @property
    def enrichment_types(self) -> list[EnrichmentType]:
        return [EnrichmentType.ASSET_CONTEXT]

    def enrich(self, asset: Asset) -> list[EnrichmentData]:
        """
        Enrich asset with tag analysis.

        Args:
            asset: Asset to enrich

        Returns:
            List of enrichment data
        """
        tags = asset.tags or {}

        # Analyze tag compliance
        compliance = {}
        for policy_name, required in self.required_tags.items():
            missing = [t for t in required if t not in tags]
            compliance[policy_name] = {
                "compliant": len(missing) == 0,
                "missing_tags": missing,
                "present_tags": [t for t in required if t in tags],
            }

        return [
            EnrichmentData(
                enrichment_type=EnrichmentType.ASSET_CONTEXT,
                source="tag_analysis",
                data={
                    "tag_count": len(tags),
                    "tag_compliance": compliance,
                    "is_fully_tagged": all(
                        c["compliant"] for c in compliance.values()
                    ),
                },
                confidence=1.0,
            )
        ]
