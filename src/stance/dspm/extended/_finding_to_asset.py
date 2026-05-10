"""Adapter: ExtendedScanFinding → stance.models.Asset.

DSPM scanners emit :class:`ExtendedScanFinding` records that go directly
into the reporter pipeline (HTML/CSV/JSON). To make them evaluable by the
existing YAML policy engine we expose a thin converter that surfaces the
fields the ``policies/saas/dspm/*.yaml`` rules check.

The resulting asset uses ``resource_type="dspm_finding"``. ``raw_config``
carries:
  - ``classification`` (str, e.g. "restricted")
  - ``categories`` (list[str], e.g. ["pii_ssn", "pci_card"])
  - ``has_pii`` / ``has_phi`` / ``has_pci`` (bool, derived from categories)
  - ``link_type`` (str), ``has_anyone_with_link`` (bool)
  - ``has_external_sharing`` (bool), ``external_user_count`` (int)
  - ``exposure_score`` (float), ``severity_band`` (str)
  - ``source_type`` (str), ``source_location`` (str), ``object_name`` (str)
"""

from __future__ import annotations

from typing import Any

from stance.dspm.extended._saas_exposure import severity_band
from stance.dspm.extended.base import ExtendedScanFinding
from stance.models import Asset


_PII_HINTS = ("pii", "name", "email", "phone", "ssn", "passport", "tax")
_PCI_HINTS = ("pci", "card", "iban", "bank")
_PHI_HINTS = ("phi", "medical", "health", "diagnosis")


def _has_category(categories: list[str], hints: tuple[str, ...]) -> bool:
    return any(any(h in c for h in hints) for c in categories)


def finding_to_asset(finding: ExtendedScanFinding, *, tenant_id: str) -> Asset:
    """Build a ``dspm_finding`` Asset from an :class:`ExtendedScanFinding`."""
    categories = [c.value for c in finding.categories]
    md = finding.metadata or {}
    link_type = (md.get("item_link_type") or "").lower()
    exposure = float(md.get("exposure_score") or 0.0)

    cfg: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "source_type": finding.source_type.value,
        "source_location": finding.source_location,
        "object_type": finding.object_type,
        "object_name": finding.object_name,
        "classification": finding.classification_level.value,
        "categories": categories,
        "has_pii": _has_category(categories, _PII_HINTS),
        "has_pci": _has_category(categories, _PCI_HINTS),
        "has_phi": _has_category(categories, _PHI_HINTS),
        "link_type": link_type,
        "has_anyone_with_link": link_type in ("anyone", "anonymous", "anyone_with_link"),
        "has_external_sharing": bool(
            md.get("site_external_user_count", 0)
            or md.get("external_perm_count", 0)
            or md.get("external_recipient_count", 0)
        ),
        "external_user_count": int(
            md.get("site_external_user_count", 0)
            or md.get("external_perm_count", 0)
            or md.get("external_recipient_count", 0)
        ),
        "exposure_score": exposure,
        "severity_band": severity_band(exposure),
    }

    return Asset(
        id=f"dspm:finding:{finding.finding_id}",
        cloud_provider=finding.source_type.value.split("_", 1)[0]
        if "_" in finding.source_type.value
        else finding.source_type.value,
        account_id=tenant_id,
        region="global",
        resource_type="dspm_finding",
        name=finding.object_name,
        raw_config=cfg,
    )
