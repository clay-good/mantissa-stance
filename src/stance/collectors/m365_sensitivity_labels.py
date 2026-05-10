"""Microsoft Purview sensitivity-label inventory.

Lists published sensitivity labels and the tenant-wide labeling policy
flags (mandatory labeling, default labels). Emits one ``m365_sensitivity_label``
per label and one ``m365_label_policy_summary`` per tenant.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365SensitivityLabelsCollector(EntraCollector):
    collector_name = "m365_sensitivity_labels"
    resource_types = ["m365_sensitivity_label", "m365_label_policy_summary"]

    def collect(self) -> AssetCollection:
        labels: list[Asset] = []
        for label in self._iter("/v1.0/security/informationProtection/sensitivityLabels"):
            lid = label.get("id", "")
            cfg = {
                "label_id": lid,
                "name": label.get("name") or label.get("displayName", ""),
                "description": label.get("description", ""),
                "is_active": bool(label.get("isActive", True)),
                "is_default": bool(label.get("isDefault", False)),
                "applies_to": label.get("applicableTo", []) or [],
                "encryption_enabled": bool(
                    (label.get("contentMarking") or {}).get("isEnabled", False)
                    or label.get("hasProtection", False)
                ),
            }
            labels.append(
                Asset(
                    id=f"m365:sensitivity_label:{lid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="m365_sensitivity_label",
                    name=cfg["name"] or lid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        # Tenant-wide labeling policy: mandatory labeling, default label.
        policy = (
            self._get(
                "/beta/security/informationProtection/labelPolicy"
            )
            or {}
        )
        if "value" in policy and isinstance(policy["value"], list) and policy["value"]:
            policy = policy["value"][0]

        summary = Asset(
            id=f"m365:label_policy_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="m365_label_policy_summary",
            name="label-policy",
            last_seen=self._now(),
            raw_config={
                "label_count": len(labels),
                "active_label_count": sum(
                    1 for a in labels if a.raw_config["is_active"]
                ),
                "any_label_published": len(labels) > 0,
                "mandatory_labeling_enabled": bool(
                    policy.get("mandatoryLabelingEnabled", False)
                    or policy.get("isMandatory", False)
                ),
                "default_label_id": policy.get("defaultLabelId", ""),
                "downgrade_justification_required": bool(
                    policy.get("downgradeJustificationRequired", False)
                ),
            },
        )
        return AssetCollection(labels + [summary])
