"""Power Platform tenant DLP-policy collector.

Power Platform's DLP groups *connectors* into Business / Non-Business /
Blocked classes; absence of a tenant-default DLP policy is a frequent
real-world finding because makers can otherwise wire SQL/HTTP connectors
to public Twitter or Webhook endpoints unchecked.

Emits one ``power_platform_dlp_policy`` per policy plus a tenant summary.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365PowerPlatformCollector(EntraCollector):
    collector_name = "m365_power_platform"
    resource_types = [
        "power_platform_dlp_policy",
        "power_platform_dlp_summary",
    ]

    def collect(self) -> AssetCollection:
        per_policy: list[Asset] = []
        for p in self._iter(
            "/providers/PowerPlatform.Governance/v1/policies"
        ) or self._iter(
            "/beta/admin/powerPlatform/dlpPolicies"
        ):
            pid = p.get("name") or p.get("id", "")
            classes = (p.get("connectorGroups") or {})
            cfg = {
                "policy_id": pid,
                "name": p.get("displayName", ""),
                "environment_type": p.get("environmentType", ""),
                "default_classification": p.get(
                    "defaultConnectorsClassification", ""
                ),
                "business_connector_count": len(
                    classes.get("Confidential", []) or []
                ),
                "non_business_connector_count": len(
                    classes.get("General", []) or []
                ),
                "blocked_connector_count": len(classes.get("Blocked", []) or []),
                "is_tenant_default": p.get("environmentType", "") == "AllEnvironments",
            }
            per_policy.append(
                Asset(
                    id=f"power_platform:dlp_policy:{pid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="power_platform_dlp_policy",
                    name=cfg["name"] or pid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        summary = Asset(
            id=f"power_platform:dlp_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="power_platform_dlp_summary",
            name="power-platform-dlp",
            last_seen=self._now(),
            raw_config={
                "policy_count": len(per_policy),
                "any_tenant_default_policy": any(
                    a.raw_config.get("is_tenant_default") for a in per_policy
                ),
            },
        )
        return AssetCollection(per_policy + [summary])
