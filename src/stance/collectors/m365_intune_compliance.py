"""Intune device-compliance policy inventory.

Enumerates device-compliance policies and their assignments so the
``compliance-policy-required-for-corporate`` rule can verify that every
platform with corporate enrollments has an enforced compliance baseline.
Emits one ``intune_compliance_policy`` per policy and one
``intune_compliance_summary`` per tenant.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


_CORPORATE_PLATFORMS: frozenset[str] = frozenset(
    {"windows10", "iOS", "macOS", "androidWorkProfile", "windows81"}
)


class M365IntuneComplianceCollector(EntraCollector):
    collector_name = "m365_intune_compliance"
    resource_types = ["intune_compliance_policy", "intune_compliance_summary"]

    def collect(self) -> AssetCollection:
        per_policy: list[Asset] = []
        platforms_with_active_policy: set[str] = set()
        for p in self._iter("/v1.0/deviceManagement/deviceCompliancePolicies"):
            pid = p.get("id", "")
            type_str = (p.get("@odata.type") or "").lower()
            platform = self._infer_platform(type_str, p)
            assignments = list(
                self._iter(
                    f"/v1.0/deviceManagement/deviceCompliancePolicies/{pid}/assignments"
                )
            )
            cfg = {
                "policy_id": pid,
                "name": p.get("displayName", ""),
                "platform": platform,
                "assignment_count": len(assignments),
                "is_assigned": len(assignments) > 0,
                "passcode_required": bool(p.get("passcodeRequired", False)),
                "storage_encryption_required": bool(
                    p.get("storageRequireEncryption", False)
                ),
                "os_minimum_version": p.get("osMinimumVersion", ""),
            }
            if cfg["is_assigned"] and platform:
                platforms_with_active_policy.add(platform)
            per_policy.append(
                Asset(
                    id=f"intune:compliance_policy:{pid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="intune_compliance_policy",
                    name=cfg["name"] or pid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        missing = sorted(_CORPORATE_PLATFORMS - platforms_with_active_policy)
        summary = Asset(
            id=f"intune:compliance_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="intune_compliance_summary",
            name="intune-compliance",
            last_seen=self._now(),
            raw_config={
                "policy_count": len(per_policy),
                "assigned_policy_count": sum(
                    1 for a in per_policy if a.raw_config.get("is_assigned")
                ),
                "platforms_with_assigned_policy": sorted(
                    platforms_with_active_policy
                ),
                "corporate_platforms_missing_policy": missing,
                "all_corporate_platforms_covered": missing == [],
            },
        )
        return AssetCollection(per_policy + [summary])

    @staticmethod
    def _infer_platform(type_str: str, p: dict[str, Any]) -> str:
        for plat in _CORPORATE_PLATFORMS | {"android"}:
            if plat.lower() in type_str:
                return plat
        return p.get("platform", "")
