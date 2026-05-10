"""Microsoft Entra security defaults collector.

Reads ``/policies/identitySecurityDefaultsEnforcementPolicy`` and emits a
single ``entra_security_defaults`` asset.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class EntraSecurityDefaultsCollector(EntraCollector):
    """Snapshots security-defaults state and synthesizes an
    ``entra_tenant_baseline`` asset that records whether the tenant has
    *some* identity baseline in effect — either security defaults or at
    least one enabled Conditional Access policy. The baseline asset exists
    to satisfy the "security-defaults-or-conditional-access" rule, which is
    inherently an OR across two collectors' surfaces.
    """

    collector_name = "m365_entra_security_defaults"
    resource_types = ["entra_security_defaults", "entra_tenant_baseline"]

    def collect(self) -> AssetCollection:
        policy = self._get(
            "/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
        ) or {}
        if "value" in policy and isinstance(policy["value"], list) and policy["value"]:
            policy = policy["value"][0]
        sd_enabled = bool(policy.get("isEnabled", False))
        cfg: dict[str, Any] = {
            "is_enabled": sd_enabled,
            "display_name": policy.get("displayName", ""),
            "description": policy.get("description", ""),
        }
        sd_asset = Asset(
            id=f"entra:security_defaults:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_security_defaults",
            name="security-defaults",
            last_seen=self._now(),
            raw_config=cfg,
        )

        enabled_ca = 0
        for ca in self._iter("/v1.0/identity/conditionalAccess/policies"):
            if ca.get("state") == "enabled":
                enabled_ca += 1
        baseline_cfg: dict[str, Any] = {
            "security_defaults_enabled": sd_enabled,
            "enabled_ca_policy_count": enabled_ca,
            "has_identity_baseline": sd_enabled or enabled_ca > 0,
        }
        baseline = Asset(
            id=f"entra:tenant_baseline:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_tenant_baseline",
            name="entra-tenant-baseline",
            last_seen=self._now(),
            raw_config=baseline_cfg,
        )
        return AssetCollection([sd_asset, baseline])
