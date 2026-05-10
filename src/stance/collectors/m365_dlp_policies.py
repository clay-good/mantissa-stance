"""Microsoft Purview / M365 DLP policy inventory.

Lists tenant DLP policies and their enabled/disabled state. Emits one
``m365_dlp_policy`` per policy plus an ``m365_dlp_summary`` so the
``sensitive-info-dlp-policy-active`` rule can be a single check.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


# Sensitive-info-type names that satisfy "covers PII / financial / health".
_SENSITIVE_INFO_HINTS: frozenset[str] = frozenset(
    {
        "credit card", "social security", "ssn", "passport", "iban",
        "tax", "bank", "phi", "medical", "health", "pii",
    }
)


class M365DLPPoliciesCollector(EntraCollector):
    collector_name = "m365_dlp_policies"
    resource_types = ["m365_dlp_policy", "m365_dlp_summary"]

    def collect(self) -> AssetCollection:
        per_policy: list[Asset] = []
        any_enabled_with_sensitive = False
        for p in self._iter("/beta/security/dataLossPreventionPolicies"):
            pid = p.get("id", "")
            mode = p.get("mode", "Enable")  # "Enable" / "TestWithNotifications" / "Disable"
            sit_names = self._extract_sensitive_info_types(p)
            enabled = mode == "Enable"
            covers_sensitive = any(
                any(hint in (s or "").lower() for hint in _SENSITIVE_INFO_HINTS)
                for s in sit_names
            )
            cfg = {
                "policy_id": pid,
                "name": p.get("name") or p.get("displayName", ""),
                "mode": mode,
                "is_enabled": enabled,
                "workloads": p.get("workloads", []) or [],
                "sensitive_info_types": sit_names,
                "covers_sensitive_info_types": covers_sensitive,
            }
            if enabled and covers_sensitive:
                any_enabled_with_sensitive = True
            per_policy.append(
                Asset(
                    id=f"m365:dlp_policy:{pid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="m365_dlp_policy",
                    name=cfg["name"] or pid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )

        summary = Asset(
            id=f"m365:dlp_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="m365_dlp_summary",
            name="dlp-summary",
            last_seen=self._now(),
            raw_config={
                "policy_count": len(per_policy),
                "enabled_policy_count": sum(
                    1 for a in per_policy if a.raw_config["is_enabled"]
                ),
                "any_enabled_policy_covers_sensitive_info": (
                    any_enabled_with_sensitive
                ),
            },
        )
        return AssetCollection(per_policy + [summary])

    @staticmethod
    def _extract_sensitive_info_types(p: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for rule in p.get("rules", []) or []:
            for cond in rule.get("conditions", []) or []:
                for sit in cond.get("sensitiveInformationTypes", []) or []:
                    name = sit.get("name") or sit.get("displayName")
                    if name:
                        out.append(name)
        return out
