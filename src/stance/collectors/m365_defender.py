"""Microsoft Defender for Office 365 anti-phish / safe-links / safe-attachments
policy collector.

Lists the three Defender policy families that CIS M365 mandates and emits a
single ``defender_policy_summary`` asset capturing whether each family has
at least one enabled, "Strict"-grade policy in scope. Per-policy assets are
also emitted for inventory.

Defender policies are exposed under ``/beta/security/threatProtection`` in
Graph beta. Where a tenant has Defender for Office 365 P1/P2 disabled, the
endpoints return empty lists and the summary reports `False` for every
family — the correct posture for a tenant with no Defender coverage at all.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365DefenderCollector(EntraCollector):
    collector_name = "m365_defender"
    resource_types = ["defender_policy", "defender_policy_summary"]

    def collect(self) -> AssetCollection:
        sl = list(self._iter("/beta/security/threatProtection/safeLinksPolicies"))
        sa = list(self._iter("/beta/security/threatProtection/safeAttachmentsPolicies"))
        ap = list(self._iter("/beta/security/threatProtection/antiPhishingPolicies"))

        per_policy: list[Asset] = []
        per_policy.extend(self._policy_assets(sl, "safe_links"))
        per_policy.extend(self._policy_assets(sa, "safe_attachments"))
        per_policy.extend(self._policy_assets(ap, "anti_phish"))

        summary_cfg: dict[str, Any] = {
            "safe_links_policy_count": len(sl),
            "safe_attachments_policy_count": len(sa),
            "anti_phish_policy_count": len(ap),
            "any_safe_links_policy_enabled": any(
                p.get("isEnabled", True) for p in sl
            ),
            "any_safe_attachments_policy_enabled": any(
                p.get("isEnabled", True) for p in sa
            ),
            "any_anti_phish_policy_enabled": any(
                p.get("isEnabled", True) for p in ap
            ),
            "any_anti_phish_strict_policy_enabled": any(
                p.get("isEnabled", True)
                and (
                    p.get("preset") == "Strict"
                    or "strict" in (p.get("name") or p.get("displayName") or "").lower()
                    or p.get("enableMailboxIntelligenceProtection")
                )
                for p in ap
            ),
        }
        summary = Asset(
            id=f"defender:summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="defender_policy_summary",
            name="defender-summary",
            last_seen=self._now(),
            raw_config=summary_cfg,
        )
        return AssetCollection(per_policy + [summary])

    def _policy_assets(
        self, policies: list[dict[str, Any]], family: str
    ) -> list[Asset]:
        out: list[Asset] = []
        for p in policies:
            pid = p.get("id") or p.get("name", "")
            cfg = {
                "policy_id": pid,
                "family": family,
                "name": p.get("name") or p.get("displayName", ""),
                "is_enabled": bool(p.get("isEnabled", True)),
                "preset": p.get("preset", ""),
                "raw": p,
            }
            out.append(
                Asset(
                    id=f"defender:{family}:{pid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="defender_policy",
                    name=cfg["name"] or pid,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return out
