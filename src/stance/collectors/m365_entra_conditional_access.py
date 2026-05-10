"""Microsoft Entra Conditional Access policy collector.

Emits one ``entra_ca_policy`` asset per CA policy plus a single
``entra_ca_summary`` that the policy engine can use for tenant-wide
"any policy does X" checks (legacy auth blocked, MFA for admins, compliant
device for admins).
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


_DIRECTORY_ROLE_ALL_GUIDS_HINT = "All"

_LEGACY_AUTH_PROTOCOLS: frozenset[str] = frozenset(
    {"exchangeActiveSync", "other"}  # Graph names
)


class EntraConditionalAccessCollector(EntraCollector):
    collector_name = "m365_entra_conditional_access"
    resource_types = ["entra_ca_policy", "entra_ca_summary"]

    def collect(self) -> AssetCollection:
        policies: list[Asset] = []
        any_blocks_legacy = False
        any_requires_mfa_for_admins = False
        any_requires_compliant_device_for_admins = False
        any_requires_mfa_all_users = False

        for p in self._iter("/v1.0/identity/conditionalAccess/policies"):
            asset = self._policy_to_asset(p)
            cfg = asset.raw_config
            if cfg["state"] == "enabled":
                if cfg["blocks_legacy_auth"]:
                    any_blocks_legacy = True
                if cfg["targets_admin_roles"]:
                    if cfg["requires_mfa"]:
                        any_requires_mfa_for_admins = True
                    if cfg["requires_compliant_device"]:
                        any_requires_compliant_device_for_admins = True
                if cfg["targets_all_users"] and cfg["requires_mfa"]:
                    any_requires_mfa_all_users = True
            policies.append(asset)

        summary = Asset(
            id=f"entra:ca_summary:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_ca_summary",
            name="conditional-access-summary",
            last_seen=self._now(),
            raw_config={
                "policy_count": len(policies),
                "enabled_policy_count": sum(
                    1 for a in policies if a.raw_config["state"] == "enabled"
                ),
                "any_policy_blocks_legacy_auth": any_blocks_legacy,
                "any_policy_requires_mfa_for_admins": any_requires_mfa_for_admins,
                "any_policy_requires_compliant_device_for_admins": (
                    any_requires_compliant_device_for_admins
                ),
                "any_policy_requires_mfa_all_users": any_requires_mfa_all_users,
            },
        )
        return AssetCollection(policies + [summary])

    def _policy_to_asset(self, p: dict[str, Any]) -> Asset:
        pid = p.get("id", "")
        conditions = p.get("conditions") or {}
        users = conditions.get("users") or {}
        client_apps = conditions.get("clientAppTypes", []) or []
        platforms = conditions.get("platforms") or {}
        applications = conditions.get("applications") or {}

        grant = p.get("grantControls") or {}
        built_in_controls = grant.get("builtInControls", []) or []

        included_roles = users.get("includeRoles", []) or []
        included_users = users.get("includeUsers", []) or []
        included_groups = users.get("includeGroups", []) or []

        targets_admin_roles = bool(included_roles) or any(
            "admin" in str(r).lower() for r in included_roles
        )
        targets_all_users = (
            "All" in included_users
            or "All" in included_groups
            or users.get("includeUsersGroupsAndRoles") == "All"
        )
        targets_all_apps = "All" in (applications.get("includeApplications", []) or [])

        requires_mfa = "mfa" in built_in_controls
        requires_compliant_device = "compliantDevice" in built_in_controls or (
            "domainJoinedDevice" in built_in_controls
        )
        blocks = "block" in built_in_controls

        # Legacy-auth detection: policies that block "exchangeActiveSync,other"
        # client app types are the canonical "block legacy auth" pattern.
        blocks_legacy_auth = (
            blocks
            and bool(set(client_apps) & _LEGACY_AUTH_PROTOCOLS)
        )

        cfg: dict[str, Any] = {
            "policy_id": pid,
            "display_name": p.get("displayName", ""),
            "state": p.get("state", "disabled"),
            "client_app_types": client_apps,
            "blocks_legacy_auth": blocks_legacy_auth,
            "targets_admin_roles": targets_admin_roles,
            "targets_all_users": targets_all_users,
            "targets_all_apps": targets_all_apps,
            "requires_mfa": requires_mfa,
            "requires_compliant_device": requires_compliant_device,
            "blocks": blocks,
            "included_roles": included_roles,
            "platforms_include": platforms.get("includePlatforms", []) or [],
        }
        return Asset(
            id=f"entra:ca_policy:{pid}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="entra_ca_policy",
            name=cfg["display_name"] or pid,
            last_seen=self._now(),
            raw_config=cfg,
        )
