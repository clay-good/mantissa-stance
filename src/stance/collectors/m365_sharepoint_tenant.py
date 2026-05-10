"""SharePoint tenant-level sharing settings collector.

Pulls ``/v1.0/admin/sharepoint/settings`` and emits one
``sharepoint_tenant_settings`` asset. The five fields most-checked by CIS
M365 (sharing capability, anonymous-link policy, default link type,
external collaboration domains, idle session timeout) are all normalized
into top-level booleans/enums on the asset's ``raw_config``.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


# SharePoint sharing capability values, in increasing permissiveness.
_SHARING_CAPABILITY_ORDER = {
    "disabled": 0,
    "existingExternalUserSharingOnly": 1,
    "externalUserSharingOnly": 2,
    "externalUserAndGuestSharing": 3,
}


class M365SharePointTenantCollector(EntraCollector):
    collector_name = "m365_sharepoint_tenant"
    resource_types = ["sharepoint_tenant_settings"]

    def collect(self) -> AssetCollection:
        s = self._get("/v1.0/admin/sharepoint/settings") or {}
        sharing = s.get("sharingCapability", "externalUserAndGuestSharing")
        allowed_domains = s.get("sharingAllowedDomainList", []) or []
        blocked_domains = s.get("sharingBlockedDomainList", []) or []
        domain_restriction = s.get(
            "sharingDomainRestrictionMode", "none"
        )  # "none" | "allowList" | "blockList"
        idle_timeout = s.get("idleSessionSignOut") or {}

        cfg: dict[str, Any] = {
            "sharing_capability": sharing,
            "sharing_capability_rank": _SHARING_CAPABILITY_ORDER.get(sharing, 3),
            "anonymous_links_disabled": sharing
            in ("disabled", "existingExternalUserSharingOnly", "externalUserSharingOnly"),
            "external_sharing_restricted": sharing
            in ("disabled", "existingExternalUserSharingOnly"),
            "default_link_type": s.get("defaultSharingLinkType", "anyone"),
            "default_link_to_existing_access": bool(
                s.get("defaultLinkToExistingAccess", False)
            ),
            "domain_restriction_mode": domain_restriction,
            "sharing_allowed_domains": allowed_domains,
            "sharing_blocked_domains": blocked_domains,
            "external_sharing_domain_allowlist_enforced": (
                domain_restriction == "allowList" and len(allowed_domains) > 0
            ),
            "idle_session_timeout_enabled": bool(idle_timeout.get("isEnabled", False)),
            "idle_session_timeout_minutes": int(
                idle_timeout.get("signOutAfterInSeconds", 0) or 0
            )
            // 60
            if isinstance(idle_timeout.get("signOutAfterInSeconds"), int)
            else None,
            "external_user_expiration_required": bool(
                s.get("externalUserExpirationRequired", False)
            ),
            "block_download_for_anonymous": bool(
                s.get("isLoopEnabled", False) is False
                or s.get("blockDownloadOfAllFilesOnUnmanagedDevices", False)
            ),
        }
        asset = Asset(
            id=f"sharepoint:tenant_settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="sharepoint_tenant_settings",
            name="sharepoint-tenant",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
