"""SharePoint per-site posture collector.

Lists tenant sites and, for each, captures sharing capability, sensitivity
label, anonymous-link state, external-user count, and managed-device
restrictions. Emits one ``sharepoint_site`` asset per site.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


_SHARING_CAPABILITY_ORDER = {
    "disabled": 0,
    "existingExternalUserSharingOnly": 1,
    "externalUserSharingOnly": 2,
    "externalUserAndGuestSharing": 3,
}


class M365SharePointSitesCollector(EntraCollector):
    collector_name = "m365_sharepoint_sites"
    resource_types = ["sharepoint_site"]

    def collect(self) -> AssetCollection:
        out: list[Asset] = []
        for site in self._iter("/v1.0/sites?search=*&$select=id,displayName,webUrl"):
            site_id = site.get("id", "")
            web_url = site.get("webUrl", "")
            display = site.get("displayName", "")

            details = self._get(f"/v1.0/admin/sharepoint/sites/{site_id}") or {}
            sharing = details.get("sharingCapability", "")
            label = details.get("sensitivityLabel") or {}
            cfg: dict[str, Any] = {
                "site_id": site_id,
                "display_name": display,
                "web_url": web_url,
                "sharing_capability": sharing,
                "sharing_capability_rank": _SHARING_CAPABILITY_ORDER.get(sharing, 3),
                "anonymous_links_disabled": sharing in (
                    "disabled",
                    "existingExternalUserSharingOnly",
                    "externalUserSharingOnly",
                ),
                "external_sharing_restricted": sharing in (
                    "disabled",
                    "existingExternalUserSharingOnly",
                ),
                "external_user_count": int(details.get("externalUserCount", 0) or 0),
                "has_external_users": int(details.get("externalUserCount", 0) or 0) > 0,
                "sensitivity_label_id": label.get("id", ""),
                "sensitivity_label_name": label.get("displayName", ""),
                "is_labelled": bool(label.get("id")),
                "block_download_unmanaged_devices": bool(
                    details.get("blockDownloadOfAllFilesOnUnmanagedDevices", False)
                ),
                "is_archived": bool(details.get("isArchived", False)),
            }
            out.append(
                Asset(
                    id=f"sharepoint:site:{site_id}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="sharepoint_site",
                    name=display or web_url or site_id,
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            )
        return AssetCollection(out)
