"""OneDrive sharing/sync posture collector.

Reads OneDrive-specific settings from
``/v1.0/admin/sharepoint/settings`` (the SharePoint and OneDrive admin
controls share a payload but the OneDrive-flavored fields are namespaced)
plus the OneDrive sync-client restrictions. Emits a single
``onedrive_settings`` asset.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


_SHARING_RANK = {
    "disabled": 0,
    "existingExternalUserSharingOnly": 1,
    "externalUserSharingOnly": 2,
    "externalUserAndGuestSharing": 3,
}


class M365OneDriveCollector(EntraCollector):
    collector_name = "m365_onedrive"
    resource_types = ["onedrive_settings"]

    def collect(self) -> AssetCollection:
        s = self._get("/v1.0/admin/sharepoint/settings") or {}
        # OneDrive-specific knobs: sharing + sync client posture.
        od_sharing = s.get(
            "oneDriveSharingCapability",
            s.get("sharingCapability", "externalUserAndGuestSharing"),
        )
        sync = s.get("oneDriveSyncRestrictions") or {}

        cfg: dict[str, Any] = {
            "sharing_capability": od_sharing,
            "sharing_capability_rank": _SHARING_RANK.get(od_sharing, 3),
            "external_sharing_restricted": od_sharing in (
                "disabled",
                "existingExternalUserSharingOnly",
            ),
            "default_link_type": s.get(
                "oneDriveDefaultSharingLinkType",
                s.get("defaultSharingLinkType", "anyone"),
            ),
            "sync_to_managed_devices_only": bool(
                sync.get("allowSyncOnlyOnManagedDevices", False)
            ),
            "sync_blocked_domains": sync.get("blockedDomains", []) or [],
            "sync_blocked_file_extensions": s.get(
                "excludedFileExtensionsForSyncApp", []
            )
            or [],
            "block_macos_sync": bool(sync.get("blockMacOSSync", False)),
            "block_download_unmanaged_devices": bool(
                s.get("blockDownloadOfAllFilesOnUnmanagedDevices", False)
            ),
        }
        asset = Asset(
            id=f"onedrive:settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="onedrive_settings",
            name="onedrive",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
