"""Microsoft Teams admin-policy collector.

Snapshots the four Teams admin posture surfaces relevant to CIS M365:
external access (federation with other Teams tenants and Skype), guest
access, app permission policy, and the global meeting policy where it
overlaps with external join.
"""

from __future__ import annotations

from typing import Any

from stance.collectors.m365_base import EntraCollector
from stance.models import Asset, AssetCollection


class M365TeamsCollector(EntraCollector):
    collector_name = "m365_teams"
    resource_types = ["teams_settings"]

    def collect(self) -> AssetCollection:
        ext = (
            self._get("/beta/admin/teams/federationConfiguration")
            or self._get("/beta/admin/teams/externalAccessConfiguration")
            or {}
        )
        guest = self._get("/beta/admin/teams/guestAccessConfiguration") or {}
        apps = self._get("/beta/admin/teams/appSetupPolicy") or {}
        meeting = self._get("/beta/admin/teams/meetingPolicy") or {}

        external_access_enabled = bool(
            ext.get("allowFederatedUsers", ext.get("allowTeamsConsumer", True))
        )
        federation_mode = ext.get("federationMode", "open")
        # "blocklist" / "allowlist" / "open" / "blocked"
        external_access_restricted = federation_mode in ("allowlist", "blocked") or (
            not external_access_enabled
        )

        cfg: dict[str, Any] = {
            "external_access_enabled": external_access_enabled,
            "external_access_restricted": external_access_restricted,
            "federation_mode": federation_mode,
            "allowed_domains": ext.get("allowedDomains", []) or [],
            "blocked_domains": ext.get("blockedDomains", []) or [],
            "allow_teams_consumer": bool(ext.get("allowTeamsConsumer", True)),
            "allow_skype_users": bool(ext.get("allowFederatedUsers", True)),
            "guest_access_enabled": bool(
                guest.get("allowGuestUser", True)
            ),
            "guest_can_make_calls": bool(guest.get("allowMakePrivateCalls", True)),
            "guest_can_share_screen": bool(guest.get("allowScreenSharing", True)),
            "guest_can_meet_now": bool(guest.get("allowMeetNow", True)),
            "guest_access_controlled": (
                bool(guest.get("allowGuestUser", True))
                and not bool(guest.get("allowMakePrivateCalls", True))
                and not bool(guest.get("allowMeetNow", True))
            ),
            "app_permission_policy_default": apps.get("defaultPolicy", "AllowAllApps"),
            "app_permission_policy_enforced": apps.get("defaultPolicy", "AllowAllApps")
            in ("BlockAllApps", "AllowSpecificApps", "Restricted"),
            "anonymous_join_allowed": bool(
                meeting.get("allowAnonymousUsersToJoinMeeting", True)
            ),
        }
        asset = Asset(
            id=f"teams:settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="teams_settings",
            name="teams",
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
