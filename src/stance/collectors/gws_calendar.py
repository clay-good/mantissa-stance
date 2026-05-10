"""Google Workspace Calendar external-sharing collector."""

from __future__ import annotations

from typing import Any

from stance.collectors._gws_policy_snapshot import merge_policy_settings
from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection


_FIELD_MAP: dict[str, str] = {
    "settings/calendar.external_sharing": "external_sharing_default",
    "settings/calendar.allow_video_recordings": "allow_video_recordings",
    "settings/calendar.warn_on_external_invite": "warn_on_external_invite",
}

_DEFAULTS: dict[str, Any] = {
    # Workspace default: full event-detail sharing with external users.
    "external_sharing_default": "READ_WRITE",
    "allow_video_recordings": True,
    "warn_on_external_invite": False,
}


def _extract(field: str, value: dict[str, Any]) -> Any:
    if field == "external_sharing_default":
        return value.get("level", value.get("default", "READ_WRITE")) or "READ_WRITE"
    return bool(value.get("enabled", value.get("allowed", False)))


class GWSCalendarCollector(SaaSCollector):
    collector_name = "gws_calendar"
    resource_types = ["gws_calendar_settings"]
    cloud_provider = "google_workspace"

    def __init__(
        self,
        service: Any,
        tenant_id: str,
        customer: str = "my_customer",
        primary_domain: str = "",
    ) -> None:
        super().__init__(service, tenant_id)
        self._customer = customer
        self._primary_domain = primary_domain

    def collect(self) -> AssetCollection:
        cfg = merge_policy_settings(
            self._service, self._customer, _FIELD_MAP, _DEFAULTS, _extract
        )
        cfg["external_sharing_restricted"] = cfg["external_sharing_default"] in (
            "ONLY_FREE_BUSY",
            "NO_SHARING",
            "OFF",
        )
        asset = Asset(
            id=f"gws:calendar_settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_calendar_settings",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
