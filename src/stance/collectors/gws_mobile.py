"""Google Workspace mobile-management posture collector."""

from __future__ import annotations

from typing import Any

from stance.collectors._gws_policy_snapshot import merge_policy_settings
from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection


_FIELD_MAP: dict[str, str] = {
    "settings/mobile.management_mode": "management_mode",
    "settings/mobile.screen_lock_required": "screen_lock_required",
    "settings/mobile.encryption_required": "encryption_required",
    "settings/mobile.device_approval_required": "device_approval_required",
    "settings/mobile.allow_personal_devices": "allow_personal_devices",
}

_DEFAULTS: dict[str, Any] = {
    "management_mode": "BASIC",  # BASIC | ADVANCED | CUSTOM
    "screen_lock_required": False,
    "encryption_required": False,
    "device_approval_required": False,
    "allow_personal_devices": True,
}


def _extract(field: str, value: dict[str, Any]) -> Any:
    if field == "management_mode":
        return value.get("mode", "BASIC") or "BASIC"
    return bool(value.get("enabled", value.get("required", False)))


class GWSMobileCollector(SaaSCollector):
    collector_name = "gws_mobile"
    resource_types = ["gws_mobile_settings"]
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
        cfg["advanced_management_required"] = cfg["management_mode"] in (
            "ADVANCED",
            "CUSTOM",
        )
        asset = Asset(
            id=f"gws:mobile_settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_mobile_settings",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
