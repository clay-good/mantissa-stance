"""Google Workspace Chrome browser/OS posture collector."""

from __future__ import annotations

from typing import Any

from stance.collectors._gws_policy_snapshot import merge_policy_settings
from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection


_FIELD_MAP: dict[str, str] = {
    "settings/chrome.enterprise_enrollment": "enterprise_policies_enforced",
    "settings/chrome.extension_install_mode": "extension_install_mode",
    "settings/chrome.extension_allowlist": "extension_allowlist",
    "settings/chrome.safe_browsing": "safe_browsing_mode",
    "settings/chrome.password_manager": "password_manager_enforced",
    "settings/chrome.force_install": "force_install_count",
}

# Workspace defaults: enterprise policy not enforced, no allowlist, safe
# browsing on but not enforced.
_DEFAULTS: dict[str, Any] = {
    "enterprise_policies_enforced": False,
    "extension_install_mode": "BLOCKLIST",  # default = "anything not blocked is allowed"
    "extension_allowlist": [],
    "safe_browsing_mode": "STANDARD",
    "password_manager_enforced": False,
    "force_install_count": 0,
}


def _extract(field: str, value: dict[str, Any]) -> Any:
    if field == "enterprise_policies_enforced":
        return bool(value.get("enforced", value.get("enabled", False)))
    if field == "extension_install_mode":
        return value.get("mode", "BLOCKLIST") or "BLOCKLIST"
    if field == "extension_allowlist":
        return list(value.get("ids", value.get("allowlist", [])) or [])
    if field == "safe_browsing_mode":
        return value.get("mode", value.get("level", "STANDARD")) or "STANDARD"
    if field == "password_manager_enforced":
        return bool(value.get("enforced", False))
    if field == "force_install_count":
        return int(value.get("count", value.get("size", 0)) or 0)
    return value


class GWSChromeCollector(SaaSCollector):
    collector_name = "gws_chrome"
    resource_types = ["gws_chrome_policy"]
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
        cfg["extension_allowlist_only"] = cfg["extension_install_mode"] in (
            "ALLOWLIST",
            "FORCE_INSTALL",
        )
        cfg["safe_browsing_enforced"] = cfg["safe_browsing_mode"] in (
            "ENHANCED",
            "ENFORCED",
        )
        asset = Asset(
            id=f"gws:chrome_policy:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_chrome_policy",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=cfg,
        )
        return AssetCollection([asset])
