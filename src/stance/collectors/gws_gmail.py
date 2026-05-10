"""Google Workspace Gmail security-settings collector."""

from __future__ import annotations

from typing import Any

from stance.collectors._gws_policy_snapshot import merge_policy_settings
from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection


_FIELD_MAP: dict[str, str] = {
    "settings/gmail.attachment_compliance": "attachment_compliance_enabled",
    "settings/gmail.content_compliance": "content_compliance_enabled",
    "settings/gmail.smime": "smime_enabled",
    "settings/gmail.confidential_mode": "confidential_mode_enabled",
    "settings/gmail.external_recipient_warning": (
        "external_recipient_warning_enabled"
    ),
    "settings/gmail.org_wide_forwarding": "org_wide_forwarding_allowed",
    "settings/gmail.allowlist_required": "allowlist_required",
    "settings/gmail.spam_filter": "spam_filter_enabled",
}


_DEFAULTS: dict[str, Any] = {
    "attachment_compliance_enabled": False,
    "content_compliance_enabled": False,
    "smime_enabled": False,
    "confidential_mode_enabled": True,
    "external_recipient_warning_enabled": False,
    "org_wide_forwarding_allowed": True,
    "allowlist_required": False,
    "spam_filter_enabled": True,
}


def _extract(field: str, value: dict[str, Any]) -> Any:
    if field == "org_wide_forwarding_allowed":
        return bool(value.get("allowed", value.get("enabled", True)))
    return bool(value.get("enabled", value.get("enforced", False)))


class GWSGmailCollector(SaaSCollector):
    """Snapshots tenant-wide Gmail security settings."""

    collector_name = "gws_gmail"
    resource_types = ["gws_gmail_settings"]
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
        config = merge_policy_settings(
            self._service, self._customer, _FIELD_MAP, _DEFAULTS, _extract
        )
        # Derived: the policy `smime-or-confidential-mode` accepts either.
        config["smime_or_confidential_mode_enabled"] = bool(
            config.get("smime_enabled") or config.get("confidential_mode_enabled")
        )
        asset = Asset(
            id=f"gws:gmail_settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_gmail_settings",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=config,
        )
        return AssetCollection([asset])
