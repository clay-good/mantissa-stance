"""
Google Workspace Drive sharing-settings collector.

Produces two resource types:

- ``gws_drive_settings`` — one tenant-level snapshot of Drive sharing defaults
  (external sharing, link-sharing default audience, trust rules, target
  audiences, shared-drive defaults). Sourced from Cloud Identity Policy API
  setting types under ``settings/drive.*``.
- ``gws_shared_drive`` — one asset per shared drive, with the tenant
  restrictions in effect (``domainUsersOnly``, ``copyRequiresWriterPermission``,
  ``driveMembersOnly``, ``adminManagedRestrictions``) and an external-member
  count when membership is enumerable.

The collector is read-only and tolerant of partial data: missing policies fall
back to documented Workspace defaults so the engine still has something to
evaluate.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


_DRIVE_FIELD_MAP: dict[str, str] = {
    "settings/drive.sharing_options": "external_sharing_mode",
    "settings/drive.link_sharing_defaults": "link_sharing_default",
    "settings/drive.shared_drive_creation": "shared_drive_creation_allowed",
    "settings/drive.warn_on_external_sharing": "warn_on_external_sharing",
    "settings/drive.allow_publishing_to_web": "allow_publishing_to_web",
    "settings/drive.target_audiences": "default_target_audiences",
    "settings/drive.trust_rules_enabled": "trust_rules_enabled",
    "settings/drive.shared_drive_default_membership": (
        "shared_drive_default_membership"
    ),
}


# Workspace defaults if the Policy API gives us nothing.
_DRIVE_DEFAULTS: dict[str, Any] = {
    # Modes per Workspace Drive sharing settings: "OFF", "ALLOWLIST",
    # "TRUSTED_DOMAINS", "ON". "ON" = anyone can share externally.
    "external_sharing_mode": "ON",
    "link_sharing_default": "ANYONE_WITH_LINK",
    "shared_drive_creation_allowed": True,
    "warn_on_external_sharing": False,
    "allow_publishing_to_web": True,
    "default_target_audiences": [],
    "trust_rules_enabled": False,
    "shared_drive_default_membership": "DOMAIN",
}


class GWSDriveSettingsCollector(SaaSCollector):
    """Collects Google Workspace Drive sharing posture."""

    collector_name = "gws_drive_settings"
    resource_types = ["gws_drive_settings", "gws_shared_drive"]
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
        self._primary_domain = primary_domain.lower()

    def collect(self) -> AssetCollection:
        assets: list[Asset] = []
        try:
            assets.append(self._collect_tenant_settings())
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("gws_drive_settings: tenant settings failed: %s", e)
        try:
            assets.extend(self._collect_shared_drives())
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("gws_drive_settings: shared drives failed: %s", e)
        return AssetCollection(assets)

    # ----------------------------------------------------------- tenant blob

    def _collect_tenant_settings(self) -> Asset:
        config: dict[str, Any] = dict(_DRIVE_DEFAULTS)
        try:
            policies = self._service.policies()
            request = policies.list(
                filter=f"customer=={self._customer}", pageSize=200
            )
            response = request.execute() or {}
            for policy in response.get("policies", []) or []:
                setting = policy.get("setting", {}) or {}
                type_key = policy.get("type") or setting.get("type", "")
                value = setting.get("value", {}) or {}
                field = _DRIVE_FIELD_MAP.get(type_key)
                if field is None:
                    continue
                config[field] = self._extract(field, value)
        except Exception as e:
            logger.debug("gws_drive_settings: policies.list unavailable: %s", e)

        config["external_sharing_disabled"] = config["external_sharing_mode"] in (
            "OFF",
            "DISABLED",
        )
        config["external_sharing_restricted"] = config["external_sharing_mode"] in (
            "OFF",
            "DISABLED",
            "ALLOWLIST",
            "TRUSTED_DOMAINS",
        )
        config["link_sharing_default_private"] = config["link_sharing_default"] in (
            "PRIVATE",
            "DOMAIN",
            "OFF",
        )

        return Asset(
            id=f"gws:drive_settings:{self._tenant_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_drive_settings",
            name=self._primary_domain or self._tenant_id,
            last_seen=self._now(),
            raw_config=config,
        )

    @staticmethod
    def _extract(field: str, value: dict[str, Any]) -> Any:
        if field == "external_sharing_mode":
            return value.get("mode", value.get("sharingMode", "ON")) or "ON"
        if field == "link_sharing_default":
            return value.get("defaultAccess", value.get("audience", "ANYONE_WITH_LINK"))
        if field == "shared_drive_creation_allowed":
            return bool(value.get("allowed", value.get("enabled", True)))
        if field == "warn_on_external_sharing":
            return bool(value.get("enabled", value.get("warn", False)))
        if field == "allow_publishing_to_web":
            return bool(value.get("enabled", value.get("allowed", True)))
        if field == "default_target_audiences":
            return list(value.get("audiences", []) or [])
        if field == "trust_rules_enabled":
            return bool(value.get("enabled", False))
        if field == "shared_drive_default_membership":
            return value.get("membership", "DOMAIN")
        return value

    # ----------------------------------------------------------- shared drives

    def _collect_shared_drives(self) -> Iterator[Asset]:
        drives_resource = self._service.drives()
        request = drives_resource.list(
            useDomainAdminAccess=True,
            pageSize=100,
            fields=(
                "nextPageToken,drives(id,name,createdTime,restrictions,"
                "capabilities,hidden)"
            ),
        )
        while request is not None:
            response = request.execute() or {}
            for drive in response.get("drives", []) or []:
                yield self._drive_to_asset(drive)
            list_next = getattr(drives_resource, "list_next", None)
            request = list_next(request, response) if list_next else None

    def _drive_to_asset(self, drive: dict[str, Any]) -> Asset:
        drive_id = drive.get("id", "")
        restrictions = drive.get("restrictions", {}) or {}
        cfg: dict[str, Any] = {
            "drive_id": drive_id,
            "drive_name": drive.get("name", ""),
            "hidden": bool(drive.get("hidden", False)),
            "domain_users_only": bool(restrictions.get("domainUsersOnly", False)),
            "copy_requires_writer_permission": bool(
                restrictions.get("copyRequiresWriterPermission", False)
            ),
            "drive_members_only": bool(restrictions.get("driveMembersOnly", False)),
            "admin_managed_restrictions": bool(
                restrictions.get("adminManagedRestrictions", False)
            ),
            "external_member_count": self._count_external_members(drive_id),
        }
        cfg["has_external_members"] = cfg["external_member_count"] > 0

        return Asset(
            id=f"gws:shared_drive:{drive_id}",
            cloud_provider=self.cloud_provider,
            account_id=self._tenant_id,
            region="global",
            resource_type="gws_shared_drive",
            name=cfg["drive_name"] or drive_id,
            last_seen=self._now(),
            raw_config=cfg,
        )

    def _count_external_members(self, drive_id: str) -> int:
        if not drive_id:
            return 0
        try:
            permissions = self._service.permissions()
        except Exception:
            return 0
        try:
            request = permissions.list(
                fileId=drive_id,
                supportsAllDrives=True,
                useDomainAdminAccess=True,
                pageSize=100,
                fields="nextPageToken,permissions(emailAddress,domain,type)",
            )
        except Exception as e:
            logger.debug("gws_drive_settings: permissions.list(%s) failed: %s",
                         drive_id, e)
            return 0

        external = 0
        while request is not None:
            try:
                response = request.execute() or {}
            except Exception as e:
                logger.debug(
                    "gws_drive_settings: permissions.execute(%s) failed: %s",
                    drive_id, e,
                )
                break
            for perm in response.get("permissions", []) or []:
                if self._is_external(perm):
                    external += 1
            list_next = getattr(permissions, "list_next", None)
            request = list_next(request, response) if list_next else None
        return external

    def _is_external(self, perm: dict[str, Any]) -> bool:
        if perm.get("type") == "anyone":
            return True
        domain = (perm.get("domain") or "").lower()
        if domain and self._primary_domain and domain != self._primary_domain:
            return True
        email = (perm.get("emailAddress") or "").lower()
        if email and "@" in email and self._primary_domain:
            return email.split("@", 1)[1] != self._primary_domain
        return False
