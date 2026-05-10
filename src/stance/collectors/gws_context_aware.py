"""Google Workspace Context-Aware Access collector.

Reads access levels and their bindings (Cloud Identity / Access Context
Manager). Emits two resource types:

- ``gws_caa_access_level`` — one asset per access level (the predicate).
- ``gws_caa_binding`` — one asset per (access-level → role/group) binding.

The most useful policy check is whether at least one CAA binding covers
admin roles. The collector therefore tags each binding with
``binds_admin_role`` based on the role name pattern.
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


_ADMIN_ROLE_HINTS: tuple[str, ...] = (
    "admin",
    "_seed_admin",
    "super_admin",
    "groups_admin",
    "user_management_admin",
)


def _looks_like_admin_role(role_name: str) -> bool:
    rn = (role_name or "").lower()
    return any(hint in rn for hint in _ADMIN_ROLE_HINTS)


class GWSContextAwareCollector(SaaSCollector):
    collector_name = "gws_context_aware"
    resource_types = [
        "gws_caa_access_level",
        "gws_caa_binding",
        "gws_caa_summary",
    ]
    cloud_provider = "google_workspace"

    def __init__(
        self,
        service: Any,
        tenant_id: str,
        customer: str = "my_customer",
    ) -> None:
        super().__init__(service, tenant_id)
        self._customer = customer

    def collect(self) -> AssetCollection:
        assets: list[Asset] = []
        try:
            assets.extend(self._collect_access_levels())
        except Exception as e:
            logger.warning("gws_context_aware: access_levels failed: %s", e)
        try:
            assets.extend(self._collect_bindings())
        except Exception as e:
            logger.warning("gws_context_aware: bindings failed: %s", e)

        bindings = [a for a in assets if a.resource_type == "gws_caa_binding"]
        levels = [a for a in assets if a.resource_type == "gws_caa_access_level"]
        admin_bindings = [
            b for b in bindings if b.raw_config.get("binds_admin_role")
        ]
        summary_cfg = {
            "access_level_count": len(levels),
            "binding_count": len(bindings),
            "admin_role_binding_count": len(admin_bindings),
            "admin_roles_with_caa": sorted(
                {b.raw_config.get("role_name", "") for b in admin_bindings}
            ),
            "any_admin_role_bound": len(admin_bindings) > 0,
        }
        assets.append(
            Asset(
                id=f"gws:caa_summary:{self._tenant_id}",
                cloud_provider=self.cloud_provider,
                account_id=self._tenant_id,
                region="global",
                resource_type="gws_caa_summary",
                name="context-aware-access",
                last_seen=self._now(),
                raw_config=summary_cfg,
            )
        )
        return AssetCollection(assets)

    # ------------------------------------------------------- access levels

    def _collect_access_levels(self) -> Iterator[Asset]:
        resource = self._service.accessLevels()
        request = resource.list(parent=f"customers/{self._customer}", pageSize=200)
        while request is not None:
            response = request.execute() or {}
            for level in response.get("accessLevels", []) or []:
                cfg = {
                    "name": level.get("name", ""),
                    "title": level.get("title", ""),
                    "description": level.get("description", ""),
                    "basic": level.get("basic", {}),
                    "custom": level.get("custom", {}),
                    "combining_function": (
                        (level.get("basic") or {}).get("combiningFunction", "AND")
                    ),
                }
                yield Asset(
                    id=f"gws:caa_access_level:{cfg['name']}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_caa_access_level",
                    name=cfg["title"] or cfg["name"],
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            list_next = getattr(resource, "list_next", None)
            request = list_next(request, response) if list_next else None

    # ------------------------------------------------------------ bindings

    def _collect_bindings(self) -> Iterator[Asset]:
        resource = self._service.accessLevelBindings()
        request = resource.list(parent=f"customers/{self._customer}", pageSize=200)
        while request is not None:
            response = request.execute() or {}
            for b in response.get("accessLevelBindings", []) or []:
                role_name = b.get("roleName") or b.get("role", "")
                cfg = {
                    "name": b.get("name", ""),
                    "access_level": b.get("accessLevel", ""),
                    "role_name": role_name,
                    "group": b.get("group", ""),
                    "binds_admin_role": _looks_like_admin_role(role_name),
                }
                yield Asset(
                    id=f"gws:caa_binding:{cfg['name']}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_caa_binding",
                    name=cfg["role_name"] or cfg["name"],
                    last_seen=self._now(),
                    raw_config=cfg,
                )
            list_next = getattr(resource, "list_next", None)
            request = list_next(request, response) if list_next else None
