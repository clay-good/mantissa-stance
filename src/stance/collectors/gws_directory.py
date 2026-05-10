"""
Google Workspace directory collector.

Collects users, groups, organizational units, and admin role assignments from
the Google Admin SDK Directory API. Emits four resource types:

    gws_user, gws_group, gws_org_unit, gws_role_assignment

The collector is intentionally read-only and point-in-time (stance is not an
event store — see SAAS_POSTURE_SPEC §2). The injected ``service`` is a
duck-typed Admin SDK ``directory_v1`` resource; tests inject a MagicMock.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.collectors.saas_base import SaaSCollector
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


class GWSDirectoryCollector(SaaSCollector):
    """Collects Google Workspace directory resources."""

    collector_name = "gws_directory"
    resource_types = [
        "gws_user",
        "gws_group",
        "gws_org_unit",
        "gws_role_assignment",
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

        for collector_fn, label in (
            (self._collect_users, "users"),
            (self._collect_groups, "groups"),
            (self._collect_org_units, "org units"),
            (self._collect_role_assignments, "role assignments"),
        ):
            try:
                assets.extend(collector_fn())
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("gws_directory: failed to collect %s: %s", label, e)

        return AssetCollection(assets)

    def _list_pages(
        self, resource: Any, list_kwargs: dict[str, Any], items_key: str
    ) -> Iterator[dict[str, Any]]:
        request = resource.list(**list_kwargs)
        while request is not None:
            response = request.execute()
            for item in response.get(items_key, []) or []:
                yield item
            list_next = getattr(resource, "list_next", None)
            request = list_next(request, response) if list_next else None

    # ------------------------------------------------------------------ users

    def _collect_users(self) -> list[Asset]:
        users_resource = self._service.users()
        now = self._now()
        assets: list[Asset] = []

        kwargs = {
            "customer": self._customer,
            "maxResults": 500,
            "projection": "full",
        }
        for user in self._list_pages(users_resource, kwargs, "users"):
            uid = user.get("id") or user.get("primaryEmail") or ""
            email = user.get("primaryEmail", "")
            last_login = _parse_dt(user.get("lastLoginTime"))
            creation = _parse_dt(user.get("creationTime"))

            days_since_login: int | None = None
            if last_login and last_login.year > 1970:
                days_since_login = (now - last_login).days
            elif last_login:
                # 1970-01-01 means "never logged in"
                days_since_login = None

            two_factor_enrolled = bool(user.get("isEnrolledIn2Sv"))
            two_factor_enforced = bool(user.get("isEnforcedIn2Sv"))
            is_admin = bool(user.get("isAdmin"))
            is_delegated = bool(user.get("isDelegatedAdmin"))
            suspended = bool(user.get("suspended"))
            archived = bool(user.get("archived"))

            username = email.split("@", 1)[0].lower() if "@" in email else email.lower()
            raw_config: dict[str, Any] = {
                "user_id": uid,
                "primary_email": email,
                "username": username,
                "full_name": (user.get("name") or {}).get("fullName", ""),
                "is_admin": is_admin,
                "is_delegated_admin": is_delegated,
                "is_super_admin": is_admin and not is_delegated,
                "suspended": suspended,
                "archived": archived,
                "org_unit_path": user.get("orgUnitPath", "/"),
                "two_factor_enrolled": two_factor_enrolled,
                "two_factor_enforced": two_factor_enforced,
                "creation_time": creation.isoformat() if creation else None,
                "last_login_time": last_login.isoformat() if last_login else None,
                "days_since_last_login": days_since_login,
                "is_inactive": (
                    days_since_login is not None and days_since_login > 90
                ),
                "aliases": user.get("aliases", []) or [],
            }

            assets.append(
                Asset(
                    id=f"gws:user:{uid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_user",
                    name=email or uid,
                    tags={},
                    created_at=creation,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    # ----------------------------------------------------------------- groups

    def _collect_groups(self) -> list[Asset]:
        groups_resource = self._service.groups()
        now = self._now()
        assets: list[Asset] = []

        kwargs = {"customer": self._customer, "maxResults": 200}
        for group in self._list_pages(groups_resource, kwargs, "groups"):
            gid = group.get("id") or group.get("email") or ""
            email = group.get("email", "")
            member_count = int(group.get("directMembersCount", 0) or 0)

            external_members = 0
            try:
                members_resource = self._service.members()
                m_kwargs = {"groupKey": gid, "maxResults": 200}
                for member in self._list_pages(members_resource, m_kwargs, "members"):
                    m_email = (member.get("email") or "").lower()
                    if m_email and not m_email.endswith("@" + self._domain_hint(email)):
                        if member.get("type") in ("USER", "GROUP"):
                            external_members += 1
            except Exception as e:
                logger.debug("gws_directory: members(%s) failed: %s", gid, e)

            raw_config: dict[str, Any] = {
                "group_id": gid,
                "email": email,
                "name": group.get("name", ""),
                "description": group.get("description", ""),
                "direct_members_count": member_count,
                "external_members_count": external_members,
                "has_external_members": external_members > 0,
                "admin_created": bool(group.get("adminCreated", True)),
                "aliases": group.get("aliases", []) or [],
            }

            assets.append(
                Asset(
                    id=f"gws:group:{gid}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_group",
                    name=email or gid,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    @staticmethod
    def _domain_hint(email: str) -> str:
        if "@" in email:
            return email.split("@", 1)[1].lower()
        return ""

    # -------------------------------------------------------------- org units

    def _collect_org_units(self) -> list[Asset]:
        ous_resource = self._service.orgunits()
        now = self._now()
        assets: list[Asset] = []

        request = ous_resource.list(customerId=self._customer, type="all")
        response = request.execute()
        for ou in response.get("organizationUnits", []) or []:
            ou_id = ou.get("orgUnitId") or ou.get("orgUnitPath") or ""
            raw_config: dict[str, Any] = {
                "org_unit_id": ou_id,
                "org_unit_path": ou.get("orgUnitPath", "/"),
                "name": ou.get("name", ""),
                "description": ou.get("description", ""),
                "parent_org_unit_path": ou.get("parentOrgUnitPath", "/"),
                "block_inheritance": bool(ou.get("blockInheritance", False)),
            }
            assets.append(
                Asset(
                    id=f"gws:ou:{ou_id}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_org_unit",
                    name=ou.get("orgUnitPath", "/"),
                    last_seen=now,
                    raw_config=raw_config,
                )
            )
        return assets

    # ------------------------------------------------------- role assignments

    def _collect_role_assignments(self) -> list[Asset]:
        roles_resource = self._service.roles()
        assignments_resource = self._service.roleAssignments()
        now = self._now()
        assets: list[Asset] = []

        roles_by_id: dict[str, dict[str, Any]] = {}
        try:
            for role in self._list_pages(
                roles_resource, {"customer": self._customer}, "items"
            ):
                rid = str(role.get("roleId", ""))
                roles_by_id[rid] = {
                    "role_name": role.get("roleName", ""),
                    "is_system_role": bool(role.get("isSystemRole", False)),
                    "is_super_admin_role": bool(role.get("isSuperAdminRole", False)),
                }
        except Exception as e:
            logger.debug("gws_directory: roles list failed: %s", e)

        for assignment in self._list_pages(
            assignments_resource, {"customer": self._customer}, "items"
        ):
            rid = str(assignment.get("roleId", ""))
            role_meta = roles_by_id.get(rid, {})
            assignment_id = str(assignment.get("roleAssignmentId", ""))

            raw_config: dict[str, Any] = {
                "role_assignment_id": assignment_id,
                "role_id": rid,
                "role_name": role_meta.get("role_name", ""),
                "is_system_role": role_meta.get("is_system_role", False),
                "is_super_admin_role": role_meta.get("is_super_admin_role", False),
                "assigned_to": assignment.get("assignedTo", ""),
                "scope_type": assignment.get("scopeType", "CUSTOMER"),
                "org_unit_id": assignment.get("orgUnitId", ""),
            }

            assets.append(
                Asset(
                    id=f"gws:role_assignment:{assignment_id}",
                    cloud_provider=self.cloud_provider,
                    account_id=self._tenant_id,
                    region="global",
                    resource_type="gws_role_assignment",
                    name=role_meta.get("role_name", "") or rid,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets
