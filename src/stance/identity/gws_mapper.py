"""Google Workspace identity mapper.

Consumes the ``AssetCollection`` produced by the PR-1/PR-2 GWS collectors
(``gws_user``, ``gws_group``, ``gws_role_assignment``, ``gws_oauth_app``,
plus optional ``gws_tenant_security`` for super-admin counts) and emits a
:class:`stance.identity.saas_graph.PermissionGraph` slice.

The mapper is read-only and reuses the snapshot — no live API calls. This
keeps stance's "no event collection" property (SAAS_POSTURE_SPEC §2) and
makes the mapper trivially testable.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.identity.base import PermissionLevel
from stance.identity.saas_graph import (
    Edge,
    EdgeKind,
    Node,
    NodeKind,
    PermissionGraph,
)
from stance.models import Asset, AssetCollection

logger = logging.getLogger(__name__)


_GWS_CLOUD = "google_workspace"


class GWSIdentityMapper:
    """Builds a :class:`PermissionGraph` from a GWS asset snapshot."""

    cloud_provider = _GWS_CLOUD

    def __init__(self, assets: AssetCollection, primary_domain: str = "") -> None:
        self._assets = assets
        self._domain = primary_domain.lower()

    # --------------------------------------------------------------- API

    def build(self) -> PermissionGraph:
        graph = PermissionGraph()

        users: list[Asset] = []
        groups: list[Asset] = []
        ras: list[Asset] = []
        oauth_apps: list[Asset] = []
        for a in self._assets:
            if a.resource_type == "gws_user":
                users.append(a)
            elif a.resource_type == "gws_group":
                groups.append(a)
            elif a.resource_type == "gws_role_assignment":
                ras.append(a)
            elif a.resource_type == "gws_oauth_app":
                oauth_apps.append(a)

        for u in users:
            graph.add_node(self._user_node(u))
        for g in groups:
            graph.add_node(self._group_node(g))
        for ra in ras:
            self._add_role_assignment(graph, ra)
        for app in oauth_apps:
            self._add_oauth_app(graph, app)

        return graph

    # --------------------------------------------------------- node builders

    def _user_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        email = (cfg.get("primary_email") or asset.name or "").lower()
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.USER,
            cloud_provider=_GWS_CLOUD,
            name=email or asset.name,
            account_id=asset.account_id,
            metadata={
                "email": email,
                "is_admin": bool(cfg.get("is_admin")),
                "is_super_admin": bool(cfg.get("is_super_admin")),
                "is_delegated_admin": bool(cfg.get("is_delegated_admin")),
                "two_factor_enrolled": bool(cfg.get("two_factor_enrolled")),
                "suspended": bool(cfg.get("suspended")),
                "is_inactive": bool(cfg.get("is_inactive")),
                "org_unit_path": cfg.get("org_unit_path", "/"),
            },
        )

    def _group_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        email = (cfg.get("email") or asset.name or "").lower()
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.GROUP,
            cloud_provider=_GWS_CLOUD,
            name=email or asset.name,
            account_id=asset.account_id,
            metadata={
                "email": email,
                "direct_members_count": int(cfg.get("direct_members_count", 0) or 0),
                "external_members_count": int(
                    cfg.get("external_members_count", 0) or 0
                ),
                "has_external_members": bool(cfg.get("has_external_members")),
            },
        )

    # ----------------------------------------------------- role assignments

    def _add_role_assignment(self, graph: PermissionGraph, asset: Asset) -> None:
        cfg = asset.raw_config
        role_id = cfg.get("role_id", "")
        role_name = cfg.get("role_name", "") or role_id
        if not role_id:
            return
        role_node_id = f"gws:role:{role_id}"
        graph.add_node(
            Node.make(
                node_id=role_node_id,
                kind=NodeKind.ROLE,
                cloud_provider=_GWS_CLOUD,
                name=role_name,
                account_id=asset.account_id,
                metadata={
                    "is_super_admin": bool(cfg.get("is_super_admin_role")),
                    "is_system_role": bool(cfg.get("is_system_role")),
                    "is_admin": bool(cfg.get("is_super_admin_role"))
                    or "admin" in role_name.lower(),
                    "is_privileged": bool(cfg.get("is_super_admin_role"))
                    or "admin" in role_name.lower(),
                },
            )
        )

        principal_id = cfg.get("assigned_to") or ""
        if not principal_id:
            return

        # The role assignment "assignedTo" field can be either a user_id or a
        # group_id. We don't know which; emit a "principal:<id>" alias node and
        # let cross-collection joins resolve it. Production callers with the
        # full directory can replace this with a typed lookup.
        principal_node_id = self._resolve_principal_id(principal_id)
        if principal_node_id is None:
            principal_node_id = f"gws:principal:{principal_id}"
            graph.add_node(
                Node.make(
                    node_id=principal_node_id,
                    kind=NodeKind.USER,
                    cloud_provider=_GWS_CLOUD,
                    name=principal_id,
                    account_id=asset.account_id,
                )
            )

        is_admin = bool(cfg.get("is_super_admin_role")) or (
            "admin" in role_name.lower()
        )
        graph.add_edge(
            Edge.make(
                src=principal_node_id,
                dst=role_node_id,
                kind=EdgeKind.HAS_ROLE,
                permission_level=(
                    PermissionLevel.ADMIN if is_admin else PermissionLevel.WRITE
                ),
                cloud_provider=_GWS_CLOUD,
                metadata={
                    "scope_type": cfg.get("scope_type", "CUSTOMER"),
                    "org_unit_id": cfg.get("org_unit_id", ""),
                    "assignment_id": cfg.get("role_assignment_id", ""),
                },
            )
        )

    def _resolve_principal_id(self, raw_id: str) -> str | None:
        """Return the canonical graph node id for a Workspace principal id.

        ``role_assignment.assigned_to`` can be a user object id or a group
        object id; the asset id format is ``gws:user:<id>`` /
        ``gws:group:<id>``. We probe both forms.
        """
        for prefix in ("gws:user:", "gws:group:"):
            for n in self._assets:
                if n.id == prefix + raw_id:
                    return n.id
        return None

    # ----------------------------------------------------- oauth applications

    def _add_oauth_app(self, graph: PermissionGraph, asset: Asset) -> None:
        cfg = asset.raw_config
        client_id = cfg.get("client_id", "")
        if not client_id:
            return
        app_node_id = f"gws:oauth_app:{client_id}"
        graph.add_node(
            Node.make(
                node_id=app_node_id,
                kind=NodeKind.APPLICATION,
                cloud_provider=_GWS_CLOUD,
                name=cfg.get("display_text", "") or client_id,
                account_id=asset.account_id,
                metadata={
                    "scope_risk": cfg.get("scope_risk", "data"),
                    "verified": bool(cfg.get("verified")),
                    "domain_wide_delegated": bool(cfg.get("domain_wide_delegated")),
                    "is_trusted": bool(cfg.get("is_trusted")),
                    "user_count": int(cfg.get("user_count", 0) or 0),
                },
            )
        )

        scope_risk = cfg.get("scope_risk", "data")
        level = {
            "critical": PermissionLevel.ADMIN,
            "high": PermissionLevel.WRITE,
            "data": PermissionLevel.READ,
            "other": PermissionLevel.LIST,
        }.get(scope_risk, PermissionLevel.UNKNOWN)

        # Edge per user the app is authorized for. For graph-size sanity we
        # use the sample list (≤10) the collector keeps; the user_count is on
        # the node metadata for aggregate queries.
        for user_email in cfg.get("users_sample", []) or []:
            user_id = self._user_id_for_email(user_email)
            if user_id is None:
                continue
            graph.add_edge(
                Edge.make(
                    src=app_node_id,
                    dst=user_id,
                    kind=EdgeKind.AUTHORIZED_FOR,
                    permission_level=level,
                    cloud_provider=_GWS_CLOUD,
                    metadata={"scope_risk": scope_risk},
                )
            )

        if cfg.get("domain_wide_delegated"):
            # DWD lets the app act-as any user — represent as a single
            # delegation edge to the tenant.
            tenant_id = f"gws:tenant:{asset.account_id}"
            graph.add_node(
                Node.make(
                    node_id=tenant_id,
                    kind=NodeKind.TENANT,
                    cloud_provider=_GWS_CLOUD,
                    name=asset.account_id,
                    account_id=asset.account_id,
                )
            )
            graph.add_edge(
                Edge.make(
                    src=app_node_id,
                    dst=tenant_id,
                    kind=EdgeKind.DELEGATED_TO,
                    permission_level=PermissionLevel.ADMIN,
                    cloud_provider=_GWS_CLOUD,
                    metadata={"scope_risk": scope_risk},
                )
            )

    def _user_id_for_email(self, email: str) -> str | None:
        e = (email or "").lower()
        if not e:
            return None
        for a in self._assets:
            if a.resource_type != "gws_user":
                continue
            if (a.raw_config.get("primary_email", "") or "").lower() == e:
                return a.id
        return None
