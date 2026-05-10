"""Microsoft Entra identity mapper.

Consumes the Entra collector snapshots (``entra_user``, ``entra_group``,
``entra_directory_role``, ``entra_role_assignment``, ``entra_app_registration``,
``entra_service_principal``, ``entra_oauth2_grant``, ``entra_pim_eligibility``,
``entra_domain``) and emits a :class:`PermissionGraph` slice.

Active and PIM-eligible role assignments are both represented; the
``status`` metadata on the ``HAS_ROLE`` edge tells consumers whether the
role is permanent ("active") or just-in-time ("eligible"). This is the
input the privilege-escalation analyzer uses to flag patterns like "user
is owner of an app registration that has Mail.ReadWrite on every mailbox".
"""

from __future__ import annotations

import logging

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


_M365_CLOUD = "microsoft_365"


class EntraIdentityMapper:
    cloud_provider = _M365_CLOUD

    def __init__(self, assets: AssetCollection, primary_domain: str = "") -> None:
        self._assets = assets
        self._domain = primary_domain.lower()

    def build(self) -> PermissionGraph:
        graph = PermissionGraph()

        users: list[Asset] = []
        groups: list[Asset] = []
        roles: list[Asset] = []
        ras: list[Asset] = []
        apps: list[Asset] = []
        sps: list[Asset] = []
        grants: list[Asset] = []
        domains: list[Asset] = []
        for a in self._assets:
            t = a.resource_type
            if t == "entra_user":
                users.append(a)
            elif t == "entra_group":
                groups.append(a)
            elif t == "entra_directory_role":
                roles.append(a)
            elif t == "entra_role_assignment":
                ras.append(a)
            elif t == "entra_app_registration":
                apps.append(a)
            elif t == "entra_service_principal":
                sps.append(a)
            elif t == "entra_oauth2_grant":
                grants.append(a)
            elif t == "entra_domain":
                domains.append(a)

        for u in users:
            graph.add_node(self._user_node(u))
        for g in groups:
            graph.add_node(self._group_node(g))
        for r in roles:
            graph.add_node(self._role_node(r))
        for ra in ras:
            self._add_role_assignment(graph, ra, roles)
        for a in apps:
            graph.add_node(self._app_node(a))
            self._add_app_owners(graph, a)
        for sp in sps:
            graph.add_node(self._sp_node(sp))
        for g in grants:
            self._add_oauth_grant(graph, g)
        for d in domains:
            self._add_domain(graph, d)

        return graph

    # --------------------------------------------------------------- nodes

    def _user_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        upn = (cfg.get("user_principal_name") or asset.name or "").lower()
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.USER,
            cloud_provider=_M365_CLOUD,
            name=upn or asset.name,
            account_id=asset.account_id,
            metadata={
                "email": upn,
                "user_principal_name": upn,
                "is_guest": bool(cfg.get("is_guest")),
                "account_enabled": bool(cfg.get("account_enabled", True)),
                "last_sign_in": cfg.get("last_sign_in", ""),
            },
        )

    def _group_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.GROUP,
            cloud_provider=_M365_CLOUD,
            name=cfg.get("display_name", "") or asset.name,
            account_id=asset.account_id,
            metadata={
                "is_dynamic": bool(cfg.get("is_dynamic")),
                "visibility": cfg.get("visibility", ""),
            },
        )

    def _role_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.ROLE,
            cloud_provider=_M365_CLOUD,
            name=cfg.get("role_name", "") or asset.name,
            account_id=asset.account_id,
            metadata={
                "is_admin": bool(cfg.get("is_privileged"))
                or "admin" in (cfg.get("role_name", "") or "").lower(),
                "is_privileged": bool(cfg.get("is_privileged")),
                "is_built_in": bool(cfg.get("is_built_in", True)),
                "template_id": cfg.get("template_id", ""),
            },
        )

    def _app_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.APPLICATION,
            cloud_provider=_M365_CLOUD,
            name=cfg.get("display_name", "") or asset.name,
            account_id=asset.account_id,
            metadata={
                "app_id": cfg.get("app_id", ""),
                "publisher_domain": cfg.get("publisher_domain", ""),
                "has_high_risk_graph_permissions": bool(
                    cfg.get("has_high_risk_graph_permissions")
                ),
                "is_orphaned": bool(cfg.get("is_orphaned")),
            },
        )

    def _sp_node(self, asset: Asset) -> Node:
        cfg = asset.raw_config
        return Node.make(
            node_id=asset.id,
            kind=NodeKind.SERVICE_PRINCIPAL,
            cloud_provider=_M365_CLOUD,
            name=cfg.get("display_name", "") or asset.name,
            account_id=asset.account_id,
            metadata={
                "app_id": cfg.get("app_id", ""),
                "service_principal_type": cfg.get("service_principal_type", ""),
            },
        )

    # ------------------------------------------------------ app ownership
    #
    # SAAS_POSTURE_SPEC §5.1 calls out the privilege-escalation pattern
    # "user is owner of an app registration that has Mail.ReadWrite on
    # every mailbox." Emitting an OWNS edge from owner → app gives the
    # escalation analyzer the join it needs. The owner's permission level
    # is ADMIN because app owners can mint new credentials and consent to
    # additional Graph permissions.

    def _add_app_owners(self, graph: PermissionGraph, app_asset: Asset) -> None:
        cfg = app_asset.raw_config
        owners = cfg.get("owners") or []
        for owner in owners:
            owner_id = owner.get("id") or ""
            if not owner_id:
                continue
            odata = (owner.get("odata_type") or "").lower()
            # The owners endpoint returns either users or service principals.
            # We resolve to the corresponding asset id when present in the
            # snapshot; otherwise we synthesize a placeholder so the OWNS
            # edge still lands and a future scan can rewire it.
            if "serviceprincipal" in odata:
                resolved = self._asset_id_for_principal(owner_id) or (
                    f"entra:service_principal:{owner_id}"
                )
            else:
                resolved = self._asset_id_for_principal(owner_id) or (
                    f"entra:user:{owner_id}"
                )
            graph.add_edge(
                Edge.make(
                    src=resolved,
                    dst=app_asset.id,
                    kind=EdgeKind.OWNS,
                    permission_level=PermissionLevel.ADMIN,
                    cloud_provider=_M365_CLOUD,
                    metadata={
                        "owner_display_name": owner.get("display_name", ""),
                        "owner_user_principal_name": owner.get(
                            "user_principal_name", ""
                        ),
                        "app_has_high_risk_graph_permissions": bool(
                            cfg.get("has_high_risk_graph_permissions")
                        ),
                    },
                )
            )

    # ----------------------------------------------------- role assignments

    def _add_role_assignment(
        self,
        graph: PermissionGraph,
        asset: Asset,
        roles: list[Asset],
    ) -> None:
        cfg = asset.raw_config
        principal_id_raw = cfg.get("principal_id", "")
        role_id_raw = cfg.get("role_id", "")
        if not principal_id_raw or not role_id_raw:
            return

        # Resolve principal node — could be user, group, or service principal.
        principal_node_id = (
            self._asset_id_for_principal(principal_id_raw) or principal_id_raw
        )
        role_node_id = f"entra:directory_role:{role_id_raw}"

        is_priv = bool(cfg.get("is_privileged_role")) or (
            "admin" in (cfg.get("role_name", "") or "").lower()
        )
        graph.add_edge(
            Edge.make(
                src=principal_node_id,
                dst=role_node_id,
                kind=EdgeKind.HAS_ROLE,
                permission_level=(
                    PermissionLevel.ADMIN if is_priv else PermissionLevel.WRITE
                ),
                cloud_provider=_M365_CLOUD,
                metadata={
                    "status": cfg.get("status", "active"),
                    "scope": cfg.get("directory_scope_id", "/"),
                    "is_permanent": bool(cfg.get("is_permanent")),
                },
            )
        )

    def _asset_id_for_principal(self, principal_id: str) -> str | None:
        for a in self._assets:
            if a.resource_type in ("entra_user", "entra_group", "entra_service_principal"):
                # Match the GUID embedded in the asset id.
                if a.id.endswith(":" + principal_id) or a.raw_config.get(
                    "principal_id"
                ) == principal_id:
                    return a.id
                # Fallback for users whose object ID matches.
                if a.raw_config.get("user_id") == principal_id:
                    return a.id
                if a.raw_config.get("group_id") == principal_id:
                    return a.id
                if a.raw_config.get("sp_object_id") == principal_id:
                    return a.id
        return None

    # ------------------------------------------------------ oauth2 grants

    def _add_oauth_grant(self, graph: PermissionGraph, asset: Asset) -> None:
        cfg = asset.raw_config
        client_id = cfg.get("client_id", "")
        principal_id = cfg.get("principal_id", "")
        if not client_id:
            return

        # The `clientId` on an oauth2 grant is the SP object id of the app
        # in the *consumer* tenant. Match against entra_service_principal.id
        # which is "entra:service_principal:<obj-id>".
        sp_node_id = f"entra:service_principal:{client_id}"
        if cfg.get("is_admin_consent"):
            tenant_id = f"entra:tenant:{asset.account_id}"
            graph.add_node(
                Node.make(
                    node_id=tenant_id,
                    kind=NodeKind.TENANT,
                    cloud_provider=_M365_CLOUD,
                    name=asset.account_id,
                    account_id=asset.account_id,
                )
            )
            graph.add_edge(
                Edge.make(
                    src=sp_node_id,
                    dst=tenant_id,
                    kind=EdgeKind.DELEGATED_TO,
                    permission_level=PermissionLevel.ADMIN,
                    cloud_provider=_M365_CLOUD,
                    metadata={
                        "scopes": cfg.get("scopes", []),
                        "consent_type": "AllPrincipals",
                    },
                )
            )
        elif principal_id:
            target = self._asset_id_for_principal(principal_id) or principal_id
            graph.add_edge(
                Edge.make(
                    src=sp_node_id,
                    dst=target,
                    kind=EdgeKind.AUTHORIZED_FOR,
                    permission_level=PermissionLevel.READ,
                    cloud_provider=_M365_CLOUD,
                    metadata={
                        "scopes": cfg.get("scopes", []),
                        "consent_type": "Principal",
                    },
                )
            )

    # ------------------------------------------------------ federation

    def _add_domain(self, graph: PermissionGraph, asset: Asset) -> None:
        cfg = asset.raw_config
        if not cfg.get("is_federated"):
            return
        domain = cfg.get("domain", "") or asset.name
        if not domain:
            return
        fed_id = f"entra:federated_domain:{domain}"
        graph.add_node(
            Node.make(
                node_id=fed_id,
                kind=NodeKind.FEDERATED_PRINCIPAL,
                cloud_provider=_M365_CLOUD,
                name=domain,
                account_id=asset.account_id,
                metadata={
                    "is_verified": bool(cfg.get("is_verified")),
                    "domain": domain,
                },
            )
        )
        tenant_id = f"entra:tenant:{asset.account_id}"
        graph.add_node(
            Node.make(
                node_id=tenant_id,
                kind=NodeKind.TENANT,
                cloud_provider=_M365_CLOUD,
                name=asset.account_id,
                account_id=asset.account_id,
            )
        )
        graph.add_edge(
            Edge.make(
                src=fed_id,
                dst=tenant_id,
                kind=EdgeKind.FEDERATED_TO,
                cloud_provider=_M365_CLOUD,
                metadata={"is_verified": bool(cfg.get("is_verified"))},
            )
        )
