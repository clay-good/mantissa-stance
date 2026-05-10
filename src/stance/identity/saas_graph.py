"""
SaaS / cross-surface permission graph.

The cloud-specific data-access mappers in this package
(:mod:`stance.identity.aws_mapper`, ``azure_mapper``, ``gcp_mapper``) work
against live cloud APIs and answer "who can access this resource?". The SaaS
mappers (``gws_mapper``, ``entra_mapper``) take a different shape: they
consume already-collected ``AssetCollection`` snapshots and emit a
permission *graph* whose nodes can be joined across surfaces.

The graph is intentionally minimal — just enough to answer the cross-surface
questions called out in SAAS_POSTURE_SPEC §5.2:

  - "Which Entra users are also AWS admins via SAML federation?"
  - "Which GWS super admins also hold GCP Organization Admin?"
  - "Which M365 service principals hold permissions in AWS via OIDC trust?"

Nodes are typed (USER, GROUP, ROLE, SERVICE_PRINCIPAL, RESOURCE,
FEDERATED_PRINCIPAL). Edges carry a relation kind plus a privilege rank
borrowed from :class:`stance.identity.base.PermissionLevel`. The graph is
provider-agnostic; mappers populate their slice and ``PermissionGraph.merge``
unions them.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Iterator

from stance.identity.base import PermissionLevel, PrincipalType

logger = logging.getLogger(__name__)


class NodeKind(Enum):
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    SERVICE_PRINCIPAL = "service_principal"
    APPLICATION = "application"
    RESOURCE = "resource"
    FEDERATED_PRINCIPAL = "federated_principal"
    TENANT = "tenant"


class EdgeKind(Enum):
    MEMBER_OF = "member_of"  # user → group, group → group
    HAS_ROLE = "has_role"  # principal → role
    GRANTS_PERMISSION = "grants_permission"  # role → resource (or principal → resource)
    OWNS = "owns"  # principal → app / SP
    DELEGATED_TO = "delegated_to"  # service principal → user (DWD)
    FEDERATED_TO = "federated_to"  # federated principal → tenant
    AUTHORIZED_FOR = "authorized_for"  # oauth-app principal → user (token grant)


@dataclass(frozen=True)
class Node:
    id: str
    kind: NodeKind
    cloud_provider: str  # "google_workspace" | "microsoft_365" | "aws" | "gcp" | "azure"
    name: str = ""
    account_id: str = ""
    metadata: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(
        cls,
        node_id: str,
        kind: NodeKind,
        cloud_provider: str,
        name: str = "",
        account_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Node:
        return cls(
            id=node_id,
            kind=kind,
            cloud_provider=cloud_provider,
            name=name,
            account_id=account_id,
            metadata=tuple(sorted((metadata or {}).items())),
        )

    @property
    def metadata_dict(self) -> dict[str, Any]:
        return dict(self.metadata)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    permission_level: PermissionLevel = PermissionLevel.UNKNOWN
    cloud_provider: str = ""
    metadata: tuple[tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(
        cls,
        src: str,
        dst: str,
        kind: EdgeKind,
        permission_level: PermissionLevel = PermissionLevel.UNKNOWN,
        cloud_provider: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> Edge:
        return cls(
            src=src,
            dst=dst,
            kind=kind,
            permission_level=permission_level,
            cloud_provider=cloud_provider,
            metadata=tuple(sorted((metadata or {}).items())),
        )

    @property
    def metadata_dict(self) -> dict[str, Any]:
        return dict(self.metadata)


class PermissionGraph:
    """Provider-agnostic permission graph used for cross-surface CIEM.

    The graph is a thin in-memory store. Lookups are by node id; "user
    correlations across providers" are produced by joining nodes whose
    ``email`` metadata matches.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._out_index: dict[str, list[Edge]] = {}
        self._in_index: dict[str, list[Edge]] = {}

    # ----------------------------------------------------------- mutation

    def add_node(self, node: Node) -> None:
        existing = self._nodes.get(node.id)
        if existing is None:
            self._nodes[node.id] = node
            return
        # Merge: keep the richer name + union metadata.
        merged_meta = {**existing.metadata_dict, **node.metadata_dict}
        merged = Node.make(
            node_id=existing.id,
            kind=existing.kind,
            cloud_provider=existing.cloud_provider,
            name=existing.name or node.name,
            account_id=existing.account_id or node.account_id,
            metadata=merged_meta,
        )
        self._nodes[node.id] = merged

    def add_edge(self, edge: Edge) -> None:
        # Ensure endpoints exist as placeholder nodes if not added yet.
        for endpoint in (edge.src, edge.dst):
            if endpoint not in self._nodes:
                self._nodes[endpoint] = Node.make(
                    node_id=endpoint,
                    kind=NodeKind.RESOURCE,
                    cloud_provider=edge.cloud_provider,
                )
        self._edges.append(edge)
        self._out_index.setdefault(edge.src, []).append(edge)
        self._in_index.setdefault(edge.dst, []).append(edge)

    def merge(self, other: PermissionGraph) -> None:
        for n in other._nodes.values():
            self.add_node(n)
        for e in other._edges:
            self._edges.append(e)
            self._out_index.setdefault(e.src, []).append(e)
            self._in_index.setdefault(e.dst, []).append(e)

    # ------------------------------------------------------------ access

    @property
    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[Edge]:
        return list(self._edges)

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def out_edges(self, node_id: str) -> list[Edge]:
        return list(self._out_index.get(node_id, []))

    def in_edges(self, node_id: str) -> list[Edge]:
        return list(self._in_index.get(node_id, []))

    def nodes_by_kind(self, kind: NodeKind) -> Iterator[Node]:
        for n in self._nodes.values():
            if n.kind == kind:
                yield n

    # ----------------------------------------------------------- queries

    def reachable_roles(self, principal_id: str) -> list[Node]:
        """Roles a principal effectively holds (direct or via group)."""
        roles: list[Node] = []
        seen: set[str] = set()
        stack: list[str] = [principal_id]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            for e in self.out_edges(cur):
                if e.kind == EdgeKind.HAS_ROLE:
                    target = self.get_node(e.dst)
                    if target is not None:
                        roles.append(target)
                elif e.kind == EdgeKind.MEMBER_OF:
                    stack.append(e.dst)
        return roles

    def is_admin(self, principal_id: str) -> bool:
        """True if the principal holds at least one role flagged as admin."""
        for role in self.reachable_roles(principal_id):
            md = role.metadata_dict
            if md.get("is_admin") or md.get("is_super_admin") or md.get(
                "is_privileged"
            ):
                return True
        return False

    def find_users_by_email(self, email: str) -> list[Node]:
        norm = email.strip().lower()
        if not norm:
            return []
        out: list[Node] = []
        for n in self._nodes.values():
            if n.kind != NodeKind.USER:
                continue
            md = n.metadata_dict
            candidate = (md.get("email") or n.name or n.id).lower()
            if candidate == norm:
                out.append(n)
        return out


def edges_with_kind(edges: Iterable[Edge], kind: EdgeKind) -> list[Edge]:
    return [e for e in edges if e.kind == kind]
