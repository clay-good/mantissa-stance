"""Cross-surface CIEM joins.

The differentiator called out in SAAS_POSTURE_SPEC §5.2: once GWS, Entra,
and the existing AWS / GCP / Azure mappers all populate a unified
:class:`PermissionGraph`, we can answer cross-surface questions like:

  - "Which Entra users are also AWS admins via SAML federation?"
  - "Which GWS super admins also hold GCP Organization Admin?"
  - "Which M365 service principals hold permissions in AWS via OIDC trust?"

This module is intentionally read-only and operates on an already-merged
graph. The correlation key is the user's email / UPN — pragmatic because
SSO provisioning into AWS / GCP / Azure typically uses the same identifier.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from stance.identity.saas_graph import (
    EdgeKind,
    Node,
    NodeKind,
    PermissionGraph,
)


@dataclass(frozen=True)
class CrossSurfaceUser:
    """A user with admin (or other privileged) presence in 2+ providers."""

    email: str
    nodes_by_provider: dict[str, list[str]]  # provider → node ids
    admin_in: list[str] = field(default_factory=list)  # providers in which the user is admin

    @property
    def provider_count(self) -> int:
        return len(self.nodes_by_provider)

    @property
    def admin_provider_count(self) -> int:
        return len(self.admin_in)


def correlate_users_by_email(graph: PermissionGraph) -> list[CrossSurfaceUser]:
    """Find user nodes that share an email across two or more providers.

    Returns one :class:`CrossSurfaceUser` per correlated email, ordered by
    descending ``provider_count``. Single-provider users are not returned.
    """
    by_email: dict[str, dict[str, list[Node]]] = defaultdict(lambda: defaultdict(list))
    for node in graph.nodes_by_kind(NodeKind.USER):
        email = (node.metadata_dict.get("email") or node.name or "").lower()
        if not email or "@" not in email:
            continue
        by_email[email][node.cloud_provider].append(node)

    out: list[CrossSurfaceUser] = []
    for email, provider_to_nodes in by_email.items():
        if len(provider_to_nodes) < 2:
            continue
        nodes_by_provider = {
            p: [n.id for n in ns] for p, ns in provider_to_nodes.items()
        }
        admin_in: list[str] = []
        for provider, nodes in provider_to_nodes.items():
            if any(graph.is_admin(n.id) for n in nodes):
                admin_in.append(provider)
        out.append(
            CrossSurfaceUser(
                email=email,
                nodes_by_provider=nodes_by_provider,
                admin_in=sorted(admin_in),
            )
        )
    out.sort(
        key=lambda u: (-u.admin_provider_count, -u.provider_count, u.email)
    )
    return out


@dataclass(frozen=True)
class CrossSurfaceFederation:
    """A federation edge from an external IdP / domain into a tenant."""

    federated_principal: str
    target_tenant: str
    is_verified: bool
    cloud_provider: str


def federations(graph: PermissionGraph) -> list[CrossSurfaceFederation]:
    """All FEDERATED_TO edges in the graph, normalized for reporting."""
    out: list[CrossSurfaceFederation] = []
    for e in graph.edges:
        if e.kind != EdgeKind.FEDERATED_TO:
            continue
        meta = e.metadata_dict
        out.append(
            CrossSurfaceFederation(
                federated_principal=e.src,
                target_tenant=e.dst,
                is_verified=bool(meta.get("is_verified", False)),
                cloud_provider=e.cloud_provider,
            )
        )
    return out


@dataclass(frozen=True)
class CrossSurfaceFinding:
    """A finding produced by joining two providers' permission graphs."""

    title: str
    severity: str
    description: str
    principal_id: str
    related_node_ids: tuple[str, ...] = ()


def find_cross_admin_users(
    graph: PermissionGraph, providers: Iterable[str] | None = None
) -> list[CrossSurfaceFinding]:
    """Users with admin role in 2+ providers (the headline finding from §5.2)."""
    findings: list[CrossSurfaceFinding] = []
    allowed = set(providers) if providers else None
    for u in correlate_users_by_email(graph):
        if u.admin_provider_count < 2:
            continue
        if allowed and not (set(u.admin_in) & allowed):
            continue
        findings.append(
            CrossSurfaceFinding(
                title=f"{u.email} is admin in {len(u.admin_in)} providers",
                severity="critical" if u.admin_provider_count >= 3 else "high",
                description=(
                    f"{u.email} holds admin-level roles in: "
                    + ", ".join(u.admin_in)
                    + ". Compromise of this single identity grants attacker "
                    + "lateral access across surfaces."
                ),
                principal_id=u.email,
                related_node_ids=tuple(
                    nid
                    for nids in u.nodes_by_provider.values()
                    for nid in nids
                ),
            )
        )
    return findings


def find_unverified_federated_admins(
    graph: PermissionGraph,
) -> list[CrossSurfaceFinding]:
    """Tenants whose federated domains are unverified — a known account-takeover vector."""
    findings: list[CrossSurfaceFinding] = []
    for fed in federations(graph):
        if fed.is_verified:
            continue
        findings.append(
            CrossSurfaceFinding(
                title=f"Unverified federated domain {fed.federated_principal}",
                severity="critical",
                description=(
                    f"Domain {fed.federated_principal} is federated to tenant "
                    f"{fed.target_tenant} but not verified. Unverified federated "
                    "domains have been used in real-world account-takeover attacks."
                ),
                principal_id=fed.federated_principal,
                related_node_ids=(fed.federated_principal, fed.target_tenant),
            )
        )
    return findings


def find_high_risk_app_owners(
    graph: PermissionGraph,
) -> list[CrossSurfaceFinding]:
    """The §5.1 privilege-escalation pattern.

    Flags users (or service principals) that own an app registration which
    holds high-risk Microsoft Graph application permissions. An app owner
    can mint new credentials, grant additional consents, and effectively
    *become* the app — so owning an app that holds e.g. ``Mail.ReadWrite.All``
    is functionally equivalent to holding it directly, without the
    audit-trail visibility of a real role assignment.
    """
    findings: list[CrossSurfaceFinding] = []
    for e in graph.edges:
        if e.kind != EdgeKind.OWNS:
            continue
        if not e.metadata_dict.get("app_has_high_risk_graph_permissions"):
            continue
        owner = graph.get_node(e.src)
        app = graph.get_node(e.dst)
        if owner is None or app is None:
            continue
        findings.append(
            CrossSurfaceFinding(
                title=(
                    f"{owner.name or e.src} owns app {app.name or e.dst} with "
                    "high-risk Graph permissions"
                ),
                severity="high",
                description=(
                    f"Owner {owner.name or e.src} can mint new credentials "
                    f"for app {app.name or e.dst}, which holds high-risk "
                    "application permissions (e.g. Mail.ReadWrite.All). "
                    "App ownership is functionally equivalent to holding "
                    "the underlying permissions directly."
                ),
                principal_id=e.src,
                related_node_ids=(e.src, e.dst),
            )
        )
    return findings


def find_dwd_apps(graph: PermissionGraph) -> list[CrossSurfaceFinding]:
    """Apps with domain-wide / admin-consent delegation to a tenant."""
    findings: list[CrossSurfaceFinding] = []
    for e in graph.edges:
        if e.kind != EdgeKind.DELEGATED_TO:
            continue
        node = graph.get_node(e.src)
        if node is None:
            continue
        meta = node.metadata_dict
        is_verified = bool(meta.get("verified") or meta.get("is_trusted"))
        severity = "critical" if not is_verified else "high"
        findings.append(
            CrossSurfaceFinding(
                title=(
                    f"App {node.name or e.src} has tenant-wide delegation "
                    f"({node.cloud_provider})"
                ),
                severity=severity,
                description=(
                    f"App {node.name or e.src} can act as any user in tenant "
                    f"{e.dst}. Verified={is_verified}. Tenant-wide delegation is "
                    "the most-sensitive secret class in the connector."
                ),
                principal_id=e.src,
                related_node_ids=(e.src, e.dst),
            )
        )
    return findings
