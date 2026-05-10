"""Unit tests for the SaaS CIEM mappers and cross-surface joins (PR 7).

Covers:
- ``GWSIdentityMapper`` — building a permission graph from GWS asset snapshots.
- ``EntraIdentityMapper`` — same for Entra.
- ``cross_surface.correlate_users_by_email`` — the differentiator query
  ("which users are admin in 2+ providers"), plus federation + DWD findings.
"""

from __future__ import annotations

from typing import Any

from stance.identity.cross_surface import (
    correlate_users_by_email,
    find_cross_admin_users,
    find_dwd_apps,
    find_unverified_federated_admins,
)
from stance.identity.entra_mapper import EntraIdentityMapper
from stance.identity.gws_mapper import GWSIdentityMapper
from stance.identity.saas_graph import EdgeKind, NodeKind, PermissionGraph
from stance.models import Asset, AssetCollection


# --------------------------------------------------------------------------- #
# Asset fixtures
# --------------------------------------------------------------------------- #


def _gws_user(email: str, **o: Any) -> Asset:
    cfg = {
        "user_id": email.split("@", 1)[0],
        "primary_email": email,
        "username": email.split("@", 1)[0],
        "is_admin": False,
        "is_super_admin": False,
        "is_delegated_admin": False,
        "two_factor_enrolled": True,
        "suspended": False,
        "is_inactive": False,
        "org_unit_path": "/",
    }
    cfg.update(o)
    return Asset(
        id=f"gws:user:{cfg['user_id']}",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_user",
        name=email,
        raw_config=cfg,
    )


def _gws_role_assignment(
    *, user_id: str, role_id: str, role_name: str, super_admin: bool = False
) -> Asset:
    cfg = {
        "role_assignment_id": f"ra-{user_id}-{role_id}",
        "role_id": role_id,
        "role_name": role_name,
        "is_system_role": False,
        "is_super_admin_role": super_admin,
        "assigned_to": user_id,
        "scope_type": "CUSTOMER",
        "org_unit_id": "",
    }
    return Asset(
        id=f"gws:role_assignment:{cfg['role_assignment_id']}",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_role_assignment",
        name=role_name,
        raw_config=cfg,
    )


def _gws_oauth_app(
    *, client_id: str, scope_risk: str, dwd: bool, verified: bool, users: list[str]
) -> Asset:
    cfg = {
        "client_id": client_id,
        "display_text": f"App {client_id}",
        "scopes": [],
        "scope_count": 0,
        "scope_risk": scope_risk,
        "scope_tiers": [scope_risk],
        "user_count": len(users),
        "users_sample": users,
        "is_google_app": False,
        "is_trusted": verified,
        "verified": verified,
        "domain_wide_delegated": dwd,
        "anonymous": False,
        "native_app": False,
        "has_drive_full_scope": False,
        "has_gmail_full_scope": False,
        "has_admin_directory_scope": False,
    }
    return Asset(
        id=f"gws:oauth_app:{client_id}",
        cloud_provider="google_workspace",
        account_id="C0",
        region="global",
        resource_type="gws_oauth_app",
        name=cfg["display_text"],
        raw_config=cfg,
    )


def _entra_user(upn: str, *, is_guest: bool = False) -> Asset:
    uid = upn.replace("@", "_at_")
    cfg = {
        "user_id": uid,
        "user_principal_name": upn,
        "display_name": upn,
        "account_enabled": True,
        "user_type": "Guest" if is_guest else "Member",
        "is_guest": is_guest,
        "last_sign_in": "",
    }
    return Asset(
        id=f"entra:user:{uid}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_user",
        name=upn,
        raw_config=cfg,
    )


def _entra_role(role_id: str, role_name: str, privileged: bool) -> Asset:
    cfg = {
        "role_id": role_id,
        "template_id": "",
        "role_name": role_name,
        "is_built_in": True,
        "is_privileged": privileged,
    }
    return Asset(
        id=f"entra:directory_role:{role_id}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_directory_role",
        name=role_name,
        raw_config=cfg,
    )


def _entra_role_assignment(
    *, user_uid: str, role_id: str, role_name: str, privileged: bool, status: str = "active"
) -> Asset:
    aid = f"ra-{user_uid}-{role_id}-{status}"
    cfg = {
        "assignment_id": aid,
        "status": status,
        "role_id": role_id,
        "role_name": role_name,
        "is_privileged_role": privileged,
        "principal_id": user_uid,
        "directory_scope_id": "/",
        "is_permanent": status == "active",
    }
    return Asset(
        id=f"entra:role_assignment:{aid}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_role_assignment",
        name=role_name,
        raw_config=cfg,
    )


def _entra_domain(domain: str, *, federated: bool, verified: bool) -> Asset:
    cfg = {
        "domain": domain,
        "authentication_type": "Federated" if federated else "Managed",
        "is_default": False,
        "is_initial": False,
        "is_verified": verified,
        "is_federated": federated,
        "supported_services": [],
    }
    return Asset(
        id=f"entra:domain:{domain}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_domain",
        name=domain,
        raw_config=cfg,
    )


# --------------------------------------------------------------------------- #
# GWS mapper
# --------------------------------------------------------------------------- #


class TestGWSMapper:
    def test_admin_role_lights_up_principal(self):
        assets = AssetCollection(
            [
                _gws_user("alice@example.com", is_admin=True, is_super_admin=True),
                _gws_user("bob@example.com"),
                _gws_role_assignment(
                    user_id="alice",
                    role_id="r-super",
                    role_name="_SEED_ADMIN_ROLE",
                    super_admin=True,
                ),
                _gws_role_assignment(
                    user_id="bob",
                    role_id="r-help",
                    role_name="Help Desk Admin",
                    super_admin=False,
                ),
            ]
        )
        graph = GWSIdentityMapper(assets, primary_domain="example.com").build()
        alice_node = next(
            n for n in graph.nodes_by_kind(NodeKind.USER)
            if n.metadata_dict.get("email") == "alice@example.com"
        )
        # The role-assignment was assigned_to="alice" (not the asset id), so
        # the mapper falls back to a synthetic gws:principal:alice node — verify
        # the synthetic node carries the role.
        candidates = [n for n in graph.nodes_by_kind(NodeKind.USER) if "alice" in n.id]
        admin_users = [n for n in candidates if graph.is_admin(n.id)]
        assert admin_users, "expected at least one alice node to be admin"

    def test_dwd_oauth_app_emits_delegation(self):
        assets = AssetCollection(
            [
                _gws_user("alice@example.com"),
                _gws_oauth_app(
                    client_id="dwd-1",
                    scope_risk="critical",
                    dwd=True,
                    verified=False,
                    users=["alice@example.com"],
                ),
            ]
        )
        graph = GWSIdentityMapper(assets, primary_domain="example.com").build()
        delegations = [e for e in graph.edges if e.kind == EdgeKind.DELEGATED_TO]
        assert any(
            "gws:oauth_app:dwd-1" in e.src and "gws:tenant:" in e.dst
            for e in delegations
        )

    def test_oauth_app_authorized_for_user(self):
        assets = AssetCollection(
            [
                _gws_user("alice@example.com"),
                _gws_oauth_app(
                    client_id="app-1",
                    scope_risk="high",
                    dwd=False,
                    verified=True,
                    users=["alice@example.com"],
                ),
            ]
        )
        graph = GWSIdentityMapper(assets, primary_domain="example.com").build()
        authorized = [e for e in graph.edges if e.kind == EdgeKind.AUTHORIZED_FOR]
        assert authorized
        assert any(e.dst.startswith("gws:user:") for e in authorized)


# --------------------------------------------------------------------------- #
# Entra mapper
# --------------------------------------------------------------------------- #


class TestEntraMapper:
    def test_user_with_global_admin(self):
        ga = _entra_role("r-ga", "Global Administrator", privileged=True)
        u = _entra_user("alice@example.com")
        ra = _entra_role_assignment(
            user_uid=u.raw_config["user_id"],
            role_id="r-ga",
            role_name="Global Administrator",
            privileged=True,
        )
        graph = EntraIdentityMapper(AssetCollection([u, ga, ra])).build()
        admin_users = [
            n for n in graph.nodes_by_kind(NodeKind.USER) if graph.is_admin(n.id)
        ]
        assert admin_users
        assert admin_users[0].metadata_dict["email"] == "alice@example.com"

    def test_unverified_federated_domain(self):
        d_ok = _entra_domain("good.com", federated=True, verified=True)
        d_bad = _entra_domain("bad.com", federated=True, verified=False)
        graph = EntraIdentityMapper(AssetCollection([d_ok, d_bad])).build()
        feds = [e for e in graph.edges if e.kind == EdgeKind.FEDERATED_TO]
        assert len(feds) == 2
        bad = [e for e in feds if "bad.com" in e.src]
        assert bad and bad[0].metadata_dict["is_verified"] is False


# --------------------------------------------------------------------------- #
# Cross-surface
# --------------------------------------------------------------------------- #


class TestCrossSurface:
    def _alice_in_both_clouds_admin_in_one(self) -> PermissionGraph:
        # GWS: alice is super admin
        gws = AssetCollection(
            [
                _gws_user("alice@example.com", is_admin=True, is_super_admin=True),
                _gws_role_assignment(
                    user_id="alice",
                    role_id="r-super",
                    role_name="_SEED_ADMIN_ROLE",
                    super_admin=True,
                ),
            ]
        )
        # Entra: alice is just a member
        entra = AssetCollection([_entra_user("alice@example.com")])
        g = GWSIdentityMapper(gws, "example.com").build()
        g.merge(EntraIdentityMapper(entra).build())
        return g

    def _alice_admin_in_both(self) -> PermissionGraph:
        gws_assets = AssetCollection(
            [
                _gws_user("alice@example.com", is_admin=True, is_super_admin=True),
                _gws_role_assignment(
                    user_id="alice",
                    role_id="r-super",
                    role_name="_SEED_ADMIN_ROLE",
                    super_admin=True,
                ),
            ]
        )
        u = _entra_user("alice@example.com")
        ra = _entra_role_assignment(
            user_uid=u.raw_config["user_id"],
            role_id="r-ga",
            role_name="Global Administrator",
            privileged=True,
        )
        ga = _entra_role("r-ga", "Global Administrator", privileged=True)
        g = GWSIdentityMapper(gws_assets, "example.com").build()
        g.merge(EntraIdentityMapper(AssetCollection([u, ga, ra])).build())
        return g

    def test_correlate_finds_user_in_two_providers(self):
        graph = self._alice_in_both_clouds_admin_in_one()
        users = correlate_users_by_email(graph)
        emails = [u.email for u in users]
        assert "alice@example.com" in emails
        alice = next(u for u in users if u.email == "alice@example.com")
        assert alice.provider_count == 2
        # Admin only in GWS in this fixture.
        assert alice.admin_in == ["google_workspace"]

    def test_cross_admin_finding_when_admin_in_both(self):
        graph = self._alice_admin_in_both()
        findings = find_cross_admin_users(graph)
        assert any("alice@example.com" in f.principal_id for f in findings)
        # 2 providers → "high"; 3+ → "critical"
        finding = next(f for f in findings if "alice@example.com" in f.principal_id)
        assert finding.severity == "high"

    def test_cross_admin_finding_skipped_when_only_one_admin(self):
        graph = self._alice_in_both_clouds_admin_in_one()
        findings = find_cross_admin_users(graph)
        assert not any("alice@example.com" in f.principal_id for f in findings)

    def test_unverified_federation_finding(self):
        d_bad = _entra_domain("bad.com", federated=True, verified=False)
        graph = EntraIdentityMapper(AssetCollection([d_bad])).build()
        findings = find_unverified_federated_admins(graph)
        assert findings
        assert "bad.com" in findings[0].principal_id

    def test_dwd_finding(self):
        gws = AssetCollection(
            [
                _gws_user("alice@example.com"),
                _gws_oauth_app(
                    client_id="dwd-1",
                    scope_risk="critical",
                    dwd=True,
                    verified=False,
                    users=["alice@example.com"],
                ),
            ]
        )
        graph = GWSIdentityMapper(gws, "example.com").build()
        findings = find_dwd_apps(graph)
        assert findings
        assert findings[0].severity == "critical"  # not verified → critical

    def test_no_match_when_emails_differ(self):
        gws = AssetCollection([_gws_user("alice@example.com", is_super_admin=True)])
        entra = AssetCollection([_entra_user("ALICE@OTHER.COM")])
        g = GWSIdentityMapper(gws, "example.com").build()
        g.merge(EntraIdentityMapper(entra).build())
        users = correlate_users_by_email(g)
        assert users == []

    def test_email_match_is_case_insensitive(self):
        gws = AssetCollection([_gws_user("Alice@Example.com")])
        entra = AssetCollection([_entra_user("alice@EXAMPLE.com")])
        g = GWSIdentityMapper(gws, "example.com").build()
        g.merge(EntraIdentityMapper(entra).build())
        users = correlate_users_by_email(g)
        assert len(users) == 1
        assert users[0].email == "alice@example.com"


# --------------------------------------------------------------------------- #
# Graph plumbing
# --------------------------------------------------------------------------- #


class TestPermissionGraph:
    def test_merge_unions_nodes_and_edges(self):
        g1 = PermissionGraph()
        g2 = PermissionGraph()
        from stance.identity.saas_graph import Node, Edge

        n1 = Node.make("user:1", NodeKind.USER, "x", name="u1", metadata={"email": "u1@x"})
        n2 = Node.make("role:1", NodeKind.ROLE, "x", name="r1", metadata={"is_admin": True})
        e1 = Edge.make("user:1", "role:1", EdgeKind.HAS_ROLE)
        g1.add_node(n1)
        g1.add_node(n2)
        g1.add_edge(e1)

        n3 = Node.make("user:2", NodeKind.USER, "y", name="u2")
        g2.add_node(n3)
        g1.merge(g2)
        assert len(g1.nodes) == 3
        assert g1.is_admin("user:1") is True
        assert g1.is_admin("user:2") is False
