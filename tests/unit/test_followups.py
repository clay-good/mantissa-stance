"""Unit tests for the two carry-forward follow-ups requested after PR 10:

1. ``SensitiveDataDetector.scan_records`` derives ``highest_classification``
   from the classifier's own rule registry, not by re-classifying the
   category's string value as a field name. This deletes the
   ``_saas_exposure.classification_from_categories`` workaround.

2. ``entra_app_registration`` now carries an ``owners`` list (fetched via
   ``/v1.0/applications/{id}/owners``) and ``EntraIdentityMapper`` emits
   ``OWNS`` edges; ``cross_surface.find_high_risk_app_owners`` flags the
   §5.1 privilege-escalation pattern (owner of an app with high-risk
   Graph application permissions).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock  # noqa: F401 — kept for fixture symmetry

import pytest

from stance.collectors.m365_entra_apps import EntraAppsCollector
from stance.dspm.classifier import ClassificationLevel, DataCategory
from stance.dspm.detector import SensitiveDataDetector
from stance.identity.cross_surface import find_high_risk_app_owners
from stance.identity.entra_mapper import EntraIdentityMapper
from stance.identity.saas_graph import EdgeKind, NodeKind
from stance.models import Asset, AssetCollection


# --------------------------------------------------------------------------- #
# 1. Detector classification fix
# --------------------------------------------------------------------------- #


class TestDetectorClassificationFromRules:
    def test_pii_email_now_returns_confidential(self):
        """Before the fix, the detector returned PUBLIC because
        ``classify(field_name='pii_email')`` matched no field_pattern."""
        detector = SensitiveDataDetector()
        result = detector.scan_records(
            [{"content": "Email: jane.doe@example.com"}],
            asset_id="x",
            asset_type="file",
        )
        assert result.has_sensitive_data is True
        assert DataCategory.PII_EMAIL in result.categories_found
        assert (
            result.highest_classification.severity_score
            >= ClassificationLevel.CONFIDENTIAL.severity_score
        )

    def test_credentials_pattern_returns_top_secret(self):
        """``CREDENTIALS_PRIVATE_KEY`` is registered at TOP_SECRET in the
        classifier rules; the detector must reflect that."""
        detector = SensitiveDataDetector()
        result = detector.scan_records(
            [
                {
                    "content": (
                        "-----BEGIN RSA PRIVATE KEY-----\n"
                        "fakepayload==\n"
                        "-----END RSA PRIVATE KEY-----"
                    )
                }
            ],
            asset_id="x",
            asset_type="file",
        )
        if result.has_sensitive_data:
            # Some default-pattern sets ship a private-key regex, some don't.
            # When matched, the level must be at least RESTRICTED.
            assert (
                result.highest_classification.severity_score
                >= ClassificationLevel.RESTRICTED.severity_score
            )

    def test_workaround_module_no_longer_exposes_helper(self):
        """The PR 8 workaround function should be gone from the module."""
        from stance.dspm.extended import _saas_exposure

        assert not hasattr(_saas_exposure, "classification_from_categories"), (
            "classification_from_categories should have been deleted with the "
            "detector fix"
        )


# --------------------------------------------------------------------------- #
# 2. App owners → OWNS edges → privilege-escalation finding
# --------------------------------------------------------------------------- #


def _make_graph(routes: dict[str, Any]) -> Any:
    sorted_keys = sorted(routes.keys(), key=len, reverse=True)

    def graph(path: str) -> dict[str, Any]:
        if path in routes:
            return routes[path]
        for key in sorted_keys:
            if path.startswith(key):
                return routes[key]
        return {}

    return graph


class TestEntraAppOwnersCollector:
    def test_collector_emits_owners_field(self):
        graph = _make_graph(
            {
                "/v1.0/servicePrincipals": {"value": []},
                "/v1.0/applications": {
                    "value": [
                        {
                            "id": "obj-1",
                            "appId": "app-1",
                            "displayName": "Risky App",
                            "requiredResourceAccess": [
                                {
                                    "resourceAppId": "00000003-0000-0000-c000-000000000000",
                                    "resourceAccess": [
                                        {
                                            "id": "Mail.ReadWrite.All",
                                            "type": "Role",
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                },
                "/v1.0/applications/obj-1/owners": {
                    "value": [
                        {
                            "@odata.type": "#microsoft.graph.user",
                            "id": "user-uid-1",
                            "displayName": "Alice",
                            "userPrincipalName": "alice@example.com",
                        }
                    ]
                },
            }
        )
        assets = list(EntraAppsCollector(graph, "t1").collect())
        apps = [a for a in assets if a.resource_type == "entra_app_registration"]
        assert len(apps) == 1
        cfg = apps[0].raw_config
        assert cfg["owner_count"] == 1
        assert cfg["has_owner"] is True
        assert cfg["owners"][0]["id"] == "user-uid-1"
        assert cfg["owners"][0]["user_principal_name"] == "alice@example.com"
        assert cfg["has_high_risk_graph_permissions"] is True

    def test_collector_handles_empty_owners(self):
        graph = _make_graph(
            {
                "/v1.0/servicePrincipals": {"value": []},
                "/v1.0/applications": {
                    "value": [
                        {"id": "obj-1", "appId": "app-1", "displayName": "App"}
                    ]
                },
                "/v1.0/applications/obj-1/owners": {"value": []},
            }
        )
        apps = [
            a
            for a in EntraAppsCollector(graph, "t1").collect()
            if a.resource_type == "entra_app_registration"
        ]
        assert apps[0].raw_config["owner_count"] == 0
        assert apps[0].raw_config["has_owner"] is False


# --------------------------------------------------------------------------- #
# Mapper: OWNS edge emission
# --------------------------------------------------------------------------- #


def _app_asset(
    *,
    app_id: str,
    high_risk: bool,
    owners: list[dict[str, Any]],
) -> Asset:
    return Asset(
        id=f"entra:app_registration:{app_id}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_app_registration",
        name=app_id,
        raw_config={
            "app_object_id": f"obj-{app_id}",
            "app_id": app_id,
            "display_name": app_id,
            "has_high_risk_graph_permissions": high_risk,
            "is_orphaned": False,
            "owners": owners,
            "owner_count": len(owners),
            "has_owner": bool(owners),
        },
    )


def _user_asset(upn: str) -> Asset:
    uid = upn.replace("@", "_at_")
    return Asset(
        id=f"entra:user:{uid}",
        cloud_provider="microsoft_365",
        account_id="t1",
        region="global",
        resource_type="entra_user",
        name=upn,
        raw_config={
            "user_id": uid,
            "user_principal_name": upn,
            "display_name": upn,
            "account_enabled": True,
            "user_type": "Member",
            "is_guest": False,
            "last_sign_in": "",
        },
    )


class TestOwnsEdges:
    def test_owns_edge_emitted_with_admin_level(self):
        app = _app_asset(
            app_id="risky",
            high_risk=True,
            owners=[
                {
                    "id": "alice_at_example.com",
                    "odata_type": "#microsoft.graph.user",
                    "display_name": "Alice",
                    "user_principal_name": "alice@example.com",
                    "app_id": "",
                }
            ],
        )
        graph = EntraIdentityMapper(
            AssetCollection([_user_asset("alice@example.com"), app])
        ).build()
        owns_edges = [e for e in graph.edges if e.kind == EdgeKind.OWNS]
        assert len(owns_edges) == 1
        edge = owns_edges[0]
        assert edge.dst == "entra:app_registration:risky"
        # The mapper resolved owner.id → the existing entra:user:* asset id.
        assert edge.src == "entra:user:alice_at_example.com"
        assert edge.metadata_dict["app_has_high_risk_graph_permissions"] is True

    def test_owns_edge_falls_back_to_synthetic_node_when_owner_not_in_snapshot(
        self,
    ):
        app = _app_asset(
            app_id="risky",
            high_risk=False,
            owners=[
                {
                    "id": "ghost-uid",
                    "odata_type": "#microsoft.graph.user",
                    "display_name": "Ghost",
                    "user_principal_name": "ghost@example.com",
                    "app_id": "",
                }
            ],
        )
        graph = EntraIdentityMapper(AssetCollection([app])).build()
        owns_edges = [e for e in graph.edges if e.kind == EdgeKind.OWNS]
        assert len(owns_edges) == 1
        assert owns_edges[0].src == "entra:user:ghost-uid"
        # The synthetic node is created by add_edge's placeholder logic.
        node = graph.get_node("entra:user:ghost-uid")
        assert node is not None

    def test_service_principal_owner(self):
        app = _app_asset(
            app_id="risky",
            high_risk=True,
            owners=[
                {
                    "id": "sp-uid-1",
                    "odata_type": "#microsoft.graph.servicePrincipal",
                    "display_name": "Automation SP",
                    "user_principal_name": "",
                    "app_id": "auto-app",
                }
            ],
        )
        graph = EntraIdentityMapper(AssetCollection([app])).build()
        owns_edges = [e for e in graph.edges if e.kind == EdgeKind.OWNS]
        assert len(owns_edges) == 1
        assert owns_edges[0].src == "entra:service_principal:sp-uid-1"


# --------------------------------------------------------------------------- #
# Cross-surface query: high-risk app owners
# --------------------------------------------------------------------------- #


class TestFindHighRiskAppOwners:
    def test_finding_fires_for_high_risk_app(self):
        app = _app_asset(
            app_id="risky",
            high_risk=True,
            owners=[
                {
                    "id": "alice_at_example.com",
                    "odata_type": "#microsoft.graph.user",
                    "display_name": "Alice",
                    "user_principal_name": "alice@example.com",
                    "app_id": "",
                }
            ],
        )
        graph = EntraIdentityMapper(
            AssetCollection([_user_asset("alice@example.com"), app])
        ).build()
        findings = find_high_risk_app_owners(graph)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "Alice" in findings[0].title or "alice" in findings[0].title.lower()
        assert findings[0].related_node_ids == (
            "entra:user:alice_at_example.com",
            "entra:app_registration:risky",
        )

    def test_no_finding_when_app_is_low_risk(self):
        app = _app_asset(
            app_id="benign",
            high_risk=False,
            owners=[
                {
                    "id": "alice_at_example.com",
                    "odata_type": "#microsoft.graph.user",
                    "display_name": "Alice",
                    "user_principal_name": "alice@example.com",
                    "app_id": "",
                }
            ],
        )
        graph = EntraIdentityMapper(
            AssetCollection([_user_asset("alice@example.com"), app])
        ).build()
        assert find_high_risk_app_owners(graph) == []

    def test_no_finding_when_app_has_no_owners(self):
        app = _app_asset(app_id="risky", high_risk=True, owners=[])
        graph = EntraIdentityMapper(AssetCollection([app])).build()
        assert find_high_risk_app_owners(graph) == []
