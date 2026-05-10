"""Unit tests for the SaaS CLI surface (PR 9 — SAAS_POSTURE_SPEC §9).

Covers ``stance saas connect | scan | graph``, the ``--source`` extension
to ``stance dspm scan``, and the ``--include-saas`` extension to
``stance ciem graph``. Tests drive the handlers directly via an
``argparse.Namespace`` so no subprocess / argv parsing is involved.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from stance.cli_ciem import _ciem_graph
from stance.cli_dspm import _cmd_dspm_scan, _cmd_dspm_scan_saas_source
from stance.cli_saas import _cmd_connect, _cmd_graph, _cmd_scan, cmd_saas


# --------------------------------------------------------------------------- #
# Fixture helpers
# --------------------------------------------------------------------------- #


REPO_ROOT = Path(__file__).resolve().parents[2]


def _capture(handler, args) -> tuple[int, str]:
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        rc = handler(args)
    finally:
        sys.stdout = real
    return rc, buf.getvalue()


def _gws_user_snapshot_entry(email: str, *, super_admin: bool = False) -> dict[str, Any]:
    return {
        "id": f"gws:user:{email.split('@', 1)[0]}",
        "cloud_provider": "google_workspace",
        "account_id": "C0",
        "region": "global",
        "resource_type": "gws_user",
        "name": email,
        "raw_config": {
            "user_id": email.split("@", 1)[0],
            "primary_email": email,
            "username": email.split("@", 1)[0],
            "is_admin": super_admin,
            "is_super_admin": super_admin,
            "is_delegated_admin": False,
            "two_factor_enrolled": True,
            "suspended": False,
            "is_inactive": False,
            "org_unit_path": "/",
        },
    }


def _gws_role_assignment_entry(user_id: str) -> dict[str, Any]:
    return {
        "id": f"gws:role_assignment:ra-{user_id}",
        "cloud_provider": "google_workspace",
        "account_id": "C0",
        "region": "global",
        "resource_type": "gws_role_assignment",
        "name": "_SEED_ADMIN_ROLE",
        "raw_config": {
            "role_assignment_id": f"ra-{user_id}",
            "role_id": "r-super",
            "role_name": "_SEED_ADMIN_ROLE",
            "is_system_role": True,
            "is_super_admin_role": True,
            "assigned_to": user_id,
            "scope_type": "CUSTOMER",
            "org_unit_id": "",
        },
    }


def _entra_user_snapshot_entry(
    upn: str, *, role_id: str | None = None
) -> list[dict[str, Any]]:
    uid = upn.replace("@", "_at_")
    out = [
        {
            "id": f"entra:user:{uid}",
            "cloud_provider": "microsoft_365",
            "account_id": "t1",
            "region": "global",
            "resource_type": "entra_user",
            "name": upn,
            "raw_config": {
                "user_id": uid,
                "user_principal_name": upn,
                "display_name": upn,
                "account_enabled": True,
                "user_type": "Member",
                "is_guest": False,
                "last_sign_in": "",
            },
        }
    ]
    if role_id:
        out.append(
            {
                "id": f"entra:directory_role:{role_id}",
                "cloud_provider": "microsoft_365",
                "account_id": "t1",
                "region": "global",
                "resource_type": "entra_directory_role",
                "name": "Global Administrator",
                "raw_config": {
                    "role_id": role_id,
                    "role_name": "Global Administrator",
                    "is_privileged": True,
                    "is_built_in": True,
                    "template_id": "",
                },
            }
        )
        out.append(
            {
                "id": f"entra:role_assignment:ra-{uid}-{role_id}",
                "cloud_provider": "microsoft_365",
                "account_id": "t1",
                "region": "global",
                "resource_type": "entra_role_assignment",
                "name": "Global Administrator",
                "raw_config": {
                    "assignment_id": f"ra-{uid}-{role_id}",
                    "status": "active",
                    "role_id": role_id,
                    "role_name": "Global Administrator",
                    "is_privileged_role": True,
                    "principal_id": uid,
                    "directory_scope_id": "/",
                    "is_permanent": True,
                },
            }
        )
    return out


@pytest.fixture
def snapshot_path(tmp_path: Path) -> Path:
    # alice is super admin in BOTH clouds → drives the cross-admin finding.
    entries = [
        _gws_user_snapshot_entry("alice@example.com", super_admin=True),
        _gws_role_assignment_entry("alice"),
        *_entra_user_snapshot_entry("alice@example.com", role_id="r-ga"),
        # bob exists in GWS only → no cross-correlation
        _gws_user_snapshot_entry("bob@example.com", super_admin=False),
    ]
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps({"assets": entries}))
    return path


# --------------------------------------------------------------------------- #
# connect
# --------------------------------------------------------------------------- #


class TestConnect:
    def test_gws_connect_emits_stub(self):
        args = argparse.Namespace(provider="google-workspace", output="")
        rc, out = _capture(_cmd_connect, args)
        assert rc == 0
        assert '"service_account_file"' in out
        assert "Setup steps for google-workspace" in out

    def test_m365_connect_writes_file(self, tmp_path: Path):
        stub = tmp_path / "stub.json"
        args = argparse.Namespace(provider="microsoft-365", output=str(stub))
        rc, out = _capture(_cmd_connect, args)
        assert rc == 0
        assert stub.exists()
        data = json.loads(stub.read_text())
        assert data["provider"] == "microsoft_365"
        assert "Setup steps for microsoft-365" in out


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


class TestScan:
    def test_gws_scan_loads_snapshot_and_evaluates(self, snapshot_path: Path):
        # The default policies/saas/google_workspace tree is on disk.
        args = argparse.Namespace(
            provider="gws",
            snapshot=str(snapshot_path),
            policies_dir=str(REPO_ROOT / "policies" / "saas"),
            format="json",
        )
        rc, out = _capture(_cmd_scan, args)
        assert rc == 0
        body = json.loads(out)
        assert body["provider"] == "gws"
        assert body["assets_evaluated"] > 0
        assert body["policies_evaluated"] > 0
        # The snapshot has no gws_tenant_security asset, so most rules silently
        # skip — but the schema is what matters here.
        assert "findings" in body

    def test_scan_missing_snapshot_errors(self, tmp_path: Path):
        args = argparse.Namespace(
            provider="gws",
            snapshot=str(tmp_path / "nope.json"),
            policies_dir=str(REPO_ROOT / "policies" / "saas"),
            format="table",
        )
        rc, out = _capture(_cmd_scan, args)
        assert rc == 1
        assert "could not load snapshot" in out


# --------------------------------------------------------------------------- #
# graph
# --------------------------------------------------------------------------- #


class TestGraph:
    def test_graph_finds_cross_admin(self, snapshot_path: Path):
        args = argparse.Namespace(
            snapshot=str(snapshot_path),
            include_saas=True,
            primary_domain="example.com",
            format="json",
        )
        rc, out = _capture(_cmd_graph, args)
        assert rc == 0
        body = json.loads(out)
        assert body["node_count"] > 0
        assert any(
            "alice@example.com" in u["email"] for u in body["correlated_users"]
        )
        # Alice is admin in BOTH providers → the cross-admin finding must fire.
        assert body["cross_admin_findings"], (
            f"expected at least one cross-admin finding, got {body}"
        )

    def test_graph_table_output(self, snapshot_path: Path):
        args = argparse.Namespace(
            snapshot=str(snapshot_path),
            include_saas=True,
            primary_domain="example.com",
            format="table",
        )
        rc, out = _capture(_cmd_graph, args)
        assert rc == 0
        assert "Graph:" in out
        assert "Cross-surface users" in out


# --------------------------------------------------------------------------- #
# cmd_saas dispatcher
# --------------------------------------------------------------------------- #


class TestCmdSaas:
    def test_no_action_prints_help(self):
        args = argparse.Namespace(saas_action=None)
        rc, out = _capture(cmd_saas, args)
        assert rc == 0
        assert "Usage: stance saas" in out

    def test_unknown_action_returns_1(self):
        args = argparse.Namespace(saas_action="bogus")
        rc, _ = _capture(cmd_saas, args)
        assert rc == 1


# --------------------------------------------------------------------------- #
# cli_dspm --source SaaS extension
# --------------------------------------------------------------------------- #


class TestDSPMSourceExtension:
    def test_source_without_snapshot_errors(self):
        args = argparse.Namespace(
            source="m365-sharepoint",
            snapshot="",
            format="table",
        )
        rc, out = _capture(_cmd_dspm_scan_saas_source, args)
        assert rc == 1
        assert "--snapshot is required" in out

    def test_source_reads_finding_snapshot(self, tmp_path: Path):
        snapshot = tmp_path / "findings.json"
        snapshot.write_text(
            json.dumps(
                {
                    "source_type": "m365_sharepoint",
                    "target": "site-1",
                    "findings": [
                        {
                            "severity": "critical",
                            "object_name": "secrets.csv",
                            "metadata": {"exposure_score": 88.0},
                        }
                    ],
                    "summary": {
                        "total_objects_scanned": 1,
                        "total_objects_skipped": 0,
                    },
                }
            )
        )
        args = argparse.Namespace(
            source="m365-sharepoint",
            snapshot=str(snapshot),
            format="json",
        )
        rc, out = _capture(_cmd_dspm_scan_saas_source, args)
        assert rc == 0
        body = json.loads(out)
        assert body["source"] == "m365_sharepoint"
        assert body["findings"][0]["severity"] == "critical"

    def test_dspm_scan_dispatches_to_saas_when_source_set(self, tmp_path: Path):
        # _cmd_dspm_scan should detect args.source and route to the SaaS path.
        snapshot = tmp_path / "f.json"
        snapshot.write_text(
            json.dumps({"findings": [], "summary": {}, "source_type": "m365_onedrive"})
        )
        args = argparse.Namespace(
            target="ignored",
            cloud=None,
            source="m365-onedrive",
            snapshot=str(snapshot),
            format="table",
            sample_size=10,
            max_file_size=1024,
            include=None,
            exclude=None,
        )
        rc, out = _capture(_cmd_dspm_scan, args)
        assert rc == 0
        assert "m365_onedrive" in out

    def test_dspm_scan_without_cloud_or_source_errors(self):
        args = argparse.Namespace(
            target="bucket",
            cloud=None,
            source=None,
            snapshot="",
            format="table",
            sample_size=10,
            max_file_size=1024,
            include=None,
            exclude=None,
        )
        rc, out = _capture(_cmd_dspm_scan, args)
        assert rc == 1
        assert "--cloud is required" in out


# --------------------------------------------------------------------------- #
# cli_ciem graph --include-saas extension
# --------------------------------------------------------------------------- #


class TestCIEMGraphExtension:
    def test_graph_without_include_saas_errors(self):
        args = argparse.Namespace(include_saas=False, snapshot="", format="table")
        rc, out = _capture(_ciem_graph, args)
        assert rc == 1
        assert "--include-saas" in out

    def test_graph_without_snapshot_errors(self):
        args = argparse.Namespace(include_saas=True, snapshot="", format="table")
        rc, out = _capture(_ciem_graph, args)
        assert rc == 1
        assert "--snapshot is required" in out

    def test_graph_delegates_to_cli_saas(self, snapshot_path: Path):
        args = argparse.Namespace(
            include_saas=True,
            snapshot=str(snapshot_path),
            primary_domain="example.com",
            format="json",
        )
        rc, out = _capture(_ciem_graph, args)
        assert rc == 0
        body = json.loads(out)
        assert body["node_count"] > 0
