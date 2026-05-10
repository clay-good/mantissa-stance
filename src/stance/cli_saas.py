"""
CLI command handlers for SaaS posture (Google Workspace, Microsoft 365).

Surface (matches SAAS_POSTURE_SPEC §9):

    stance saas connect google-workspace
    stance saas connect microsoft-365
    stance saas scan --provider gws --snapshot snapshot.json
    stance saas scan --provider m365 --snapshot snapshot.json
    stance saas graph --include-saas --snapshot snapshot.json

A "snapshot" is a JSON file containing already-collected assets — one entry
per ``stance.models.Asset.to_dict()``. The connect flow (production) is
expected to drive the collectors live and persist a snapshot; the CLI then
evaluates policies and builds the cross-surface graph against the snapshot.
This split keeps the CLI itself read-only and deterministic, which makes it
trivially testable without live cloud credentials.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Argparse registration
# --------------------------------------------------------------------------- #


def add_saas_parser(subparsers: Any) -> None:
    """Register the ``saas`` subcommand tree on the top-level parser."""
    saas_parser = subparsers.add_parser(
        "saas", help="SaaS posture commands (Google Workspace, Microsoft 365)"
    )
    saas_sub = saas_parser.add_subparsers(dest="saas_action")

    # connect
    connect = saas_sub.add_parser(
        "connect", help="Generate connector setup guidance + stub config"
    )
    connect.add_argument(
        "provider",
        choices=["google-workspace", "microsoft-365"],
        help="SaaS provider to connect",
    )
    connect.add_argument(
        "--output",
        default="",
        help="Write the connector stub config to this path (default: stdout)",
    )

    # scan
    scan = saas_sub.add_parser(
        "scan", help="Evaluate SaaS policies against a tenant snapshot"
    )
    scan.add_argument(
        "--provider",
        choices=["gws", "m365"],
        required=True,
        help="Which provider's policies to evaluate",
    )
    scan.add_argument(
        "--snapshot",
        required=True,
        help="Path to a JSON file of collected Asset records",
    )
    scan.add_argument(
        "--policies-dir",
        default="policies/saas",
        help="Policy root directory (default: policies/saas)",
    )
    scan.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )

    # graph
    graph = saas_sub.add_parser(
        "graph", help="Build the cross-surface CIEM graph from a snapshot"
    )
    graph.add_argument(
        "--snapshot",
        required=True,
        help="Path to a JSON file of collected Asset records",
    )
    graph.add_argument(
        "--include-saas",
        action="store_true",
        help="Include GWS + Entra mappers (default: on for stance saas)",
    )
    graph.add_argument(
        "--primary-domain",
        default="",
        help="Primary tenant domain (used for external/internal classification)",
    )
    graph.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
    )


# --------------------------------------------------------------------------- #
# Dispatcher
# --------------------------------------------------------------------------- #


def cmd_saas(args: argparse.Namespace) -> int:
    action = getattr(args, "saas_action", None)
    if action == "connect":
        return _cmd_connect(args)
    if action == "scan":
        return _cmd_scan(args)
    if action == "graph":
        return _cmd_graph(args)
    _print_root_help()
    return 0 if action is None else 1


def _print_root_help() -> None:
    print("Usage: stance saas <command>")
    print("")
    print("Commands:")
    print("  connect <provider>   Print setup steps + write a stub config")
    print("  scan --provider X    Evaluate SaaS policies against a snapshot")
    print("  graph --snapshot X   Build the cross-surface CIEM graph")
    print("")
    print("Run 'stance saas <command> --help' for more information")


# --------------------------------------------------------------------------- #
# connect
# --------------------------------------------------------------------------- #


_CONNECT_STUBS: dict[str, dict[str, Any]] = {
    "google-workspace": {
        "provider": "google_workspace",
        "tenant_id": "<customer-id, e.g. C0123abcd>",
        "primary_domain": "<example.com>",
        "auth": {
            "service_account_file": "<path/to/sa.json>",
            "delegated_user": "<admin@example.com>",
            "scopes": [
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.group.readonly",
                "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
                "https://www.googleapis.com/auth/admin.directory.domain.readonly",
            ],
        },
        "trusted_client_ids": [],
        "domain_wide_delegated_client_ids": [],
    },
    "microsoft-365": {
        "provider": "microsoft_365",
        "tenant_id": "<tenant-guid>",
        "primary_domain": "<contoso.onmicrosoft.com>",
        "auth": {
            "client_id": "<entra-app-client-id>",
            "client_secret_env": "STANCE_M365_CLIENT_SECRET",
            "scopes": [
                "Directory.Read.All",
                "Policy.Read.All",
                "Application.Read.All",
                "RoleManagement.Read.Directory",
                "IdentityRiskyUser.Read.All",
                "Sites.FullControl.All",
            ],
        },
        "enable_mailbox_scan_for": [],
    },
}


_CONNECT_GUIDANCE: dict[str, list[str]] = {
    "google-workspace": [
        "1. Create a Google Cloud service account in the workspace-management project.",
        "2. Enable the Admin SDK API + Cloud Identity API on that project.",
        "3. In Workspace admin → Security → API controls → Domain-wide delegation,",
        "   add the service account client ID with the scopes listed above.",
        "4. Save the service account JSON key locally and reference it in the config.",
        "5. Delegate to a super-admin via ``delegated_user``.",
    ],
    "microsoft-365": [
        "1. In Entra admin → App registrations → New registration: name it `mantissa-stance`.",
        "2. API permissions → Microsoft Graph → Application: add the scopes listed above,",
        "   then grant admin consent for the tenant.",
        "3. Certificates & secrets → New client secret. Store it in the env var",
        "   referenced by ``client_secret_env``.",
        "4. (Optional) For DSPM mailbox scans, add the relevant mailboxes to",
        "   ``enable_mailbox_scan_for`` — stance never scans mailbox content by default.",
    ],
}


def _cmd_connect(args: argparse.Namespace) -> int:
    provider = args.provider
    stub = _CONNECT_STUBS.get(provider)
    guidance = _CONNECT_GUIDANCE.get(provider)
    if stub is None or guidance is None:
        print(f"Unknown provider: {provider}")
        return 1

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(stub, indent=2) + "\n")
        print(f"Wrote stub config to {out_path}")
    else:
        print(json.dumps(stub, indent=2))

    print("")
    print(f"Setup steps for {provider}:")
    for line in guidance:
        print(f"  {line}")
    return 0


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def _load_snapshot(path: str) -> list[Any]:
    """Load a list of Asset records from a JSON snapshot file.

    The file format is intentionally tiny: either a top-level JSON list of
    asset dicts, or ``{"assets": [...]}``. Each entry must be a dict that
    ``stance.models.Asset.from_dict`` accepts.
    """
    from stance.models import Asset

    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        records = data.get("assets") or data.get("value") or []
    else:
        records = data
    return [Asset.from_dict(r) for r in records]


def _cmd_scan(args: argparse.Namespace) -> int:
    from stance.engine.evaluator import PolicyEvaluator
    from stance.engine.loader import PolicyLoader
    from stance.models import AssetCollection

    provider = args.provider  # "gws" or "m365"
    snapshot_path = args.snapshot
    fmt = getattr(args, "format", "table")

    try:
        assets_list = _load_snapshot(snapshot_path)
    except Exception as e:
        print(f"Error: could not load snapshot {snapshot_path}: {e}")
        return 1

    assets = AssetCollection(assets_list)
    sub_dir = "google_workspace" if provider == "gws" else "microsoft_365"
    policies_root = Path(args.policies_dir) / sub_dir
    # Also include the shared DSPM rules — they apply to both providers.
    dspm_dir = Path(args.policies_dir) / "dspm"

    loader = PolicyLoader(
        policy_dirs=[str(policies_root)]
        + ([str(dspm_dir)] if dspm_dir.exists() else [])
    )
    policies = loader.load_all()
    findings, eval_result = PolicyEvaluator().evaluate_all(policies, assets)

    if fmt == "json":
        print(
            json.dumps(
                {
                    "provider": provider,
                    "snapshot": snapshot_path,
                    "assets_evaluated": eval_result.assets_evaluated,
                    "policies_evaluated": eval_result.policies_evaluated,
                    "findings": [f.to_dict() for f in findings],
                },
                indent=2,
                default=str,
            )
        )
    else:
        print(f"Provider:           {provider}")
        print(f"Snapshot:           {snapshot_path}")
        print(f"Assets evaluated:   {eval_result.assets_evaluated}")
        print(f"Policies evaluated: {eval_result.policies_evaluated}")
        print(f"Findings:           {len(findings)}")
        if findings:
            print("")
            print(f"{'Rule ID':<25} {'Severity':<10} Asset")
            print(f"{'-'*25} {'-'*10} {'-'*40}")
            for f in findings:
                print(f"{f.rule_id or '':<25} {f.severity.value:<10} {f.asset_id}")
    return 0


# --------------------------------------------------------------------------- #
# graph
# --------------------------------------------------------------------------- #


def _cmd_graph(args: argparse.Namespace) -> int:
    from stance.identity.cross_surface import (
        correlate_users_by_email,
        find_cross_admin_users,
        find_dwd_apps,
        find_high_risk_app_owners,
        find_unverified_federated_admins,
    )
    from stance.identity.entra_mapper import EntraIdentityMapper
    from stance.identity.gws_mapper import GWSIdentityMapper
    from stance.models import AssetCollection

    snapshot_path = args.snapshot
    fmt = getattr(args, "format", "table")
    primary_domain = getattr(args, "primary_domain", "")

    try:
        assets_list = _load_snapshot(snapshot_path)
    except Exception as e:
        print(f"Error: could not load snapshot {snapshot_path}: {e}")
        return 1

    gws_assets = AssetCollection(
        [a for a in assets_list if a.cloud_provider == "google_workspace"]
    )
    entra_assets = AssetCollection(
        [a for a in assets_list if a.cloud_provider == "microsoft_365"]
    )

    graph = GWSIdentityMapper(gws_assets, primary_domain=primary_domain).build()
    graph.merge(
        EntraIdentityMapper(entra_assets, primary_domain=primary_domain).build()
    )

    cross_admins = find_cross_admin_users(graph)
    fed_findings = find_unverified_federated_admins(graph)
    dwd_findings = find_dwd_apps(graph)
    app_owner_findings = find_high_risk_app_owners(graph)
    correlated = correlate_users_by_email(graph)

    if fmt == "json":
        print(
            json.dumps(
                {
                    "node_count": len(graph.nodes),
                    "edge_count": len(graph.edges),
                    "correlated_users": [
                        {
                            "email": u.email,
                            "provider_count": u.provider_count,
                            "admin_in": u.admin_in,
                        }
                        for u in correlated
                    ],
                    "cross_admin_findings": [
                        {"severity": f.severity, "title": f.title} for f in cross_admins
                    ],
                    "unverified_federation_findings": [
                        {"severity": f.severity, "title": f.title} for f in fed_findings
                    ],
                    "dwd_findings": [
                        {"severity": f.severity, "title": f.title} for f in dwd_findings
                    ],
                    "app_owner_findings": [
                        {"severity": f.severity, "title": f.title}
                        for f in app_owner_findings
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        print(f"Cross-surface users (in 2+ providers): {len(correlated)}")
        for u in correlated[:10]:
            print(
                f"  {u.email:<40} providers={u.provider_count} "
                f"admin_in={','.join(u.admin_in) or '-'}"
            )
        print(f"Cross-admin findings: {len(cross_admins)}")
        for f in cross_admins:
            print(f"  [{f.severity}] {f.title}")
        print(f"Unverified-federation findings: {len(fed_findings)}")
        for f in fed_findings:
            print(f"  [{f.severity}] {f.title}")
        print(f"Tenant-wide delegation findings: {len(dwd_findings)}")
        for f in dwd_findings:
            print(f"  [{f.severity}] {f.title}")
        print(f"High-risk app-owner findings: {len(app_owner_findings)}")
        for f in app_owner_findings:
            print(f"  [{f.severity}] {f.title}")
    return 0
