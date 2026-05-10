"""OneDrive personal-store DSPM scanner.

Scans the per-user OneDrive namespace. Architecturally identical to the
SharePoint scanner — the difference is which Graph endpoints are walked
and that exposure scoring weights "shared with anyone outside the
tenant" more heavily because OneDrive content lives in personal namespaces
rather than curated team sites.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from stance.dspm.extended._saas_exposure import compute_exposure_score
from stance.dspm.extended.base import (
    BaseExtendedScanner,
    ExtendedScanConfig,
    ExtendedScanFinding,
    ExtendedScanResult,
    ExtendedScanSummary,
    ExtendedSourceType,
)

logger = logging.getLogger(__name__)


GraphCallable = Callable[[str], dict[str, Any]]


class M365OneDriveDSPMScanner(BaseExtendedScanner):
    source_type = ExtendedSourceType.M365_ONEDRIVE

    _SCANNABLE_EXTS: frozenset[str] = frozenset(
        {".txt", ".csv", ".tsv", ".log", ".json", ".md", ".html", ".xml"}
    )

    def __init__(
        self,
        graph: GraphCallable,
        tenant_id: str,
        primary_domain: str = "",
        content_loader: Callable[[str, str], str | None] | None = None,
        scan_config: ExtendedScanConfig | None = None,
    ) -> None:
        super().__init__(scan_config)
        self._graph = graph
        self._tenant_id = tenant_id
        self._primary_domain = primary_domain.lower()
        self._content_loader = content_loader

    def test_connection(self) -> bool:
        try:
            response = self._graph("/v1.0/users?$select=id&$top=1")
            return bool(response.get("value"))
        except Exception as e:
            logger.error("onedrive dspm connection test failed: %s", e)
            return False

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for user in self._users_in_target(target):
            out.extend(self._items_for_user(user))
        return out

    def scan(self, target: str) -> ExtendedScanResult:
        scan_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)
        result = ExtendedScanResult(
            scan_id=scan_id,
            source_type=self.source_type,
            target=target,
            config=self._config,
            started_at=started_at,
            summary=ExtendedScanSummary(),
        )

        scanned = 0
        skipped = 0
        for user in self._users_in_target(target):
            user_meta = {
                "user_id": user.get("id", ""),
                "user_principal_name": user.get("userPrincipalName", ""),
            }
            for item in self._items_for_user(user):
                if scanned >= self._config.sample_size:
                    skipped += 1
                    continue
                finding = self._scan_item(user_meta, item)
                scanned += 1
                if finding is not None:
                    result.findings.append(finding)

        result.summary.total_objects_scanned = scanned
        result.summary.total_objects_skipped = skipped
        result.summary.total_files_scanned = scanned
        result.summary.total_findings = len(result.findings)
        result.summary.findings_by_severity = self._count_by_severity(result.findings)
        result.completed_at = datetime.now(timezone.utc)
        result.summary.scan_duration_seconds = (
            result.completed_at - started_at
        ).total_seconds()
        return result

    # ---------------------------------------------------------- internals

    def _users_in_target(self, target: str) -> list[dict[str, Any]]:
        if target and target not in ("all", ""):
            single = self._graph(f"/v1.0/users/{target}") or {}
            return [single] if single else []
        response = self._graph(
            "/v1.0/users?$select=id,userPrincipalName,accountEnabled&$top=200"
        ) or {}
        return [
            u
            for u in response.get("value", []) or []
            if u.get("accountEnabled", True)
        ]

    def _items_for_user(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        uid = user.get("id", "")
        if not uid:
            return []
        response = self._graph(
            f"/v1.0/users/{uid}/drive/root/children?$select="
            "id,name,size,file,permissions"
        ) or {}
        return [
            i
            for i in response.get("value", []) or []
            if i.get("file") is not None
        ]

    def _scan_item(
        self, user_meta: dict[str, Any], item: dict[str, Any]
    ) -> ExtendedScanFinding | None:
        name = item.get("name", "")
        item_id = item.get("id", "")
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext and ext not in self._SCANNABLE_EXTS:
            if self._content_loader is None:
                return None

        content = self._load_content(user_meta["user_id"], item_id)
        if not content:
            return None

        detection = self._detector.scan_records(
            [{"content": content}], asset_id=name, asset_type="file"
        )
        if not detection.has_sensitive_data:
            return None

        perms = item.get("permissions", []) or []
        link_type = self._dominant_link_type(perms)
        external_count = self._external_perm_count(
            perms, primary_domain=self._primary_domain
        )
        score = compute_exposure_score(
            detection.highest_classification,
            has_external_sharing=external_count > 0,
            external_user_count=external_count,
            link_type=link_type,
            total_user_count=max(1, len(perms)),
        )

        return self._create_finding_from_detection(
            source_location=f"onedrive://{user_meta['user_principal_name']}/{name}",
            object_type="file",
            object_name=name,
            detection_result=detection,
            metadata={
                "user_principal_name": user_meta["user_principal_name"],
                "item_id": item_id,
                "exposure_score": score,
                "external_perm_count": external_count,
                "item_link_type": link_type,
            },
        )

    def _load_content(self, user_id: str, item_id: str) -> str | None:
        if self._content_loader is not None:
            return self._content_loader(user_id, item_id)
        response = self._graph(
            f"/v1.0/users/{user_id}/drive/items/{item_id}/content"
        )
        if isinstance(response, dict) and response.get("text"):
            return str(response["text"])
        return None

    @staticmethod
    def _dominant_link_type(perms: list[dict[str, Any]]) -> str:
        for p in perms:
            link = p.get("link") or {}
            if link.get("scope"):
                return link["scope"]
        return ""

    @staticmethod
    def _external_perm_count(
        perms: list[dict[str, Any]], *, primary_domain: str
    ) -> int:
        n = 0
        for p in perms:
            link = p.get("link") or {}
            if link.get("scope") in ("anonymous", "anyone"):
                n += 1
                continue
            for ident in p.get("grantedToIdentitiesV2", []) or p.get(
                "grantedToIdentities", []
            ) or []:
                email = (((ident.get("user") or {}).get("email")) or "").lower()
                if email and (
                    not primary_domain or not email.endswith("@" + primary_domain)
                ):
                    n += 1
        return n

    @staticmethod
    def _count_by_severity(
        findings: list[ExtendedScanFinding],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
