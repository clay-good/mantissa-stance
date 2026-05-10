"""SharePoint Online DSPM scanner.

Samples files from a SharePoint site (or set of sites), classifies their
content via the existing :class:`SensitiveDataDetector`, and computes the
spec §6 exposure score per finding. Read-only; consumes a duck-typed Graph
callable identical to the PR-4 collector convention so it composes with
the rest of the M365 surfaces without a second auth path.

The scanner is intentionally minimal — it does not maintain its own version
graph or differential index. Mantissa Stance is point-in-time; "what
changed" lives in mantissa-log.
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


class M365SharePointDSPMScanner(BaseExtendedScanner):
    """DSPM scanner over SharePoint Online sites + drive items.

    The constructor accepts a duck-typed ``graph(path) -> dict`` callable
    plus an optional ``content_loader`` that maps an item id → text. In
    production wiring the loader fetches ``drives/{drive}/items/{item}/content``
    and decodes via the existing OOXML/PDF helpers; tests pass a closure
    over a fixture dict.
    """

    source_type = ExtendedSourceType.M365_SHAREPOINT

    # Documents that we'll attempt to classify as text. Other types
    # (.zip, .pdf, .pptx) require the production-side loader to extract text.
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

    # ----------------------------------------------------------- protocol

    def test_connection(self) -> bool:
        try:
            response = self._graph("/v1.0/sites?$select=id&$top=1")
            return bool(response.get("value"))
        except Exception as e:
            logger.error("sharepoint dspm connection test failed: %s", e)
            return False

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        sites = self._sites_in_target(target)
        out: list[dict[str, Any]] = []
        for site in sites:
            for item in self._list_items(site):
                out.append(item)
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
        for site in self._sites_in_target(target):
            site_id = site.get("id", "")
            site_url = site.get("webUrl", "")
            site_meta = self._site_meta(site_id)
            for item in self._list_items(site):
                if scanned >= self._config.sample_size:
                    skipped += 1
                    continue
                finding = self._scan_item(site_url, site_meta, item)
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

    def _sites_in_target(self, target: str) -> list[dict[str, Any]]:
        if target and target != "all":
            single = self._graph(f"/v1.0/sites/{target}") or {}
            return [single] if single else []
        response = self._graph("/v1.0/sites?search=*&$select=id,displayName,webUrl") or {}
        return list(response.get("value", []) or [])

    def _site_meta(self, site_id: str) -> dict[str, Any]:
        details = self._graph(f"/v1.0/admin/sharepoint/sites/{site_id}") or {}
        sharing = details.get("sharingCapability", "")
        external_users = int(details.get("externalUserCount", 0) or 0)
        return {
            "site_id": site_id,
            "sharing_capability": sharing,
            "external_user_count": external_users,
            "has_external_users": external_users > 0,
            "default_link_type": details.get("defaultSharingLinkType", "anyone"),
        }

    def _list_items(self, site: dict[str, Any]) -> list[dict[str, Any]]:
        site_id = site.get("id", "")
        if not site_id:
            return []
        # Only enumerating the default document library here — adequate for
        # baseline coverage; per-library scoping is a future enhancement.
        response = self._graph(
            f"/v1.0/sites/{site_id}/drive/root/children?$select="
            "id,name,size,file,parentReference,permissions"
        ) or {}
        return [
            i
            for i in response.get("value", []) or []
            if i.get("file") is not None
        ]

    def _scan_item(
        self,
        site_url: str,
        site_meta: dict[str, Any],
        item: dict[str, Any],
    ) -> ExtendedScanFinding | None:
        name = item.get("name", "")
        item_id = item.get("id", "")
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext and ext not in self._SCANNABLE_EXTS:
            # Defer to production-side loader; without one, skip.
            if self._content_loader is None:
                return None

        content = self._load_content(site_meta["site_id"], item_id, name)
        if not content:
            return None

        detection = self._detector.scan_records(
            [{"content": content}], asset_id=name, asset_type="file"
        )
        if not detection.has_sensitive_data:
            return None

        # Per-item sharing posture: the count of external permissions on the
        # item is a tighter signal than the site-level external-user count.
        item_perms = item.get("permissions", []) or []
        item_link_type = self._dominant_link_type(item_perms)
        score = compute_exposure_score(
            detection.highest_classification,
            has_external_sharing=site_meta["has_external_users"]
            or self._has_external_perm(item_perms),
            external_user_count=site_meta["external_user_count"],
            link_type=item_link_type or site_meta["default_link_type"],
            total_user_count=max(1, site_meta["external_user_count"]),
        )

        return self._create_finding_from_detection(
            source_location=f"{site_url}/{name}",
            object_type="file",
            object_name=name,
            detection_result=detection,
            metadata={
                "site_id": site_meta["site_id"],
                "item_id": item_id,
                "exposure_score": score,
                "site_sharing_capability": site_meta["sharing_capability"],
                "site_external_user_count": site_meta["external_user_count"],
                "item_link_type": item_link_type,
            },
        )

    def _load_content(self, site_id: str, item_id: str, name: str) -> str | None:
        if self._content_loader is not None:
            return self._content_loader(site_id, item_id)
        path = f"/v1.0/sites/{site_id}/drive/items/{item_id}/content"
        response = self._graph(path)
        if isinstance(response, dict) and response.get("text"):
            return str(response["text"])
        return None

    @staticmethod
    def _has_external_perm(perms: list[dict[str, Any]]) -> bool:
        for p in perms:
            link = p.get("link") or {}
            if link.get("scope") in ("anonymous", "anyone"):
                return True
            for ident in p.get("grantedToIdentitiesV2", []) or p.get(
                "grantedToIdentities", []
            ) or []:
                if (ident.get("user") or {}).get("email"):
                    return True
        return False

    @staticmethod
    def _dominant_link_type(perms: list[dict[str, Any]]) -> str:
        for p in perms:
            link = p.get("link") or {}
            if link.get("scope"):
                return link["scope"]
        return ""

    @staticmethod
    def _count_by_severity(
        findings: list[ExtendedScanFinding],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts
