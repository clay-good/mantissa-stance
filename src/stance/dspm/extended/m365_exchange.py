"""Exchange Online mailbox-content DSPM scanner — *optional / heavy*.

Spec §6 marks this scanner as optional because mailbox content scans are
expensive and have privacy implications. The default ``mailbox_sample`` is
10 messages per mailbox; the connector should be opt-in per mailbox via a
side-car configuration in the secret backend.

The scanner emits a finding when a sampled message contains sensitive
content. Exposure-score inputs are simpler than the file-share case: an
email message is "shared" with everyone in its To/Cc/Bcc, and any external
recipient counts toward the external_user_count factor.
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


class M365ExchangeDSPMScanner(BaseExtendedScanner):
    source_type = ExtendedSourceType.M365_EXCHANGE

    def __init__(
        self,
        graph: GraphCallable,
        tenant_id: str,
        primary_domain: str = "",
        scan_config: ExtendedScanConfig | None = None,
        mailbox_sample: int = 10,
    ) -> None:
        super().__init__(scan_config)
        self._graph = graph
        self._tenant_id = tenant_id
        self._primary_domain = primary_domain.lower()
        self._mailbox_sample = mailbox_sample

    def test_connection(self) -> bool:
        try:
            response = self._graph("/v1.0/users?$select=id&$top=1")
            return bool(response.get("value"))
        except Exception as e:
            logger.error("exchange dspm connection test failed: %s", e)
            return False

    def list_scannable_objects(self, target: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for user in self._mailboxes_in_target(target):
            out.extend(self._messages_for_user(user))
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
        for user in self._mailboxes_in_target(target):
            upn = user.get("userPrincipalName", "")
            for msg in self._messages_for_user(user)[: self._mailbox_sample]:
                if scanned >= self._config.sample_size:
                    skipped += 1
                    continue
                finding = self._scan_message(upn, msg)
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

    def _mailboxes_in_target(self, target: str) -> list[dict[str, Any]]:
        if target and target not in ("all", ""):
            single = self._graph(f"/v1.0/users/{target}") or {}
            return [single] if single else []
        response = self._graph(
            "/v1.0/users?$select=id,userPrincipalName&$top=50"
        ) or {}
        return list(response.get("value", []) or [])

    def _messages_for_user(self, user: dict[str, Any]) -> list[dict[str, Any]]:
        uid = user.get("id") or user.get("userPrincipalName", "")
        if not uid:
            return []
        response = self._graph(
            f"/v1.0/users/{uid}/messages?$select="
            "id,subject,body,toRecipients,ccRecipients,from"
            f"&$top={self._mailbox_sample}"
        ) or {}
        return list(response.get("value", []) or [])

    def _scan_message(
        self, mailbox_upn: str, msg: dict[str, Any]
    ) -> ExtendedScanFinding | None:
        body = (msg.get("body") or {}).get("content", "") or ""
        subject = msg.get("subject", "") or ""
        scan_text = f"{subject}\n{body}"
        if not scan_text.strip():
            return None
        detection = self._detector.scan_records(
            [{"content": scan_text}],
            asset_id=subject or "(no subject)",
            asset_type="message",
        )
        if not detection.has_sensitive_data:
            return None

        recipients = (msg.get("toRecipients", []) or []) + (
            msg.get("ccRecipients", []) or []
        )
        external_count = self._external_recipient_count(recipients)
        score = compute_exposure_score(
            detection.highest_classification,
            has_external_sharing=external_count > 0,
            external_user_count=external_count,
            link_type="organization" if external_count == 0 else "anyone",
            total_user_count=max(1, len(recipients)),
        )

        return self._create_finding_from_detection(
            source_location=f"exchange://{mailbox_upn}/{msg.get('id', '')}",
            object_type="message",
            object_name=subject or "(no subject)",
            detection_result=detection,
            metadata={
                "mailbox_upn": mailbox_upn,
                "external_recipient_count": external_count,
                "exposure_score": score,
            },
        )

    def _external_recipient_count(
        self, recipients: list[dict[str, Any]]
    ) -> int:
        if not self._primary_domain:
            return 0
        n = 0
        for r in recipients:
            email = ((r.get("emailAddress") or {}).get("address") or "").lower()
            if not email or "@" not in email:
                continue
            if email.split("@", 1)[1] != self._primary_domain:
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
