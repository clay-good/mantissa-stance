"""Shared helper: exposure-score formula for SaaS DSPM scanners.

SAAS_POSTURE_SPEC §6 specifies the formula as:

    exposure = sensitive_content × external_sharing × link_permissiveness × user_count

Each factor is normalized into ``[0.0, 1.0]`` so the score itself stays in
``[0, 100]`` after scaling. The same scorer is used by SharePoint, OneDrive,
and Exchange so the number is comparable across surfaces (and against the
existing Drive scanner once it adopts the helper).
"""

from __future__ import annotations

from stance.dspm.classifier import ClassificationLevel


# Sensitive-content weight per classification level (top-secret = 1.0).
_SENSITIVITY_WEIGHT = {
    ClassificationLevel.PUBLIC: 0.0,
    ClassificationLevel.INTERNAL: 0.25,
    ClassificationLevel.CONFIDENTIAL: 0.6,
    ClassificationLevel.RESTRICTED: 0.85,
    ClassificationLevel.TOP_SECRET: 1.0,
}


def _link_weight(link_type: str) -> float:
    """Map a SaaS sharing-link type into the link-permissiveness factor."""
    lt = (link_type or "").lower()
    if lt in ("anonymous", "anyone", "anyone_with_link", "public"):
        return 1.0
    if lt in ("organization", "domain", "anyone_in_org"):
        return 0.5
    if lt in ("specific_people", "internal", "private", "owner_only", ""):
        return 0.1
    return 0.5


def _external_weight(has_external: bool, external_user_count: int) -> float:
    """Bounded external-sharing factor; saturates at 25 external users."""
    if not has_external and external_user_count <= 0:
        return 0.05  # tiny floor so internal-only content can still be scored
    return min(1.0, max(0.2, external_user_count / 25.0))


def _user_count_weight(total_users: int) -> float:
    """Sub-linear scaling so 1 vs 100 users matters more than 100 vs 200."""
    if total_users <= 0:
        return 0.05
    if total_users <= 10:
        return 0.2 + 0.04 * total_users  # 0.24 .. 0.6
    if total_users <= 100:
        return 0.6 + (total_users - 10) / 100.0 * 0.3  # 0.6 .. 0.9
    return min(1.0, 0.9 + (total_users - 100) / 1000.0 * 0.1)


def compute_exposure_score(
    classification: ClassificationLevel,
    *,
    has_external_sharing: bool,
    external_user_count: int,
    link_type: str,
    total_user_count: int,
) -> float:
    """Compute the spec §6 exposure score in ``[0, 100]``.

    All four factors are independent. The product is multiplied by 100 so a
    file with restricted PII shared via an "anyone with link" URL to many
    users scores in the 80–100 band.
    """
    sensitivity = _SENSITIVITY_WEIGHT.get(classification, 0.0)
    if sensitivity <= 0.0:
        return 0.0
    external = _external_weight(has_external_sharing, external_user_count)
    link = _link_weight(link_type)
    users = _user_count_weight(total_user_count)
    return round(sensitivity * external * link * users * 100.0, 2)


def severity_band(score: float) -> str:
    """Bucket the score into the same severity strings the engine uses."""
    if score >= 75.0:
        return "critical"
    if score >= 50.0:
        return "high"
    if score >= 25.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# NOTE: The earlier ``classification_from_categories`` workaround that
# lived here was deleted once ``SensitiveDataDetector.scan_records`` started
# deriving ``highest_classification`` from the classifier's own rule
# registry. The detector's ``highest_classification`` is now authoritative;
# scanners can use it directly. See the SAAS_POSTURE_SPEC follow-up note
# attached to PR 8.
