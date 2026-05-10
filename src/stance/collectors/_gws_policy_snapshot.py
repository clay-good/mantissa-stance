"""
Shared helper for tenant-level Workspace policy snapshots.

Most of the PR-3 collectors (Gmail, Calendar, Chrome, Mobile, CAA) read a
small set of settings from the Cloud Identity Policy API
(``service.policies().list(...)``), normalize each into a flat field, and
emit a single tenant-scoped asset. This module factors that pattern out so
each collector is just a setting-type map plus a defaults dict.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


def merge_policy_settings(
    service: Any,
    customer: str,
    field_map: dict[str, str],
    defaults: dict[str, Any],
    extract: Callable[[str, dict[str, Any]], Any],
) -> dict[str, Any]:
    """Pull tenant policies from the Cloud Identity Policy API and merge them
    into a flat normalized dict.

    Args:
        service: Duck-typed service exposing ``.policies().list(...)``.
        customer: Customer key (typically ``"my_customer"``).
        field_map: Map from Cloud Identity ``settingType`` strings to
            normalized field names on the output asset.
        defaults: Workspace-documented defaults used when a setting is absent.
        extract: ``(field, value) -> normalized_value``.

    Returns:
        A copy of ``defaults`` with any matched policies overlaid.
    """
    config: dict[str, Any] = dict(defaults)
    try:
        policies = service.policies()
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("policies() unavailable: %s", e)
        return config

    try:
        request = policies.list(filter=f"customer=={customer}", pageSize=200)
    except Exception as e:  # pragma: no cover - defensive
        logger.debug("policies.list unavailable: %s", e)
        return config

    while request is not None:
        try:
            response = request.execute() or {}
        except Exception as e:
            logger.debug("policies.execute failed: %s", e)
            break
        for policy in response.get("policies", []) or []:
            setting = policy.get("setting", {}) or {}
            type_key = policy.get("type") or setting.get("type", "")
            value = setting.get("value", {}) or {}
            field = field_map.get(type_key)
            if field is None:
                continue
            try:
                config[field] = extract(field, value)
            except Exception as e:
                logger.debug("policy extract(%s) failed: %s", field, e)
        list_next = getattr(policies, "list_next", None)
        request = list_next(request, response) if list_next else None
    return config
