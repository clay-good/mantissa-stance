"""
Base for Microsoft 365 / Entra collectors.

The Microsoft Graph SDK has a fluent builder API that's awkward to mock; the
underlying HTTP surface is just GETs against ``https://graph.microsoft.com``.
``EntraCollector`` therefore takes a duck-typed ``graph`` callable that maps
``(path: str) -> dict``. Production wiring composes ``msgraph-sdk`` or
``httpx`` behind that callable; tests inject a closure that returns canned
JSON keyed by path.

Pagination is handled by following ``@odata.nextLink`` if present.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Iterator
from urllib.parse import urlparse

from stance.models import AssetCollection

logger = logging.getLogger(__name__)


GraphCallable = Callable[[str], dict[str, Any]]


class EntraCollector(ABC):
    """Abstract base for Microsoft Entra (Azure AD) posture collectors."""

    collector_name: str = "entra_base"
    resource_types: list[str] = []
    cloud_provider: str = "microsoft_365"

    def __init__(self, graph: GraphCallable, tenant_id: str) -> None:
        self._graph = graph
        self._tenant_id = tenant_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _get(self, path: str) -> dict[str, Any]:
        try:
            return self._graph(path) or {}
        except Exception as e:
            logger.debug("graph(%s) failed: %s", path, e)
            return {}

    def _iter(self, path: str) -> Iterator[dict[str, Any]]:
        """Iterate over a paginated Graph collection.

        Follows ``@odata.nextLink`` until exhausted. Treats both absolute and
        relative next-links uniformly by stripping the host prefix.
        """
        next_path: str | None = path
        seen: set[str] = set()
        while next_path and next_path not in seen:
            seen.add(next_path)
            response = self._get(next_path)
            for item in response.get("value", []) or []:
                yield item
            next_link = response.get("@odata.nextLink")
            if not next_link:
                return
            parsed = urlparse(next_link)
            next_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    @abstractmethod
    def collect(self) -> AssetCollection:
        """Collect resources and return them as an AssetCollection."""
