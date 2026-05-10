"""
Base class for SaaS posture collectors (Google Workspace, Microsoft 365).

Unlike the cloud BaseCollector, SaaS collectors don't depend on boto3 and
don't require an AWS region. They take an injected, duck-typed API service
object — production code passes a real Google Admin SDK / Microsoft Graph
client; tests pass a MagicMock.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from stance.models import AssetCollection


class SaaSCollector(ABC):
    """Abstract base for SaaS posture collectors."""

    collector_name: str = "saas_base"
    resource_types: list[str] = []
    cloud_provider: str = "saas"

    def __init__(self, service: Any, tenant_id: str) -> None:
        """
        Args:
            service: Duck-typed API client (Admin SDK, MS Graph, ...).
            tenant_id: Stable tenant identifier used as the asset account_id
                (Google customer_id or Entra tenant GUID).
        """
        self._service = service
        self._tenant_id = tenant_id

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    @property
    def service(self) -> Any:
        return self._service

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    @abstractmethod
    def collect(self) -> AssetCollection:
        """Collect resources and return them as an AssetCollection."""
