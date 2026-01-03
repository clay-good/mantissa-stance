"""
Base collector framework for Mantissa Stance.

This module provides the abstract base class for all collectors,
along with the CollectorRunner for orchestrating multiple collectors.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.models import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNAL

logger = logging.getLogger(__name__)

# Import boto3 optionally
try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


@dataclass
class CollectorResult:
    """
    Result from running a collector.

    Attributes:
        collector_name: Name of the collector that ran
        assets: Collection of assets discovered
        duration_seconds: How long the collection took
        errors: List of any errors encountered
    """

    collector_name: str
    assets: AssetCollection
    duration_seconds: float
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        """Check if collection completed without errors."""
        return len(self.errors) == 0

    @property
    def asset_count(self) -> int:
        """Get number of assets collected."""
        return len(self.assets)


class BaseCollector(ABC):
    """
    Abstract base class for cloud resource collectors.

    All collectors must inherit from this class and implement
    the collect() method. Collectors are responsible for gathering
    configuration data from cloud services using read-only API calls.

    Attributes:
        collector_name: Unique name for this collector
        resource_types: List of resource types this collector handles
    """

    collector_name: str = "base"
    resource_types: list[str] = []

    def __init__(self, session: Any | None = None, region: str = "us-east-1") -> None:
        """
        Initialize the collector.

        Args:
            session: Optional boto3 Session. If None, uses default credentials.
            region: AWS region to collect from (default: us-east-1)
        """
        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for collectors. Install with: pip install boto3"
            )

        self._session = session or boto3.Session()
        self._region = region
        self._account_id: str | None = None
        self._clients: dict[str, Any] = {}

    @property
    def account_id(self) -> str:
        """Get the AWS account ID."""
        if self._account_id is None:
            sts = self._get_client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]
        return self._account_id

    @property
    def region(self) -> str:
        """Get the AWS region."""
        return self._region

    def _get_client(self, service: str) -> Any:
        """
        Get a boto3 client for the specified service.

        Clients are cached for reuse.

        Args:
            service: AWS service name (e.g., 'iam', 's3', 'ec2')

        Returns:
            boto3 client for the service
        """
        cache_key = f"{service}:{self._region}"
        if cache_key not in self._clients:
            self._clients[cache_key] = self._session.client(
                service, region_name=self._region
            )
        return self._clients[cache_key]

    def _paginate(
        self, client: Any, method: str, result_key: str, **kwargs: Any
    ) -> Iterator[Any]:
        """
        Handle AWS API pagination.

        Args:
            client: boto3 client
            method: API method name
            result_key: Key in response containing results
            **kwargs: Arguments to pass to the API method

        Yields:
            Individual items from paginated results
        """
        paginator = client.get_paginator(method)
        for page in paginator.paginate(**kwargs):
            for item in page.get(result_key, []):
                yield item

    def _extract_tags(self, tag_list: list[dict[str, str]] | None) -> dict[str, str]:
        """
        Normalize AWS tags from list format to dictionary.

        Args:
            tag_list: List of {"Key": "k", "Value": "v"} dicts

        Returns:
            Dictionary of {key: value} pairs
        """
        if not tag_list:
            return {}

        tags = {}
        for tag in tag_list:
            key = tag.get("Key", tag.get("key", ""))
            value = tag.get("Value", tag.get("value", ""))
            if key:
                tags[key] = value
        return tags

    def _get_name_from_tags(
        self, tags: dict[str, str], default: str = ""
    ) -> str:
        """
        Extract the Name tag value.

        Args:
            tags: Dictionary of tags
            default: Default value if Name tag not found

        Returns:
            Name tag value or default
        """
        return tags.get("Name", tags.get("name", default))

    def _determine_network_exposure(self, resource: dict[str, Any]) -> str:
        """
        Analyze resource to determine network exposure level.

        Override in subclasses for resource-specific logic.

        Args:
            resource: Resource configuration dict

        Returns:
            Network exposure level string
        """
        return NETWORK_EXPOSURE_INTERNAL

    def _build_arn(
        self,
        service: str,
        resource_type: str,
        resource_id: str,
        region: str = "",
        account_id: str = "",
    ) -> str:
        """
        Build an ARN string.

        Args:
            service: AWS service name
            resource_type: Resource type
            resource_id: Resource identifier
            region: AWS region (empty for global resources)
            account_id: AWS account ID (empty for some resources)

        Returns:
            Formatted ARN string
        """
        account = account_id or self.account_id
        return f"arn:aws:{service}:{region}:{account}:{resource_type}/{resource_id}"

    def _now(self) -> datetime:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc)

    @abstractmethod
    def collect(self) -> AssetCollection:
        """
        Collect resources and return as AssetCollection.

        Must be implemented by all collector subclasses.

        Returns:
            Collection of discovered assets
        """
        pass


class CollectorRunner:
    """
    Runs multiple collectors and aggregates results.

    Orchestrates the execution of collectors, handles errors,
    and merges results into a single asset collection.
    """

    def __init__(self, collectors: list[BaseCollector]) -> None:
        """
        Initialize the collector runner.

        Args:
            collectors: List of collector instances to run
        """
        self._collectors = collectors

    @property
    def collectors(self) -> list[BaseCollector]:
        """Get the list of collectors."""
        return self._collectors

    def run_collector(self, collector: BaseCollector) -> CollectorResult:
        """
        Run a single collector with timing and error handling.

        Args:
            collector: Collector instance to run

        Returns:
            CollectorResult with assets and metadata
        """
        start_time = time.time()
        errors: list[str] = []
        assets = AssetCollection()

        try:
            logger.info(f"Running collector: {collector.collector_name}")
            assets = collector.collect()
            logger.info(
                f"Collector {collector.collector_name} found {len(assets)} assets"
            )
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_msg = e.response.get("Error", {}).get("Message", str(e))
            error = f"{collector.collector_name}: {error_code} - {error_msg}"
            errors.append(error)
            logger.error(f"Collector error: {error}")
        except Exception as e:
            error = f"{collector.collector_name}: {type(e).__name__} - {str(e)}"
            errors.append(error)
            logger.error(f"Collector error: {error}")

        duration = time.time() - start_time

        return CollectorResult(
            collector_name=collector.collector_name,
            assets=assets,
            duration_seconds=duration,
            errors=errors,
        )

    def run_all(self) -> tuple[AssetCollection, list[CollectorResult]]:
        """
        Run all collectors and merge results.

        Returns:
            Tuple of (combined AssetCollection, list of CollectorResults)
        """
        results: list[CollectorResult] = []
        all_assets = AssetCollection()

        for collector in self._collectors:
            result = self.run_collector(collector)
            results.append(result)
            all_assets = all_assets.merge(result.assets)

        total_assets = len(all_assets)
        total_errors = sum(len(r.errors) for r in results)
        total_time = sum(r.duration_seconds for r in results)

        logger.info(
            f"Collection complete: {total_assets} assets, "
            f"{total_errors} errors, {total_time:.2f}s total"
        )

        return all_assets, results

    def run_by_name(self, names: list[str]) -> tuple[AssetCollection, list[CollectorResult]]:
        """
        Run only collectors matching the given names.

        Args:
            names: List of collector names to run

        Returns:
            Tuple of (combined AssetCollection, list of CollectorResults)
        """
        filtered = [c for c in self._collectors if c.collector_name in names]
        runner = CollectorRunner(filtered)
        return runner.run_all()
