"""
Azure Activity Log Access Analyzer for DSPM.

Analyzes Azure Activity Logs to detect stale Blob Storage access patterns
and identify unused or over-privileged permissions.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.dspm.access.base import (
    BaseAccessAnalyzer,
    AccessReviewConfig,
    AccessEvent,
    AccessSummary,
    StaleAccessFinding,
    AccessReviewResult,
)

logger = logging.getLogger(__name__)

# Import Azure libraries optionally
try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.monitor import MonitorManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.core.exceptions import (
        AzureError,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    DefaultAzureCredential = None  # type: ignore
    MonitorManagementClient = None  # type: ignore
    StorageManagementClient = None  # type: ignore
    AzureError = Exception  # type: ignore
    ResourceNotFoundError = Exception  # type: ignore
    ClientAuthenticationError = Exception  # type: ignore


# Azure Storage operation mapping
AZURE_ACTION_MAPPING = {
    "GetBlob": "read",
    "GetBlobProperties": "read",
    "GetBlobMetadata": "read",
    "HeadBlob": "read",
    "ListBlobs": "list",
    "ListContainers": "list",
    "PutBlob": "write",
    "PutBlockList": "write",
    "PutBlock": "write",
    "CopyBlob": "write",
    "SetBlobProperties": "write",
    "SetBlobMetadata": "write",
    "DeleteBlob": "delete",
    "DeleteContainer": "delete",
    "SetContainerAcl": "admin",
    "SetBlobTier": "write",
}


class AzureActivityLogAnalyzer(BaseAccessAnalyzer):
    """
    Azure Activity Log analyzer for Blob Storage access patterns.

    Queries Azure Activity Logs and Storage Analytics to identify:
    - Stale access (permissions not used in X days)
    - Unused permissions (no access recorded)
    - Over-privileged access (write permissions but only reads)

    All operations are read-only.
    """

    cloud_provider = "azure"

    def __init__(
        self,
        config: AccessReviewConfig | None = None,
        subscription_id: str | None = None,
        credential: Any | None = None,
        resource_group: str | None = None,
        storage_account: str | None = None,
    ):
        """
        Initialize Azure Activity Log analyzer.

        Args:
            config: Optional access review configuration
            subscription_id: Azure subscription ID
            credential: Optional Azure credential object
            resource_group: Resource group name
            storage_account: Storage account name
        """
        super().__init__(config)

        if not AZURE_AVAILABLE:
            raise ImportError(
                "azure-mgmt-monitor and azure-mgmt-storage are required "
                "for Azure activity log analysis. Install with: "
                "pip install azure-mgmt-monitor azure-mgmt-storage azure-identity"
            )

        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._storage_account = storage_account
        self._credential = credential or DefaultAzureCredential()

        self._monitor_client = MonitorManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
        )
        self._storage_client = StorageManagementClient(
            credential=self._credential,
            subscription_id=subscription_id,
        )

    def analyze_resource(self, resource_id: str) -> AccessReviewResult:
        """
        Analyze access patterns for an Azure Blob container.

        Args:
            resource_id: Container name or full resource path

        Returns:
            Access review result with findings
        """
        # Parse resource ID
        container_name = self._parse_container_name(resource_id)
        review_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting Azure activity log access review: container={container_name}, "
            f"review_id={review_id}"
        )

        result = AccessReviewResult(
            review_id=review_id,
            resource_id=container_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Calculate time range
            start_time, end_time = self._calculate_lookback_range()

            # Get access events from Activity Log
            events = self.get_access_events(container_name, start_time, end_time)

            # Aggregate events by principal
            summaries = self._aggregate_events(events)
            result.summaries = list(summaries.values())
            result.total_events_analyzed = sum(s.total_access_count for s in summaries.values())
            result.total_principals_analyzed = len(summaries)

            # Get current permissions for the container
            permissions = self.get_resource_permissions(container_name)

            # Generate findings
            result.findings = self._generate_findings(summaries, permissions, container_name)

        except AzureError as e:
            error_msg = f"Azure error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"Azure activity log access review complete: "
            f"{result.total_principals_analyzed} principals, "
            f"{len(result.findings)} findings"
        )

        return result

    def _parse_container_name(self, resource_id: str) -> str:
        """Parse container name from various input formats."""
        # Handle azure:// prefix
        if resource_id.startswith("azure://"):
            resource_id = resource_id[8:]

        # Handle full resource path
        if "/" in resource_id:
            parts = resource_id.split("/")
            return parts[-1]

        return resource_id

    def get_access_events(
        self,
        resource_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[AccessEvent]:
        """
        Retrieve Blob Storage access events from Azure Activity Logs.

        Args:
            resource_id: Container name
            start_time: Start of time range
            end_time: End of time range

        Yields:
            Access events for the container
        """
        container_name = self._parse_container_name(resource_id)

        # Build the activity log filter
        filter_str = self._build_activity_log_filter(container_name, start_time, end_time)

        try:
            # Query Activity Logs
            activity_logs = self._monitor_client.activity_logs.list(filter=filter_str)

            for log in activity_logs:
                parsed = self._parse_activity_log_entry(log, container_name)
                if parsed:
                    yield parsed

        except AzureError as e:
            logger.warning(f"Failed to query Activity Logs: {e}")

    def _build_activity_log_filter(
        self,
        container_name: str,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build Azure Activity Log filter string."""
        # Format timestamps for Azure
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        filter_parts = [
            f"eventTimestamp ge '{start_str}'",
            f"eventTimestamp le '{end_str}'",
            "resourceProvider eq 'Microsoft.Storage'",
        ]

        # Add storage account filter if available
        if self._storage_account:
            filter_parts.append(
                f"resourceUri contains '{self._storage_account}'"
            )

        return " and ".join(filter_parts)

    def _parse_activity_log_entry(
        self,
        log: Any,
        container_name: str,
    ) -> AccessEvent | None:
        """Parse an Azure Activity Log entry into an AccessEvent."""
        try:
            # Get operation name
            operation_name = log.operation_name.value if log.operation_name else ""
            if not operation_name:
                return None

            # Extract the operation type
            operation_type = operation_name.split("/")[-1] if "/" in operation_name else operation_name

            # Map to action
            action = None
            for azure_op, mapped_action in AZURE_ACTION_MAPPING.items():
                if azure_op.lower() in operation_type.lower():
                    action = mapped_action
                    break

            if not action:
                # Try to infer from operation name
                op_lower = operation_type.lower()
                if "read" in op_lower or "get" in op_lower or "list" in op_lower:
                    action = "read"
                elif "write" in op_lower or "put" in op_lower or "create" in op_lower:
                    action = "write"
                elif "delete" in op_lower:
                    action = "delete"
                else:
                    return None

            # Extract principal info
            caller = log.caller if hasattr(log, "caller") else None
            if not caller:
                claims = log.claims or {}
                caller = claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "")
                if not caller:
                    caller = claims.get("appid", "unknown")

            principal_type = self._guess_principal_type(caller)

            # Extract source IP
            source_ip = None
            if log.http_request:
                source_ip = log.http_request.client_ip_address

            return AccessEvent(
                event_id=log.event_data_id or str(uuid.uuid4()),
                timestamp=log.event_timestamp,
                principal_id=caller,
                principal_type=principal_type,
                resource_id=container_name,
                action=action,
                source_ip=source_ip,
                success=log.status and log.status.value == "Succeeded",
                metadata={
                    "operation_name": operation_name,
                    "resource_id": log.resource_id,
                    "correlation_id": log.correlation_id,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to parse activity log entry: {e}")
            return None

    def _guess_principal_type(self, caller: str) -> str:
        """Guess the type of principal from the caller identifier."""
        if not caller:
            return "unknown"

        # Service principal (app ID is a GUID)
        if self._is_guid(caller):
            return "service_account"

        # User principal (email format)
        if "@" in caller:
            return "user"

        # Managed identity
        if "managedidentity" in caller.lower():
            return "service_account"

        return "unknown"

    def _is_guid(self, value: str) -> bool:
        """Check if value is a GUID format."""
        import re
        guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        return bool(re.match(guid_pattern, value))

    def get_resource_permissions(
        self,
        resource_id: str,
    ) -> dict[str, dict[str, Any]]:
        """
        Get current permissions for an Azure Blob container.

        Analyzes storage account role assignments.

        Args:
            resource_id: Container name

        Returns:
            Dictionary mapping principal_id to permission details
        """
        permissions: dict[str, dict[str, Any]] = {}

        if not self._storage_account or not self._resource_group:
            logger.warning("Storage account and resource group required for permissions")
            return permissions

        try:
            # Get storage account
            storage_account = self._storage_client.storage_accounts.get_properties(
                resource_group_name=self._resource_group,
                account_name=self._storage_account,
            )

            # Get role assignments for the storage account
            # Note: This would require azure-mgmt-authorization for full implementation
            # For now, we return an empty dict and rely on access log analysis

            logger.info("Role assignment retrieval requires azure-mgmt-authorization")

        except ResourceNotFoundError:
            logger.warning(f"Storage account not found: {self._storage_account}")
        except ClientAuthenticationError:
            logger.warning(f"Access denied to storage account: {self._storage_account}")
        except Exception as e:
            logger.warning(f"Error getting storage account permissions: {e}")

        return permissions

    def get_storage_account_info(self) -> dict[str, Any]:
        """Get storage account information."""
        if not self._storage_account or not self._resource_group:
            return {}

        try:
            account = self._storage_client.storage_accounts.get_properties(
                resource_group_name=self._resource_group,
                account_name=self._storage_account,
            )
            return {
                "name": account.name,
                "location": account.location,
                "sku": account.sku.name if account.sku else None,
                "kind": account.kind,
            }
        except Exception as e:
            logger.warning(f"Error getting storage account info: {e}")
            return {}

    def list_containers(self) -> Iterator[dict[str, Any]]:
        """List all containers in the storage account."""
        if not self._storage_account or not self._resource_group:
            return

        try:
            containers = self._storage_client.blob_containers.list(
                resource_group_name=self._resource_group,
                account_name=self._storage_account,
            )
            for container in containers:
                yield {
                    "name": container.name,
                    "last_modified": container.last_modified_time,
                    "public_access": container.public_access,
                }
        except Exception as e:
            logger.warning(f"Error listing containers: {e}")
