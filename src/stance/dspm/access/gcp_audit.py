"""
GCP Cloud Audit Logs Access Analyzer for DSPM.

Analyzes Cloud Audit Logs to detect stale GCS access patterns
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

# Import GCP libraries optionally
try:
    from google.cloud import logging as cloud_logging
    from google.cloud import storage
    from google.api_core.exceptions import GoogleAPIError, NotFound, Forbidden

    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    cloud_logging = None  # type: ignore
    storage = None  # type: ignore
    GoogleAPIError = Exception  # type: ignore
    NotFound = Exception  # type: ignore
    Forbidden = Exception  # type: ignore


# GCS method to action mapping
GCS_ACTION_MAPPING = {
    "storage.objects.get": "read",
    "storage.objects.list": "list",
    "storage.objects.create": "write",
    "storage.objects.update": "write",
    "storage.objects.delete": "delete",
    "storage.buckets.get": "read",
    "storage.buckets.getIamPolicy": "read",
    "storage.buckets.list": "list",
    "storage.buckets.update": "write",
    "storage.buckets.setIamPolicy": "admin",
}


class GCPAuditLogAnalyzer(BaseAccessAnalyzer):
    """
    GCP Cloud Audit Logs analyzer for GCS access patterns.

    Queries Cloud Audit Logs to identify:
    - Stale access (permissions not used in X days)
    - Unused permissions (no access recorded)
    - Over-privileged access (write permissions but only reads)

    All operations are read-only.
    """

    cloud_provider = "gcp"

    def __init__(
        self,
        config: AccessReviewConfig | None = None,
        project: str | None = None,
        credentials: Any | None = None,
    ):
        """
        Initialize GCP Cloud Audit Log analyzer.

        Args:
            config: Optional access review configuration
            project: GCP project ID
            credentials: Optional credentials object
        """
        super().__init__(config)

        if not GCP_AVAILABLE:
            raise ImportError(
                "google-cloud-logging and google-cloud-storage are required "
                "for GCP audit log analysis. Install with: "
                "pip install google-cloud-logging google-cloud-storage"
            )

        self._project = project
        self._credentials = credentials
        self._logging_client = cloud_logging.Client(
            project=project, credentials=credentials
        )
        self._storage_client = storage.Client(
            project=project, credentials=credentials
        )

    def analyze_resource(self, resource_id: str) -> AccessReviewResult:
        """
        Analyze access patterns for a GCS bucket.

        Args:
            resource_id: GCS bucket name (with or without gs:// prefix)

        Returns:
            Access review result with findings
        """
        bucket_name = resource_id.replace("gs://", "").split("/")[0]
        review_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting GCP audit log access review: bucket={bucket_name}, "
            f"review_id={review_id}"
        )

        result = AccessReviewResult(
            review_id=review_id,
            resource_id=bucket_name,
            config=self._config,
            started_at=started_at,
        )

        try:
            # Calculate time range
            start_time, end_time = self._calculate_lookback_range()

            # Get access events from Cloud Audit Logs
            events = self.get_access_events(bucket_name, start_time, end_time)

            # Aggregate events by principal
            summaries = self._aggregate_events(events)
            result.summaries = list(summaries.values())
            result.total_events_analyzed = sum(s.total_access_count for s in summaries.values())
            result.total_principals_analyzed = len(summaries)

            # Get current permissions for the bucket
            permissions = self.get_resource_permissions(bucket_name)

            # Generate findings
            result.findings = self._generate_findings(summaries, permissions, bucket_name)

        except GoogleAPIError as e:
            error_msg = f"GCP error: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"GCP audit log access review complete: "
            f"{result.total_principals_analyzed} principals, "
            f"{len(result.findings)} findings"
        )

        return result

    def get_access_events(
        self,
        resource_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[AccessEvent]:
        """
        Retrieve GCS access events from Cloud Audit Logs.

        Args:
            resource_id: GCS bucket name
            start_time: Start of time range
            end_time: End of time range

        Yields:
            Access events for the bucket
        """
        bucket_name = resource_id.replace("gs://", "").split("/")[0]

        # Build the log filter
        filter_str = self._build_log_filter(bucket_name, start_time, end_time)

        try:
            # Query Cloud Audit Logs
            for entry in self._logging_client.list_entries(filter_=filter_str):
                parsed = self._parse_audit_log_entry(entry, bucket_name)
                if parsed:
                    yield parsed
        except GoogleAPIError as e:
            logger.warning(f"Failed to query Cloud Audit Logs: {e}")

    def _build_log_filter(
        self,
        bucket_name: str,
        start_time: datetime,
        end_time: datetime,
    ) -> str:
        """Build Cloud Logging filter string."""
        # Format timestamps for Cloud Logging
        start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Filter for GCS data access logs
        filter_parts = [
            'resource.type="gcs_bucket"',
            f'resource.labels.bucket_name="{bucket_name}"',
            'logName:"cloudaudit.googleapis.com%2Fdata_access"',
            f'timestamp >= "{start_str}"',
            f'timestamp <= "{end_str}"',
        ]

        return " AND ".join(filter_parts)

    def _parse_audit_log_entry(
        self,
        entry: Any,
        bucket_name: str,
    ) -> AccessEvent | None:
        """Parse a Cloud Audit Log entry into an AccessEvent."""
        try:
            # Get the proto payload
            payload = entry.payload

            # Extract method name
            method_name = ""
            if hasattr(payload, "method_name"):
                method_name = payload.method_name
            elif isinstance(payload, dict):
                method_name = payload.get("methodName", "")

            # Map to action
            action = None
            for gcs_method, mapped_action in GCS_ACTION_MAPPING.items():
                if gcs_method in method_name.lower():
                    action = mapped_action
                    break

            if not action:
                return None

            # Extract principal info
            authentication_info = None
            if hasattr(payload, "authentication_info"):
                authentication_info = payload.authentication_info
            elif isinstance(payload, dict):
                authentication_info = payload.get("authenticationInfo", {})

            principal_email = ""
            if authentication_info:
                if hasattr(authentication_info, "principal_email"):
                    principal_email = authentication_info.principal_email
                elif isinstance(authentication_info, dict):
                    principal_email = authentication_info.get("principalEmail", "")

            if not principal_email:
                return None

            # Determine principal type
            principal_type = self._guess_principal_type(principal_email)

            # Extract request metadata
            request_metadata = None
            if hasattr(payload, "request_metadata"):
                request_metadata = payload.request_metadata
            elif isinstance(payload, dict):
                request_metadata = payload.get("requestMetadata", {})

            source_ip = None
            if request_metadata:
                if hasattr(request_metadata, "caller_ip"):
                    source_ip = request_metadata.caller_ip
                elif isinstance(request_metadata, dict):
                    source_ip = request_metadata.get("callerIp")

            return AccessEvent(
                event_id=entry.insert_id or str(uuid.uuid4()),
                timestamp=entry.timestamp,
                principal_id=principal_email,
                principal_type=principal_type,
                resource_id=bucket_name,
                action=action,
                source_ip=source_ip,
                success=not bool(entry.severity and entry.severity.name == "ERROR"),
                metadata={
                    "method_name": method_name,
                    "log_name": entry.log_name,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to parse audit log entry: {e}")
            return None

    def _guess_principal_type(self, principal_email: str) -> str:
        """Guess the type of principal from the email."""
        if principal_email.endswith(".iam.gserviceaccount.com"):
            return "service_account"
        if principal_email.startswith("service-"):
            return "service_account"
        if "@" in principal_email:
            return "user"
        return "unknown"

    def get_resource_permissions(
        self,
        resource_id: str,
    ) -> dict[str, dict[str, Any]]:
        """
        Get current permissions for a GCS bucket.

        Analyzes bucket IAM policy to determine who has access.

        Args:
            resource_id: GCS bucket name

        Returns:
            Dictionary mapping principal_id to permission details
        """
        bucket_name = resource_id.replace("gs://", "").split("/")[0]
        permissions: dict[str, dict[str, Any]] = {}

        try:
            bucket = self._storage_client.bucket(bucket_name)
            policy = bucket.get_iam_policy()

            for binding in policy.bindings:
                role = binding.get("role", "")
                members = binding.get("members", [])

                # Map role to permission level
                level = self._role_to_permission_level(role)

                for member in members:
                    # Parse member format: type:email
                    if ":" in member:
                        member_type, member_id = member.split(":", 1)
                    else:
                        member_type = "unknown"
                        member_id = member

                    principal_type = self._member_type_to_principal_type(member_type)

                    # Skip public access indicators for this analysis
                    if member_id in ("allUsers", "allAuthenticatedUsers"):
                        continue

                    if member_id not in permissions:
                        permissions[member_id] = {
                            "type": principal_type,
                            "level": level,
                            "roles": [],
                        }
                    permissions[member_id]["roles"].append(role)

                    # Upgrade permission level if higher
                    current_level = permissions[member_id]["level"]
                    if self._permission_level_rank(level) > self._permission_level_rank(current_level):
                        permissions[member_id]["level"] = level

        except NotFound:
            logger.warning(f"Bucket not found: {bucket_name}")
        except Forbidden:
            logger.warning(f"Access denied to bucket IAM: {bucket_name}")
        except Exception as e:
            logger.warning(f"Error getting bucket permissions: {e}")

        return permissions

    def _role_to_permission_level(self, role: str) -> str:
        """Map GCP IAM role to permission level."""
        role_lower = role.lower()

        if "owner" in role_lower or "admin" in role_lower:
            return "admin"
        if "objectcreator" in role_lower or "objectadmin" in role_lower:
            return "write"
        if "writer" in role_lower or "legacybucketwriter" in role_lower:
            return "write"
        if "viewer" in role_lower or "reader" in role_lower or "objectviewer" in role_lower:
            return "read"
        if "legacybucketreader" in role_lower:
            return "read"

        return "unknown"

    def _member_type_to_principal_type(self, member_type: str) -> str:
        """Map GCP member type to our principal type."""
        mapping = {
            "user": "user",
            "serviceAccount": "service_account",
            "group": "group",
            "domain": "domain",
            "projectOwner": "role",
            "projectEditor": "role",
            "projectViewer": "role",
        }
        return mapping.get(member_type, "unknown")

    def _permission_level_rank(self, level: str) -> int:
        """Get numeric rank for permission level comparison."""
        ranks = {
            "admin": 4,
            "write": 3,
            "read": 2,
            "unknown": 1,
        }
        return ranks.get(level, 0)

    def get_bucket_location(self, bucket_name: str) -> str:
        """Get the location where a bucket is stored."""
        try:
            bucket = self._storage_client.get_bucket(bucket_name)
            return bucket.location or "US"
        except Exception:
            return "UNKNOWN"
