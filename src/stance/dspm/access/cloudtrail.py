"""
AWS CloudTrail Access Analyzer for DSPM.

Analyzes CloudTrail logs to detect stale S3 access patterns
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

# Import boto3 optionally
try:
    import boto3
    from botocore.exceptions import ClientError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    boto3 = None  # type: ignore
    ClientError = Exception  # type: ignore


# S3 data event action mapping
S3_ACTION_MAPPING = {
    "GetObject": "read",
    "HeadObject": "read",
    "GetObjectAcl": "read",
    "GetObjectTagging": "read",
    "GetObjectAttributes": "read",
    "PutObject": "write",
    "PutObjectAcl": "write",
    "PutObjectTagging": "write",
    "CopyObject": "write",
    "UploadPart": "write",
    "CompleteMultipartUpload": "write",
    "DeleteObject": "delete",
    "DeleteObjects": "delete",
    "DeleteObjectTagging": "delete",
    "ListBucket": "list",
    "ListBucketVersions": "list",
    "ListMultipartUploadParts": "list",
}


class CloudTrailAccessAnalyzer(BaseAccessAnalyzer):
    """
    AWS CloudTrail analyzer for S3 access patterns.

    Queries CloudTrail data events to identify:
    - Stale access (permissions not used in X days)
    - Unused permissions (no access recorded)
    - Over-privileged access (write permissions but only reads)

    All operations are read-only.
    """

    cloud_provider = "aws"

    def __init__(
        self,
        config: AccessReviewConfig | None = None,
        session: Any | None = None,
        region: str = "us-east-1",
        trail_name: str | None = None,
        use_lake: bool = False,
        lake_query_results_bucket: str | None = None,
    ):
        """
        Initialize CloudTrail access analyzer.

        Args:
            config: Optional access review configuration
            session: Optional boto3 Session
            region: AWS region
            trail_name: CloudTrail trail name (for lookup events)
            use_lake: Whether to use CloudTrail Lake for queries
            lake_query_results_bucket: S3 bucket for Lake query results
        """
        super().__init__(config)

        if not BOTO3_AVAILABLE:
            raise ImportError(
                "boto3 is required for CloudTrail analysis. "
                "Install with: pip install boto3"
            )

        self._session = session or boto3.Session()
        self._region = region
        self._trail_name = trail_name
        self._use_lake = use_lake
        self._lake_results_bucket = lake_query_results_bucket

        self._cloudtrail = self._session.client("cloudtrail", region_name=region)
        self._s3 = self._session.client("s3", region_name=region)
        self._iam = self._session.client("iam", region_name=region)

    def analyze_resource(self, resource_id: str) -> AccessReviewResult:
        """
        Analyze access patterns for an S3 bucket.

        Args:
            resource_id: S3 bucket name

        Returns:
            Access review result with findings
        """
        bucket_name = resource_id.replace("s3://", "").split("/")[0]
        review_id = str(uuid.uuid4())[:8]
        started_at = datetime.now(timezone.utc)

        logger.info(
            f"Starting CloudTrail access review: bucket={bucket_name}, "
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

            # Get access events from CloudTrail
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

        except ClientError as e:
            error_msg = f"AWS error: {e.response.get('Error', {}).get('Message', str(e))}"
            result.errors.append(error_msg)
            logger.error(error_msg)
        except Exception as e:
            error_msg = f"Analysis error: {type(e).__name__}: {str(e)}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        result.completed_at = datetime.now(timezone.utc)

        logger.info(
            f"CloudTrail access review complete: "
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
        Retrieve S3 access events from CloudTrail.

        Args:
            resource_id: S3 bucket name
            start_time: Start of time range
            end_time: End of time range

        Yields:
            Access events for the bucket
        """
        bucket_name = resource_id.replace("s3://", "").split("/")[0]

        if self._use_lake:
            yield from self._query_cloudtrail_lake(bucket_name, start_time, end_time)
        else:
            yield from self._lookup_events(bucket_name, start_time, end_time)

    def _lookup_events(
        self,
        bucket_name: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[AccessEvent]:
        """
        Use CloudTrail LookupEvents API for recent events.

        Note: LookupEvents only returns management events and recent data events.
        For comprehensive data event analysis, use CloudTrail Lake.
        """
        lookup_attrs = [
            {
                "AttributeKey": "ResourceName",
                "AttributeValue": bucket_name,
            }
        ]

        paginator = self._cloudtrail.get_paginator("lookup_events")

        try:
            for page in paginator.paginate(
                LookupAttributes=lookup_attrs,
                StartTime=start_time,
                EndTime=end_time,
            ):
                for event in page.get("Events", []):
                    parsed = self._parse_cloudtrail_event(event, bucket_name)
                    if parsed:
                        yield parsed
        except ClientError as e:
            logger.warning(f"CloudTrail lookup failed: {e}")

    def _query_cloudtrail_lake(
        self,
        bucket_name: str,
        start_time: datetime,
        end_time: datetime,
    ) -> Iterator[AccessEvent]:
        """
        Query CloudTrail Lake for comprehensive data event analysis.

        Requires CloudTrail Lake to be configured with S3 data events.
        """
        # CloudTrail Lake SQL query for S3 data events
        query = f"""
        SELECT
            eventID,
            eventTime,
            userIdentity.principalId,
            userIdentity.type,
            eventName,
            sourceIPAddress,
            userAgent,
            errorCode,
            requestParameters
        FROM cloudtrail_events
        WHERE
            eventSource = 's3.amazonaws.com'
            AND requestParameters LIKE '%{bucket_name}%'
            AND eventTime >= '{start_time.strftime("%Y-%m-%d %H:%M:%S")}'
            AND eventTime <= '{end_time.strftime("%Y-%m-%d %H:%M:%S")}'
        """

        try:
            # Start query
            response = self._cloudtrail.start_query(QueryStatement=query)
            query_id = response["QueryId"]

            # Poll for results (simplified - in production use proper async)
            import time
            for _ in range(60):  # Max 60 seconds wait
                status = self._cloudtrail.describe_query(QueryId=query_id)
                if status["QueryStatus"] == "FINISHED":
                    break
                if status["QueryStatus"] in ("FAILED", "CANCELLED"):
                    logger.error(f"CloudTrail Lake query failed: {status}")
                    return
                time.sleep(1)

            # Get results
            paginator = self._cloudtrail.get_paginator("get_query_results")
            for page in paginator.paginate(QueryId=query_id):
                for row in page.get("QueryResultRows", []):
                    parsed = self._parse_lake_result(row, bucket_name)
                    if parsed:
                        yield parsed

        except ClientError as e:
            logger.warning(f"CloudTrail Lake query failed: {e}")

    def _parse_cloudtrail_event(
        self,
        event: dict[str, Any],
        bucket_name: str,
    ) -> AccessEvent | None:
        """Parse a CloudTrail event into an AccessEvent."""
        try:
            # Parse the CloudTrail event JSON
            import json
            cloud_trail_event = json.loads(event.get("CloudTrailEvent", "{}"))

            event_name = cloud_trail_event.get("eventName", "")
            if event_name not in S3_ACTION_MAPPING:
                return None

            user_identity = cloud_trail_event.get("userIdentity", {})
            principal_id = user_identity.get("principalId", user_identity.get("arn", "unknown"))
            principal_type = self._map_principal_type(user_identity.get("type", "Unknown"))

            # Parse timestamp
            event_time = event.get("EventTime")
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))

            return AccessEvent(
                event_id=cloud_trail_event.get("eventID", str(uuid.uuid4())),
                timestamp=event_time,
                principal_id=principal_id,
                principal_type=principal_type,
                resource_id=bucket_name,
                action=S3_ACTION_MAPPING.get(event_name, event_name),
                source_ip=cloud_trail_event.get("sourceIPAddress"),
                user_agent=cloud_trail_event.get("userAgent"),
                success=cloud_trail_event.get("errorCode") is None,
                metadata={
                    "event_name": event_name,
                    "aws_region": cloud_trail_event.get("awsRegion"),
                },
            )
        except Exception as e:
            logger.debug(f"Failed to parse CloudTrail event: {e}")
            return None

    def _parse_lake_result(
        self,
        row: list[dict[str, str]],
        bucket_name: str,
    ) -> AccessEvent | None:
        """Parse a CloudTrail Lake query result row."""
        try:
            # Lake results are a list of column dicts
            data = {col["key"]: col.get("value", "") for col in row}

            event_name = data.get("eventName", "")
            if event_name not in S3_ACTION_MAPPING:
                return None

            return AccessEvent(
                event_id=data.get("eventID", str(uuid.uuid4())),
                timestamp=datetime.fromisoformat(data.get("eventTime", "").replace("Z", "+00:00")),
                principal_id=data.get("userIdentity.principalId", "unknown"),
                principal_type=self._map_principal_type(data.get("userIdentity.type", "Unknown")),
                resource_id=bucket_name,
                action=S3_ACTION_MAPPING.get(event_name, event_name),
                source_ip=data.get("sourceIPAddress"),
                user_agent=data.get("userAgent"),
                success=data.get("errorCode") in (None, "", "null"),
            )
        except Exception as e:
            logger.debug(f"Failed to parse Lake result: {e}")
            return None

    def _map_principal_type(self, aws_type: str) -> str:
        """Map AWS identity type to our principal type."""
        type_mapping = {
            "IAMUser": "user",
            "AssumedRole": "role",
            "FederatedUser": "user",
            "Root": "user",
            "AWSAccount": "account",
            "AWSService": "service_account",
            "SAMLUser": "user",
            "WebIdentityUser": "user",
        }
        return type_mapping.get(aws_type, "unknown")

    def get_resource_permissions(
        self,
        resource_id: str,
    ) -> dict[str, dict[str, Any]]:
        """
        Get current permissions for an S3 bucket.

        Analyzes bucket policy and ACL to determine who has access.

        Args:
            resource_id: S3 bucket name

        Returns:
            Dictionary mapping principal_id to permission details
        """
        bucket_name = resource_id.replace("s3://", "").split("/")[0]
        permissions: dict[str, dict[str, Any]] = {}

        # Get bucket policy
        try:
            policy_response = self._s3.get_bucket_policy(Bucket=bucket_name)
            import json
            policy = json.loads(policy_response.get("Policy", "{}"))

            for statement in policy.get("Statement", []):
                principals = statement.get("Principal", {})
                actions = statement.get("Action", [])
                effect = statement.get("Effect", "Deny")

                if effect != "Allow":
                    continue

                # Normalize principals
                if isinstance(principals, str):
                    principals = [principals]
                elif isinstance(principals, dict):
                    principals = principals.get("AWS", [])
                    if isinstance(principals, str):
                        principals = [principals]

                # Determine permission level from actions
                level = self._actions_to_permission_level(actions)

                for principal in principals:
                    if principal == "*":
                        principal = "Public"
                    permissions[principal] = {
                        "type": self._guess_principal_type(principal),
                        "level": level,
                        "source": "bucket_policy",
                    }

        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                logger.debug(f"Could not get bucket policy: {e}")

        # Get bucket ACL
        try:
            acl = self._s3.get_bucket_acl(Bucket=bucket_name)

            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                permission = grant.get("Permission", "")

                grantee_id = grantee.get("ID") or grantee.get("URI", "").split("/")[-1]
                if not grantee_id:
                    continue

                level = "read" if permission in ("READ", "READ_ACP") else "write"
                if permission == "FULL_CONTROL":
                    level = "admin"

                permissions[grantee_id] = {
                    "type": grantee.get("Type", "unknown").lower(),
                    "level": level,
                    "source": "bucket_acl",
                }

        except ClientError as e:
            logger.debug(f"Could not get bucket ACL: {e}")

        return permissions

    def _actions_to_permission_level(self, actions: list[str] | str) -> str:
        """Map S3 actions to a permission level."""
        if isinstance(actions, str):
            actions = [actions]

        actions_lower = [a.lower() for a in actions]

        if any("*" in a for a in actions_lower):
            return "admin"
        if any("delete" in a for a in actions_lower):
            return "admin"
        if any("put" in a for a in actions_lower):
            return "write"
        if any("get" in a or "list" in a for a in actions_lower):
            return "read"
        return "unknown"

    def _guess_principal_type(self, principal: str) -> str:
        """Guess the type of principal from its ARN or ID."""
        if ":user/" in principal:
            return "user"
        if ":role/" in principal:
            return "role"
        if ":root" in principal:
            return "user"
        if principal.startswith("arn:aws:iam::") and principal.endswith(":root"):
            return "account"
        return "unknown"

    def get_bucket_location(self, bucket_name: str) -> str:
        """Get the region where a bucket is located."""
        try:
            response = self._s3.get_bucket_location(Bucket=bucket_name)
            location = response.get("LocationConstraint")
            return location if location else "us-east-1"
        except ClientError:
            return self._region
