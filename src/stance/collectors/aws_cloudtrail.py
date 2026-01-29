"""
AWS CloudTrail collector for Mantissa Stance.

Collects CloudTrail trail resources and configuration for security posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)


class CloudTrailCollector(BaseCollector):
    """
    Collects AWS CloudTrail trail resources and configuration.

    Gathers trail settings including multi-region configuration, logging status,
    encryption, log validation, S3 bucket settings, and CloudWatch integration.
    All API calls are read-only.
    """

    collector_name = "aws_cloudtrail"
    resource_types = ["aws_cloudtrail"]

    def collect(self) -> AssetCollection:
        """
        Collect all CloudTrail trails with their configurations.

        Returns:
            Collection of CloudTrail trail assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_trails())
        except Exception as e:
            logger.warning(f"Failed to collect CloudTrail trails: {e}")

        return AssetCollection(assets)

    def _collect_trails(self) -> list[Asset]:
        """Collect CloudTrail trails with their configurations."""
        cloudtrail = self._get_client("cloudtrail")
        s3 = self._get_client("s3")
        assets: list[Asset] = []
        now = self._now()

        # Describe all trails
        response = cloudtrail.describe_trails(includeShadowTrails=False)

        for trail in response.get("trailList", []):
            trail_name = trail.get("Name", "")
            trail_arn = trail.get("TrailARN", "")

            # Get trail status to determine if logging is enabled
            is_logging = False
            try:
                status_response = cloudtrail.get_trail_status(Name=trail_arn)
                is_logging = status_response.get("IsLogging", False)
            except Exception as e:
                logger.warning(f"Failed to get status for trail {trail_name}: {e}")

            # Check S3 bucket public access settings
            s3_bucket_name = trail.get("S3BucketName", "")
            s3_bucket_public_access_blocked = False
            if s3_bucket_name:
                try:
                    pab_response = s3.get_public_access_block(Bucket=s3_bucket_name)
                    pab_config = pab_response.get("PublicAccessBlockConfiguration", {})
                    # All four settings must be enabled to be considered fully blocked
                    s3_bucket_public_access_blocked = (
                        pab_config.get("BlockPublicAcls", False)
                        and pab_config.get("IgnorePublicAcls", False)
                        and pab_config.get("BlockPublicPolicy", False)
                        and pab_config.get("RestrictPublicBuckets", False)
                    )
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    # No public access block configured
                    s3_bucket_public_access_blocked = False
                except Exception as e:
                    logger.warning(
                        f"Failed to get public access block for bucket {s3_bucket_name}: {e}"
                    )

            # Build raw_config with all properties needed by policies
            raw_config: dict[str, Any] = {
                # Core trail properties
                "name": trail_name,
                "trail_arn": trail_arn,
                "home_region": trail.get("HomeRegion", ""),
                # Multi-region and logging status (cloudtrail-enabled.yaml)
                "is_multi_region_trail": trail.get("IsMultiRegionTrail", False),
                "is_logging": is_logging,
                # Log validation (cloudtrail-log-validation.yaml)
                "log_file_validation_enabled": trail.get(
                    "LogFileValidationEnabled", False
                ),
                # KMS encryption (cloudtrail-encryption.yaml)
                "kms_key_id": trail.get("KmsKeyId"),
                "has_kms_encryption": trail.get("KmsKeyId") is not None
                and trail.get("KmsKeyId") != "",
                # S3 bucket configuration (cloudtrail-s3-public-access.yaml)
                "s3_bucket_name": s3_bucket_name,
                "s3_key_prefix": trail.get("S3KeyPrefix", ""),
                "s3_bucket_public_access_blocked": s3_bucket_public_access_blocked,
                # CloudWatch integration (cloudtrail-cloudwatch-integration.yaml)
                "cloud_watch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
                "cloud_watch_logs_role_arn": trail.get("CloudWatchLogsRoleArn"),
                "has_cloudwatch_integration": trail.get("CloudWatchLogsLogGroupArn")
                is not None
                and trail.get("CloudWatchLogsLogGroupArn") != "",
                # SNS configuration
                "sns_topic_name": trail.get("SnsTopicName"),
                "sns_topic_arn": trail.get("SnsTopicARN"),
                # Organization trail
                "is_organization_trail": trail.get("IsOrganizationTrail", False),
                # Include global service events
                "include_global_service_events": trail.get(
                    "IncludeGlobalServiceEvents", True
                ),
            }

            # Determine region - use home region if available
            region = trail.get("HomeRegion", self._region)

            assets.append(
                Asset(
                    id=trail_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=region,
                    resource_type="aws_cloudtrail",
                    name=trail_name,
                    tags={},  # CloudTrail trails don't have standard tags in describe_trails
                    network_exposure=NETWORK_EXPOSURE_INTERNAL,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets
