"""
AWS S3 collector for Mantissa Stance.

Collects S3 bucket resources and configuration for security posture assessment.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)

logger = logging.getLogger(__name__)


class S3Collector(BaseCollector):
    """
    Collects AWS S3 bucket resources and configuration.

    Gathers bucket encryption, public access settings, policies,
    ACLs, versioning, logging, and tags. All API calls are read-only.
    """

    collector_name = "aws_s3"
    resource_types = ["aws_s3_bucket"]

    def collect(self) -> AssetCollection:
        """
        Collect all S3 buckets with their configurations.

        Returns:
            Collection of S3 bucket assets
        """
        assets: list[Asset] = []

        try:
            assets.extend(self._collect_buckets())
        except Exception as e:
            logger.warning(f"Failed to collect S3 buckets: {e}")

        return AssetCollection(assets)

    def _collect_buckets(self) -> list[Asset]:
        """Collect S3 buckets with their configurations."""
        s3 = self._get_client("s3")
        assets: list[Asset] = []
        now = self._now()

        # List all buckets
        response = s3.list_buckets()

        for bucket in response.get("Buckets", []):
            bucket_name = bucket["Name"]

            # Get bucket configuration
            try:
                raw_config = self._get_bucket_config(bucket_name)
            except Exception as e:
                logger.warning(f"Failed to get config for bucket {bucket_name}: {e}")
                raw_config = {"bucket_name": bucket_name, "error": str(e)}

            # Determine bucket region
            bucket_region = raw_config.get("region", self._region)

            # Build ARN
            bucket_arn = f"arn:aws:s3:::{bucket_name}"

            # Determine network exposure
            network_exposure = self._determine_bucket_exposure(raw_config)

            # Get tags
            tags = raw_config.get("tags", {})

            created_at = bucket.get("CreationDate")
            if created_at:
                from datetime import timezone
                created_at = created_at.replace(tzinfo=timezone.utc)

            assets.append(
                Asset(
                    id=bucket_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=bucket_region,
                    resource_type="aws_s3_bucket",
                    name=bucket_name,
                    tags=tags,
                    network_exposure=network_exposure,
                    created_at=created_at,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _get_bucket_config(self, bucket_name: str) -> dict[str, Any]:
        """
        Get comprehensive bucket configuration.

        Args:
            bucket_name: Name of the bucket

        Returns:
            Dictionary containing bucket configuration
        """
        s3 = self._get_client("s3")
        config: dict[str, Any] = {"bucket_name": bucket_name}

        # Get bucket location (region)
        try:
            location = s3.get_bucket_location(Bucket=bucket_name)
            # LocationConstraint is None for us-east-1
            region = location.get("LocationConstraint") or "us-east-1"
            config["region"] = region
        except Exception as e:
            logger.debug(f"Could not get location for bucket {bucket_name}: {e}")
            config["region"] = "unknown"

        # Get encryption configuration
        try:
            encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )
            if rules:
                rule = rules[0].get("ApplyServerSideEncryptionByDefault", {})
                config["encryption"] = {
                    "enabled": True,
                    "sse_algorithm": rule.get("SSEAlgorithm"),
                    "kms_key_id": rule.get("KMSMasterKeyID"),
                }
            else:
                config["encryption"] = {"enabled": False}
        except s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ServerSideEncryptionConfigurationNotFoundError":
                config["encryption"] = {"enabled": False}
            else:
                logger.debug(f"Could not get encryption for bucket {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Could not get encryption for bucket {bucket_name}: {e}")

        # Get public access block configuration
        try:
            public_access = s3.get_public_access_block(Bucket=bucket_name)
            pab = public_access.get("PublicAccessBlockConfiguration", {})
            config["public_access_block"] = {
                "block_public_acls": pab.get("BlockPublicAcls", False),
                "ignore_public_acls": pab.get("IgnorePublicAcls", False),
                "block_public_policy": pab.get("BlockPublicPolicy", False),
                "restrict_public_buckets": pab.get("RestrictPublicBuckets", False),
            }
            config["public_access_block_enabled"] = all(
                [
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False),
                ]
            )
        except s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
                config["public_access_block"] = {
                    "block_public_acls": False,
                    "ignore_public_acls": False,
                    "block_public_policy": False,
                    "restrict_public_buckets": False,
                }
                config["public_access_block_enabled"] = False
            else:
                logger.debug(f"Could not get public access block for bucket {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Could not get public access block for bucket {bucket_name}: {e}")

        # Get bucket policy
        try:
            policy_response = s3.get_bucket_policy(Bucket=bucket_name)
            config["bucket_policy"] = policy_response.get("Policy")
            config["has_bucket_policy"] = True

            # Analyze policy for public access
            import json
            try:
                policy = json.loads(config["bucket_policy"])
                config["policy_allows_public"] = self._check_policy_allows_public(policy)
            except json.JSONDecodeError:
                config["policy_allows_public"] = False
        except s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                config["has_bucket_policy"] = False
                config["bucket_policy"] = None
                config["policy_allows_public"] = False
            else:
                logger.debug(f"Could not get policy for bucket {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Could not get policy for bucket {bucket_name}: {e}")

        # Get bucket ACL
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            grants = acl.get("Grants", [])
            config["acl_grants"] = []
            config["acl_allows_public"] = False

            for grant in grants:
                grantee = grant.get("Grantee", {})
                grant_info = {
                    "permission": grant.get("Permission"),
                    "type": grantee.get("Type"),
                }
                if grantee.get("URI"):
                    grant_info["uri"] = grantee["URI"]
                    # Check for public access
                    if "AllUsers" in grantee["URI"] or "AuthenticatedUsers" in grantee["URI"]:
                        config["acl_allows_public"] = True
                if grantee.get("ID"):
                    grant_info["canonical_id"] = grantee["ID"]

                config["acl_grants"].append(grant_info)
        except Exception as e:
            logger.debug(f"Could not get ACL for bucket {bucket_name}: {e}")

        # Get versioning configuration
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            config["versioning"] = {
                "status": versioning.get("Status", "Disabled"),
                "mfa_delete": versioning.get("MFADelete", "Disabled"),
            }
            config["versioning_enabled"] = versioning.get("Status") == "Enabled"
        except Exception as e:
            logger.debug(f"Could not get versioning for bucket {bucket_name}: {e}")

        # Get logging configuration
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            logging_enabled = logging_config.get("LoggingEnabled")
            if logging_enabled:
                config["logging"] = {
                    "enabled": True,
                    "target_bucket": logging_enabled.get("TargetBucket"),
                    "target_prefix": logging_enabled.get("TargetPrefix"),
                }
            else:
                config["logging"] = {"enabled": False}
        except Exception as e:
            logger.debug(f"Could not get logging for bucket {bucket_name}: {e}")

        # Get tags
        try:
            tags_response = s3.get_bucket_tagging(Bucket=bucket_name)
            config["tags"] = self._extract_tags(tags_response.get("TagSet", []))
        except s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchTagSet":
                config["tags"] = {}
            else:
                logger.debug(f"Could not get tags for bucket {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Could not get tags for bucket {bucket_name}: {e}")

        # Get lifecycle configuration
        try:
            lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
            config["lifecycle_rules"] = len(lifecycle.get("Rules", []))
            config["has_lifecycle_rules"] = config["lifecycle_rules"] > 0
        except s3.exceptions.ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchLifecycleConfiguration":
                config["lifecycle_rules"] = 0
                config["has_lifecycle_rules"] = False
            else:
                logger.debug(f"Could not get lifecycle for bucket {bucket_name}: {e}")
        except Exception as e:
            logger.debug(f"Could not get lifecycle for bucket {bucket_name}: {e}")

        return config

    def _check_policy_allows_public(self, policy: dict[str, Any]) -> bool:
        """
        Check if bucket policy allows public access.

        Args:
            policy: Parsed bucket policy

        Returns:
            True if policy allows public access
        """
        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})

            # Check for wildcard principal
            if principal == "*":
                # Check if there's a condition that restricts access
                if not statement.get("Condition"):
                    return True
                continue

            if isinstance(principal, dict):
                aws_principal = principal.get("AWS", [])
                if isinstance(aws_principal, str):
                    aws_principal = [aws_principal]
                if "*" in aws_principal:
                    if not statement.get("Condition"):
                        return True

        return False

    def _determine_bucket_exposure(self, config: dict[str, Any]) -> str:
        """
        Determine network exposure level for a bucket.

        Args:
            config: Bucket configuration dictionary

        Returns:
            Network exposure level string
        """
        # If public access block is fully enabled, bucket is internal
        if config.get("public_access_block_enabled", False):
            return NETWORK_EXPOSURE_INTERNAL

        # Check if ACL or policy allows public access
        if config.get("acl_allows_public", False):
            return NETWORK_EXPOSURE_INTERNET

        if config.get("policy_allows_public", False):
            return NETWORK_EXPOSURE_INTERNET

        return NETWORK_EXPOSURE_INTERNAL
