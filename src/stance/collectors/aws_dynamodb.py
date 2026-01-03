"""
AWS DynamoDB collector for Mantissa Stance.

Collects DynamoDB tables, global tables, and their configurations
for security posture assessment.
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


class DynamoDBCollector(BaseCollector):
    """
    Collects AWS DynamoDB tables and related configurations.

    Gathers DynamoDB tables, global tables, backups, and security configurations.
    All API calls are read-only.
    """

    collector_name = "aws_dynamodb"
    resource_types = [
        "aws_dynamodb_table",
        "aws_dynamodb_global_table",
        "aws_dynamodb_backup",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all DynamoDB resources.

        Returns:
            Collection of DynamoDB assets
        """
        assets: list[Asset] = []

        # Collect tables
        try:
            assets.extend(self._collect_tables())
        except Exception as e:
            logger.warning(f"Failed to collect DynamoDB tables: {e}")

        # Collect backups
        try:
            assets.extend(self._collect_backups())
        except Exception as e:
            logger.warning(f"Failed to collect DynamoDB backups: {e}")

        return AssetCollection(assets)

    def _collect_tables(self) -> list[Asset]:
        """Collect DynamoDB tables with their configurations."""
        dynamodb = self._get_client("dynamodb")
        assets: list[Asset] = []
        now = self._now()

        # List all table names
        for table_name in self._paginate(
            dynamodb, "list_tables", "TableNames"
        ):
            try:
                # Get detailed table description
                response = dynamodb.describe_table(TableName=table_name)
                table = response.get("Table", {})

                table_arn = table.get("TableArn", "")

                # Build ARN if not provided
                if not table_arn:
                    table_arn = self._build_arn(
                        "dynamodb",
                        "table",
                        table_name,
                        region=self._region,
                        account_id=self.account_id,
                    )

                # Extract tags
                tags = self._get_table_tags(table_arn)
                name = self._get_name_from_tags(tags, table_name)

                # Get additional configurations
                continuous_backups = self._get_continuous_backups(table_name)
                ttl_config = self._get_ttl_config(table_name)
                contributor_insights = self._get_contributor_insights(table_name)
                resource_policy = self._get_resource_policy(table_arn)

                # Determine network exposure
                # DynamoDB tables are accessed via AWS API, so they're essentially
                # "internal" but resource policies can make them publicly accessible
                network_exposure = self._determine_dynamodb_exposure(resource_policy)

                # Check for encryption configuration
                sse_description = table.get("SSEDescription", {})
                encryption_enabled = sse_description.get("Status") == "ENABLED"
                encryption_type = sse_description.get("SSEType", "")
                kms_key_arn = sse_description.get("KMSMasterKeyArn", "")

                # Build raw config
                raw_config: dict[str, Any] = {
                    "table_name": table_name,
                    "table_status": table.get("TableStatus"),
                    "table_id": table.get("TableId"),
                    "creation_date_time": (
                        table["CreationDateTime"].isoformat()
                        if table.get("CreationDateTime")
                        else None
                    ),
                    # Key schema
                    "key_schema": [
                        {
                            "attribute_name": key.get("AttributeName"),
                            "key_type": key.get("KeyType"),
                        }
                        for key in table.get("KeySchema", [])
                    ],
                    "attribute_definitions": [
                        {
                            "attribute_name": attr.get("AttributeName"),
                            "attribute_type": attr.get("AttributeType"),
                        }
                        for attr in table.get("AttributeDefinitions", [])
                    ],
                    # Provisioned throughput
                    "billing_mode_summary": {
                        "billing_mode": table.get("BillingModeSummary", {}).get(
                            "BillingMode", "PROVISIONED"
                        ),
                        "last_update_to_pay_per_request_date_time": (
                            table.get("BillingModeSummary", {})
                            .get("LastUpdateToPayPerRequestDateTime", "")
                        ),
                    },
                    "provisioned_throughput": {
                        "read_capacity_units": table.get(
                            "ProvisionedThroughput", {}
                        ).get("ReadCapacityUnits"),
                        "write_capacity_units": table.get(
                            "ProvisionedThroughput", {}
                        ).get("WriteCapacityUnits"),
                        "last_increase_date_time": (
                            table.get("ProvisionedThroughput", {})
                            .get("LastIncreaseDateTime", "")
                        ),
                        "last_decrease_date_time": (
                            table.get("ProvisionedThroughput", {})
                            .get("LastDecreaseDateTime", "")
                        ),
                        "number_of_decreases_today": table.get(
                            "ProvisionedThroughput", {}
                        ).get("NumberOfDecreasesToday"),
                    },
                    # Indexes
                    "local_secondary_indexes": [
                        {
                            "index_name": idx.get("IndexName"),
                            "key_schema": idx.get("KeySchema", []),
                            "projection": idx.get("Projection", {}),
                            "index_size_bytes": idx.get("IndexSizeBytes"),
                            "item_count": idx.get("ItemCount"),
                        }
                        for idx in table.get("LocalSecondaryIndexes", [])
                    ],
                    "global_secondary_indexes": [
                        {
                            "index_name": idx.get("IndexName"),
                            "key_schema": idx.get("KeySchema", []),
                            "projection": idx.get("Projection", {}),
                            "index_status": idx.get("IndexStatus"),
                            "backfilling": idx.get("Backfilling", False),
                            "provisioned_throughput": idx.get(
                                "ProvisionedThroughput", {}
                            ),
                            "index_size_bytes": idx.get("IndexSizeBytes"),
                            "item_count": idx.get("ItemCount"),
                        }
                        for idx in table.get("GlobalSecondaryIndexes", [])
                    ],
                    # Stream specification
                    "stream_specification": {
                        "stream_enabled": table.get(
                            "StreamSpecification", {}
                        ).get("StreamEnabled", False),
                        "stream_view_type": table.get(
                            "StreamSpecification", {}
                        ).get("StreamViewType"),
                    } if table.get("StreamSpecification") else None,
                    "latest_stream_label": table.get("LatestStreamLabel"),
                    "latest_stream_arn": table.get("LatestStreamArn"),
                    # Global table configuration
                    "global_table_version": table.get("GlobalTableVersion"),
                    "replicas": [
                        {
                            "region_name": replica.get("RegionName"),
                            "replica_status": replica.get("ReplicaStatus"),
                            "replica_status_description": replica.get(
                                "ReplicaStatusDescription"
                            ),
                            "replica_status_percent_progress": replica.get(
                                "ReplicaStatusPercentProgress"
                            ),
                            "kms_master_key_id": replica.get("KMSMasterKeyId"),
                            "provisioned_throughput_override": replica.get(
                                "ProvisionedThroughputOverride"
                            ),
                            "global_secondary_indexes": replica.get(
                                "GlobalSecondaryIndexes", []
                            ),
                            "replica_table_class_summary": replica.get(
                                "ReplicaTableClassSummary"
                            ),
                        }
                        for replica in table.get("Replicas", [])
                    ],
                    # Restore summary
                    "restore_summary": {
                        "source_backup_arn": table.get(
                            "RestoreSummary", {}
                        ).get("SourceBackupArn"),
                        "source_table_arn": table.get(
                            "RestoreSummary", {}
                        ).get("SourceTableArn"),
                        "restore_date_time": (
                            table.get("RestoreSummary", {})
                            .get("RestoreDateTime", "")
                        ),
                        "restore_in_progress": table.get(
                            "RestoreSummary", {}
                        ).get("RestoreInProgress", False),
                    } if table.get("RestoreSummary") else None,
                    # Encryption
                    "sse_description": {
                        "status": sse_description.get("Status"),
                        "sse_type": encryption_type,
                        "kms_master_key_arn": kms_key_arn,
                        "inaccessible_encryption_date_time": (
                            sse_description.get(
                                "InaccessibleEncryptionDateTime", ""
                            )
                        ),
                    },
                    "encryption_enabled": encryption_enabled,
                    "encryption_type": encryption_type,
                    "kms_key_arn": kms_key_arn,
                    # Table class
                    "table_class_summary": {
                        "table_class": table.get(
                            "TableClassSummary", {}
                        ).get("TableClass"),
                        "last_update_date_time": (
                            table.get("TableClassSummary", {})
                            .get("LastUpdateDateTime", "")
                        ),
                    } if table.get("TableClassSummary") else None,
                    # Archival
                    "archival_summary": {
                        "archival_date_time": (
                            table.get("ArchivalSummary", {})
                            .get("ArchivalDateTime", "")
                        ),
                        "archival_reason": table.get(
                            "ArchivalSummary", {}
                        ).get("ArchivalReason"),
                        "archival_backup_arn": table.get(
                            "ArchivalSummary", {}
                        ).get("ArchivalBackupArn"),
                    } if table.get("ArchivalSummary") else None,
                    # Statistics
                    "table_size_bytes": table.get("TableSizeBytes"),
                    "item_count": table.get("ItemCount"),
                    # Additional configurations
                    "deletion_protection_enabled": table.get(
                        "DeletionProtectionEnabled", False
                    ),
                    # Continuous backups (PITR)
                    "continuous_backups": continuous_backups,
                    # TTL
                    "ttl_config": ttl_config,
                    # Contributor insights
                    "contributor_insights": contributor_insights,
                    # Resource policy
                    "resource_policy": resource_policy,
                }

                asset = Asset(
                    id=table_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_dynamodb_table",
                    name=name,
                    tags=tags,
                    network_exposure=network_exposure,
                    created_at=table.get("CreationDateTime", now),
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(asset)

            except Exception as e:
                logger.warning(f"Failed to describe table {table_name}: {e}")

        return assets

    def _get_table_tags(self, table_arn: str) -> dict[str, str]:
        """Get tags for a DynamoDB table."""
        dynamodb = self._get_client("dynamodb")

        try:
            response = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
            tags = response.get("Tags", [])
            return {tag.get("Key", ""): tag.get("Value", "") for tag in tags}
        except Exception as e:
            logger.debug(f"Could not get tags for table {table_arn}: {e}")
            return {}

    def _get_continuous_backups(self, table_name: str) -> dict[str, Any]:
        """Get continuous backup (PITR) configuration for a table."""
        dynamodb = self._get_client("dynamodb")

        try:
            response = dynamodb.describe_continuous_backups(TableName=table_name)
            desc = response.get("ContinuousBackupsDescription", {})

            pitr = desc.get("PointInTimeRecoveryDescription", {})

            return {
                "continuous_backups_status": desc.get("ContinuousBackupsStatus"),
                "point_in_time_recovery_status": pitr.get(
                    "PointInTimeRecoveryStatus"
                ),
                "earliest_restorable_date_time": (
                    pitr.get("EarliestRestorableDateTime", "")
                ),
                "latest_restorable_date_time": (
                    pitr.get("LatestRestorableDateTime", "")
                ),
            }
        except Exception as e:
            logger.debug(f"Could not get continuous backups for {table_name}: {e}")
            return {}

    def _get_ttl_config(self, table_name: str) -> dict[str, Any]:
        """Get TTL configuration for a table."""
        dynamodb = self._get_client("dynamodb")

        try:
            response = dynamodb.describe_time_to_live(TableName=table_name)
            ttl = response.get("TimeToLiveDescription", {})

            return {
                "time_to_live_status": ttl.get("TimeToLiveStatus"),
                "attribute_name": ttl.get("AttributeName"),
            }
        except Exception as e:
            logger.debug(f"Could not get TTL config for {table_name}: {e}")
            return {}

    def _get_contributor_insights(self, table_name: str) -> dict[str, Any]:
        """Get contributor insights configuration for a table."""
        dynamodb = self._get_client("dynamodb")

        try:
            response = dynamodb.describe_contributor_insights(
                TableName=table_name
            )

            return {
                "contributor_insights_status": response.get(
                    "ContributorInsightsStatus"
                ),
                "last_update_date_time": (
                    response.get("LastUpdateDateTime", "")
                ),
                "failure_exception": response.get("FailureException"),
            }
        except Exception as e:
            logger.debug(
                f"Could not get contributor insights for {table_name}: {e}"
            )
            return {}

    def _get_resource_policy(self, table_arn: str) -> dict[str, Any] | None:
        """Get resource-based policy for a table."""
        dynamodb = self._get_client("dynamodb")

        try:
            response = dynamodb.get_resource_policy(ResourceArn=table_arn)
            policy = response.get("Policy")
            if policy:
                import json
                return json.loads(policy)
            return None
        except dynamodb.exceptions.PolicyNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get resource policy for {table_arn}: {e}")
            return None

    def _determine_dynamodb_exposure(
        self, resource_policy: dict[str, Any] | None
    ) -> str:
        """
        Determine network exposure based on resource policy.

        DynamoDB is accessed via AWS API (private by default).
        A resource policy with Principal: "*" can make it publicly accessible.

        Args:
            resource_policy: The table's resource-based policy

        Returns:
            Network exposure level
        """
        if not resource_policy:
            return NETWORK_EXPOSURE_INTERNAL

        # Check for public access in the policy
        statements = resource_policy.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect", "")
            principal = statement.get("Principal", {})

            # Check for Allow with * principal
            if effect == "Allow":
                if principal == "*":
                    return NETWORK_EXPOSURE_INTERNET
                if isinstance(principal, dict):
                    if principal.get("AWS") == "*":
                        return NETWORK_EXPOSURE_INTERNET

        return NETWORK_EXPOSURE_INTERNAL

    def _collect_backups(self) -> list[Asset]:
        """Collect DynamoDB backups."""
        dynamodb = self._get_client("dynamodb")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all backups
            for backup in self._paginate(
                dynamodb, "list_backups", "BackupSummaries"
            ):
                backup_arn = backup.get("BackupArn", "")
                backup_name = backup.get("BackupName", "")
                table_name = backup.get("TableName", "")

                if not backup_arn:
                    continue

                # Get detailed backup description
                try:
                    backup_response = dynamodb.describe_backup(
                        BackupArn=backup_arn
                    )
                    backup_desc = backup_response.get("BackupDescription", {})
                    backup_details = backup_desc.get("BackupDetails", {})
                    source_table = backup_desc.get("SourceTableDetails", {})
                    source_feature = backup_desc.get(
                        "SourceTableFeatureDetails", {}
                    )
                except Exception:
                    backup_details = backup
                    source_table = {}
                    source_feature = {}

                # Build raw config
                raw_config: dict[str, Any] = {
                    "backup_arn": backup_arn,
                    "backup_name": backup_name,
                    "backup_size_bytes": backup.get("BackupSizeBytes"),
                    "backup_status": backup.get("BackupStatus"),
                    "backup_type": backup.get("BackupType"),
                    "backup_creation_date_time": (
                        backup["BackupCreationDateTime"].isoformat()
                        if backup.get("BackupCreationDateTime")
                        else None
                    ),
                    "backup_expiry_date_time": (
                        backup_details.get("BackupExpiryDateTime", "")
                    ),
                    # Source table details
                    "source_table_name": table_name,
                    "source_table_arn": source_table.get("TableArn"),
                    "source_table_id": source_table.get("TableId"),
                    "source_table_size_bytes": source_table.get("TableSizeBytes"),
                    "source_item_count": source_table.get("ItemCount"),
                    "source_key_schema": source_table.get("KeySchema", []),
                    "source_table_creation_date_time": (
                        source_table.get("TableCreationDateTime", "")
                    ),
                    "source_provisioned_throughput": source_table.get(
                        "ProvisionedThroughput", {}
                    ),
                    "source_billing_mode": source_table.get("BillingMode"),
                    # Source table features
                    "source_local_secondary_indexes": source_feature.get(
                        "LocalSecondaryIndexes", []
                    ),
                    "source_global_secondary_indexes": source_feature.get(
                        "GlobalSecondaryIndexes", []
                    ),
                    "source_stream_description": source_feature.get(
                        "StreamDescription"
                    ),
                    "source_time_to_live_description": source_feature.get(
                        "TimeToLiveDescription"
                    ),
                    "source_sse_description": source_feature.get(
                        "SSEDescription"
                    ),
                }

                asset = Asset(
                    id=backup_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_dynamodb_backup",
                    name=backup_name or f"{table_name}-backup",
                    tags={},
                    network_exposure=NETWORK_EXPOSURE_INTERNAL,
                    created_at=backup.get("BackupCreationDateTime", now),
                    last_seen=now,
                    raw_config=raw_config,
                )
                assets.append(asset)

        except Exception as e:
            logger.warning(f"Failed to list DynamoDB backups: {e}")

        return assets
