"""
AWS RDS collector for Mantissa Stance.

Collects RDS database instances, clusters, and their configurations
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


class RDSCollector(BaseCollector):
    """
    Collects AWS RDS database instances, clusters, and related configurations.

    Gathers RDS instances, Aurora clusters, parameter groups, subnet groups,
    and security configurations. All API calls are read-only.
    """

    collector_name = "aws_rds"
    resource_types = [
        "aws_rds_instance",
        "aws_rds_cluster",
        "aws_rds_parameter_group",
        "aws_rds_subnet_group",
        "aws_rds_snapshot",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all RDS resources.

        Returns:
            Collection of RDS assets
        """
        assets: list[Asset] = []

        # Collect DB instances
        try:
            assets.extend(self._collect_instances())
        except Exception as e:
            logger.warning(f"Failed to collect RDS instances: {e}")

        # Collect Aurora clusters
        try:
            assets.extend(self._collect_clusters())
        except Exception as e:
            logger.warning(f"Failed to collect RDS clusters: {e}")

        # Collect parameter groups
        try:
            assets.extend(self._collect_parameter_groups())
        except Exception as e:
            logger.warning(f"Failed to collect parameter groups: {e}")

        # Collect subnet groups
        try:
            assets.extend(self._collect_subnet_groups())
        except Exception as e:
            logger.warning(f"Failed to collect subnet groups: {e}")

        # Collect snapshots
        try:
            assets.extend(self._collect_snapshots())
        except Exception as e:
            logger.warning(f"Failed to collect RDS snapshots: {e}")

        return AssetCollection(assets)

    def _collect_instances(self) -> list[Asset]:
        """Collect RDS DB instances with their configurations."""
        rds = self._get_client("rds")
        assets: list[Asset] = []
        now = self._now()

        for instance in self._paginate(
            rds, "describe_db_instances", "DBInstances"
        ):
            db_instance_id = instance["DBInstanceIdentifier"]
            db_instance_arn = instance.get("DBInstanceArn", "")

            # Build ARN if not provided
            if not db_instance_arn:
                db_instance_arn = self._build_arn(
                    "rds",
                    "db",
                    db_instance_id,
                    region=self._region,
                    account_id=self.account_id,
                )

            # Extract tags
            tags = self._extract_rds_tags(instance.get("TagList"))
            name = self._get_name_from_tags(tags, db_instance_id)

            # Determine network exposure
            publicly_accessible = instance.get("PubliclyAccessible", False)
            network_exposure = (
                NETWORK_EXPOSURE_INTERNET if publicly_accessible
                else NETWORK_EXPOSURE_INTERNAL
            )

            # Build raw config
            raw_config: dict[str, Any] = {
                "db_instance_identifier": db_instance_id,
                "db_instance_class": instance.get("DBInstanceClass"),
                "engine": instance.get("Engine"),
                "engine_version": instance.get("EngineVersion"),
                "db_instance_status": instance.get("DBInstanceStatus"),
                "master_username": instance.get("MasterUsername"),
                "db_name": instance.get("DBName"),
                "endpoint": {
                    "address": instance.get("Endpoint", {}).get("Address"),
                    "port": instance.get("Endpoint", {}).get("Port"),
                    "hosted_zone_id": instance.get("Endpoint", {}).get("HostedZoneId"),
                } if instance.get("Endpoint") else None,
                "allocated_storage": instance.get("AllocatedStorage"),
                "max_allocated_storage": instance.get("MaxAllocatedStorage"),
                "instance_create_time": (
                    instance["InstanceCreateTime"].isoformat()
                    if instance.get("InstanceCreateTime")
                    else None
                ),
                # Availability and replication
                "availability_zone": instance.get("AvailabilityZone"),
                "multi_az": instance.get("MultiAZ", False),
                "secondary_availability_zone": instance.get("SecondaryAvailabilityZone"),
                "read_replica_source_db_instance_identifier": instance.get(
                    "ReadReplicaSourceDBInstanceIdentifier"
                ),
                "read_replica_db_instance_identifiers": instance.get(
                    "ReadReplicaDBInstanceIdentifiers", []
                ),
                # Network configuration
                "publicly_accessible": publicly_accessible,
                "vpc_security_groups": [
                    {
                        "vpc_security_group_id": sg.get("VpcSecurityGroupId"),
                        "status": sg.get("Status"),
                    }
                    for sg in instance.get("VpcSecurityGroups", [])
                ],
                "db_subnet_group": {
                    "name": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupName"),
                    "description": instance.get("DBSubnetGroup", {}).get("DBSubnetGroupDescription"),
                    "vpc_id": instance.get("DBSubnetGroup", {}).get("VpcId"),
                    "subnet_group_status": instance.get("DBSubnetGroup", {}).get("SubnetGroupStatus"),
                } if instance.get("DBSubnetGroup") else None,
                # Storage configuration
                "storage_type": instance.get("StorageType"),
                "iops": instance.get("Iops"),
                "storage_throughput": instance.get("StorageThroughput"),
                "storage_encrypted": instance.get("StorageEncrypted", False),
                "kms_key_id": instance.get("KmsKeyId"),
                # Backup configuration
                "backup_retention_period": instance.get("BackupRetentionPeriod", 0),
                "preferred_backup_window": instance.get("PreferredBackupWindow"),
                "latest_restorable_time": (
                    instance["LatestRestorableTime"].isoformat()
                    if instance.get("LatestRestorableTime")
                    else None
                ),
                "copy_tags_to_snapshot": instance.get("CopyTagsToSnapshot", False),
                # Maintenance
                "preferred_maintenance_window": instance.get("PreferredMaintenanceWindow"),
                "auto_minor_version_upgrade": instance.get("AutoMinorVersionUpgrade", False),
                "pending_modified_values": instance.get("PendingModifiedValues", {}),
                # Enhanced monitoring
                "monitoring_interval": instance.get("MonitoringInterval", 0),
                "monitoring_role_arn": instance.get("MonitoringRoleArn"),
                "enhanced_monitoring_resource_arn": instance.get(
                    "EnhancedMonitoringResourceArn"
                ),
                # Performance Insights
                "performance_insights_enabled": instance.get(
                    "PerformanceInsightsEnabled", False
                ),
                "performance_insights_kms_key_id": instance.get(
                    "PerformanceInsightsKMSKeyId"
                ),
                "performance_insights_retention_period": instance.get(
                    "PerformanceInsightsRetentionPeriod"
                ),
                # Security
                "iam_database_authentication_enabled": instance.get(
                    "IAMDatabaseAuthenticationEnabled", False
                ),
                "deletion_protection": instance.get("DeletionProtection", False),
                "ca_certificate_identifier": instance.get("CACertificateIdentifier"),
                "customer_owned_ip_enabled": instance.get("CustomerOwnedIpEnabled", False),
                # Aurora specific
                "db_cluster_identifier": instance.get("DBClusterIdentifier"),
                # Parameter and option groups
                "db_parameter_groups": [
                    {
                        "name": pg.get("DBParameterGroupName"),
                        "status": pg.get("ParameterApplyStatus"),
                    }
                    for pg in instance.get("DBParameterGroups", [])
                ],
                "option_group_memberships": [
                    {
                        "name": og.get("OptionGroupName"),
                        "status": og.get("Status"),
                    }
                    for og in instance.get("OptionGroupMemberships", [])
                ],
                # Enabled features
                "enabled_cloudwatch_logs_exports": instance.get(
                    "EnabledCloudwatchLogsExports", []
                ),
                "processor_features": instance.get("ProcessorFeatures", []),
                "associated_roles": [
                    {
                        "role_arn": role.get("RoleArn"),
                        "feature_name": role.get("FeatureName"),
                        "status": role.get("Status"),
                    }
                    for role in instance.get("AssociatedRoles", [])
                ],
                # Activity Stream
                "activity_stream_status": instance.get("ActivityStreamStatus"),
                "activity_stream_kms_key_id": instance.get("ActivityStreamKmsKeyId"),
                "activity_stream_kinesis_stream_name": instance.get(
                    "ActivityStreamKinesisStreamName"
                ),
                "activity_stream_mode": instance.get("ActivityStreamMode"),
                "activity_stream_engine_native_audit_fields_included": instance.get(
                    "ActivityStreamEngineNativeAuditFieldsIncluded"
                ),
            }

            asset = Asset(
                id=db_instance_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_rds_instance",
                name=name,
                tags=tags,
                network_exposure=network_exposure,
                created_at=instance.get("InstanceCreateTime", now),
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_clusters(self) -> list[Asset]:
        """Collect Aurora DB clusters."""
        rds = self._get_client("rds")
        assets: list[Asset] = []
        now = self._now()

        for cluster in self._paginate(
            rds, "describe_db_clusters", "DBClusters"
        ):
            cluster_id = cluster["DBClusterIdentifier"]
            cluster_arn = cluster.get("DBClusterArn", "")

            # Build ARN if not provided
            if not cluster_arn:
                cluster_arn = self._build_arn(
                    "rds",
                    "cluster",
                    cluster_id,
                    region=self._region,
                    account_id=self.account_id,
                )

            # Extract tags
            tags = self._extract_rds_tags(cluster.get("TagList"))
            name = self._get_name_from_tags(tags, cluster_id)

            # Determine network exposure - clusters themselves are not publicly
            # accessible directly, but their instances might be
            network_exposure = NETWORK_EXPOSURE_INTERNAL

            # Build raw config
            raw_config: dict[str, Any] = {
                "db_cluster_identifier": cluster_id,
                "engine": cluster.get("Engine"),
                "engine_version": cluster.get("EngineVersion"),
                "engine_mode": cluster.get("EngineMode"),
                "status": cluster.get("Status"),
                "database_name": cluster.get("DatabaseName"),
                "master_username": cluster.get("MasterUsername"),
                # Endpoint configuration
                "endpoint": cluster.get("Endpoint"),
                "port": cluster.get("Port"),
                "reader_endpoint": cluster.get("ReaderEndpoint"),
                "custom_endpoints": cluster.get("CustomEndpoints", []),
                # Storage
                "allocated_storage": cluster.get("AllocatedStorage"),
                "storage_encrypted": cluster.get("StorageEncrypted", False),
                "kms_key_id": cluster.get("KmsKeyId"),
                "storage_type": cluster.get("StorageType"),
                "iops": cluster.get("Iops"),
                # High availability
                "multi_az": cluster.get("MultiAZ", False),
                "availability_zones": cluster.get("AvailabilityZones", []),
                # Cluster members
                "db_cluster_members": [
                    {
                        "db_instance_identifier": member.get("DBInstanceIdentifier"),
                        "is_cluster_writer": member.get("IsClusterWriter", False),
                        "db_cluster_parameter_group_status": member.get(
                            "DBClusterParameterGroupStatus"
                        ),
                        "promotion_tier": member.get("PromotionTier"),
                    }
                    for member in cluster.get("DBClusterMembers", [])
                ],
                # Read replicas
                "read_replica_identifiers": cluster.get("ReadReplicaIdentifiers", []),
                "replication_source_identifier": cluster.get(
                    "ReplicationSourceIdentifier"
                ),
                # Network
                "vpc_security_groups": [
                    {
                        "vpc_security_group_id": sg.get("VpcSecurityGroupId"),
                        "status": sg.get("Status"),
                    }
                    for sg in cluster.get("VpcSecurityGroups", [])
                ],
                "db_subnet_group": cluster.get("DBSubnetGroup"),
                # Backup
                "backup_retention_period": cluster.get("BackupRetentionPeriod", 0),
                "preferred_backup_window": cluster.get("PreferredBackupWindow"),
                "earliest_restorable_time": (
                    cluster["EarliestRestorableTime"].isoformat()
                    if cluster.get("EarliestRestorableTime")
                    else None
                ),
                "latest_restorable_time": (
                    cluster["LatestRestorableTime"].isoformat()
                    if cluster.get("LatestRestorableTime")
                    else None
                ),
                "copy_tags_to_snapshot": cluster.get("CopyTagsToSnapshot", False),
                # Maintenance
                "preferred_maintenance_window": cluster.get("PreferredMaintenanceWindow"),
                # Security
                "iam_database_authentication_enabled": cluster.get(
                    "IAMDatabaseAuthenticationEnabled", False
                ),
                "deletion_protection": cluster.get("DeletionProtection", False),
                "http_endpoint_enabled": cluster.get("HttpEndpointEnabled", False),
                # Parameter group
                "db_cluster_parameter_group": cluster.get("DBClusterParameterGroup"),
                # Cloudwatch logs
                "enabled_cloudwatch_logs_exports": cluster.get(
                    "EnabledCloudwatchLogsExports", []
                ),
                # Global cluster
                "global_write_forwarding_status": cluster.get(
                    "GlobalWriteForwardingStatus"
                ),
                "global_write_forwarding_requested": cluster.get(
                    "GlobalWriteForwardingRequested"
                ),
                # Serverless
                "scaling_configuration_info": cluster.get("ScalingConfigurationInfo"),
                "serverless_v2_scaling_configuration": cluster.get(
                    "ServerlessV2ScalingConfiguration"
                ),
                # Activity stream
                "activity_stream_status": cluster.get("ActivityStreamStatus"),
                "activity_stream_kms_key_id": cluster.get("ActivityStreamKmsKeyId"),
                "activity_stream_kinesis_stream_name": cluster.get(
                    "ActivityStreamKinesisStreamName"
                ),
                "activity_stream_mode": cluster.get("ActivityStreamMode"),
                # Associated roles
                "associated_roles": [
                    {
                        "role_arn": role.get("RoleArn"),
                        "feature_name": role.get("FeatureName"),
                        "status": role.get("Status"),
                    }
                    for role in cluster.get("AssociatedRoles", [])
                ],
                # Timestamps
                "cluster_create_time": (
                    cluster["ClusterCreateTime"].isoformat()
                    if cluster.get("ClusterCreateTime")
                    else None
                ),
                "earliest_backtrack_time": (
                    cluster["EarliestBacktrackTime"].isoformat()
                    if cluster.get("EarliestBacktrackTime")
                    else None
                ),
                "backtrack_window": cluster.get("BacktrackWindow"),
                "backtrack_consumed_change_records": cluster.get(
                    "BacktrackConsumedChangeRecords"
                ),
                # Performance Insights
                "performance_insights_enabled": cluster.get(
                    "PerformanceInsightsEnabled", False
                ),
                "performance_insights_kms_key_id": cluster.get(
                    "PerformanceInsightsKMSKeyId"
                ),
                "performance_insights_retention_period": cluster.get(
                    "PerformanceInsightsRetentionPeriod"
                ),
            }

            asset = Asset(
                id=cluster_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_rds_cluster",
                name=name,
                tags=tags,
                network_exposure=network_exposure,
                created_at=cluster.get("ClusterCreateTime", now),
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_parameter_groups(self) -> list[Asset]:
        """Collect RDS parameter groups."""
        rds = self._get_client("rds")
        assets: list[Asset] = []
        now = self._now()

        for pg in self._paginate(
            rds, "describe_db_parameter_groups", "DBParameterGroups"
        ):
            pg_name = pg["DBParameterGroupName"]
            pg_arn = pg.get("DBParameterGroupArn", "")

            if not pg_arn:
                pg_arn = self._build_arn(
                    "rds",
                    "pg",
                    pg_name,
                    region=self._region,
                    account_id=self.account_id,
                )

            # Get parameter details (limited to important security-related ones)
            parameters = self._get_parameter_group_parameters(pg_name)

            raw_config: dict[str, Any] = {
                "db_parameter_group_name": pg_name,
                "db_parameter_group_family": pg.get("DBParameterGroupFamily"),
                "description": pg.get("Description"),
                "parameters": parameters,
            }

            asset = Asset(
                id=pg_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_rds_parameter_group",
                name=pg_name,
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=now,
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _get_parameter_group_parameters(self, pg_name: str) -> list[dict[str, Any]]:
        """Get security-relevant parameters from a parameter group."""
        rds = self._get_client("rds")

        # Security-relevant parameters to collect
        security_params = [
            "require_secure_transport",
            "rds.force_ssl",
            "ssl",
            "log_statement",
            "log_min_duration_statement",
            "log_connections",
            "log_disconnections",
            "password_encryption",
            "rds.force_admin_logging_level",
            "audit_trail",
            "pgaudit.log",
        ]

        parameters = []
        try:
            for param in self._paginate(
                rds, "describe_db_parameters", "Parameters",
                DBParameterGroupName=pg_name
            ):
                param_name = param.get("ParameterName", "")
                # Only collect security-relevant params to keep data manageable
                if any(sp in param_name.lower() for sp in security_params):
                    parameters.append({
                        "name": param_name,
                        "value": param.get("ParameterValue"),
                        "apply_type": param.get("ApplyType"),
                        "is_modifiable": param.get("IsModifiable", False),
                        "apply_method": param.get("ApplyMethod"),
                    })
        except Exception as e:
            logger.debug(f"Could not get parameters for {pg_name}: {e}")

        return parameters

    def _collect_subnet_groups(self) -> list[Asset]:
        """Collect RDS subnet groups."""
        rds = self._get_client("rds")
        assets: list[Asset] = []
        now = self._now()

        for sg in self._paginate(
            rds, "describe_db_subnet_groups", "DBSubnetGroups"
        ):
            sg_name = sg["DBSubnetGroupName"]
            sg_arn = sg.get("DBSubnetGroupArn", "")

            if not sg_arn:
                sg_arn = self._build_arn(
                    "rds",
                    "subgrp",
                    sg_name,
                    region=self._region,
                    account_id=self.account_id,
                )

            raw_config: dict[str, Any] = {
                "db_subnet_group_name": sg_name,
                "db_subnet_group_description": sg.get("DBSubnetGroupDescription"),
                "vpc_id": sg.get("VpcId"),
                "subnet_group_status": sg.get("SubnetGroupStatus"),
                "subnets": [
                    {
                        "subnet_identifier": subnet.get("SubnetIdentifier"),
                        "subnet_availability_zone": subnet.get(
                            "SubnetAvailabilityZone", {}
                        ).get("Name"),
                        "subnet_outpost": subnet.get("SubnetOutpost"),
                        "subnet_status": subnet.get("SubnetStatus"),
                    }
                    for subnet in sg.get("Subnets", [])
                ],
                "supported_network_types": sg.get("SupportedNetworkTypes", []),
            }

            asset = Asset(
                id=sg_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_rds_subnet_group",
                name=sg_name,
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=now,
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_snapshots(self) -> list[Asset]:
        """Collect RDS DB snapshots."""
        rds = self._get_client("rds")
        assets: list[Asset] = []
        now = self._now()

        # Only collect owned snapshots (not shared/public)
        for snapshot in self._paginate(
            rds, "describe_db_snapshots", "DBSnapshots",
            SnapshotType="manual"
        ):
            snapshot_id = snapshot["DBSnapshotIdentifier"]
            snapshot_arn = snapshot.get("DBSnapshotArn", "")

            if not snapshot_arn:
                snapshot_arn = self._build_arn(
                    "rds",
                    "snapshot",
                    snapshot_id,
                    region=self._region,
                    account_id=self.account_id,
                )

            # Extract tags
            tags = self._extract_rds_tags(snapshot.get("TagList"))
            name = self._get_name_from_tags(tags, snapshot_id)

            # Check if snapshot is shared (potential exposure)
            try:
                snapshot_attrs = rds.describe_db_snapshot_attributes(
                    DBSnapshotIdentifier=snapshot_id
                )
                attrs = snapshot_attrs.get("DBSnapshotAttributesResult", {})
                attr_list = attrs.get("DBSnapshotAttributes", [])

                # Check for public sharing
                is_public = False
                shared_accounts = []
                for attr in attr_list:
                    if attr.get("AttributeName") == "restore":
                        values = attr.get("AttributeValues", [])
                        if "all" in values:
                            is_public = True
                        shared_accounts = [v for v in values if v != "all"]
            except Exception:
                is_public = False
                shared_accounts = []

            # Determine network exposure based on sharing
            network_exposure = (
                NETWORK_EXPOSURE_INTERNET if is_public
                else NETWORK_EXPOSURE_INTERNAL
            )

            raw_config: dict[str, Any] = {
                "db_snapshot_identifier": snapshot_id,
                "db_instance_identifier": snapshot.get("DBInstanceIdentifier"),
                "snapshot_create_time": (
                    snapshot["SnapshotCreateTime"].isoformat()
                    if snapshot.get("SnapshotCreateTime")
                    else None
                ),
                "engine": snapshot.get("Engine"),
                "engine_version": snapshot.get("EngineVersion"),
                "status": snapshot.get("Status"),
                "allocated_storage": snapshot.get("AllocatedStorage"),
                "availability_zone": snapshot.get("AvailabilityZone"),
                "vpc_id": snapshot.get("VpcId"),
                "port": snapshot.get("Port"),
                "master_username": snapshot.get("MasterUsername"),
                "license_model": snapshot.get("LicenseModel"),
                "snapshot_type": snapshot.get("SnapshotType"),
                "iops": snapshot.get("Iops"),
                "storage_type": snapshot.get("StorageType"),
                "storage_throughput": snapshot.get("StorageThroughput"),
                # Encryption
                "encrypted": snapshot.get("Encrypted", False),
                "kms_key_id": snapshot.get("KmsKeyId"),
                # Sharing configuration
                "is_public": is_public,
                "shared_accounts": shared_accounts,
                # Source
                "source_db_snapshot_identifier": snapshot.get(
                    "SourceDBSnapshotIdentifier"
                ),
                "source_region": snapshot.get("SourceRegion"),
                # Instance details
                "tde_credential_arn": snapshot.get("TdeCredentialArn"),
                "original_snapshot_create_time": (
                    snapshot["OriginalSnapshotCreateTime"].isoformat()
                    if snapshot.get("OriginalSnapshotCreateTime")
                    else None
                ),
                "snapshot_database_time": (
                    snapshot["SnapshotDatabaseTime"].isoformat()
                    if snapshot.get("SnapshotDatabaseTime")
                    else None
                ),
                "snapshot_target": snapshot.get("SnapshotTarget"),
            }

            asset = Asset(
                id=snapshot_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_rds_snapshot",
                name=name,
                tags=tags,
                network_exposure=network_exposure,
                created_at=snapshot.get("SnapshotCreateTime", now),
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _extract_rds_tags(
        self, tag_list: list[dict[str, str]] | None
    ) -> dict[str, str]:
        """
        Extract tags from RDS TagList format.

        RDS uses TagList with {"Key": "k", "Value": "v"} format.

        Args:
            tag_list: List of tag dictionaries

        Returns:
            Dictionary of {key: value} pairs
        """
        if not tag_list:
            return {}

        tags = {}
        for tag in tag_list:
            key = tag.get("Key", "")
            value = tag.get("Value", "")
            if key:
                tags[key] = value
        return tags
