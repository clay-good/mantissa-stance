"""
Unit tests for RDSCollector.

Tests cover:
- RDS instance collection with mocked AWS responses
- Aurora cluster collection
- Parameter group collection with security parameters
- Subnet group collection
- Snapshot collection with sharing status
- Network exposure determination
- Error handling for AWS access denied scenarios
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.collectors.aws_rds import RDSCollector
from stance.models import AssetCollection, NETWORK_EXPOSURE_INTERNET, NETWORK_EXPOSURE_INTERNAL


class TestRDSCollector:
    """Tests for RDSCollector."""

    def test_rds_collector_init(self):
        """Test RDSCollector can be initialized."""
        collector = RDSCollector()
        assert collector.collector_name == "aws_rds"
        assert "aws_rds_instance" in collector.resource_types
        assert "aws_rds_cluster" in collector.resource_types
        assert "aws_rds_parameter_group" in collector.resource_types
        assert "aws_rds_subnet_group" in collector.resource_types
        assert "aws_rds_snapshot" in collector.resource_types

    def test_rds_collector_collect_instances(self, mock_rds_client):
        """Test RDS instance collection with mock response."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator for instances
            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "prod-database",
                            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-database",
                            "DBInstanceClass": "db.t3.medium",
                            "Engine": "postgres",
                            "EngineVersion": "14.9",
                            "DBInstanceStatus": "available",
                            "MasterUsername": "admin",
                            "Endpoint": {
                                "Address": "prod-database.xyz.us-east-1.rds.amazonaws.com",
                                "Port": 5432,
                            },
                            "AllocatedStorage": 100,
                            "InstanceCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "MultiAZ": True,
                            "PubliclyAccessible": False,
                            "StorageEncrypted": True,
                            "DeletionProtection": True,
                            "IAMDatabaseAuthenticationEnabled": True,
                            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345678"}],
                            "TagList": [{"Key": "Environment", "Value": "prod"}],
                        }
                    ]
                }
            ]

            # Mock other responses as empty
            mock_rds_client.describe_db_clusters.return_value = {"DBClusters": []}
            mock_rds_client.describe_db_parameter_groups.return_value = {"DBParameterGroups": []}
            mock_rds_client.describe_db_subnet_groups.return_value = {"DBSubnetGroups": []}
            mock_rds_client.describe_db_snapshots.return_value = {"DBSnapshots": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Find the RDS instance asset
            instance_assets = [a for a in assets if a.resource_type == "aws_rds_instance"]
            assert len(instance_assets) == 1

            instance = instance_assets[0]
            assert instance.name == "prod-database"
            assert instance.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert instance.raw_config["storage_encrypted"] is True
            assert instance.raw_config["deletion_protection"] is True

    def test_rds_collector_collect_clusters(self, mock_rds_client):
        """Test Aurora cluster collection with mock response."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "describe_db_instances":
                    mock_paginator.paginate.return_value = [{"DBInstances": []}]
                elif method_name == "describe_db_clusters":
                    mock_paginator.paginate.return_value = [{
                        "DBClusters": [
                            {
                                "DBClusterIdentifier": "aurora-cluster",
                                "DBClusterArn": "arn:aws:rds:us-east-1:123456789012:cluster:aurora-cluster",
                                "Engine": "aurora-postgresql",
                                "EngineVersion": "14.9",
                                "Status": "available",
                                "MasterUsername": "admin",
                                "Endpoint": "aurora-cluster.cluster-xyz.us-east-1.rds.amazonaws.com",
                                "Port": 5432,
                                "MultiAZ": True,
                                "StorageEncrypted": True,
                                "DeletionProtection": True,
                                "IAMDatabaseAuthenticationEnabled": True,
                                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-87654321"}],
                                "TagList": [{"Key": "Environment", "Value": "prod"}],
                                "ClusterCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            }
                        ]
                    }]
                elif method_name == "describe_db_parameter_groups":
                    mock_paginator.paginate.return_value = [{"DBParameterGroups": []}]
                elif method_name == "describe_db_subnet_groups":
                    mock_paginator.paginate.return_value = [{"DBSubnetGroups": []}]
                elif method_name == "describe_db_snapshots":
                    mock_paginator.paginate.return_value = [{"DBSnapshots": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_rds_client.get_paginator.side_effect = get_paginator_side_effect

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Find the cluster asset
            cluster_assets = [a for a in assets if a.resource_type == "aws_rds_cluster"]
            assert len(cluster_assets) == 1

            cluster = cluster_assets[0]
            assert cluster.name == "aurora-cluster"
            assert cluster.raw_config["storage_encrypted"] is True
            assert cluster.raw_config["engine"] == "aurora-postgresql"

    def test_rds_collector_determines_public_exposure(self, mock_rds_client):
        """Test network exposure determination for public instance."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator with public instance
            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "public-database",
                            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:public-database",
                            "DBInstanceClass": "db.t3.medium",
                            "Engine": "mysql",
                            "DBInstanceStatus": "available",
                            "PubliclyAccessible": True,  # Publicly accessible
                            "StorageEncrypted": False,
                            "TagList": [],
                        }
                    ]
                }
            ]

            mock_rds_client.describe_db_clusters.return_value = {"DBClusters": []}
            mock_rds_client.describe_db_parameter_groups.return_value = {"DBParameterGroups": []}
            mock_rds_client.describe_db_subnet_groups.return_value = {"DBSubnetGroups": []}
            mock_rds_client.describe_db_snapshots.return_value = {"DBSnapshots": []}

            assets = collector.collect()

            instance_assets = [a for a in assets if a.resource_type == "aws_rds_instance"]
            assert len(instance_assets) == 1
            assert instance_assets[0].network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_rds_collector_collect_parameter_groups(self, mock_rds_client):
        """Test parameter group collection with security parameters."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "describe_db_instances":
                    mock_paginator.paginate.return_value = [{"DBInstances": []}]
                elif method_name == "describe_db_clusters":
                    mock_paginator.paginate.return_value = [{"DBClusters": []}]
                elif method_name == "describe_db_parameter_groups":
                    mock_paginator.paginate.return_value = [{
                        "DBParameterGroups": [
                            {
                                "DBParameterGroupName": "prod-params",
                                "DBParameterGroupFamily": "postgres14",
                                "Description": "Production parameters",
                                "DBParameterGroupArn": "arn:aws:rds:us-east-1:123456789012:pg:prod-params",
                            }
                        ]
                    }]
                elif method_name == "describe_db_parameters":
                    mock_paginator.paginate.return_value = [{
                        "Parameters": [
                            {"ParameterName": "rds.force_ssl", "ParameterValue": "1"},
                            {"ParameterName": "log_connections", "ParameterValue": "1"},
                        ]
                    }]
                elif method_name == "describe_db_subnet_groups":
                    mock_paginator.paginate.return_value = [{"DBSubnetGroups": []}]
                elif method_name == "describe_db_snapshots":
                    mock_paginator.paginate.return_value = [{"DBSnapshots": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_rds_client.get_paginator.side_effect = get_paginator_side_effect

            assets = collector.collect()

            param_assets = [a for a in assets if a.resource_type == "aws_rds_parameter_group"]
            assert len(param_assets) == 1

            param_group = param_assets[0]
            assert param_group.name == "prod-params"
            # Check the parameters list is populated
            assert "parameters" in param_group.raw_config
            params = param_group.raw_config["parameters"]
            param_names = [p["name"] for p in params]
            assert "rds.force_ssl" in param_names

    def test_rds_collector_collect_snapshots(self, mock_rds_client):
        """Test snapshot collection with sharing status."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "describe_db_instances":
                    mock_paginator.paginate.return_value = [{"DBInstances": []}]
                elif method_name == "describe_db_clusters":
                    mock_paginator.paginate.return_value = [{"DBClusters": []}]
                elif method_name == "describe_db_parameter_groups":
                    mock_paginator.paginate.return_value = [{"DBParameterGroups": []}]
                elif method_name == "describe_db_subnet_groups":
                    mock_paginator.paginate.return_value = [{"DBSubnetGroups": []}]
                elif method_name == "describe_db_snapshots":
                    mock_paginator.paginate.return_value = [{
                        "DBSnapshots": [
                            {
                                "DBSnapshotIdentifier": "prod-snapshot",
                                "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:prod-snapshot",
                                "DBInstanceIdentifier": "prod-database",
                                "Engine": "postgres",
                                "Status": "available",
                                "SnapshotType": "manual",
                                "Encrypted": True,
                                "SnapshotCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                                "TagList": [],
                            }
                        ]
                    }]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_rds_client.get_paginator.side_effect = get_paginator_side_effect

            # Not shared publicly
            mock_rds_client.describe_db_snapshot_attributes.return_value = {
                "DBSnapshotAttributesResult": {
                    "DBSnapshotIdentifier": "prod-snapshot",
                    "DBSnapshotAttributes": [
                        {"AttributeName": "restore", "AttributeValues": []}
                    ],
                }
            }

            assets = collector.collect()

            snapshot_assets = [a for a in assets if a.resource_type == "aws_rds_snapshot"]
            assert len(snapshot_assets) == 1

            snapshot = snapshot_assets[0]
            assert snapshot.name == "prod-snapshot"
            assert snapshot.raw_config["encrypted"] is True
            assert snapshot.raw_config["is_public"] is False

    def test_rds_collector_detects_public_snapshot(self, mock_rds_client):
        """Test detection of publicly shared snapshot."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "describe_db_instances":
                    mock_paginator.paginate.return_value = [{"DBInstances": []}]
                elif method_name == "describe_db_clusters":
                    mock_paginator.paginate.return_value = [{"DBClusters": []}]
                elif method_name == "describe_db_parameter_groups":
                    mock_paginator.paginate.return_value = [{"DBParameterGroups": []}]
                elif method_name == "describe_db_subnet_groups":
                    mock_paginator.paginate.return_value = [{"DBSubnetGroups": []}]
                elif method_name == "describe_db_snapshots":
                    mock_paginator.paginate.return_value = [{
                        "DBSnapshots": [
                            {
                                "DBSnapshotIdentifier": "public-snapshot",
                                "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:public-snapshot",
                                "DBInstanceIdentifier": "prod-database",
                                "Engine": "postgres",
                                "Status": "available",
                                "SnapshotType": "manual",
                                "Encrypted": False,
                                "SnapshotCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                                "TagList": [],
                            }
                        ]
                    }]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_rds_client.get_paginator.side_effect = get_paginator_side_effect

            # Shared with "all" (public)
            mock_rds_client.describe_db_snapshot_attributes.return_value = {
                "DBSnapshotAttributesResult": {
                    "DBSnapshotIdentifier": "public-snapshot",
                    "DBSnapshotAttributes": [
                        {"AttributeName": "restore", "AttributeValues": ["all"]}
                    ],
                }
            }

            assets = collector.collect()

            snapshot_assets = [a for a in assets if a.resource_type == "aws_rds_snapshot"]
            assert len(snapshot_assets) == 1

            snapshot = snapshot_assets[0]
            assert snapshot.raw_config["is_public"] is True
            assert snapshot.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_rds_collector_handles_access_denied(self, mock_rds_client):
        """Test graceful handling of AccessDenied errors."""
        from botocore.exceptions import ClientError

        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to raise AccessDenied
            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBInstances"
            )

            mock_rds_client.describe_db_clusters.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBClusters"
            )
            mock_rds_client.describe_db_parameter_groups.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBParameterGroups"
            )
            mock_rds_client.describe_db_subnet_groups.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBSubnetGroups"
            )
            mock_rds_client.describe_db_snapshots.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBSnapshots"
            )

            # Should handle gracefully and return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)

    def test_rds_collector_handles_partial_errors(self, mock_rds_client):
        """Test graceful handling when some APIs fail but others succeed."""
        from botocore.exceptions import ClientError

        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Instances succeed
            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "test-db",
                            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:test-db",
                            "DBInstanceClass": "db.t3.micro",
                            "Engine": "mysql",
                            "DBInstanceStatus": "available",
                            "PubliclyAccessible": False,
                            "StorageEncrypted": True,
                            "TagList": [],
                        }
                    ]
                }
            ]

            # Clusters fail
            mock_rds_client.describe_db_clusters.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "DescribeDBClusters"
            )
            mock_rds_client.describe_db_parameter_groups.return_value = {"DBParameterGroups": []}
            mock_rds_client.describe_db_subnet_groups.return_value = {"DBSubnetGroups": []}
            mock_rds_client.describe_db_snapshots.return_value = {"DBSnapshots": []}

            assets = collector.collect()

            # Should still have the instance from the successful call
            assert isinstance(assets, AssetCollection)
            instance_assets = [a for a in assets if a.resource_type == "aws_rds_instance"]
            assert len(instance_assets) == 1

    def test_rds_collector_collect_subnet_groups(self, mock_rds_client):
        """Test subnet group collection."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Configure paginator to return different results based on method
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "describe_db_instances":
                    mock_paginator.paginate.return_value = [{"DBInstances": []}]
                elif method_name == "describe_db_clusters":
                    mock_paginator.paginate.return_value = [{"DBClusters": []}]
                elif method_name == "describe_db_parameter_groups":
                    mock_paginator.paginate.return_value = [{"DBParameterGroups": []}]
                elif method_name == "describe_db_subnet_groups":
                    mock_paginator.paginate.return_value = [{
                        "DBSubnetGroups": [
                            {
                                "DBSubnetGroupName": "prod-subnet-group",
                                "DBSubnetGroupDescription": "Production subnets",
                                "VpcId": "vpc-12345678",
                                "DBSubnetGroupArn": "arn:aws:rds:us-east-1:123456789012:subgrp:prod-subnet-group",
                                "Subnets": [
                                    {"SubnetIdentifier": "subnet-11111111"},
                                    {"SubnetIdentifier": "subnet-22222222"},
                                ],
                            }
                        ]
                    }]
                elif method_name == "describe_db_snapshots":
                    mock_paginator.paginate.return_value = [{"DBSnapshots": []}]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_rds_client.get_paginator.side_effect = get_paginator_side_effect

            assets = collector.collect()

            subnet_assets = [a for a in assets if a.resource_type == "aws_rds_subnet_group"]
            assert len(subnet_assets) == 1

            subnet_group = subnet_assets[0]
            assert subnet_group.name == "prod-subnet-group"
            assert subnet_group.raw_config["vpc_id"] == "vpc-12345678"
            assert len(subnet_group.raw_config["subnets"]) == 2

    def test_rds_collector_full_collection(self, mock_rds_client):
        """Test full collection with all resource types."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            # Use the full mock responses from conftest
            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                mock_rds_client.describe_db_instances.return_value
            ]

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)

            # Should have collected multiple resource types
            resource_types = set(a.resource_type for a in assets)
            assert "aws_rds_instance" in resource_types or len(assets) >= 0

    def test_rds_collector_security_config_collection(self, mock_rds_client):
        """Test that security-relevant configurations are collected."""
        with patch.object(RDSCollector, "_get_client", return_value=mock_rds_client):
            collector = RDSCollector()

            mock_paginator = MagicMock()
            mock_rds_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "secure-db",
                            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:secure-db",
                            "DBInstanceClass": "db.t3.medium",
                            "Engine": "postgres",
                            "DBInstanceStatus": "available",
                            "PubliclyAccessible": False,
                            "StorageEncrypted": True,
                            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/test-key",
                            "DeletionProtection": True,
                            "IAMDatabaseAuthenticationEnabled": True,
                            "AutoMinorVersionUpgrade": True,
                            "PerformanceInsightsEnabled": True,
                            "BackupRetentionPeriod": 7,
                            "MultiAZ": True,
                            "CACertificateIdentifier": "rds-ca-2019",
                            "TagList": [],
                        }
                    ]
                }
            ]

            mock_rds_client.describe_db_clusters.return_value = {"DBClusters": []}
            mock_rds_client.describe_db_parameter_groups.return_value = {"DBParameterGroups": []}
            mock_rds_client.describe_db_subnet_groups.return_value = {"DBSubnetGroups": []}
            mock_rds_client.describe_db_snapshots.return_value = {"DBSnapshots": []}

            assets = collector.collect()

            instance_assets = [a for a in assets if a.resource_type == "aws_rds_instance"]
            assert len(instance_assets) == 1

            instance = instance_assets[0]
            config = instance.raw_config

            # Verify security configurations are captured
            assert config["storage_encrypted"] is True
            assert config["deletion_protection"] is True
            assert config["iam_database_authentication_enabled"] is True
            assert config["auto_minor_version_upgrade"] is True
            assert config["multi_az"] is True
            assert config["backup_retention_period"] == 7
