"""
Unit tests for DynamoDBCollector.

Tests cover:
- DynamoDB table collection with mocked AWS responses
- Backup collection
- Continuous backup (PITR) configuration
- TTL configuration
- Encryption configuration
- Resource policy and public access detection
- Network exposure determination
- Error handling for AWS access denied scenarios
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from stance.collectors.aws_dynamodb import DynamoDBCollector
from stance.models import AssetCollection, NETWORK_EXPOSURE_INTERNET, NETWORK_EXPOSURE_INTERNAL


class TestDynamoDBCollector:
    """Tests for DynamoDBCollector."""

    def test_dynamodb_collector_init(self):
        """Test DynamoDBCollector can be initialized."""
        collector = DynamoDBCollector()
        assert collector.collector_name == "aws_dynamodb"
        assert "aws_dynamodb_table" in collector.resource_types
        assert "aws_dynamodb_global_table" in collector.resource_types
        assert "aws_dynamodb_backup" in collector.resource_types

    def test_dynamodb_collector_collect_tables(self, mock_dynamodb_client):
        """Test DynamoDB table collection with mock response."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            # Configure paginator for list_tables
            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["prod-orders"]}
            ]

            # Configure describe_table response
            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "prod-orders",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/prod-orders",
                    "TableStatus": "ACTIVE",
                    "TableId": "12345678-1234-1234-1234-123456789012",
                    "CreationDateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                    "KeySchema": [
                        {"AttributeName": "order_id", "KeyType": "HASH"},
                        {"AttributeName": "created_at", "KeyType": "RANGE"},
                    ],
                    "AttributeDefinitions": [
                        {"AttributeName": "order_id", "AttributeType": "S"},
                        {"AttributeName": "created_at", "AttributeType": "N"},
                    ],
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 100,
                        "WriteCapacityUnits": 50,
                    },
                    "TableSizeBytes": 1000000,
                    "ItemCount": 5000,
                    "SSEDescription": {
                        "Status": "ENABLED",
                        "SSEType": "KMS",
                        "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/test-key",
                    },
                    "DeletionProtectionEnabled": True,
                }
            }

            # Configure additional API responses
            mock_dynamodb_client.list_tags_of_resource.return_value = {
                "Tags": [{"Key": "Environment", "Value": "prod"}]
            }
            mock_dynamodb_client.describe_continuous_backups.return_value = {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED",
                    },
                }
            }
            mock_dynamodb_client.describe_time_to_live.return_value = {
                "TimeToLiveDescription": {
                    "TimeToLiveStatus": "ENABLED",
                    "AttributeName": "expiration_time",
                }
            }
            mock_dynamodb_client.describe_contributor_insights.return_value = {
                "ContributorInsightsStatus": "ENABLED",
            }

            # No resource policy
            mock_dynamodb_client.exceptions = MagicMock()
            mock_dynamodb_client.exceptions.PolicyNotFoundException = Exception
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            assert table.name == "prod-orders"
            assert table.network_exposure == NETWORK_EXPOSURE_INTERNAL
            assert table.raw_config["encryption_enabled"] is True
            assert table.raw_config["deletion_protection_enabled"] is True
            assert table.tags.get("Environment") == "prod"

    def test_dynamodb_collector_encryption_types(self, mock_dynamodb_client):
        """Test detection of different encryption configurations."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["encrypted-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "encrypted-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/encrypted-table",
                    "TableStatus": "ACTIVE",
                    "SSEDescription": {
                        "Status": "ENABLED",
                        "SSEType": "KMS",
                        "KMSMasterKeyArn": "arn:aws:kms:us-east-1:123456789012:key/custom-key",
                    },
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            assert table.raw_config["encryption_enabled"] is True
            assert table.raw_config["encryption_type"] == "KMS"
            assert "custom-key" in table.raw_config["kms_key_arn"]

    def test_dynamodb_collector_pitr_enabled(self, mock_dynamodb_client):
        """Test detection of point-in-time recovery configuration."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["pitr-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "pitr-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/pitr-table",
                    "TableStatus": "ACTIVE",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {
                "ContinuousBackupsDescription": {
                    "ContinuousBackupsStatus": "ENABLED",
                    "PointInTimeRecoveryDescription": {
                        "PointInTimeRecoveryStatus": "ENABLED",
                        "EarliestRestorableDateTime": "2024-01-01T00:00:00Z",
                        "LatestRestorableDateTime": "2024-01-15T12:00:00Z",
                    },
                }
            }
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            pitr = table.raw_config["continuous_backups"]
            assert pitr["point_in_time_recovery_status"] == "ENABLED"

    def test_dynamodb_collector_ttl_config(self, mock_dynamodb_client):
        """Test detection of TTL configuration."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["ttl-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "ttl-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/ttl-table",
                    "TableStatus": "ACTIVE",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {
                "TimeToLiveDescription": {
                    "TimeToLiveStatus": "ENABLED",
                    "AttributeName": "expiry",
                }
            }
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            ttl = table.raw_config["ttl_config"]
            assert ttl["time_to_live_status"] == "ENABLED"
            assert ttl["attribute_name"] == "expiry"

    def test_dynamodb_collector_public_resource_policy(self, mock_dynamodb_client):
        """Test detection of public resource policy."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["public-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "public-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/public-table",
                    "TableStatus": "ACTIVE",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}

            # Public resource policy with Principal: "*"
            import json
            mock_dynamodb_client.get_resource_policy.return_value = {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "dynamodb:GetItem",
                            "Resource": "*"
                        }
                    ]
                })
            }

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            assert table.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_dynamodb_collector_private_resource_policy(self, mock_dynamodb_client):
        """Test detection of private resource policy (AWS account principal)."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["private-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "private-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/private-table",
                    "TableStatus": "ACTIVE",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}

            # Resource policy with specific AWS account principal
            import json
            mock_dynamodb_client.get_resource_policy.return_value = {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                            "Action": "dynamodb:GetItem",
                            "Resource": "*"
                        }
                    ]
                })
            }

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            assert table.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_dynamodb_collector_collect_backups(self, mock_dynamodb_client):
        """Test DynamoDB backup collection."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            # Configure paginator for tables (empty)
            def get_paginator_side_effect(method_name):
                mock_paginator = MagicMock()
                if method_name == "list_tables":
                    mock_paginator.paginate.return_value = [{"TableNames": []}]
                elif method_name == "list_backups":
                    mock_paginator.paginate.return_value = [{
                        "BackupSummaries": [
                            {
                                "TableName": "prod-orders",
                                "BackupArn": "arn:aws:dynamodb:us-east-1:123456789012:table/prod-orders/backup/01234567890123-abcdefgh",
                                "BackupName": "prod-orders-backup",
                                "BackupCreationDateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                                "BackupStatus": "AVAILABLE",
                                "BackupType": "USER",
                                "BackupSizeBytes": 1000000,
                            }
                        ]
                    }]
                else:
                    mock_paginator.paginate.return_value = [{}]
                return mock_paginator

            mock_dynamodb_client.get_paginator.side_effect = get_paginator_side_effect

            mock_dynamodb_client.describe_backup.return_value = {
                "BackupDescription": {
                    "BackupDetails": {
                        "BackupArn": "arn:aws:dynamodb:us-east-1:123456789012:table/prod-orders/backup/01234567890123-abcdefgh",
                        "BackupName": "prod-orders-backup",
                        "BackupStatus": "AVAILABLE",
                        "BackupType": "USER",
                        "BackupSizeBytes": 1000000,
                    },
                    "SourceTableDetails": {
                        "TableName": "prod-orders",
                        "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/prod-orders",
                        "TableSizeBytes": 1000000,
                        "ItemCount": 5000,
                    },
                }
            }

            assets = collector.collect()

            backup_assets = [a for a in assets if a.resource_type == "aws_dynamodb_backup"]
            assert len(backup_assets) == 1

            backup = backup_assets[0]
            assert backup.name == "prod-orders-backup"
            assert backup.raw_config["backup_status"] == "AVAILABLE"
            assert backup.raw_config["source_table_name"] == "prod-orders"

    def test_dynamodb_collector_handles_access_denied(self, mock_dynamodb_client):
        """Test graceful handling of AccessDenied errors."""
        from botocore.exceptions import ClientError

        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
                "ListTables"
            )

            # Should handle gracefully and return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_dynamodb_collector_handles_api_errors(self, mock_dynamodb_client):
        """Test graceful handling when describe_table fails."""
        from botocore.exceptions import ClientError

        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["failing-table"]}
            ]

            mock_dynamodb_client.describe_table.side_effect = ClientError(
                {"Error": {"Code": "ResourceNotFoundException", "Message": "Table not found"}},
                "DescribeTable"
            )

            # Should handle gracefully
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)
            # The failing table should be skipped
            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 0

    def test_dynamodb_collector_global_secondary_indexes(self, mock_dynamodb_client):
        """Test collection of GSI configuration."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["gsi-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "gsi-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/gsi-table",
                    "TableStatus": "ACTIVE",
                    "GlobalSecondaryIndexes": [
                        {
                            "IndexName": "user-email-index",
                            "KeySchema": [
                                {"AttributeName": "email", "KeyType": "HASH"}
                            ],
                            "Projection": {"ProjectionType": "ALL"},
                            "IndexStatus": "ACTIVE",
                            "ProvisionedThroughput": {
                                "ReadCapacityUnits": 50,
                                "WriteCapacityUnits": 25,
                            },
                        }
                    ],
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            gsis = table.raw_config["global_secondary_indexes"]
            assert len(gsis) == 1
            assert gsis[0]["index_name"] == "user-email-index"
            assert gsis[0]["index_status"] == "ACTIVE"

    def test_dynamodb_collector_stream_configuration(self, mock_dynamodb_client):
        """Test collection of DynamoDB stream configuration."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["stream-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "stream-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/stream-table",
                    "TableStatus": "ACTIVE",
                    "StreamSpecification": {
                        "StreamEnabled": True,
                        "StreamViewType": "NEW_AND_OLD_IMAGES",
                    },
                    "LatestStreamArn": "arn:aws:dynamodb:us-east-1:123456789012:table/stream-table/stream/2024-01-01T00:00:00.000",
                    "LatestStreamLabel": "2024-01-01T00:00:00.000",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {"Tags": []}
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            stream = table.raw_config["stream_specification"]
            assert stream["stream_enabled"] is True
            assert stream["stream_view_type"] == "NEW_AND_OLD_IMAGES"
            assert table.raw_config["latest_stream_arn"] is not None

    def test_dynamodb_collector_tags_extraction(self, mock_dynamodb_client):
        """Test proper extraction of table tags."""
        with patch.object(DynamoDBCollector, "_get_client", return_value=mock_dynamodb_client):
            collector = DynamoDBCollector()

            mock_paginator = MagicMock()
            mock_dynamodb_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {"TableNames": ["tagged-table"]}
            ]

            mock_dynamodb_client.describe_table.return_value = {
                "Table": {
                    "TableName": "tagged-table",
                    "TableArn": "arn:aws:dynamodb:us-east-1:123456789012:table/tagged-table",
                    "TableStatus": "ACTIVE",
                }
            }

            mock_dynamodb_client.list_tags_of_resource.return_value = {
                "Tags": [
                    {"Key": "Name", "Value": "My Tagged Table"},
                    {"Key": "Environment", "Value": "production"},
                    {"Key": "Team", "Value": "platform"},
                    {"Key": "CostCenter", "Value": "12345"},
                ]
            }
            mock_dynamodb_client.describe_continuous_backups.return_value = {}
            mock_dynamodb_client.describe_time_to_live.return_value = {}
            mock_dynamodb_client.describe_contributor_insights.return_value = {}
            mock_dynamodb_client.get_resource_policy.side_effect = Exception("PolicyNotFoundException")

            assets = collector.collect()

            table_assets = [a for a in assets if a.resource_type == "aws_dynamodb_table"]
            assert len(table_assets) == 1

            table = table_assets[0]
            assert table.name == "My Tagged Table"  # Should use Name tag
            assert table.tags["Environment"] == "production"
            assert table.tags["Team"] == "platform"
            assert table.tags["CostCenter"] == "12345"


@pytest.fixture
def mock_dynamodb_client():
    """Create a mock DynamoDB client."""
    mock = MagicMock()
    mock.exceptions = MagicMock()
    mock.exceptions.PolicyNotFoundException = Exception
    return mock
