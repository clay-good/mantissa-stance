"""
Pytest configuration and fixtures for Mantissa Stance tests.

This module provides common fixtures used across unit and integration tests.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

from stance.models import (
    Asset,
    AssetCollection,
    Finding,
    FindingCollection,
    FindingType,
    Severity,
    FindingStatus,
    Policy,
    PolicyCollection,
    Check,
    CheckType,
    ComplianceMapping,
    Remediation,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)
from stance.storage import LocalStorage


# Sample data fixtures


@pytest.fixture
def sample_asset() -> Asset:
    """Return a sample Asset for testing."""
    return Asset(
        id="arn:aws:s3:::test-bucket",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        name="test-bucket",
        tags={"Environment": "test", "Team": "security"},
        network_exposure=NETWORK_EXPOSURE_INTERNAL,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        raw_config={
            "encryption": {"enabled": True},
            "versioning": {"status": "Enabled"},
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
            },
        },
    )


@pytest.fixture
def sample_internet_facing_asset() -> Asset:
    """Return an internet-facing Asset for testing."""
    return Asset(
        id="arn:aws:s3:::public-bucket",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_s3_bucket",
        name="public-bucket",
        tags={"Environment": "prod"},
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        raw_config={
            "encryption": {"enabled": False},
            "public_access_block": {
                "block_public_acls": False,
                "block_public_policy": False,
            },
        },
    )


@pytest.fixture
def sample_ec2_asset() -> Asset:
    """Return a sample EC2 instance Asset for testing."""
    return Asset(
        id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        cloud_provider="aws",
        account_id="123456789012",
        region="us-east-1",
        resource_type="aws_ec2_instance",
        name="web-server-1",
        tags={"Name": "web-server-1", "Environment": "prod"},
        network_exposure=NETWORK_EXPOSURE_INTERNET,
        created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        raw_config={
            "instance_type": "t3.medium",
            "public_ip": "203.0.113.1",
            "security_groups": ["sg-12345678"],
        },
    )


@pytest.fixture
def asset_collection(
    sample_asset: Asset,
    sample_internet_facing_asset: Asset,
    sample_ec2_asset: Asset,
) -> AssetCollection:
    """Return an AssetCollection with multiple assets."""
    return AssetCollection([
        sample_asset,
        sample_internet_facing_asset,
        sample_ec2_asset,
    ])


@pytest.fixture
def sample_finding() -> Finding:
    """Return a sample Finding for testing."""
    return Finding(
        id="finding-001",
        asset_id="arn:aws:s3:::test-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.HIGH,
        status=FindingStatus.OPEN,
        title="S3 bucket encryption disabled",
        description="The S3 bucket does not have server-side encryption enabled.",
        first_seen=datetime(2024, 1, 10, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        rule_id="aws-s3-001",
        resource_path="encryption.enabled",
        expected_value="true",
        actual_value="false",
        compliance_frameworks=["CIS 2.1.1", "PCI-DSS 3.4"],
        remediation_guidance="Enable server-side encryption on the S3 bucket.",
    )


@pytest.fixture
def sample_vulnerability_finding() -> Finding:
    """Return a sample vulnerability Finding for testing."""
    return Finding(
        id="vuln-001",
        asset_id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        finding_type=FindingType.VULNERABILITY,
        severity=Severity.CRITICAL,
        status=FindingStatus.OPEN,
        title="CVE-2024-0001: Critical RCE vulnerability",
        description="A critical remote code execution vulnerability in package xyz.",
        first_seen=datetime(2024, 1, 12, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
        cve_id="CVE-2024-0001",
        cvss_score=9.8,
        package_name="xyz-package",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        remediation_guidance="Update xyz-package to version 1.0.1 or later.",
    )


@pytest.fixture
def finding_collection(
    sample_finding: Finding,
    sample_vulnerability_finding: Finding,
) -> FindingCollection:
    """Return a FindingCollection with multiple findings."""
    medium_finding = Finding(
        id="finding-002",
        asset_id="arn:aws:s3:::test-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        status=FindingStatus.OPEN,
        title="S3 bucket versioning disabled",
        description="The S3 bucket does not have versioning enabled.",
        rule_id="aws-s3-002",
    )

    resolved_finding = Finding(
        id="finding-003",
        asset_id="arn:aws:s3:::test-bucket",
        finding_type=FindingType.MISCONFIGURATION,
        severity=Severity.LOW,
        status=FindingStatus.RESOLVED,
        title="S3 bucket logging disabled",
        description="The S3 bucket does not have access logging enabled.",
        rule_id="aws-s3-003",
    )

    return FindingCollection([
        sample_finding,
        sample_vulnerability_finding,
        medium_finding,
        resolved_finding,
    ])


@pytest.fixture
def sample_policy() -> Policy:
    """Return a sample Policy for testing."""
    return Policy(
        id="aws-s3-001",
        name="S3 Bucket Encryption",
        description="Ensure S3 buckets have encryption enabled.",
        enabled=True,
        severity=Severity.HIGH,
        resource_type="aws_s3_bucket",
        check=Check(
            check_type=CheckType.EXPRESSION,
            expression="resource.encryption.enabled == true",
        ),
        compliance=[
            ComplianceMapping(
                framework="cis-aws-foundations",
                version="1.5.0",
                control="2.1.1",
            ),
            ComplianceMapping(
                framework="pci-dss",
                version="4.0",
                control="3.4",
            ),
        ],
        remediation=Remediation(
            guidance="Enable server-side encryption on the S3 bucket.",
            automation_supported=False,
        ),
        tags=["s3", "encryption", "storage"],
        references=["https://docs.aws.amazon.com/s3/"],
    )


@pytest.fixture
def sample_policy_yaml() -> str:
    """Return sample policy YAML string."""
    return """
id: aws-s3-001
name: S3 Bucket Encryption
description: Ensure S3 buckets have encryption enabled.
enabled: true
severity: high
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
compliance:
  - framework: cis-aws-foundations
    version: "1.5.0"
    control: "2.1.1"
remediation:
  guidance: Enable server-side encryption on the S3 bucket.
  automation_supported: false
tags:
  - s3
  - encryption
references:
  - https://docs.aws.amazon.com/s3/
"""


@pytest.fixture
def policy_collection(sample_policy: Policy) -> PolicyCollection:
    """Return a PolicyCollection with multiple policies."""
    policy2 = Policy(
        id="aws-s3-002",
        name="S3 Bucket Versioning",
        description="Ensure S3 buckets have versioning enabled.",
        enabled=True,
        severity=Severity.MEDIUM,
        resource_type="aws_s3_bucket",
        check=Check(
            check_type=CheckType.EXPRESSION,
            expression="resource.versioning.status == 'Enabled'",
        ),
        compliance=[],
        remediation=Remediation(
            guidance="Enable versioning on the S3 bucket.",
            automation_supported=False,
        ),
        tags=["s3", "versioning"],
        references=[],
    )

    return PolicyCollection([sample_policy, policy2])


# Storage fixtures


@pytest.fixture
def local_storage(tmp_path) -> Generator[LocalStorage, None, None]:
    """Return a LocalStorage using a temporary directory."""
    db_path = str(tmp_path / "test_stance.db")
    storage = LocalStorage(db_path=db_path)
    yield storage


@pytest.fixture
def populated_storage(
    local_storage: LocalStorage,
    asset_collection: AssetCollection,
    finding_collection: FindingCollection,
) -> LocalStorage:
    """Return a LocalStorage populated with test data."""
    snapshot_id = "20240115-120000"
    local_storage.store_assets(asset_collection, snapshot_id)
    local_storage.store_findings(finding_collection, snapshot_id)
    return local_storage


# Mock fixtures for AWS services


@pytest.fixture
def mock_boto_session():
    """Return a mocked boto3 session."""
    with patch("boto3.Session") as mock_session:
        session = MagicMock()
        mock_session.return_value = session
        yield session


@pytest.fixture
def mock_iam_client(mock_boto_session):
    """Return a mocked IAM client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    # Sample IAM responses
    client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
            "MinimumPasswordLength": 14,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "RequireUppercaseCharacters": True,
            "RequireLowercaseCharacters": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        }
    }

    client.get_account_summary.return_value = {
        "SummaryMap": {
            "Users": 10,
            "Roles": 5,
            "Policies": 20,
            "AccountMFAEnabled": 1,
        }
    }

    client.list_users.return_value = {
        "Users": [
            {
                "UserName": "test-user",
                "UserId": "AIDATEST123",
                "Arn": "arn:aws:iam::123456789012:user/test-user",
                "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
            }
        ]
    }

    return client


@pytest.fixture
def mock_s3_client(mock_boto_session):
    """Return a mocked S3 client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "test-bucket", "CreationDate": datetime(2024, 1, 1)},
            {"Name": "prod-bucket", "CreationDate": datetime(2024, 1, 2)},
        ]
    }

    client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

    client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
            ]
        }
    }

    client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    return client


@pytest.fixture
def mock_ec2_client(mock_boto_session):
    """Return a mocked EC2 client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    client.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1234567890abcdef0",
                        "InstanceType": "t3.medium",
                        "State": {"Name": "running"},
                        "PublicIpAddress": "203.0.113.1",
                        "PrivateIpAddress": "10.0.1.100",
                        "VpcId": "vpc-12345678",
                        "SubnetId": "subnet-12345678",
                        "SecurityGroups": [{"GroupId": "sg-12345678"}],
                        "Tags": [{"Key": "Name", "Value": "web-server-1"}],
                    }
                ]
            }
        ]
    }

    client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-12345678",
                "GroupName": "web-sg",
                "VpcId": "vpc-12345678",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            }
        ]
    }

    return client


@pytest.fixture
def mock_rds_client(mock_boto_session):
    """Return a mocked RDS client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    # Sample RDS instance response
    client.describe_db_instances.return_value = {
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
                    "Address": "prod-database.cluster-xyz.us-east-1.rds.amazonaws.com",
                    "Port": 5432,
                },
                "AllocatedStorage": 100,
                "InstanceCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "AvailabilityZone": "us-east-1a",
                "MultiAZ": True,
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
                "DeletionProtection": True,
                "IAMDatabaseAuthenticationEnabled": True,
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-12345678", "Status": "active"}],
                "DBSubnetGroup": {"DBSubnetGroupName": "prod-subnet-group"},
                "DBParameterGroups": [{"DBParameterGroupName": "prod-params", "ParameterApplyStatus": "in-sync"}],
                "TagList": [{"Key": "Environment", "Value": "prod"}],
            }
        ]
    }

    # Sample RDS cluster response
    client.describe_db_clusters.return_value = {
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
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/def-456",
                "DeletionProtection": True,
                "IAMDatabaseAuthenticationEnabled": True,
                "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-87654321", "Status": "active"}],
                "DBSubnetGroup": "aurora-subnet-group",
                "DBClusterParameterGroup": "aurora-params",
                "TagList": [{"Key": "Environment", "Value": "prod"}],
                "ClusterCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
            }
        ]
    }

    # Sample parameter groups response
    client.describe_db_parameter_groups.return_value = {
        "DBParameterGroups": [
            {
                "DBParameterGroupName": "prod-params",
                "DBParameterGroupFamily": "postgres14",
                "Description": "Production parameters",
                "DBParameterGroupArn": "arn:aws:rds:us-east-1:123456789012:pg:prod-params",
            }
        ]
    }

    # Sample subnet groups response
    client.describe_db_subnet_groups.return_value = {
        "DBSubnetGroups": [
            {
                "DBSubnetGroupName": "prod-subnet-group",
                "DBSubnetGroupDescription": "Production subnets",
                "VpcId": "vpc-12345678",
                "DBSubnetGroupArn": "arn:aws:rds:us-east-1:123456789012:subgrp:prod-subnet-group",
                "Subnets": [
                    {"SubnetIdentifier": "subnet-11111111", "SubnetAvailabilityZone": {"Name": "us-east-1a"}},
                    {"SubnetIdentifier": "subnet-22222222", "SubnetAvailabilityZone": {"Name": "us-east-1b"}},
                ],
            }
        ]
    }

    # Sample snapshots response
    client.describe_db_snapshots.return_value = {
        "DBSnapshots": [
            {
                "DBSnapshotIdentifier": "prod-snapshot-20240101",
                "DBSnapshotArn": "arn:aws:rds:us-east-1:123456789012:snapshot:prod-snapshot-20240101",
                "DBInstanceIdentifier": "prod-database",
                "Engine": "postgres",
                "EngineVersion": "14.9",
                "Status": "available",
                "SnapshotType": "manual",
                "Encrypted": True,
                "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
                "SnapshotCreateTime": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "TagList": [],
            }
        ]
    }

    # Sample snapshot attributes response (not shared)
    client.describe_db_snapshot_attributes.return_value = {
        "DBSnapshotAttributesResult": {
            "DBSnapshotIdentifier": "prod-snapshot-20240101",
            "DBSnapshotAttributes": [
                {"AttributeName": "restore", "AttributeValues": []}
            ],
        }
    }

    # Sample parameters response
    client.describe_db_parameters.return_value = {
        "Parameters": [
            {"ParameterName": "rds.force_ssl", "ParameterValue": "1", "ApplyType": "static"},
            {"ParameterName": "log_connections", "ParameterValue": "1", "ApplyType": "dynamic"},
            {"ParameterName": "log_disconnections", "ParameterValue": "1", "ApplyType": "dynamic"},
        ]
    }

    return client


@pytest.fixture
def mock_lambda_client(mock_boto_session):
    """Return a mocked Lambda client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    # Create mock exceptions
    class MockExceptions:
        class ResourceNotFoundException(Exception):
            def __init__(self, error_response, operation_name):
                self.response = error_response
                self.operation_name = operation_name

    client.exceptions = MockExceptions()

    # Sample Lambda function response
    client.list_functions.return_value = {
        "Functions": [
            {
                "FunctionName": "test-function",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                "Runtime": "python3.11",
                "Handler": "index.handler",
                "CodeSize": 1024,
                "Description": "Test function",
                "Timeout": 30,
                "MemorySize": 256,
                "LastModified": "2024-01-01T00:00:00.000+0000",
                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                "VpcConfig": {},
                "Environment": {"Variables": {"ENV": "prod"}},
                "TracingConfig": {"Mode": "Active"},
            }
        ]
    }

    # Sample layers response
    client.list_layers.return_value = {
        "Layers": [
            {
                "LayerName": "test-layer",
                "LayerArn": "arn:aws:lambda:us-east-1:123456789012:layer:test-layer",
                "LatestMatchingVersion": {
                    "LayerVersionArn": "arn:aws:lambda:us-east-1:123456789012:layer:test-layer:1",
                    "Version": 1,
                    "Description": "Test layer",
                    "CompatibleRuntimes": ["python3.11"],
                    "CreatedDate": "2024-01-01T00:00:00.000+0000",
                }
            }
        ]
    }

    # Sample event source mappings response
    client.list_event_source_mappings.return_value = {
        "EventSourceMappings": [
            {
                "UUID": "12345678-1234-1234-1234-123456789012",
                "EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:my-queue",
                "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:test-function",
                "BatchSize": 10,
                "State": "Enabled",
                "LastModified": datetime(2024, 1, 1, tzinfo=timezone.utc),
            }
        ]
    }

    # Default: no resource policy
    client.get_policy.side_effect = client.exceptions.ResourceNotFoundException({}, "GetPolicy")

    # Default: no function URL
    client.get_function_url_config.side_effect = client.exceptions.ResourceNotFoundException({}, "GetFunctionUrlConfig")

    # Default: no layer policy
    client.get_layer_version_policy.side_effect = client.exceptions.ResourceNotFoundException({}, "GetLayerVersionPolicy")

    # Tags response
    client.list_tags.return_value = {"Tags": {"Environment": "prod"}}

    return client


@pytest.fixture
def mock_ecr_client(mock_boto_session):
    """Return a mocked ECR client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    # Create mock exceptions
    class MockExceptions:
        class RepositoryPolicyNotFoundException(Exception):
            def __init__(self):
                pass

        class LifecyclePolicyNotFoundException(Exception):
            def __init__(self):
                pass

    client.exceptions = MockExceptions()

    # Sample ECR repositories response
    client.describe_repositories.return_value = {
        "repositories": [
            {
                "repositoryName": "prod-app",
                "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/prod-app",
                "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/prod-app",
                "registryId": "123456789012",
                "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                "imageTagMutability": "IMMUTABLE",
                "imageScanningConfiguration": {"scanOnPush": True},
                "encryptionConfiguration": {
                    "encryptionType": "KMS",
                    "kmsKey": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
                },
            },
            {
                "repositoryName": "dev-app",
                "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/dev-app",
                "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/dev-app",
                "registryId": "123456789012",
                "createdAt": datetime(2024, 1, 15, tzinfo=timezone.utc),
                "imageTagMutability": "MUTABLE",
                "imageScanningConfiguration": {"scanOnPush": False},
                "encryptionConfiguration": {"encryptionType": "AES256"},
            },
        ]
    }

    # Sample tags response
    client.list_tags_for_resource.return_value = {
        "tags": [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Team", "Value": "platform"},
        ]
    }

    # Sample repository policy response (private by default)
    client.get_repository_policy.side_effect = client.exceptions.RepositoryPolicyNotFoundException()

    # Sample lifecycle policy response
    client.get_lifecycle_policy.side_effect = client.exceptions.LifecyclePolicyNotFoundException()

    # Sample registry replication configuration
    client.describe_registry.return_value = {
        "registryId": "123456789012",
        "replicationConfiguration": {
            "rules": [
                {
                    "destinations": [
                        {"region": "us-west-2", "registryId": "123456789012"}
                    ],
                    "repositoryFilters": [],
                }
            ]
        },
    }

    # Sample images response
    client.describe_images.return_value = {
        "imageDetails": [
            {
                "imageDigest": "sha256:abc123def456",
                "imageTags": ["latest", "v1.0.0"],
                "imageSizeInBytes": 104857600,  # 100 MB
                "imagePushedAt": datetime(2024, 1, 10, tzinfo=timezone.utc),
                "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "imageScanStatus": {"status": "COMPLETE"},
                "imageScanFindingsSummary": {
                    "imageScanCompletedAt": datetime(2024, 1, 10, tzinfo=timezone.utc),
                    "vulnerabilitySourceUpdatedAt": datetime(2024, 1, 10, tzinfo=timezone.utc),
                    "findingSeverityCounts": {
                        "CRITICAL": 1,
                        "HIGH": 3,
                        "MEDIUM": 5,
                        "LOW": 10,
                    },
                },
            },
            {
                "imageDigest": "sha256:def789ghi012",
                "imageTags": ["v0.9.0"],
                "imageSizeInBytes": 52428800,  # 50 MB
                "imagePushedAt": datetime(2024, 1, 5, tzinfo=timezone.utc),
                "imageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "imageScanStatus": {"status": "PENDING"},
            },
        ]
    }

    # Sample image scan findings response
    client.describe_image_scan_findings.return_value = {
        "imageScanFindings": {
            "findings": [
                {
                    "name": "CVE-2024-0001",
                    "description": "Critical vulnerability in package xyz",
                    "severity": "CRITICAL",
                    "uri": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-0001",
                    "attributes": [
                        {"key": "package_name", "value": "xyz-package"},
                        {"key": "package_version", "value": "1.0.0"},
                        {"key": "patched_version", "value": "1.0.1"},
                        {"key": "CVSS3_SCORE", "value": "9.8"},
                    ],
                },
                {
                    "name": "CVE-2024-0002",
                    "description": "High severity vulnerability in abc library",
                    "severity": "HIGH",
                    "attributes": [
                        {"key": "package_name", "value": "abc-lib"},
                        {"key": "package_version", "value": "2.0.0"},
                    ],
                },
            ]
        }
    }

    # Sample pull through cache rules response
    client.describe_pull_through_cache_rules.return_value = {
        "pullThroughCacheRules": []
    }

    return client


# GCP mock fixtures


@pytest.fixture
def mock_gcp_ar_client():
    """Return a mocked GCP Artifact Registry client."""
    client = MagicMock()

    # Default: return empty repositories
    client.list_repositories.return_value = []
    client.list_docker_images.return_value = []

    # Default IAM policy (private)
    mock_iam_policy = MagicMock()
    mock_iam_policy.version = 1
    mock_iam_policy.bindings = []
    mock_iam_policy.etag = b"default-etag"
    client.get_iam_policy.return_value = mock_iam_policy

    return client


@pytest.fixture
def mock_gcp_ca_client():
    """Return a mocked GCP Container Analysis client."""
    client = MagicMock()

    # Mock Grafeas client
    mock_grafeas = MagicMock()
    client.get_grafeas_client.return_value = mock_grafeas

    # Default: return empty occurrences
    mock_grafeas.list_occurrences.return_value = []

    return client


# Azure mock fixtures


@pytest.fixture
def mock_azure_acr_client():
    """Return a mocked Azure Container Registry Management client."""
    client = MagicMock()

    # Default: return empty registries
    client.registries.list.return_value = []
    client.replications.list.return_value = []
    client.webhooks.list.return_value = []

    return client


# GKE mock fixtures


@pytest.fixture
def mock_gcp_gke_client():
    """Return a mocked GCP GKE Cluster Manager client."""
    client = MagicMock()

    # Create mock cluster
    mock_cluster = MagicMock()
    mock_cluster.name = "prod-cluster"
    mock_cluster.id = "cluster-123456"
    mock_cluster.location = "us-central1"
    mock_cluster.status = "RUNNING"
    mock_cluster.current_master_version = "1.28.3-gke.1203000"
    mock_cluster.current_node_version = "1.28.3-gke.1203000"
    mock_cluster.initial_cluster_version = "1.28"
    mock_cluster.endpoint = "https://10.0.0.1"
    mock_cluster.create_time = "2024-01-01T00:00:00Z"
    mock_cluster.self_link = "https://container.googleapis.com/v1/projects/test-project/locations/us-central1/clusters/prod-cluster"
    mock_cluster.network = "projects/test-project/global/networks/default"
    mock_cluster.subnetwork = "projects/test-project/regions/us-central1/subnetworks/default"
    mock_cluster.cluster_ipv4_cidr = "10.4.0.0/14"
    mock_cluster.services_ipv4_cidr = "10.8.0.0/20"
    mock_cluster.resource_labels = {"environment": "prod", "team": "platform"}

    # Private cluster config
    mock_private_config = MagicMock()
    mock_private_config.enable_private_nodes = True
    mock_private_config.enable_private_endpoint = False
    mock_private_config.master_ipv4_cidr_block = "172.16.0.0/28"
    mock_private_config.private_endpoint = "10.0.0.2"
    mock_private_config.public_endpoint = "35.192.0.1"
    mock_cluster.private_cluster_config = mock_private_config

    # Master authorized networks
    mock_auth_networks = MagicMock()
    mock_auth_networks.enabled = True
    mock_cidr_block = MagicMock()
    mock_cidr_block.display_name = "office"
    mock_cidr_block.cidr_block = "10.0.0.0/8"
    mock_auth_networks.cidr_blocks = [mock_cidr_block]
    mock_cluster.master_authorized_networks_config = mock_auth_networks

    # Workload Identity
    mock_workload_identity = MagicMock()
    mock_workload_identity.workload_pool = "test-project.svc.id.goog"
    mock_cluster.workload_identity_config = mock_workload_identity

    # Binary Authorization
    mock_binary_auth = MagicMock()
    mock_binary_auth.enabled = True
    mock_binary_auth.evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
    mock_cluster.binary_authorization = mock_binary_auth

    # Network policy
    mock_network_policy = MagicMock()
    mock_network_policy.enabled = True
    mock_network_policy.provider = "CALICO"
    mock_cluster.network_policy = mock_network_policy

    # Addons
    mock_addons = MagicMock()
    mock_addons.http_load_balancing = MagicMock(disabled=False)
    mock_addons.horizontal_pod_autoscaling = MagicMock(disabled=False)
    mock_addons.network_policy_config = MagicMock(disabled=False)
    mock_addons.dns_cache_config = MagicMock(enabled=True)
    mock_addons.gce_persistent_disk_csi_driver_config = MagicMock(enabled=True)
    mock_addons.gcs_fuse_csi_driver_config = MagicMock(enabled=False)
    mock_cluster.addons_config = mock_addons

    # Shielded nodes
    mock_shielded = MagicMock()
    mock_shielded.enabled = True
    mock_cluster.shielded_nodes = mock_shielded

    # Legacy ABAC (disabled)
    mock_legacy_abac = MagicMock()
    mock_legacy_abac.enabled = False
    mock_cluster.legacy_abac = mock_legacy_abac

    # Master auth
    mock_master_auth = MagicMock()
    mock_master_auth.username = ""
    mock_master_auth.client_certificate_config = MagicMock(issue_client_certificate=False)
    mock_master_auth.cluster_ca_certificate = "LS0tLS1CRUdJTi..."
    mock_cluster.master_auth = mock_master_auth

    # Database encryption
    mock_db_encryption = MagicMock()
    mock_db_encryption.state = "ENCRYPTED"
    mock_db_encryption.key_name = "projects/test-project/locations/us-central1/keyRings/gke/cryptoKeys/etcd"
    mock_cluster.database_encryption = mock_db_encryption

    # Logging and monitoring
    mock_cluster.logging_service = "logging.googleapis.com/kubernetes"
    mock_cluster.monitoring_service = "monitoring.googleapis.com/kubernetes"

    # Release channel
    mock_release_channel = MagicMock()
    mock_release_channel.channel = "REGULAR"
    mock_cluster.release_channel = mock_release_channel

    # Maintenance policy
    mock_cluster.maintenance_policy = MagicMock()

    # Security posture
    mock_security_posture = MagicMock()
    mock_security_posture.mode = "BASIC"
    mock_security_posture.vulnerability_mode = "VULNERABILITY_BASIC"
    mock_cluster.security_posture_config = mock_security_posture

    # Notification config
    mock_notification = MagicMock()
    mock_notification.pubsub = MagicMock(enabled=True)
    mock_cluster.notification_config = mock_notification

    # Node pools
    mock_nodepool = MagicMock()
    mock_nodepool.name = "default-pool"
    mock_nodepool.status = "RUNNING"
    mock_nodepool.version = "1.28.3-gke.1203000"
    mock_nodepool.initial_node_count = 3
    mock_nodepool.locations = ["us-central1-a", "us-central1-b"]

    # Node config
    mock_node_config = MagicMock()
    mock_node_config.machine_type = "e2-medium"
    mock_node_config.disk_size_gb = 100
    mock_node_config.disk_type = "pd-standard"
    mock_node_config.image_type = "COS_CONTAINERD"
    mock_node_config.service_account = "gke-node@test-project.iam.gserviceaccount.com"
    mock_node_config.oauth_scopes = [
        "https://www.googleapis.com/auth/devstorage.read_only",
        "https://www.googleapis.com/auth/logging.write",
        "https://www.googleapis.com/auth/monitoring",
    ]
    mock_node_config.labels = {"pool": "default"}
    mock_node_config.metadata = {}
    mock_node_config.preemptible = False
    mock_node_config.spot = False
    mock_node_config.shielded_instance_config = MagicMock(
        enable_secure_boot=True,
        enable_integrity_monitoring=True,
    )
    mock_node_config.workload_metadata_config = MagicMock(mode="GKE_METADATA")
    mock_node_config.sandbox_config = None
    mock_nodepool.config = mock_node_config

    # Autoscaling
    mock_autoscaling = MagicMock()
    mock_autoscaling.enabled = True
    mock_autoscaling.min_node_count = 1
    mock_autoscaling.max_node_count = 10
    mock_nodepool.autoscaling = mock_autoscaling

    # Management
    mock_management = MagicMock()
    mock_management.auto_repair = True
    mock_management.auto_upgrade = True
    mock_nodepool.management = mock_management

    mock_cluster.node_pools = [mock_nodepool]

    # List clusters response
    mock_response = MagicMock()
    mock_response.clusters = [mock_cluster]
    client.list_clusters.return_value = mock_response

    return client


# EKS mock fixtures


@pytest.fixture
def mock_eks_client(mock_boto_session):
    """Return a mocked EKS client with sample responses."""
    client = MagicMock()
    mock_boto_session.client.return_value = client

    # Sample EKS clusters response
    client.list_clusters.return_value = {
        "clusters": ["prod-cluster", "dev-cluster"]
    }

    # Sample cluster description response
    client.describe_cluster.return_value = {
        "cluster": {
            "name": "prod-cluster",
            "arn": "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster",
            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "version": "1.28",
            "platformVersion": "eks.5",
            "status": "ACTIVE",
            "roleArn": "arn:aws:iam::123456789012:role/eks-cluster-role",
            "endpoint": "https://ABC123.gr7.us-east-1.eks.amazonaws.com",
            "resourcesVpcConfig": {
                "vpcId": "vpc-12345678",
                "subnetIds": ["subnet-11111111", "subnet-22222222"],
                "securityGroupIds": ["sg-12345678"],
                "clusterSecurityGroupId": "sg-cluster123",
                "endpointPublicAccess": True,
                "endpointPrivateAccess": True,
                "publicAccessCidrs": ["10.0.0.0/8"],
            },
            "kubernetesNetworkConfig": {
                "serviceIpv4Cidr": "172.20.0.0/16",
                "ipFamily": "ipv4",
            },
            "logging": {
                "clusterLogging": [
                    {
                        "types": ["api", "audit", "authenticator", "controllerManager", "scheduler"],
                        "enabled": True,
                    }
                ]
            },
            "identity": {
                "oidc": {
                    "issuer": "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE12345"
                }
            },
            "encryptionConfig": [
                {
                    "resources": ["secrets"],
                    "provider": {
                        "keyArn": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
                    },
                }
            ],
            "tags": {"Environment": "prod", "Team": "platform"},
        }
    }

    # Sample node groups response
    client.list_nodegroups.return_value = {
        "nodegroups": ["prod-nodegroup"]
    }

    client.describe_nodegroup.return_value = {
        "nodegroup": {
            "nodegroupName": "prod-nodegroup",
            "nodegroupArn": "arn:aws:eks:us-east-1:123456789012:nodegroup/prod-cluster/prod-nodegroup/abc123",
            "clusterName": "prod-cluster",
            "version": "1.28",
            "releaseVersion": "1.28.3-20240101",
            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "status": "ACTIVE",
            "capacityType": "ON_DEMAND",
            "scalingConfig": {
                "minSize": 2,
                "maxSize": 10,
                "desiredSize": 3,
            },
            "instanceTypes": ["m5.large"],
            "subnets": ["subnet-11111111", "subnet-22222222"],
            "amiType": "AL2_x86_64",
            "nodeRole": "arn:aws:iam::123456789012:role/eks-node-role",
            "labels": {"role": "worker"},
            "tags": {"Environment": "prod"},
        }
    }

    # Sample Fargate profiles response
    client.list_fargate_profiles.return_value = {
        "fargateProfileNames": ["prod-fargate"]
    }

    client.describe_fargate_profile.return_value = {
        "fargateProfile": {
            "fargateProfileName": "prod-fargate",
            "fargateProfileArn": "arn:aws:eks:us-east-1:123456789012:fargateprofile/prod-cluster/prod-fargate/abc123",
            "clusterName": "prod-cluster",
            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "status": "ACTIVE",
            "podExecutionRoleArn": "arn:aws:iam::123456789012:role/eks-fargate-role",
            "subnets": ["subnet-33333333"],
            "selectors": [
                {"namespace": "kube-system"},
                {"namespace": "default", "labels": {"app": "fargate-app"}},
            ],
            "tags": {"Environment": "prod"},
        }
    }

    # Sample add-ons response
    client.list_addons.return_value = {
        "addons": ["vpc-cni", "coredns"]
    }

    client.describe_addon.return_value = {
        "addon": {
            "addonName": "vpc-cni",
            "addonArn": "arn:aws:eks:us-east-1:123456789012:addon/prod-cluster/vpc-cni/abc123",
            "clusterName": "prod-cluster",
            "addonVersion": "v1.16.0-eksbuild.1",
            "status": "ACTIVE",
            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
            "modifiedAt": datetime(2024, 1, 15, tzinfo=timezone.utc),
            "serviceAccountRoleArn": "arn:aws:iam::123456789012:role/vpc-cni-role",
            "health": {"issues": []},
            "tags": {},
        }
    }

    return client


# AKS mock fixtures


@pytest.fixture
def mock_azure_aks_client():
    """Return a mocked Azure AKS (Container Service) client."""
    client = MagicMock()

    # Create mock AKS cluster
    mock_cluster = MagicMock()
    mock_cluster.id = "/subscriptions/sub123/resourceGroups/rg-prod/providers/Microsoft.ContainerService/managedClusters/prod-aks"
    mock_cluster.name = "prod-aks"
    mock_cluster.location = "eastus"
    mock_cluster.provisioning_state = "Succeeded"
    mock_cluster.kubernetes_version = "1.28.3"
    mock_cluster.current_kubernetes_version = "1.28.3"
    mock_cluster.dns_prefix = "prod-aks"
    mock_cluster.fqdn = "prod-aks-abc123.hcp.eastus.azmk8s.io"
    mock_cluster.private_fqdn = None
    mock_cluster.azure_portal_fqdn = "prod-aks-abc123.portal.hcp.eastus.azmk8s.io"
    mock_cluster.tags = {"environment": "prod", "team": "platform"}

    # Power state
    mock_power_state = MagicMock()
    mock_power_state.code = "Running"
    mock_cluster.power_state = mock_power_state

    # Identity (managed identity)
    mock_identity = MagicMock()
    mock_identity.type = "SystemAssigned"
    mock_identity.principal_id = "principal-123"
    mock_identity.tenant_id = "tenant-123"
    mock_identity.user_assigned_identities = None
    mock_cluster.identity = mock_identity

    # Service principal (None for managed identity)
    mock_cluster.service_principal_profile = None

    # AAD profile
    mock_aad = MagicMock()
    mock_aad.managed = True
    mock_aad.enable_azure_rbac = True
    mock_aad.admin_group_object_ids = ["group-123", "group-456"]
    mock_aad.tenant_id = "tenant-123"
    mock_cluster.aad_profile = mock_aad

    # RBAC
    mock_cluster.enable_rbac = True

    # API server access profile (private cluster)
    mock_api_server = MagicMock()
    mock_api_server.authorized_ip_ranges = ["10.0.0.0/8", "172.16.0.0/12"]
    mock_api_server.enable_private_cluster = True
    mock_api_server.private_dns_zone = "system"
    mock_api_server.enable_private_cluster_public_fqdn = False
    mock_api_server.disable_run_command = True
    mock_cluster.api_server_access_profile = mock_api_server

    # Network profile
    mock_network = MagicMock()
    mock_network.network_plugin = "azure"
    mock_network.network_plugin_mode = "overlay"
    mock_network.network_policy = "calico"
    mock_network.network_mode = None
    mock_network.pod_cidr = "10.244.0.0/16"
    mock_network.service_cidr = "10.0.0.0/16"
    mock_network.dns_service_ip = "10.0.0.10"
    mock_network.outbound_type = "loadBalancer"
    mock_network.load_balancer_sku = "standard"
    mock_network.ip_families = ["IPv4"]
    mock_cluster.network_profile = mock_network

    # Linux profile
    mock_linux = MagicMock()
    mock_linux.admin_username = "azureuser"
    mock_ssh = MagicMock()
    mock_ssh.public_keys = [MagicMock()]
    mock_linux.ssh = mock_ssh
    mock_cluster.linux_profile = mock_linux

    # Windows profile (None)
    mock_cluster.windows_profile = None

    # Auto upgrade profile
    mock_auto_upgrade = MagicMock()
    mock_auto_upgrade.upgrade_channel = "stable"
    mock_auto_upgrade.node_os_upgrade_channel = "NodeImage"
    mock_cluster.auto_upgrade_profile = mock_auto_upgrade

    # Security profile
    mock_security = MagicMock()
    mock_defender = MagicMock()
    mock_defender.log_analytics_workspace_resource_id = "/subscriptions/sub123/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/logs"
    mock_security_monitoring = MagicMock()
    mock_security_monitoring.enabled = True
    mock_defender.security_monitoring = mock_security_monitoring
    mock_security.defender = mock_defender
    mock_workload_identity = MagicMock()
    mock_workload_identity.enabled = True
    mock_security.workload_identity = mock_workload_identity
    mock_image_cleaner = MagicMock()
    mock_image_cleaner.enabled = True
    mock_image_cleaner.interval_hours = 24
    mock_security.image_cleaner = mock_image_cleaner
    mock_kms = MagicMock()
    mock_kms.enabled = True
    mock_kms.key_id = "https://myvault.vault.azure.net/keys/mykey/abc123"
    mock_security.azure_key_vault_kms = mock_kms
    mock_cluster.security_profile = mock_security

    # OIDC issuer profile
    mock_oidc = MagicMock()
    mock_oidc.enabled = True
    mock_oidc.issuer_url = "https://eastus.oic.prod-aks.azure.com/tenant123/cluster123/"
    mock_cluster.oidc_issuer_profile = mock_oidc

    # HTTP proxy config (None)
    mock_cluster.http_proxy_config = None

    # Storage profile
    mock_storage = MagicMock()
    mock_disk_csi = MagicMock()
    mock_disk_csi.enabled = True
    mock_storage.disk_csi_driver = mock_disk_csi
    mock_file_csi = MagicMock()
    mock_file_csi.enabled = True
    mock_storage.file_csi_driver = mock_file_csi
    mock_storage.blob_csi_driver = None
    mock_snapshot = MagicMock()
    mock_snapshot.enabled = True
    mock_storage.snapshot_controller = mock_snapshot
    mock_cluster.storage_profile = mock_storage

    # Addon profiles
    mock_azurepolicy = MagicMock()
    mock_azurepolicy.enabled = True
    mock_azurepolicy.config = {}
    mock_omsagent = MagicMock()
    mock_omsagent.enabled = True
    mock_omsagent.config = {"logAnalyticsWorkspaceResourceID": "/subscriptions/sub123/resourceGroups/rg-logs/providers/Microsoft.OperationalInsights/workspaces/logs"}
    mock_kv_provider = MagicMock()
    mock_kv_provider.enabled = True
    mock_kv_provider.config = {"enableSecretRotation": "true"}
    mock_cluster.addon_profiles = {
        "azurepolicy": mock_azurepolicy,
        "omsagent": mock_omsagent,
        "azureKeyvaultSecretsProvider": mock_kv_provider,
    }

    # Disable local accounts
    mock_cluster.disable_local_accounts = True

    # SKU
    mock_sku = MagicMock()
    mock_sku.name = "Base"
    mock_sku.tier = "Standard"
    mock_cluster.sku = mock_sku

    # Agent pool profiles (node pools)
    mock_pool = MagicMock()
    mock_pool.name = "nodepool1"
    mock_pool.count = 3
    mock_pool.vm_size = "Standard_D4s_v3"
    mock_pool.os_disk_size_gb = 128
    mock_pool.os_disk_type = "Managed"
    mock_pool.os_type = "Linux"
    mock_pool.os_sku = "Ubuntu"
    mock_pool.mode = "System"
    mock_pool.type = "VirtualMachineScaleSets"
    mock_pool.provisioning_state = "Succeeded"
    mock_pool_power = MagicMock()
    mock_pool_power.code = "Running"
    mock_pool.power_state = mock_pool_power
    mock_pool.orchestrator_version = "1.28.3"
    mock_pool.current_orchestrator_version = "1.28.3"
    mock_pool.node_image_version = "AKSUbuntu-2204gen2containerd-202401.01.0"
    mock_pool.availability_zones = ["1", "2", "3"]
    mock_pool.enable_auto_scaling = True
    mock_pool.min_count = 1
    mock_pool.max_count = 10
    mock_pool.scale_set_priority = "Regular"
    mock_pool.spot_max_price = None
    mock_pool.scale_set_eviction_policy = None
    mock_pool.vnet_subnet_id = "/subscriptions/sub123/resourceGroups/rg-network/providers/Microsoft.Network/virtualNetworks/vnet/subnets/aks-subnet"
    mock_pool.pod_subnet_id = None
    mock_pool.max_pods = 110
    mock_pool.enable_node_public_ip = False
    mock_pool.node_public_ip_prefix_id = None
    mock_pool.node_labels = {"role": "system"}
    mock_pool.node_taints = []
    mock_upgrade_settings = MagicMock()
    mock_upgrade_settings.max_surge = "33%"
    mock_upgrade_settings.drain_timeout_in_minutes = 30
    mock_upgrade_settings.node_soak_duration_in_minutes = 0
    mock_pool.upgrade_settings = mock_upgrade_settings
    mock_pool.enable_fips = False
    mock_pool.enable_encryption_at_host = True
    mock_pool.enable_ultra_ssd = False
    mock_pool.gpu_instance_profile = None
    mock_pool.kubelet_config = None
    mock_pool.linux_os_config = None
    mock_pool.creation_data = None
    mock_pool.tags = {"nodepool": "system"}

    mock_cluster.agent_pool_profiles = [mock_pool]

    # Configure the client to return our mock cluster
    client.managed_clusters.list.return_value = [mock_cluster]

    return client


@pytest.fixture
def mock_llm_provider():
    """Return a mocked LLM provider."""
    with patch("stance.llm.get_llm_provider") as mock:
        provider = MagicMock()
        provider.generate.return_value = (
            "SELECT * FROM findings WHERE severity = 'critical'"
        )
        mock.return_value = provider
        yield provider
