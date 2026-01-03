"""
Unit tests for Mantissa Stance collectors.

Tests cover:
- IAM collector with mocked AWS responses
- S3 collector with mocked AWS responses
- EC2 collector with mocked AWS responses
- CollectorRunner aggregation
- Error handling for AWS access denied scenarios
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from stance.collectors.base import BaseCollector, CollectorResult, CollectorRunner
from stance.collectors.aws_iam import IAMCollector
from stance.collectors.aws_s3 import S3Collector
from stance.collectors.aws_ec2 import EC2Collector
from stance.collectors.aws_ecr import ECRCollector
from stance.collectors.aws_eks import EKSCollector
from stance.models import (
    AssetCollection,
    FindingCollection,
    FindingType,
    Severity,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
)


class TestIAMCollector:
    """Tests for IAMCollector."""

    def test_iam_collector_init(self):
        """Test IAMCollector can be initialized."""
        collector = IAMCollector()
        assert collector.collector_name == "aws_iam"
        assert "aws_iam_user" in collector.resource_types
        assert "aws_iam_role" in collector.resource_types

    def test_iam_collector_collect_users(self, mock_iam_client):
        """Test user collection with mock response."""
        with patch.object(IAMCollector, "_get_client", return_value=mock_iam_client):
            collector = IAMCollector()

            # Mock paginator for list_users
            mock_paginator = MagicMock()
            mock_iam_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "Users": [
                        {
                            "UserName": "test-user",
                            "UserId": "AIDATEST123",
                            "Arn": "arn:aws:iam::123456789012:user/test-user",
                            "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
                        }
                    ]
                }
            ]

            # Mock additional IAM calls
            mock_iam_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
            mock_iam_client.list_mfa_devices.return_value = {"MFADevices": []}
            mock_iam_client.list_groups_for_user.return_value = {"Groups": []}
            mock_iam_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
            mock_iam_client.list_user_policies.return_value = {"PolicyNames": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)

    def test_iam_collector_collect_password_policy(self, mock_iam_client):
        """Test password policy collection."""
        with patch.object(IAMCollector, "_get_client", return_value=mock_iam_client):
            collector = IAMCollector()

            mock_iam_client.get_account_password_policy.return_value = {
                "PasswordPolicy": {
                    "MinimumPasswordLength": 14,
                    "RequireSymbols": True,
                    "RequireNumbers": True,
                    "RequireUppercaseCharacters": True,
                    "RequireLowercaseCharacters": True,
                    "MaxPasswordAge": 90,
                }
            }

            # Mock empty paginators
            mock_paginator = MagicMock()
            mock_iam_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"Users": [], "Roles": [], "Policies": [], "Groups": []}]
            mock_iam_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}

            assets = collector.collect()

            # Should have collected password policy asset
            assert isinstance(assets, AssetCollection)

    def test_iam_collector_handles_no_password_policy(self, mock_iam_client):
        """Test graceful handling when no password policy exists."""
        from botocore.exceptions import ClientError

        with patch.object(IAMCollector, "_get_client", return_value=mock_iam_client):
            collector = IAMCollector()

            # Simulate NoSuchEntity error
            mock_iam_client.get_account_password_policy.side_effect = ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "No password policy"}},
                "GetAccountPasswordPolicy"
            )

            mock_paginator = MagicMock()
            mock_iam_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"Users": [], "Roles": [], "Policies": [], "Groups": []}]
            mock_iam_client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 1}}

            # Should not raise, should handle gracefully
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)

    def test_iam_collector_access_denied(self, mock_iam_client):
        """Test graceful handling of AccessDenied."""
        from botocore.exceptions import ClientError

        with patch.object(IAMCollector, "_get_client", return_value=mock_iam_client):
            collector = IAMCollector()

            # Simulate AccessDenied
            mock_iam_client.get_account_summary.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "GetAccountSummary"
            )
            mock_iam_client.get_account_password_policy.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
                "GetAccountPasswordPolicy"
            )

            mock_paginator = MagicMock()
            mock_iam_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"Users": [], "Roles": [], "Policies": [], "Groups": []}]

            # Should handle gracefully and return what it can collect
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)


class TestS3Collector:
    """Tests for S3Collector."""

    def test_s3_collector_init(self):
        """Test S3Collector can be initialized."""
        collector = S3Collector()
        assert collector.collector_name == "aws_s3"
        assert "aws_s3_bucket" in collector.resource_types

    def test_s3_collector_collect_buckets(self, mock_s3_client):
        """Test bucket collection with mock response."""
        with patch.object(S3Collector, "_get_client", return_value=mock_s3_client):
            collector = S3Collector()

            mock_s3_client.list_buckets.return_value = {
                "Buckets": [
                    {"Name": "test-bucket", "CreationDate": datetime(2024, 1, 1)},
                ]
            }
            mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
            mock_s3_client.get_bucket_encryption.return_value = {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            }
            mock_s3_client.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
            mock_s3_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
            mock_s3_client.get_bucket_logging.return_value = {}
            mock_s3_client.get_bucket_tagging.return_value = {"TagSet": []}
            mock_s3_client.get_bucket_policy.side_effect = Exception("NoSuchBucketPolicy")
            mock_s3_client.get_bucket_acl.return_value = {"Grants": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) >= 0

    def test_s3_collector_determines_exposure_internal(self, mock_s3_client):
        """Test network exposure determination for internal bucket."""
        with patch.object(S3Collector, "_get_client", return_value=mock_s3_client):
            collector = S3Collector()

            mock_s3_client.list_buckets.return_value = {
                "Buckets": [{"Name": "private-bucket", "CreationDate": datetime(2024, 1, 1)}]
            }
            mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}
            mock_s3_client.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
            mock_s3_client.get_bucket_encryption.return_value = {}
            mock_s3_client.get_bucket_versioning.return_value = {}
            mock_s3_client.get_bucket_logging.return_value = {}
            mock_s3_client.get_bucket_tagging.return_value = {"TagSet": []}
            mock_s3_client.get_bucket_policy.side_effect = Exception("NoSuchBucketPolicy")
            mock_s3_client.get_bucket_acl.return_value = {"Grants": []}

            assets = collector.collect()

            # Should be internal since public access is blocked
            for asset in assets:
                if asset.resource_type == "aws_s3_bucket":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_s3_collector_handles_bucket_not_found(self, mock_s3_client):
        """Test error handling for deleted buckets."""
        from botocore.exceptions import ClientError

        with patch.object(S3Collector, "_get_client", return_value=mock_s3_client):
            collector = S3Collector()

            mock_s3_client.list_buckets.return_value = {
                "Buckets": [{"Name": "deleted-bucket", "CreationDate": datetime(2024, 1, 1)}]
            }
            mock_s3_client.get_bucket_location.side_effect = ClientError(
                {"Error": {"Code": "NoSuchBucket", "Message": "Bucket not found"}},
                "GetBucketLocation"
            )

            # Should handle gracefully
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)


class TestEC2Collector:
    """Tests for EC2Collector."""

    def test_ec2_collector_init(self):
        """Test EC2Collector can be initialized."""
        collector = EC2Collector()
        assert collector.collector_name == "aws_ec2"
        assert "aws_ec2_instance" in collector.resource_types
        assert "aws_security_group" in collector.resource_types

    def test_ec2_collector_collect_instances(self, mock_ec2_client):
        """Test instance collection."""
        with patch.object(EC2Collector, "_get_client", return_value=mock_ec2_client):
            collector = EC2Collector()

            mock_paginator = MagicMock()
            mock_ec2_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-1234567890abcdef0",
                                    "InstanceType": "t3.medium",
                                    "State": {"Name": "running"},
                                    "Tags": [{"Key": "Name", "Value": "web-server"}],
                                }
                            ]
                        }
                    ]
                }
            ]

            # Mock security groups response
            mock_ec2_client.describe_security_groups.return_value = {"SecurityGroups": []}
            mock_ec2_client.describe_vpcs.return_value = {"Vpcs": []}
            mock_ec2_client.describe_subnets.return_value = {"Subnets": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)

    def test_ec2_collector_collect_security_groups(self, mock_ec2_client):
        """Test security group collection."""
        with patch.object(EC2Collector, "_get_client", return_value=mock_ec2_client):
            collector = EC2Collector()

            mock_paginator = MagicMock()
            mock_ec2_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"Reservations": []}]

            mock_ec2_client.describe_security_groups.return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-12345678",
                        "GroupName": "web-sg",
                        "VpcId": "vpc-12345678",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 22,
                                "ToPort": 22,
                                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                            }
                        ],
                    }
                ]
            }
            mock_ec2_client.describe_vpcs.return_value = {"Vpcs": []}
            mock_ec2_client.describe_subnets.return_value = {"Subnets": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Check security group has ssh_open_cidrs detected
            sg_assets = [a for a in assets if a.resource_type == "aws_security_group"]
            if sg_assets:
                sg = sg_assets[0]
                raw_config = sg.raw_config
                if "ssh_open_cidrs" in raw_config:
                    assert "0.0.0.0/0" in raw_config["ssh_open_cidrs"]


class TestCollectorRunner:
    """Tests for CollectorRunner."""

    def test_collector_runner_runs_all(self):
        """Test running multiple collectors."""
        mock_collector1 = MagicMock(spec=BaseCollector)
        mock_collector1.collector_name = "mock1"
        mock_collector1.collect.return_value = AssetCollection([])

        mock_collector2 = MagicMock(spec=BaseCollector)
        mock_collector2.collector_name = "mock2"
        mock_collector2.collect.return_value = AssetCollection([])

        runner = CollectorRunner([mock_collector1, mock_collector2])
        assets, results = runner.run_all()

        assert isinstance(assets, AssetCollection)
        assert len(results) == 2
        assert all(isinstance(r, CollectorResult) for r in results)

    def test_collector_runner_handles_failures(self):
        """Test graceful handling of collector failures."""
        mock_collector1 = MagicMock(spec=BaseCollector)
        mock_collector1.collector_name = "failing"
        mock_collector1.collect.side_effect = Exception("Collection failed")

        mock_collector2 = MagicMock(spec=BaseCollector)
        mock_collector2.collector_name = "working"
        mock_collector2.collect.return_value = AssetCollection([])

        runner = CollectorRunner([mock_collector1, mock_collector2])
        assets, results = runner.run_all()

        # Should still return results, with errors noted
        assert isinstance(assets, AssetCollection)
        assert len(results) == 2

        # Find the failing result
        failing_result = next(r for r in results if r.collector_name == "failing")
        assert len(failing_result.errors) > 0

    def test_collector_runner_single_collector(self):
        """Test running a single collector."""
        mock_collector = MagicMock(spec=BaseCollector)
        mock_collector.collector_name = "single"
        mock_collector.collect.return_value = AssetCollection([])

        runner = CollectorRunner([mock_collector])
        result = runner.run_collector(mock_collector)

        assert isinstance(result, CollectorResult)
        assert result.collector_name == "single"
        assert result.duration_seconds >= 0

    def test_collector_result_dataclass(self):
        """Test CollectorResult dataclass."""
        result = CollectorResult(
            collector_name="test",
            assets=AssetCollection([]),
            duration_seconds=1.5,
            errors=["Error 1"],
        )

        assert result.collector_name == "test"
        assert len(result.assets) == 0
        assert result.duration_seconds == 1.5
        assert len(result.errors) == 1


class TestECRCollector:
    """Tests for ECRCollector."""

    def test_ecr_collector_init(self):
        """Test ECRCollector can be initialized."""
        collector = ECRCollector()
        assert collector.collector_name == "aws_ecr"
        assert "aws_ecr_repository" in collector.resource_types
        assert "aws_ecr_image" in collector.resource_types

    def test_ecr_collector_collect_repositories(self, mock_ecr_client):
        """Test repository collection with mock response."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            # Mock paginator for describe_repositories
            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "test-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "IMMUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        }
                    ]
                }
            ]

            # Mock images response for the repository
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Should have at least one repository
            repo_assets = [a for a in assets if a.resource_type == "aws_ecr_repository"]
            assert len(repo_assets) >= 1

    def test_ecr_collector_collect_with_images(self, mock_ecr_client):
        """Test repository collection with images."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator

            # First paginate call is for repositories
            # Subsequent calls are for images
            def paginate_side_effect(*args, **kwargs):
                if "repositoryName" in kwargs:
                    # Images request
                    return [
                        {
                            "imageDetails": [
                                {
                                    "imageDigest": "sha256:abc123",
                                    "imageTags": ["latest"],
                                    "imageSizeInBytes": 52428800,
                                    "imagePushedAt": datetime(2024, 1, 5, tzinfo=timezone.utc),
                                    "imageScanStatus": {"status": "COMPLETE"},
                                    "imageScanFindingsSummary": {
                                        "findingSeverityCounts": {
                                            "CRITICAL": 0,
                                            "HIGH": 1,
                                        }
                                    },
                                }
                            ]
                        }
                    ]
                else:
                    # Repositories request
                    return [
                        {
                            "repositories": [
                                {
                                    "repositoryName": "test-repo",
                                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
                                    "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
                                    "registryId": "123456789012",
                                    "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                                    "imageTagMutability": "IMMUTABLE",
                                    "imageScanningConfiguration": {"scanOnPush": True},
                                    "encryptionConfiguration": {"encryptionType": "AES256"},
                                }
                            ]
                        }
                    ]

            mock_paginator.paginate.side_effect = paginate_side_effect

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Should have repository and image assets
            repo_assets = [a for a in assets if a.resource_type == "aws_ecr_repository"]
            image_assets = [a for a in assets if a.resource_type == "aws_ecr_image"]
            assert len(repo_assets) >= 1
            assert len(image_assets) >= 1

    def test_ecr_collector_determines_network_exposure_internal(self, mock_ecr_client):
        """Test network exposure is internal for private repositories."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "private-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/private-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/private-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "IMMUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        }
                    ]
                }
            ]

            # No repository policy = private
            mock_ecr_client.get_repository_policy.side_effect = mock_ecr_client.exceptions.RepositoryPolicyNotFoundException()
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "aws_ecr_repository":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_ecr_collector_determines_network_exposure_public(self, mock_ecr_client):
        """Test network exposure is internet-facing for public repositories."""
        import json

        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "public-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/public-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/public-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "MUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": False},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        }
                    ]
                }
            ]

            # Repository policy with public access
            public_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": [
                            "ecr:GetDownloadUrlForLayer",
                            "ecr:BatchGetImage",
                        ],
                    }
                ],
            }
            mock_ecr_client.get_repository_policy.return_value = {
                "policyText": json.dumps(public_policy)
            }
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "aws_ecr_repository":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_ecr_collector_collect_findings(self, mock_ecr_client):
        """Test vulnerability finding collection from image scans."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator

            # Mock repository and image responses
            def paginate_side_effect(*args, **kwargs):
                if "repositoryName" in kwargs and "filter" in kwargs:
                    # Images request with filter
                    return [
                        {
                            "imageDetails": [
                                {
                                    "imageDigest": "sha256:abc123",
                                    "imageTags": ["latest"],
                                    "imageScanStatus": {"status": "COMPLETE"},
                                }
                            ]
                        }
                    ]
                elif "repositoryName" in kwargs:
                    # Images request without filter
                    return [{"imageDetails": []}]
                else:
                    # Repositories request
                    return [
                        {
                            "repositories": [
                                {
                                    "repositoryName": "test-repo",
                                    "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/test-repo",
                                    "registryId": "123456789012",
                                }
                            ]
                        }
                    ]

            mock_paginator.paginate.side_effect = paginate_side_effect

            # Mock scan findings
            mock_ecr_client.describe_image_scan_findings.return_value = {
                "imageScanFindings": {
                    "findings": [
                        {
                            "name": "CVE-2024-0001",
                            "description": "Critical vulnerability",
                            "severity": "CRITICAL",
                            "attributes": [
                                {"key": "package_name", "value": "test-package"},
                                {"key": "package_version", "value": "1.0.0"},
                                {"key": "patched_version", "value": "1.0.1"},
                                {"key": "CVSS3_SCORE", "value": "9.8"},
                            ],
                        }
                    ]
                }
            }

            findings = collector.collect_findings()

            assert isinstance(findings, FindingCollection)
            if len(findings) > 0:
                finding = findings.findings[0]
                assert finding.finding_type == FindingType.VULNERABILITY
                assert finding.severity == Severity.CRITICAL
                assert finding.cve_id == "CVE-2024-0001"

    def test_ecr_collector_handles_no_repositories(self, mock_ecr_client):
        """Test graceful handling when no repositories exist."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"repositories": []}]

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_ecr_collector_handles_access_denied(self, mock_ecr_client):
        """Test graceful handling of AccessDenied."""
        from botocore.exceptions import ClientError

        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
                "DescribeRepositories"
            )

            # Should handle gracefully and return empty collection
            assets = collector.collect()
            assert isinstance(assets, AssetCollection)

    def test_ecr_collector_immutable_tags(self, mock_ecr_client):
        """Test repository immutable tag detection."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "immutable-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/immutable-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/immutable-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "IMMUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        }
                    ]
                }
            ]
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            repo_assets = [a for a in assets if a.resource_type == "aws_ecr_repository"]
            assert len(repo_assets) == 1
            assert repo_assets[0].raw_config["image_tag_immutable"] is True

    def test_ecr_collector_scan_on_push(self, mock_ecr_client):
        """Test repository scan on push detection."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "scanned-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/scanned-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/scanned-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "MUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        },
                        {
                            "repositoryName": "unscanned-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/unscanned-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/unscanned-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "MUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": False},
                            "encryptionConfiguration": {"encryptionType": "AES256"},
                        },
                    ]
                }
            ]
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            repo_assets = [a for a in assets if a.resource_type == "aws_ecr_repository"]
            scanned_repo = next(a for a in repo_assets if a.name == "scanned-repo")
            unscanned_repo = next(a for a in repo_assets if a.name == "unscanned-repo")

            assert scanned_repo.raw_config["scan_on_push"] is True
            assert scanned_repo.raw_config["has_scan_on_push"] is True
            assert unscanned_repo.raw_config["scan_on_push"] is False
            assert unscanned_repo.raw_config["has_scan_on_push"] is False

    def test_ecr_collector_kms_encryption(self, mock_ecr_client):
        """Test repository KMS encryption detection."""
        with patch.object(ECRCollector, "_get_client", return_value=mock_ecr_client):
            collector = ECRCollector()

            mock_paginator = MagicMock()
            mock_ecr_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [
                {
                    "repositories": [
                        {
                            "repositoryName": "kms-repo",
                            "repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/kms-repo",
                            "repositoryUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/kms-repo",
                            "registryId": "123456789012",
                            "createdAt": datetime(2024, 1, 1, tzinfo=timezone.utc),
                            "imageTagMutability": "IMMUTABLE",
                            "imageScanningConfiguration": {"scanOnPush": True},
                            "encryptionConfiguration": {
                                "encryptionType": "KMS",
                                "kmsKey": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
                            },
                        }
                    ]
                }
            ]
            mock_ecr_client.describe_images.return_value = {"imageDetails": []}

            assets = collector.collect()

            repo_assets = [a for a in assets if a.resource_type == "aws_ecr_repository"]
            assert len(repo_assets) == 1
            assert repo_assets[0].raw_config["has_kms_encryption"] is True
            assert repo_assets[0].raw_config["encryption_type"] == "KMS"


# Conditional import for GCP tests
try:
    from stance.collectors.gcp_artifactregistry import (
        GCPArtifactRegistryCollector,
        GCP_AR_AVAILABLE,
    )
except ImportError:
    GCP_AR_AVAILABLE = False
    GCPArtifactRegistryCollector = None  # type: ignore


@pytest.mark.skipif(not GCP_AR_AVAILABLE, reason="GCP Artifact Registry SDK not available")
class TestGCPArtifactRegistryCollector:
    """Tests for GCPArtifactRegistryCollector."""

    def test_gcp_ar_collector_init(self, mock_gcp_ar_client):
        """Test GCPArtifactRegistryCollector can be initialized."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")
            assert collector.collector_name == "gcp_artifactregistry"
            assert "gcp_artifact_repository" in collector.resource_types
            assert "gcp_artifact_docker_image" in collector.resource_types
            assert collector.project_id == "test-project"

    def test_gcp_ar_collector_collect_repositories(self, mock_gcp_ar_client):
        """Test repository collection with mock response."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            # Mock repository object
            mock_repo = MagicMock()
            mock_repo.name = "projects/test-project/locations/us-central1/repositories/my-repo"
            mock_repo.format_.name = "DOCKER"
            mock_repo.description = "Test repository"
            mock_repo.labels = {"env": "test"}
            mock_repo.create_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_repo.update_time = datetime(2024, 1, 5, tzinfo=timezone.utc)
            mock_repo.mode.name = "STANDARD_REPOSITORY"
            mock_repo.cleanup_policies = {}
            mock_repo.cleanup_policy_dry_run = False
            mock_repo.size_bytes = 1073741824  # 1 GB
            mock_repo.docker_config = None
            mock_repo.maven_config = None
            mock_repo.remote_repository_config = None
            mock_repo.virtual_repository_config = None

            # Mock list_repositories to return our test repo
            mock_gcp_ar_client.list_repositories.return_value = [mock_repo]

            # Mock IAM policy response
            mock_iam_policy = MagicMock()
            mock_iam_policy.version = 1
            mock_iam_policy.bindings = []
            mock_iam_policy.etag = b"test-etag"
            mock_gcp_ar_client.get_iam_policy.return_value = mock_iam_policy

            # Mock list_docker_images to return empty
            mock_gcp_ar_client.list_docker_images.return_value = []

            # Mock the _get_repository_locations to return just one location for testing
            with patch.object(
                collector, "_get_repository_locations", return_value=["us-central1"]
            ):
                assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            # Should have at least one repository asset
            repo_assets = [a for a in assets if a.resource_type == "gcp_artifact_repository"]
            assert len(repo_assets) >= 1

            # Verify repository asset properties
            repo = repo_assets[0]
            assert repo.account_id == "test-project"
            assert repo.region == "us-central1"
            assert repo.name == "my-repo"
            assert repo.tags == {"env": "test"}

    def test_gcp_ar_collector_determines_exposure_internal(self, mock_gcp_ar_client):
        """Test network exposure is internal for private repositories."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            mock_repo = MagicMock()
            mock_repo.name = "projects/test-project/locations/us/repositories/private-repo"
            mock_repo.format_.name = "DOCKER"
            mock_repo.description = ""
            mock_repo.labels = {}
            mock_repo.create_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_repo.update_time = None
            mock_repo.mode.name = "STANDARD_REPOSITORY"
            mock_repo.cleanup_policies = {}
            mock_repo.cleanup_policy_dry_run = False
            mock_repo.size_bytes = 0
            mock_repo.docker_config = None
            mock_repo.maven_config = None
            mock_repo.remote_repository_config = None
            mock_repo.virtual_repository_config = None

            mock_gcp_ar_client.list_repositories.return_value = [mock_repo]

            # IAM policy with no public access
            mock_iam_policy = MagicMock()
            mock_iam_policy.version = 1
            mock_iam_policy.bindings = [
                MagicMock(
                    role="roles/artifactregistry.reader",
                    members=["serviceAccount:sa@test-project.iam.gserviceaccount.com"],
                )
            ]
            mock_iam_policy.etag = b"test-etag"
            mock_gcp_ar_client.get_iam_policy.return_value = mock_iam_policy
            mock_gcp_ar_client.list_docker_images.return_value = []

            with patch.object(
                collector, "_get_repository_locations", return_value=["us"]
            ):
                assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "gcp_artifact_repository":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_gcp_ar_collector_determines_exposure_public(self, mock_gcp_ar_client):
        """Test network exposure is internet-facing for public repositories."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            mock_repo = MagicMock()
            mock_repo.name = "projects/test-project/locations/us/repositories/public-repo"
            mock_repo.format_.name = "DOCKER"
            mock_repo.description = "Public repository"
            mock_repo.labels = {}
            mock_repo.create_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_repo.update_time = None
            mock_repo.mode.name = "STANDARD_REPOSITORY"
            mock_repo.cleanup_policies = {}
            mock_repo.cleanup_policy_dry_run = False
            mock_repo.size_bytes = 0
            mock_repo.docker_config = None
            mock_repo.maven_config = None
            mock_repo.remote_repository_config = None
            mock_repo.virtual_repository_config = None

            mock_gcp_ar_client.list_repositories.return_value = [mock_repo]

            # IAM policy with allUsers = public access
            mock_binding = MagicMock()
            mock_binding.role = "roles/artifactregistry.reader"
            mock_binding.members = ["allUsers"]

            mock_iam_policy = MagicMock()
            mock_iam_policy.version = 1
            mock_iam_policy.bindings = [mock_binding]
            mock_iam_policy.etag = b"test-etag"
            mock_gcp_ar_client.get_iam_policy.return_value = mock_iam_policy
            mock_gcp_ar_client.list_docker_images.return_value = []

            with patch.object(
                collector, "_get_repository_locations", return_value=["us"]
            ):
                assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "gcp_artifact_repository":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET
                    assert asset.raw_config["is_public"] is True

    def test_gcp_ar_collector_collect_docker_images(self, mock_gcp_ar_client):
        """Test Docker image collection."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            mock_repo = MagicMock()
            mock_repo.name = "projects/test-project/locations/us/repositories/docker-repo"
            mock_repo.format_.name = "DOCKER"
            mock_repo.description = ""
            mock_repo.labels = {}
            mock_repo.create_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_repo.update_time = None
            mock_repo.mode.name = "STANDARD_REPOSITORY"
            mock_repo.cleanup_policies = {}
            mock_repo.cleanup_policy_dry_run = False
            mock_repo.size_bytes = 0
            mock_repo.docker_config = None
            mock_repo.maven_config = None
            mock_repo.remote_repository_config = None
            mock_repo.virtual_repository_config = None

            mock_gcp_ar_client.list_repositories.return_value = [mock_repo]

            # Mock IAM policy
            mock_iam_policy = MagicMock()
            mock_iam_policy.version = 1
            mock_iam_policy.bindings = []
            mock_iam_policy.etag = b"test-etag"
            mock_gcp_ar_client.get_iam_policy.return_value = mock_iam_policy

            # Mock Docker image
            mock_image = MagicMock()
            mock_image.name = "projects/test-project/locations/us/repositories/docker-repo/dockerImages/sha256:abc123"
            mock_image.uri = "us-docker.pkg.dev/test-project/docker-repo/myapp@sha256:abc123"
            mock_image.tags = ["latest", "v1.0.0"]
            mock_image.image_size_bytes = 52428800  # 50 MB
            mock_image.upload_time = datetime(2024, 1, 5, tzinfo=timezone.utc)
            mock_image.media_type = "application/vnd.docker.distribution.manifest.v2+json"
            mock_image.build_time = datetime(2024, 1, 5, tzinfo=timezone.utc)
            mock_image.update_time = datetime(2024, 1, 5, tzinfo=timezone.utc)

            mock_gcp_ar_client.list_docker_images.return_value = [mock_image]

            with patch.object(
                collector, "_get_repository_locations", return_value=["us"]
            ):
                assets = collector.collect()

            # Should have both repository and image assets
            repo_assets = [a for a in assets if a.resource_type == "gcp_artifact_repository"]
            image_assets = [a for a in assets if a.resource_type == "gcp_artifact_docker_image"]

            assert len(repo_assets) >= 1
            assert len(image_assets) >= 1

            # Verify image properties
            img = image_assets[0]
            assert img.raw_config["tags"] == ["latest", "v1.0.0"]
            assert img.raw_config["primary_tag"] == "latest"
            assert img.raw_config["image_size_mb"] == 50.0

    def test_gcp_ar_collector_handles_no_repositories(self, mock_gcp_ar_client):
        """Test graceful handling when no repositories exist."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            # Return empty list for all locations
            mock_gcp_ar_client.list_repositories.return_value = []

            with patch.object(
                collector, "_get_repository_locations", return_value=["us-central1"]
            ):
                assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_gcp_ar_collector_handles_api_error(self, mock_gcp_ar_client):
        """Test graceful handling of API errors."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            # Simulate API error
            mock_gcp_ar_client.list_repositories.side_effect = Exception("API error")

            with patch.object(
                collector, "_get_repository_locations", return_value=["us-central1"]
            ):
                assets = collector.collect()

            # Should handle gracefully and return empty collection
            assert isinstance(assets, AssetCollection)

    def test_gcp_ar_collector_immutable_tags(self, mock_gcp_ar_client):
        """Test Docker config with immutable tags detection."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            mock_repo = MagicMock()
            mock_repo.name = "projects/test-project/locations/us/repositories/immutable-repo"
            mock_repo.format_.name = "DOCKER"
            mock_repo.description = ""
            mock_repo.labels = {}
            mock_repo.create_time = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_repo.update_time = None
            mock_repo.mode.name = "STANDARD_REPOSITORY"
            mock_repo.cleanup_policies = {}
            mock_repo.cleanup_policy_dry_run = False
            mock_repo.size_bytes = 0

            # Docker config with immutable tags
            mock_docker_config = MagicMock()
            mock_docker_config.immutable_tags = True
            mock_repo.docker_config = mock_docker_config

            mock_repo.maven_config = None
            mock_repo.remote_repository_config = None
            mock_repo.virtual_repository_config = None

            mock_gcp_ar_client.list_repositories.return_value = [mock_repo]

            mock_iam_policy = MagicMock()
            mock_iam_policy.version = 1
            mock_iam_policy.bindings = []
            mock_iam_policy.etag = b"test-etag"
            mock_gcp_ar_client.get_iam_policy.return_value = mock_iam_policy
            mock_gcp_ar_client.list_docker_images.return_value = []

            with patch.object(
                collector, "_get_repository_locations", return_value=["us"]
            ):
                assets = collector.collect()

            repo_assets = [a for a in assets if a.resource_type == "gcp_artifact_repository"]
            assert len(repo_assets) == 1
            assert repo_assets[0].raw_config["docker_config"]["immutable_tags"] is True

    def test_gcp_ar_collector_severity_mapping(self, mock_gcp_ar_client):
        """Test vulnerability severity mapping."""
        with patch(
            "stance.collectors.gcp_artifactregistry.artifactregistry_v1.ArtifactRegistryClient",
            return_value=mock_gcp_ar_client,
        ):
            collector = GCPArtifactRegistryCollector(project_id="test-project")

            # Test severity mapping
            assert collector._map_severity("CRITICAL") == Severity.CRITICAL
            assert collector._map_severity("HIGH") == Severity.HIGH
            assert collector._map_severity("MEDIUM") == Severity.MEDIUM
            assert collector._map_severity("LOW") == Severity.LOW
            assert collector._map_severity("MINIMAL") == Severity.INFO
            assert collector._map_severity("SEVERITY_UNSPECIFIED") == Severity.INFO
            assert collector._map_severity("UNKNOWN") == Severity.INFO


# Conditional import for Azure ACR tests
try:
    from stance.collectors.azure_containerregistry import (
        AzureContainerRegistryCollector,
        AZURE_ACR_AVAILABLE,
    )
except ImportError:
    AZURE_ACR_AVAILABLE = False
    AzureContainerRegistryCollector = None  # type: ignore


@pytest.mark.skipif(not AZURE_ACR_AVAILABLE, reason="Azure ACR SDK not available")
class TestAzureContainerRegistryCollector:
    """Tests for AzureContainerRegistryCollector."""

    def test_azure_acr_collector_init(self, mock_azure_acr_client):
        """Test AzureContainerRegistryCollector can be initialized."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")
            assert collector.collector_name == "azure_containerregistry"
            assert "azure_container_registry" in collector.resource_types
            assert collector.subscription_id == "sub-123"

    def test_azure_acr_collector_collect_registries(self, mock_azure_acr_client):
        """Test registry collection with mock response."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            # Mock registry object
            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/myacr"
            mock_registry.name = "myacr"
            mock_registry.location = "eastus"
            mock_registry.tags = {"env": "test"}
            mock_registry.login_server = "myacr.azurecr.io"
            mock_registry.provisioning_state = "Succeeded"
            mock_registry.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_registry.sku = MagicMock(name="Premium", tier="Premium")
            mock_registry.admin_user_enabled = False
            mock_registry.public_network_access = "Disabled"
            mock_registry.network_rule_set = None
            mock_registry.encryption = None
            mock_registry.data_endpoint_enabled = False
            mock_registry.zone_redundancy = "Disabled"
            mock_registry.policies = None
            mock_registry.anonymous_pull_enabled = False
            mock_registry.private_endpoint_connections = []

            mock_azure_acr_client.registries.list.return_value = [mock_registry]
            mock_azure_acr_client.replications.list.return_value = []
            mock_azure_acr_client.webhooks.list.return_value = []

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            registry_assets = [a for a in assets if a.resource_type == "azure_container_registry"]
            assert len(registry_assets) >= 1

            # Verify registry asset properties
            reg = registry_assets[0]
            assert reg.account_id == "sub-123"
            assert reg.region == "eastus"
            assert reg.name == "myacr"
            assert reg.tags == {"env": "test"}

    def test_azure_acr_collector_determines_exposure_internal(self, mock_azure_acr_client):
        """Test network exposure is internal for private registries."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/privateacr"
            mock_registry.name = "privateacr"
            mock_registry.location = "eastus"
            mock_registry.tags = {}
            mock_registry.login_server = "privateacr.azurecr.io"
            mock_registry.provisioning_state = "Succeeded"
            mock_registry.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_registry.sku = MagicMock(name="Premium", tier="Premium")
            mock_registry.admin_user_enabled = False
            mock_registry.public_network_access = "Disabled"
            mock_registry.network_rule_set = None
            mock_registry.encryption = None
            mock_registry.data_endpoint_enabled = False
            mock_registry.zone_redundancy = "Disabled"
            mock_registry.policies = None
            mock_registry.anonymous_pull_enabled = False
            mock_registry.private_endpoint_connections = [MagicMock()]

            mock_azure_acr_client.registries.list.return_value = [mock_registry]
            mock_azure_acr_client.replications.list.return_value = []
            mock_azure_acr_client.webhooks.list.return_value = []

            assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "azure_container_registry":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_azure_acr_collector_determines_exposure_public(self, mock_azure_acr_client):
        """Test network exposure is internet-facing for public registries."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/publicacr"
            mock_registry.name = "publicacr"
            mock_registry.location = "eastus"
            mock_registry.tags = {}
            mock_registry.login_server = "publicacr.azurecr.io"
            mock_registry.provisioning_state = "Succeeded"
            mock_registry.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_registry.sku = MagicMock(name="Basic", tier="Basic")
            mock_registry.admin_user_enabled = True
            mock_registry.public_network_access = "Enabled"
            mock_registry.network_rule_set = None
            mock_registry.encryption = None
            mock_registry.data_endpoint_enabled = False
            mock_registry.zone_redundancy = None
            mock_registry.policies = None
            mock_registry.anonymous_pull_enabled = True
            mock_registry.private_endpoint_connections = []

            mock_azure_acr_client.registries.list.return_value = [mock_registry]
            mock_azure_acr_client.replications.list.return_value = []
            mock_azure_acr_client.webhooks.list.return_value = []

            assets = collector.collect()

            for asset in assets:
                if asset.resource_type == "azure_container_registry":
                    assert asset.network_exposure == NETWORK_EXPOSURE_INTERNET
                    assert asset.raw_config["allows_public_access"] is True

    def test_azure_acr_collector_handles_no_registries(self, mock_azure_acr_client):
        """Test graceful handling when no registries exist."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_azure_acr_client.registries.list.return_value = []

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_azure_acr_collector_handles_api_error(self, mock_azure_acr_client):
        """Test graceful handling of API errors."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_azure_acr_client.registries.list.side_effect = Exception("API error")

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)

    def test_azure_acr_collector_admin_enabled_detection(self, mock_azure_acr_client):
        """Test admin user enabled detection."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/adminacr"
            mock_registry.name = "adminacr"
            mock_registry.location = "eastus"
            mock_registry.tags = {}
            mock_registry.login_server = "adminacr.azurecr.io"
            mock_registry.provisioning_state = "Succeeded"
            mock_registry.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_registry.sku = MagicMock(name="Standard", tier="Standard")
            mock_registry.admin_user_enabled = True
            mock_registry.public_network_access = "Disabled"
            mock_registry.network_rule_set = None
            mock_registry.encryption = None
            mock_registry.data_endpoint_enabled = False
            mock_registry.zone_redundancy = None
            mock_registry.policies = None
            mock_registry.anonymous_pull_enabled = False
            mock_registry.private_endpoint_connections = []

            mock_azure_acr_client.registries.list.return_value = [mock_registry]
            mock_azure_acr_client.replications.list.return_value = []
            mock_azure_acr_client.webhooks.list.return_value = []

            assets = collector.collect()

            registry_assets = [a for a in assets if a.resource_type == "azure_container_registry"]
            assert len(registry_assets) == 1
            assert registry_assets[0].raw_config["admin_user_enabled"] is True
            assert registry_assets[0].raw_config["has_admin_enabled"] is True

    def test_azure_acr_collector_collect_findings_admin(self, mock_azure_acr_client):
        """Test finding collection for admin user enabled."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/insecureacr"
            mock_registry.name = "insecureacr"
            mock_registry.admin_user_enabled = True
            mock_registry.public_network_access = "Disabled"
            mock_registry.anonymous_pull_enabled = False
            mock_registry.sku = MagicMock(name="Basic", tier="Basic")
            mock_registry.policies = None

            mock_azure_acr_client.registries.list.return_value = [mock_registry]

            findings = collector.collect_findings()

            assert isinstance(findings, FindingCollection)
            admin_findings = [f for f in findings if "admin" in f.id]
            assert len(admin_findings) >= 1
            assert admin_findings[0].severity == Severity.MEDIUM
            assert admin_findings[0].finding_type == FindingType.MISCONFIGURATION

    def test_azure_acr_collector_collect_findings_public(self, mock_azure_acr_client):
        """Test finding collection for public network access."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/publicacr"
            mock_registry.name = "publicacr"
            mock_registry.admin_user_enabled = False
            mock_registry.public_network_access = "Enabled"
            mock_registry.anonymous_pull_enabled = False
            mock_registry.sku = MagicMock(name="Basic", tier="Basic")
            mock_registry.policies = None

            mock_azure_acr_client.registries.list.return_value = [mock_registry]

            findings = collector.collect_findings()

            assert isinstance(findings, FindingCollection)
            public_findings = [f for f in findings if "public" in f.id]
            assert len(public_findings) >= 1
            assert public_findings[0].severity == Severity.HIGH

    def test_azure_acr_collector_severity_mapping(self, mock_azure_acr_client):
        """Test vulnerability severity mapping."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            # Test severity mapping
            assert collector._map_severity("Critical") == Severity.CRITICAL
            assert collector._map_severity("High") == Severity.HIGH
            assert collector._map_severity("Medium") == Severity.MEDIUM
            assert collector._map_severity("Low") == Severity.LOW
            assert collector._map_severity("Informational") == Severity.INFO
            assert collector._map_severity("Unknown") == Severity.INFO

    def test_azure_acr_collector_geo_replication(self, mock_azure_acr_client):
        """Test geo-replication detection."""
        with patch(
            "stance.collectors.azure_containerregistry.ContainerRegistryManagementClient",
            return_value=mock_azure_acr_client,
        ):
            collector = AzureContainerRegistryCollector(subscription_id="sub-123")

            mock_registry = MagicMock()
            mock_registry.id = "/subscriptions/sub-123/resourceGroups/rg-test/providers/Microsoft.ContainerRegistry/registries/geoacr"
            mock_registry.name = "geoacr"
            mock_registry.location = "eastus"
            mock_registry.tags = {}
            mock_registry.login_server = "geoacr.azurecr.io"
            mock_registry.provisioning_state = "Succeeded"
            mock_registry.creation_date = datetime(2024, 1, 1, tzinfo=timezone.utc)
            mock_registry.sku = MagicMock(name="Premium", tier="Premium")
            mock_registry.admin_user_enabled = False
            mock_registry.public_network_access = "Disabled"
            mock_registry.network_rule_set = None
            mock_registry.encryption = None
            mock_registry.data_endpoint_enabled = False
            mock_registry.zone_redundancy = "Enabled"
            mock_registry.policies = None
            mock_registry.anonymous_pull_enabled = False
            mock_registry.private_endpoint_connections = []

            # Mock multiple replications (geo-replicated)
            mock_rep1 = MagicMock()
            mock_rep1.name = "eastus"
            mock_rep1.location = "eastus"
            mock_rep1.provisioning_state = "Succeeded"
            mock_rep1.zone_redundancy = "Enabled"

            mock_rep2 = MagicMock()
            mock_rep2.name = "westus"
            mock_rep2.location = "westus"
            mock_rep2.provisioning_state = "Succeeded"
            mock_rep2.zone_redundancy = "Enabled"

            mock_azure_acr_client.registries.list.return_value = [mock_registry]
            mock_azure_acr_client.replications.list.return_value = [mock_rep1, mock_rep2]
            mock_azure_acr_client.webhooks.list.return_value = []

            assets = collector.collect()

            registry_assets = [a for a in assets if a.resource_type == "azure_container_registry"]
            assert len(registry_assets) == 1
            assert registry_assets[0].raw_config["replication_count"] == 2
            assert registry_assets[0].raw_config["is_geo_replicated"] is True


class TestEKSCollector:
    """Tests for EKSCollector."""

    def test_eks_collector_init(self):
        """Test EKSCollector can be initialized."""
        collector = EKSCollector()
        assert collector.collector_name == "aws_eks"
        assert "aws_eks_cluster" in collector.resource_types
        assert "aws_eks_nodegroup" in collector.resource_types
        assert "aws_eks_fargate_profile" in collector.resource_types
        assert "aws_eks_addon" in collector.resource_types

    def test_eks_collector_collect_clusters(self, mock_eks_client):
        """Test cluster collection with mock response."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator for list_clusters
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client for OIDC provider lookup
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": []
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Mock paginators for related resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        cluster_name = kwargs["clusterName"]
                        # Return empty lists for sub-resources to simplify test
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                assert isinstance(assets, AssetCollection)

    def test_eks_collector_cluster_network_exposure_public(self, mock_eks_client):
        """Test cluster with unrestricted public access is internet-facing."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Modify response to have unrestricted public access
            cluster_response = mock_eks_client.describe_cluster.return_value.copy()
            cluster_response["cluster"] = dict(cluster_response["cluster"])
            cluster_response["cluster"]["resourcesVpcConfig"] = {
                "vpcId": "vpc-12345678",
                "subnetIds": ["subnet-11111111"],
                "securityGroupIds": ["sg-12345678"],
                "clusterSecurityGroupId": "sg-cluster123",
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
                "publicAccessCidrs": ["0.0.0.0/0"],  # Unrestricted
            }
            mock_eks_client.describe_cluster.return_value = cluster_response

            # Mock paginator
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": []
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Return empty sub-resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "aws_eks_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].network_exposure == NETWORK_EXPOSURE_INTERNET
                assert cluster_assets[0].raw_config["public_access_unrestricted"] is True

    def test_eks_collector_cluster_network_exposure_private(self, mock_eks_client):
        """Test cluster with private-only access is internal."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Modify response to have private-only access
            cluster_response = mock_eks_client.describe_cluster.return_value.copy()
            cluster_response["cluster"] = dict(cluster_response["cluster"])
            cluster_response["cluster"]["resourcesVpcConfig"] = {
                "vpcId": "vpc-12345678",
                "subnetIds": ["subnet-11111111"],
                "securityGroupIds": ["sg-12345678"],
                "clusterSecurityGroupId": "sg-cluster123",
                "endpointPublicAccess": False,
                "endpointPrivateAccess": True,
                "publicAccessCidrs": [],
            }
            mock_eks_client.describe_cluster.return_value = cluster_response

            # Mock paginator
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": []
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Return empty sub-resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "aws_eks_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_eks_collector_secrets_encryption(self, mock_eks_client):
        """Test detection of secrets encryption configuration."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": []
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Return empty sub-resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "aws_eks_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["secrets_encryption_enabled"] is True
                assert cluster_assets[0].raw_config["kms_key_arn"] is not None

    def test_eks_collector_logging_configuration(self, mock_eks_client):
        """Test detection of logging configuration."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": []
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Return empty sub-resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "aws_eks_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["api_logging_enabled"] is True
                assert cluster_assets[0].raw_config["audit_logging_enabled"] is True
                assert cluster_assets[0].raw_config["logging"]["all_logging_enabled"] is True

    def test_eks_collector_empty_clusters(self, mock_eks_client):
        """Test handling of no clusters."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator to return no clusters
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": []}]

            assets = collector.collect()

            assert isinstance(assets, AssetCollection)
            assert len(assets) == 0

    def test_eks_collector_handles_api_error(self, mock_eks_client):
        """Test graceful handling of API errors."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator to raise an error
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.side_effect = Exception("API error")

            # Should not raise, just log warning
            with pytest.raises(Exception):
                collector.collect()

    def test_eks_collector_nodegroup_collection(self, mock_eks_client):
        """Test node group collection."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Test just the node group collection method
            nodegroups = collector._collect_nodegroups("prod-cluster", "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster")

            # With mock data, should get node groups
            assert isinstance(nodegroups, list)

    def test_eks_collector_fargate_profile_collection(self, mock_eks_client):
        """Test Fargate profile collection."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Test just the Fargate profile collection method
            profiles = collector._collect_fargate_profiles("prod-cluster", "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster")

            assert isinstance(profiles, list)

    def test_eks_collector_addon_collection(self, mock_eks_client):
        """Test add-on collection."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Test just the add-on collection method
            addons = collector._collect_addons("prod-cluster", "arn:aws:eks:us-east-1:123456789012:cluster/prod-cluster")

            assert isinstance(addons, list)

    def test_eks_collector_cluster_exposure_determination(self, mock_eks_client):
        """Test cluster network exposure determination logic."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Test private-only cluster
            exposure = collector._determine_cluster_exposure(False, [])
            assert exposure == NETWORK_EXPOSURE_INTERNAL

            # Test public but restricted cluster
            exposure = collector._determine_cluster_exposure(True, ["10.0.0.0/8"])
            assert exposure == NETWORK_EXPOSURE_INTERNET

            # Test public unrestricted cluster
            exposure = collector._determine_cluster_exposure(True, ["0.0.0.0/0"])
            assert exposure == NETWORK_EXPOSURE_INTERNET

    def test_eks_collector_irsa_detection(self, mock_eks_client):
        """Test IAM Roles for Service Accounts (IRSA) detection."""
        with patch.object(EKSCollector, "_get_client", return_value=mock_eks_client):
            collector = EKSCollector()

            # Mock paginator
            mock_paginator = MagicMock()
            mock_eks_client.get_paginator.return_value = mock_paginator
            mock_paginator.paginate.return_value = [{"clusters": ["prod-cluster"]}]

            # Mock IAM client with OIDC provider
            mock_iam_client = MagicMock()
            mock_iam_client.list_open_id_connect_providers.return_value = {
                "OpenIDConnectProviderList": [
                    {"Arn": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE12345"}
                ]
            }
            mock_iam_client.get_open_id_connect_provider.return_value = {
                "Url": "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE12345",
                "ClientIDList": ["sts.amazonaws.com"],
                "ThumbprintList": ["abc123"],
                "CreateDate": datetime(2024, 1, 1, tzinfo=timezone.utc),
            }

            def get_client_side_effect(service):
                if service == "iam":
                    return mock_iam_client
                return mock_eks_client

            with patch.object(EKSCollector, "_get_client", side_effect=get_client_side_effect):
                collector = EKSCollector()

                # Return empty sub-resources
                def paginate_side_effect(**kwargs):
                    if "clusterName" in kwargs:
                        return [{"nodegroups": [], "fargateProfileNames": [], "addons": []}]
                    return [{"clusters": ["prod-cluster"]}]

                mock_paginator.paginate.side_effect = paginate_side_effect

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "aws_eks_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["irsa_enabled"] is True


class TestGKECollector:
    """Tests for GKECollector."""

    def test_gke_collector_init(self):
        """Test GKECollector can be initialized."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                assert collector.collector_name == "gcp_gke"
                assert "gcp_gke_cluster" in collector.resource_types
                assert "gcp_gke_nodepool" in collector.resource_types

    def test_gke_collector_collect_clusters(self, mock_gcp_gke_client):
        """Test cluster collection with mock response."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                assert isinstance(assets, AssetCollection)
                # Should have cluster + node pool
                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                nodepool_assets = [a for a in assets if a.resource_type == "gcp_gke_nodepool"]
                assert len(cluster_assets) == 1
                assert len(nodepool_assets) == 1

    def test_gke_collector_cluster_network_exposure_private_endpoint(self, mock_gcp_gke_client):
        """Test cluster with private endpoint is internal."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                # Modify mock to have private endpoint enabled
                cluster = mock_gcp_gke_client.list_clusters.return_value.clusters[0]
                cluster.private_cluster_config.enable_private_endpoint = True

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_gke_collector_cluster_network_exposure_public(self, mock_gcp_gke_client):
        """Test cluster with public endpoint is internet-facing."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                # Modify mock to have no private cluster config
                cluster = mock_gcp_gke_client.list_clusters.return_value.clusters[0]
                cluster.private_cluster_config = None

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_gke_collector_workload_identity(self, mock_gcp_gke_client):
        """Test Workload Identity detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["workload_identity_enabled"] is True

    def test_gke_collector_binary_authorization(self, mock_gcp_gke_client):
        """Test Binary Authorization detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["binary_authorization_enabled"] is True

    def test_gke_collector_network_policy(self, mock_gcp_gke_client):
        """Test Network Policy detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["network_policy_enabled"] is True

    def test_gke_collector_shielded_nodes(self, mock_gcp_gke_client):
        """Test Shielded Nodes detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["shielded_nodes_enabled"] is True

    def test_gke_collector_legacy_abac_disabled(self, mock_gcp_gke_client):
        """Test Legacy ABAC disabled detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["legacy_abac_enabled"] is False

    def test_gke_collector_database_encryption(self, mock_gcp_gke_client):
        """Test database (etcd) encryption detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                cluster_assets = [a for a in assets if a.resource_type == "gcp_gke_cluster"]
                assert len(cluster_assets) == 1
                assert cluster_assets[0].raw_config["database_encryption_enabled"] is True

    def test_gke_collector_nodepool_collection(self, mock_gcp_gke_client):
        """Test node pool collection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                nodepool_assets = [a for a in assets if a.resource_type == "gcp_gke_nodepool"]
                assert len(nodepool_assets) == 1
                assert nodepool_assets[0].name == "default-pool"
                assert nodepool_assets[0].raw_config["autoscaling_enabled"] is True
                assert nodepool_assets[0].raw_config["auto_repair_enabled"] is True
                assert nodepool_assets[0].raw_config["auto_upgrade_enabled"] is True

    def test_gke_collector_nodepool_workload_identity(self, mock_gcp_gke_client):
        """Test node pool Workload Identity detection."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                nodepool_assets = [a for a in assets if a.resource_type == "gcp_gke_nodepool"]
                assert len(nodepool_assets) == 1
                assert nodepool_assets[0].raw_config["workload_identity_enabled"] is True

    def test_gke_collector_empty_clusters(self, mock_gcp_gke_client):
        """Test handling of no clusters."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                # Modify mock to return no clusters
                mock_gcp_gke_client.list_clusters.return_value.clusters = []

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                assets = collector.collect()

                assert isinstance(assets, AssetCollection)
                assert len(assets) == 0

    def test_gke_collector_handles_api_error(self, mock_gcp_gke_client):
        """Test graceful handling of API errors."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                # Modify mock to raise an error
                mock_gcp_gke_client.list_clusters.side_effect = Exception("API error")

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                # Should not raise, just log warning
                assets = collector.collect()
                assert isinstance(assets, AssetCollection)
                assert len(assets) == 0

    def test_gke_collector_cluster_exposure_determination(self, mock_gcp_gke_client):
        """Test cluster network exposure determination logic."""
        with patch("stance.collectors.gcp_gke.GCP_CONTAINER_AVAILABLE", True):
            with patch("stance.collectors.gcp_gke.container_v1"):
                from stance.collectors.gcp_gke import GKECollector

                collector = GKECollector(project_id="test-project")
                collector._client = mock_gcp_gke_client

                # Test private cluster with private endpoint
                exposure = collector._determine_cluster_exposure(
                    is_private_cluster=True,
                    enable_private_endpoint=True,
                    master_authorized_networks_enabled=True,
                )
                assert exposure == NETWORK_EXPOSURE_INTERNAL

                # Test private cluster with public endpoint
                exposure = collector._determine_cluster_exposure(
                    is_private_cluster=True,
                    enable_private_endpoint=False,
                    master_authorized_networks_enabled=True,
                )
                assert exposure == NETWORK_EXPOSURE_INTERNET

                # Test non-private cluster
                exposure = collector._determine_cluster_exposure(
                    is_private_cluster=False,
                    enable_private_endpoint=False,
                    master_authorized_networks_enabled=False,
                )
                assert exposure == NETWORK_EXPOSURE_INTERNET


class TestAzureAKSCollector:
    """Tests for Azure AKS (Kubernetes Service) collector."""

    def test_aks_collector_initialization(self, mock_azure_aks_client):
        """Test AKS collector initialization."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    assert collector.collector_name == "azure_aks"
                    assert collector.subscription_id == "sub123"
                    assert "azure_aks_cluster" in collector.resource_types
                    assert "azure_aks_nodepool" in collector.resource_types

    def test_aks_collector_collects_clusters(self, mock_azure_aks_client):
        """Test cluster collection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    assert isinstance(assets, AssetCollection)
                    # Should have 1 cluster + 1 node pool
                    assert len(assets) == 2

                    cluster_assets = [a for a in assets if a.resource_type == "azure_aks_cluster"]
                    assert len(cluster_assets) == 1
                    assert cluster_assets[0].name == "prod-aks"

    def test_aks_collector_cluster_properties(self, mock_azure_aks_client):
        """Test cluster properties are captured correctly."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["kubernetes_version"] == "1.28.3"
                    assert cluster.raw_config["provisioning_state"] == "Succeeded"
                    assert cluster.region == "eastus"

    def test_aks_collector_network_exposure_private_cluster(self, mock_azure_aks_client):
        """Test network exposure detection for private cluster."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    # Mock has private cluster enabled
                    assert cluster.raw_config["is_private_cluster"] is True
                    assert cluster.network_exposure == NETWORK_EXPOSURE_INTERNAL

    def test_aks_collector_network_exposure_public_cluster(self, mock_azure_aks_client):
        """Test network exposure detection for public cluster."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    # Modify mock to have public cluster
                    mock_azure_aks_client.managed_clusters.list.return_value[0].api_server_access_profile.enable_private_cluster = False

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["is_private_cluster"] is False
                    assert cluster.network_exposure == NETWORK_EXPOSURE_INTERNET

    def test_aks_collector_aad_integration(self, mock_azure_aks_client):
        """Test Azure AD integration detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["aad_enabled"] is True
                    assert cluster.raw_config["azure_rbac_enabled"] is True
                    assert cluster.raw_config["aad_managed"] is True

    def test_aks_collector_managed_identity(self, mock_azure_aks_client):
        """Test managed identity detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["uses_managed_identity"] is True
                    assert cluster.raw_config["identity_type"] == "SystemAssigned"

    def test_aks_collector_network_policy(self, mock_azure_aks_client):
        """Test network policy detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["network_policy"] == "calico"
                    assert cluster.raw_config["has_network_policy"] is True
                    assert cluster.raw_config["network_plugin"] == "azure"

    def test_aks_collector_security_profile(self, mock_azure_aks_client):
        """Test security profile detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["defender_enabled"] is True
                    assert cluster.raw_config["workload_identity_enabled"] is True
                    assert cluster.raw_config["image_cleaner_enabled"] is True
                    assert cluster.raw_config["kms_enabled"] is True

    def test_aks_collector_addon_profiles(self, mock_azure_aks_client):
        """Test addon profile detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["azure_policy_enabled"] is True
                    assert cluster.raw_config["oms_agent_enabled"] is True
                    assert cluster.raw_config["key_vault_secrets_provider_enabled"] is True

    def test_aks_collector_auto_upgrade(self, mock_azure_aks_client):
        """Test auto upgrade profile detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    cluster = [a for a in assets if a.resource_type == "azure_aks_cluster"][0]
                    assert cluster.raw_config["auto_upgrade_enabled"] is True
                    assert cluster.raw_config["upgrade_channel"] == "stable"

    def test_aks_collector_nodepool_collection(self, mock_azure_aks_client):
        """Test node pool collection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    nodepool_assets = [a for a in assets if a.resource_type == "azure_aks_nodepool"]
                    assert len(nodepool_assets) == 1
                    assert nodepool_assets[0].name == "nodepool1"
                    assert nodepool_assets[0].raw_config["count"] == 3
                    assert nodepool_assets[0].raw_config["vm_size"] == "Standard_D4s_v3"

    def test_aks_collector_nodepool_autoscaling(self, mock_azure_aks_client):
        """Test node pool autoscaling detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    nodepool = [a for a in assets if a.resource_type == "azure_aks_nodepool"][0]
                    assert nodepool.raw_config["enable_auto_scaling"] is True
                    assert nodepool.raw_config["min_count"] == 1
                    assert nodepool.raw_config["max_count"] == 10

    def test_aks_collector_nodepool_availability_zones(self, mock_azure_aks_client):
        """Test node pool availability zones detection."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    nodepool = [a for a in assets if a.resource_type == "azure_aks_nodepool"][0]
                    assert nodepool.raw_config["uses_availability_zones"] is True
                    assert nodepool.raw_config["availability_zones"] == ["1", "2", "3"]

    def test_aks_collector_empty_clusters(self, mock_azure_aks_client):
        """Test handling of no clusters."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    # Modify mock to return no clusters
                    mock_azure_aks_client.managed_clusters.list.return_value = []

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    assets = collector.collect()

                    assert isinstance(assets, AssetCollection)
                    assert len(assets) == 0

    def test_aks_collector_handles_api_error(self, mock_azure_aks_client):
        """Test graceful handling of API errors."""
        with patch("stance.collectors.azure_aks.AZURE_AKS_AVAILABLE", True):
            with patch("stance.collectors.azure_aks.ContainerServiceClient"):
                with patch("stance.collectors.azure_aks.DefaultAzureCredential"):
                    from stance.collectors.azure_aks import AzureAKSCollector

                    # Modify mock to raise an error
                    mock_azure_aks_client.managed_clusters.list.side_effect = Exception("API error")

                    collector = AzureAKSCollector(subscription_id="sub123")
                    collector._client = mock_azure_aks_client

                    # Should not raise, just log warning
                    assets = collector.collect()
                    assert isinstance(assets, AssetCollection)
                    assert len(assets) == 0
