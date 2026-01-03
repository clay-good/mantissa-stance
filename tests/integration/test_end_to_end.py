"""
Integration tests for Mantissa Stance end-to-end workflows.

Tests cover:
- Full scan workflow from collection to findings
- Querying findings after scan
- Compliance report generation
- Incremental scan detection
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import tempfile

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
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_INTERNET,
)
from stance.storage import LocalStorage, generate_snapshot_id
from stance.engine import PolicyLoader, PolicyEvaluator, run_evaluation
from stance.engine.compliance import ComplianceCalculator


@pytest.fixture
def mock_aws_services():
    """Fixture providing mocked AWS service responses."""
    with patch("boto3.Session") as mock_session:
        session = MagicMock()
        mock_session.return_value = session

        # Mock IAM client
        iam_client = MagicMock()
        iam_client.get_account_password_policy.return_value = {
            "PasswordPolicy": {
                "MinimumPasswordLength": 14,
                "RequireSymbols": True,
                "RequireNumbers": True,
            }
        }
        iam_client.get_account_summary.return_value = {
            "SummaryMap": {"AccountMFAEnabled": 1, "Users": 5}
        }

        # Mock S3 client
        s3_client = MagicMock()
        s3_client.list_buckets.return_value = {
            "Buckets": [
                {"Name": "secure-bucket", "CreationDate": datetime(2024, 1, 1)},
                {"Name": "insecure-bucket", "CreationDate": datetime(2024, 1, 2)},
            ]
        }

        # Mock EC2 client
        ec2_client = MagicMock()
        ec2_client.describe_instances.return_value = {"Reservations": []}
        ec2_client.describe_security_groups.return_value = {"SecurityGroups": []}

        def get_client(service_name, **kwargs):
            clients = {
                "iam": iam_client,
                "s3": s3_client,
                "ec2": ec2_client,
            }
            return clients.get(service_name, MagicMock())

        session.client = get_client

        yield {
            "session": session,
            "iam": iam_client,
            "s3": s3_client,
            "ec2": ec2_client,
        }


@pytest.fixture
def sample_assets() -> AssetCollection:
    """Create sample assets for testing."""
    assets = [
        Asset(
            id="arn:aws:s3:::secure-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="secure-bucket",
            tags={"Environment": "prod"},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={
                "encryption": {"enabled": True},
                "public_access_block": {
                    "block_public_acls": True,
                    "block_public_policy": True,
                    "ignore_public_acls": True,
                    "restrict_public_buckets": True,
                },
            },
        ),
        Asset(
            id="arn:aws:s3:::insecure-bucket",
            cloud_provider="aws",
            account_id="123456789012",
            region="us-east-1",
            resource_type="aws_s3_bucket",
            name="insecure-bucket",
            tags={"Environment": "dev"},
            network_exposure=NETWORK_EXPOSURE_INTERNET,
            created_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={
                "encryption": {"enabled": False},
                "public_access_block": {
                    "block_public_acls": False,
                    "block_public_policy": False,
                    "ignore_public_acls": False,
                    "restrict_public_buckets": False,
                },
            },
        ),
        Asset(
            id="arn:aws:iam::123456789012:root",
            cloud_provider="aws",
            account_id="123456789012",
            region="global",
            resource_type="aws_iam_account_summary",
            name="account-summary",
            tags={},
            network_exposure=NETWORK_EXPOSURE_INTERNAL,
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            last_seen=datetime(2024, 1, 15, tzinfo=timezone.utc),
            raw_config={
                "account_mfa_enabled": True,
                "users": 5,
                "roles": 10,
            },
        ),
    ]
    return AssetCollection(assets)


@pytest.fixture
def sample_policies() -> PolicyCollection:
    """Create sample policies for testing."""
    policies = [
        Policy(
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
            ],
            remediation=Remediation(
                guidance="Enable encryption on the S3 bucket.",
                automation_supported=False,
            ),
            tags=["s3", "encryption"],
            references=[],
        ),
        Policy(
            id="aws-s3-002",
            name="S3 Public Access Block",
            description="Ensure S3 buckets block public access.",
            enabled=True,
            severity=Severity.CRITICAL,
            resource_type="aws_s3_bucket",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.public_access_block.block_public_acls == true",
            ),
            compliance=[
                ComplianceMapping(
                    framework="cis-aws-foundations",
                    version="1.5.0",
                    control="2.1.5",
                ),
            ],
            remediation=Remediation(
                guidance="Enable public access block on the S3 bucket.",
                automation_supported=False,
            ),
            tags=["s3", "public-access"],
            references=[],
        ),
        Policy(
            id="aws-iam-001",
            name="Root Account MFA",
            description="Ensure root account has MFA enabled.",
            enabled=True,
            severity=Severity.CRITICAL,
            resource_type="aws_iam_account_summary",
            check=Check(
                check_type=CheckType.EXPRESSION,
                expression="resource.account_mfa_enabled == true",
            ),
            compliance=[
                ComplianceMapping(
                    framework="cis-aws-foundations",
                    version="1.5.0",
                    control="1.5",
                ),
            ],
            remediation=Remediation(
                guidance="Enable MFA on the root account.",
                automation_supported=False,
            ),
            tags=["iam", "mfa"],
            references=[],
        ),
    ]
    return PolicyCollection(policies)


class TestFullScanWorkflow:
    """Test complete scan workflow."""

    def test_full_scan_workflow(self, tmp_path, sample_assets, sample_policies):
        """Test complete scan from collection to findings."""
        # 1. Initialize local storage
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)

        # 2. Generate snapshot ID
        snapshot_id = generate_snapshot_id()

        # 3. Store assets (simulating collection)
        storage.store_assets(sample_assets, snapshot_id)

        # 4. Evaluate policies
        evaluator = PolicyEvaluator()
        findings, eval_result = evaluator.evaluate_all(sample_policies, sample_assets)

        # 5. Store findings
        storage.store_findings(findings, snapshot_id)

        # 6. Verify findings match expected
        assert len(findings) >= 1  # At least insecure-bucket should fail

        # Check we found the encryption issue
        encryption_findings = [
            f for f in findings if f.rule_id == "aws-s3-001"
        ]
        assert len(encryption_findings) == 1
        assert encryption_findings[0].asset_id == "arn:aws:s3:::insecure-bucket"
        assert encryption_findings[0].severity == Severity.HIGH

        # Check we found the public access issue
        public_access_findings = [
            f for f in findings if f.rule_id == "aws-s3-002"
        ]
        assert len(public_access_findings) == 1
        assert public_access_findings[0].severity == Severity.CRITICAL

        # Root MFA should pass (account_mfa_enabled is True)
        mfa_findings = [f for f in findings if f.rule_id == "aws-iam-001"]
        assert len(mfa_findings) == 0  # No finding = compliant

    def test_findings_stored_correctly(self, tmp_path, sample_assets, sample_policies):
        """Test that findings are stored and retrievable."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(sample_policies, sample_assets)
        storage.store_findings(findings, snapshot_id)

        # Retrieve findings
        retrieved = storage.get_findings(snapshot_id)

        assert len(retrieved) == len(findings)


class TestQueryAfterScan:
    """Test querying findings after scan."""

    def test_query_findings_by_severity(self, tmp_path, sample_assets, sample_policies):
        """Test querying findings by severity."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(sample_policies, sample_assets)
        storage.store_findings(findings, snapshot_id)

        # Query critical findings
        critical_findings = storage.get_findings(
            snapshot_id=snapshot_id,
            severity=Severity.CRITICAL,
        )

        # Should find at least the public access issue
        assert len(critical_findings) >= 1
        for f in critical_findings:
            assert f.severity == Severity.CRITICAL

    def test_query_findings_by_status(self, tmp_path, sample_assets, sample_policies):
        """Test querying findings by status."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(sample_policies, sample_assets)
        storage.store_findings(findings, snapshot_id)

        # All new findings should be OPEN
        open_findings = storage.get_findings(
            snapshot_id=snapshot_id,
            status=FindingStatus.OPEN,
        )

        assert len(open_findings) == len(findings)

    def test_query_assets_by_type(self, tmp_path, sample_assets):
        """Test querying assets by resource type."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)

        # Retrieve assets
        retrieved = storage.get_assets(snapshot_id)

        # Filter by type
        s3_assets = retrieved.filter_by_type("aws_s3_bucket")
        assert len(s3_assets) == 2


class TestComplianceReport:
    """Test compliance report generation."""

    def test_compliance_report_generation(self, tmp_path, sample_assets, sample_policies):
        """Test generating compliance report."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)
        snapshot_id = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_id)

        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(sample_policies, sample_assets)
        storage.store_findings(findings, snapshot_id)

        # Calculate compliance scores
        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(
            sample_policies,
            findings,
            sample_assets,
        )

        assert report is not None
        assert report.overall_score >= 0
        assert report.overall_score <= 100
        assert len(report.frameworks) > 0

    def test_compliance_score_calculation(self, sample_assets, sample_policies):
        """Test compliance score is calculated correctly."""
        evaluator = PolicyEvaluator()
        findings, _ = evaluator.evaluate_all(sample_policies, sample_assets)

        calculator = ComplianceCalculator()
        report = calculator.calculate_scores(
            sample_policies,
            findings,
            sample_assets,
        )

        # Find CIS framework score
        cis_score = None
        for fw in report.frameworks:
            if fw.framework_id == "cis-aws-foundations":
                cis_score = fw
                break

        if cis_score:
            # We have 3 CIS controls, 1 passes (root MFA), 2 fail
            # So score should be around 33%
            assert cis_score.controls_passed >= 1
            assert cis_score.controls_failed >= 1


class TestIncrementalScan:
    """Test incremental scan detection."""

    def test_incremental_scan_detects_changes(self, tmp_path, sample_policies):
        """Test scanning picks up changes between scans."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)

        # First scan with insecure bucket
        assets_v1 = AssetCollection([
            Asset(
                id="arn:aws:s3:::my-bucket",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="my-bucket",
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                raw_config={"encryption": {"enabled": False}},
            ),
        ])

        snapshot_1 = "20240115-100000"
        storage.store_assets(assets_v1, snapshot_1)

        evaluator = PolicyEvaluator()
        findings_v1, _ = evaluator.evaluate_all(sample_policies, assets_v1)
        storage.store_findings(findings_v1, snapshot_1)

        # Should have encryption finding
        assert len([f for f in findings_v1 if f.rule_id == "aws-s3-001"]) == 1

        # Second scan with fixed bucket
        assets_v2 = AssetCollection([
            Asset(
                id="arn:aws:s3:::my-bucket",
                cloud_provider="aws",
                account_id="123456789012",
                region="us-east-1",
                resource_type="aws_s3_bucket",
                name="my-bucket",
                tags={},
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                raw_config={"encryption": {"enabled": True}},  # Fixed!
            ),
        ])

        snapshot_2 = "20240115-110000"
        storage.store_assets(assets_v2, snapshot_2)

        findings_v2, _ = evaluator.evaluate_all(sample_policies, assets_v2)
        storage.store_findings(findings_v2, snapshot_2)

        # Should have no encryption finding now
        assert len([f for f in findings_v2 if f.rule_id == "aws-s3-001"]) == 0

    def test_snapshot_tracking(self, tmp_path, sample_assets):
        """Test snapshot IDs are tracked correctly."""
        db_path = str(tmp_path / "stance.db")
        storage = LocalStorage(db_path=db_path)

        # Store multiple snapshots
        snapshot_1 = "20240115-100000"
        snapshot_2 = "20240115-110000"
        snapshot_3 = "20240115-120000"

        storage.store_assets(sample_assets, snapshot_1)
        storage.store_assets(sample_assets, snapshot_2)
        storage.store_assets(sample_assets, snapshot_3)

        # Get list of snapshots
        snapshots = storage.list_snapshots(limit=10)

        assert len(snapshots) >= 3
        assert snapshot_3 in snapshots  # Most recent should be included

        # Get latest snapshot
        latest = storage.get_latest_snapshot_id()
        assert latest == snapshot_3


class TestRunEvaluationConvenience:
    """Test the run_evaluation convenience function."""

    def test_run_evaluation_with_policy_dirs(self, tmp_path, sample_assets):
        """Test run_evaluation with custom policy directory."""
        # Create a temporary policy file
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()

        policy_yaml = """
id: test-policy-001
name: Test Policy
description: A test policy.
enabled: true
severity: low
resource_type: aws_s3_bucket
check:
  type: expression
  expression: "resource.encryption.enabled == true"
remediation:
  guidance: Test guidance.
  automation_supported: false
tags:
  - test
"""
        (policy_dir / "test-policy.yaml").write_text(policy_yaml)

        # Run evaluation
        findings, result = run_evaluation(
            sample_assets,
            policy_dirs=[str(policy_dir)],
        )

        assert isinstance(findings, FindingCollection)
        assert result.policies_evaluated >= 1
