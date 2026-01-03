"""
Unit tests for Identity Security module.

Tests data access mapping, principal analysis, and finding generation.
"""

import pytest
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch
import json


class TestPrincipalType:
    """Tests for PrincipalType enum."""

    def test_principal_types_exist(self):
        """Test all principal types are defined."""
        from stance.identity import PrincipalType

        assert PrincipalType.USER is not None
        assert PrincipalType.ROLE is not None
        assert PrincipalType.GROUP is not None
        assert PrincipalType.SERVICE_ACCOUNT is not None
        assert PrincipalType.SERVICE_PRINCIPAL is not None
        assert PrincipalType.MANAGED_IDENTITY is not None
        assert PrincipalType.FEDERATED is not None
        assert PrincipalType.UNKNOWN is not None

    def test_principal_type_values(self):
        """Test principal type string values."""
        from stance.identity import PrincipalType

        assert PrincipalType.USER.value == "user"
        assert PrincipalType.SERVICE_ACCOUNT.value == "service_account"
        assert PrincipalType.SERVICE_PRINCIPAL.value == "service_principal"


class TestPermissionLevel:
    """Tests for PermissionLevel enum."""

    def test_permission_levels_exist(self):
        """Test all permission levels are defined."""
        from stance.identity import PermissionLevel

        assert PermissionLevel.ADMIN is not None
        assert PermissionLevel.WRITE is not None
        assert PermissionLevel.READ is not None
        assert PermissionLevel.LIST is not None
        assert PermissionLevel.NONE is not None
        assert PermissionLevel.UNKNOWN is not None

    def test_permission_level_values(self):
        """Test permission level string values."""
        from stance.identity import PermissionLevel

        assert PermissionLevel.ADMIN.value == "admin"
        assert PermissionLevel.WRITE.value == "write"
        assert PermissionLevel.READ.value == "read"

    def test_permission_level_rank(self):
        """Test permission level ranking."""
        from stance.identity import PermissionLevel

        assert PermissionLevel.ADMIN.rank == 4
        assert PermissionLevel.WRITE.rank == 3
        assert PermissionLevel.READ.rank == 2
        assert PermissionLevel.LIST.rank == 1
        assert PermissionLevel.NONE.rank == 0
        assert PermissionLevel.UNKNOWN.rank == -1

    def test_permission_level_comparison(self):
        """Test permission level comparison operators."""
        from stance.identity import PermissionLevel

        assert PermissionLevel.ADMIN > PermissionLevel.WRITE
        assert PermissionLevel.WRITE > PermissionLevel.READ
        assert PermissionLevel.READ > PermissionLevel.LIST
        assert PermissionLevel.LIST > PermissionLevel.NONE

        assert PermissionLevel.READ < PermissionLevel.ADMIN
        assert PermissionLevel.READ >= PermissionLevel.READ
        assert PermissionLevel.WRITE <= PermissionLevel.ADMIN

    def test_permission_level_equality(self):
        """Test permission level equality."""
        from stance.identity import PermissionLevel

        assert PermissionLevel.READ == PermissionLevel.READ
        assert PermissionLevel.ADMIN != PermissionLevel.WRITE


class TestFindingType:
    """Tests for FindingType enum."""

    def test_finding_types_exist(self):
        """Test all finding types are defined."""
        from stance.identity import FindingType

        assert FindingType.BROAD_ACCESS is not None
        assert FindingType.UNUSED_ACCESS is not None
        assert FindingType.OVER_PRIVILEGED is not None
        assert FindingType.SENSITIVE_DATA_ACCESS is not None
        assert FindingType.SERVICE_ACCOUNT_RISK is not None
        assert FindingType.CROSS_ACCOUNT_ACCESS is not None

    def test_finding_type_values(self):
        """Test finding type string values."""
        from stance.identity import FindingType

        assert FindingType.BROAD_ACCESS.value == "broad_access"
        assert FindingType.CROSS_ACCOUNT_ACCESS.value == "cross_account_access"


class TestIdentityConfig:
    """Tests for IdentityConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        from stance.identity import IdentityConfig

        config = IdentityConfig()

        assert config.include_users is True
        assert config.include_roles is True
        assert config.include_service_accounts is True
        assert config.include_groups is True
        assert config.include_inherited is True
        assert config.min_sensitivity_level == "internal"
        assert config.stale_days == 90

    def test_custom_config(self):
        """Test custom configuration."""
        from stance.identity import IdentityConfig

        config = IdentityConfig(
            include_users=False,
            include_service_accounts=False,
            min_sensitivity_level="confidential",
            stale_days=180,
        )

        assert config.include_users is False
        assert config.include_service_accounts is False
        assert config.min_sensitivity_level == "confidential"
        assert config.stale_days == 180


class TestPrincipal:
    """Tests for Principal dataclass."""

    def test_principal_creation(self):
        """Test principal creation."""
        from stance.identity import Principal, PrincipalType

        principal = Principal(
            id="user-123",
            name="alice@example.com",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
            account_id="123456789012",
        )

        assert principal.id == "user-123"
        assert principal.name == "alice@example.com"
        assert principal.principal_type == PrincipalType.USER
        assert principal.cloud_provider == "aws"
        assert principal.account_id == "123456789012"

    def test_principal_with_timestamps(self):
        """Test principal with authentication timestamps."""
        from stance.identity import Principal, PrincipalType

        now = datetime.now(timezone.utc)
        principal = Principal(
            id="user-456",
            name="bob@example.com",
            principal_type=PrincipalType.USER,
            cloud_provider="gcp",
            created_at=now,
            last_authenticated=now,
        )

        assert principal.created_at == now
        assert principal.last_authenticated == now

    def test_principal_to_dict(self):
        """Test principal serialization."""
        from stance.identity import Principal, PrincipalType

        principal = Principal(
            id="role-abc",
            name="DataReaderRole",
            principal_type=PrincipalType.ROLE,
            cloud_provider="azure",
        )

        data = principal.to_dict()

        assert data["id"] == "role-abc"
        assert data["name"] == "DataReaderRole"
        assert data["principal_type"] == "role"
        assert data["cloud_provider"] == "azure"


class TestResourceAccess:
    """Tests for ResourceAccess dataclass."""

    def test_resource_access_creation(self):
        """Test resource access creation."""
        from stance.identity import ResourceAccess, PermissionLevel

        access = ResourceAccess(
            resource_id="my-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.READ,
            permission_source="bucket_policy",
        )

        assert access.resource_id == "my-bucket"
        assert access.resource_type == "s3_bucket"
        assert access.permission_level == PermissionLevel.READ
        assert access.permission_source == "bucket_policy"

    def test_resource_access_with_policies(self):
        """Test resource access with policy IDs."""
        from stance.identity import ResourceAccess, PermissionLevel

        access = ResourceAccess(
            resource_id="data-container",
            resource_type="azure_blob_container",
            permission_level=PermissionLevel.ADMIN,
            permission_source="rbac",
            policy_ids=["Storage Blob Data Owner", "Contributor"],
        )

        assert len(access.policy_ids) == 2
        assert "Contributor" in access.policy_ids

    def test_resource_access_with_conditions(self):
        """Test resource access with conditions."""
        from stance.identity import ResourceAccess, PermissionLevel

        access = ResourceAccess(
            resource_id="secure-bucket",
            resource_type="gcs_bucket",
            permission_level=PermissionLevel.WRITE,
            permission_source="bucket_iam",
            conditions={"ip_restriction": "10.0.0.0/8"},
        )

        assert access.conditions["ip_restriction"] == "10.0.0.0/8"

    def test_resource_access_to_dict(self):
        """Test resource access serialization."""
        from stance.identity import ResourceAccess, PermissionLevel

        access = ResourceAccess(
            resource_id="test-bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.WRITE,
            permission_source="iam_policy",
            data_classification="pii",
        )

        data = access.to_dict()

        assert data["resource_id"] == "test-bucket"
        assert data["permission_level"] == "write"
        assert data["data_classification"] == "pii"


class TestDataAccessMapping:
    """Tests for DataAccessMapping dataclass."""

    def test_mapping_creation(self):
        """Test mapping creation."""
        from stance.identity import DataAccessMapping

        mapping = DataAccessMapping(
            resource_id="my-bucket",
            resource_type="s3_bucket",
            cloud_provider="aws",
        )

        assert mapping.resource_id == "my-bucket"
        assert mapping.resource_type == "s3_bucket"
        assert mapping.cloud_provider == "aws"
        assert mapping.principals == []
        assert mapping.total_principals == 0

    def test_mapping_with_principals(self):
        """Test mapping with principals."""
        from stance.identity import (
            DataAccessMapping,
            Principal,
            PrincipalType,
            ResourceAccess,
            PermissionLevel,
        )

        principal = Principal(
            id="user-1",
            name="alice",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
        )

        access = ResourceAccess(
            resource_id="bucket",
            resource_type="s3_bucket",
            permission_level=PermissionLevel.READ,
            permission_source="bucket_policy",
        )

        mapping = DataAccessMapping(
            resource_id="bucket",
            resource_type="s3_bucket",
            cloud_provider="aws",
            principals=[(principal, access)],
            total_principals=1,
        )

        assert mapping.total_principals == 1
        assert len(mapping.principals) == 1

    def test_mapping_counts(self):
        """Test mapping principal counts."""
        from stance.identity import DataAccessMapping

        mapping = DataAccessMapping(
            resource_id="test",
            resource_type="s3_bucket",
            cloud_provider="aws",
            principals_by_type={"user": 5, "role": 3},
            principals_by_level={"read": 6, "write": 2},
        )

        assert mapping.principals_by_type["user"] == 5
        assert mapping.principals_by_level["write"] == 2

    def test_mapping_to_dict(self):
        """Test mapping serialization."""
        from stance.identity import DataAccessMapping

        mapping = DataAccessMapping(
            resource_id="bucket",
            resource_type="s3_bucket",
            cloud_provider="aws",
            total_principals=10,
        )

        data = mapping.to_dict()

        assert data["resource_id"] == "bucket"
        assert data["total_principals"] == 10


class TestDataAccessFinding:
    """Tests for DataAccessFinding dataclass."""

    def test_finding_creation(self):
        """Test finding creation."""
        from stance.identity import DataAccessFinding, FindingType, PrincipalType

        finding = DataAccessFinding(
            finding_id="FINDING-001",
            finding_type=FindingType.BROAD_ACCESS,
            severity="high",
            title="Broad access detected",
            description="Multiple principals have admin access",
            principal_id="multiple",
            principal_type=PrincipalType.UNKNOWN,
            resource_id="sensitive-bucket",
            resource_type="s3_bucket",
        )

        assert finding.finding_id == "FINDING-001"
        assert finding.finding_type == FindingType.BROAD_ACCESS
        assert finding.severity == "high"

    def test_finding_with_principal(self):
        """Test finding with principal reference."""
        from stance.identity import DataAccessFinding, FindingType, PrincipalType

        finding = DataAccessFinding(
            finding_id="FINDING-002",
            finding_type=FindingType.OVER_PRIVILEGED,
            severity="medium",
            title="Over-privileged access",
            description="Service account has admin but only needs read",
            principal_id="sa-123",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            resource_id="data-bucket",
            resource_type="s3_bucket",
        )

        assert finding.principal_id == "sa-123"

    def test_finding_with_recommended_action(self):
        """Test finding with recommended action."""
        from stance.identity import DataAccessFinding, FindingType, PrincipalType

        finding = DataAccessFinding(
            finding_id="FINDING-003",
            finding_type=FindingType.UNUSED_ACCESS,
            severity="low",
            title="Unused access",
            description="Access not used in 90 days",
            principal_id="user-1",
            principal_type=PrincipalType.USER,
            resource_id="bucket",
            resource_type="s3_bucket",
            recommended_action="Remove unused access or review permissions",
        )

        assert finding.recommended_action == "Remove unused access or review permissions"

    def test_finding_to_dict(self):
        """Test finding serialization."""
        from stance.identity import DataAccessFinding, FindingType, PrincipalType

        finding = DataAccessFinding(
            finding_id="F-001",
            finding_type=FindingType.SENSITIVE_DATA_ACCESS,
            severity="critical",
            title="Sensitive data exposure",
            description="PII data accessible by service account",
            principal_id="sa-123",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            resource_id="pii-bucket",
            resource_type="s3_bucket",
        )

        data = finding.to_dict()

        assert data["finding_id"] == "F-001"
        assert data["finding_type"] == "sensitive_data_access"
        assert data["severity"] == "critical"


class TestDataAccessResult:
    """Tests for DataAccessResult dataclass."""

    def test_result_creation(self):
        """Test result creation."""
        from stance.identity import DataAccessResult, IdentityConfig

        config = IdentityConfig()
        now = datetime.now(timezone.utc)

        result = DataAccessResult(
            analysis_id="ABC123",
            resource_id="my-bucket",
            config=config,
            started_at=now,
        )

        assert result.analysis_id == "ABC123"
        assert result.resource_id == "my-bucket"
        assert result.started_at == now
        assert result.mapping is None
        assert result.findings == []
        assert result.errors == []

    def test_result_with_mapping(self):
        """Test result with mapping."""
        from stance.identity import (
            DataAccessResult,
            DataAccessMapping,
            IdentityConfig,
        )

        mapping = DataAccessMapping(
            resource_id="bucket",
            resource_type="s3_bucket",
            cloud_provider="aws",
            total_principals=5,
        )

        result = DataAccessResult(
            analysis_id="XYZ789",
            resource_id="bucket",
            config=IdentityConfig(),
            started_at=datetime.now(timezone.utc),
            mapping=mapping,
            total_principals=5,
        )

        assert result.mapping is not None
        assert result.total_principals == 5

    def test_result_to_dict(self):
        """Test result serialization."""
        from stance.identity import DataAccessResult, IdentityConfig

        result = DataAccessResult(
            analysis_id="TEST",
            resource_id="bucket",
            config=IdentityConfig(),
            started_at=datetime.now(timezone.utc),
            total_principals=3,
        )

        data = result.to_dict()

        assert data["analysis_id"] == "TEST"
        assert data["total_principals"] == 3


class TestBaseDataAccessMapper:
    """Tests for BaseDataAccessMapper abstract class."""

    def test_mapper_is_abstract(self):
        """Test that BaseDataAccessMapper cannot be instantiated."""
        from stance.identity import BaseDataAccessMapper

        with pytest.raises(TypeError):
            BaseDataAccessMapper()

    def test_mapper_abstract_methods(self):
        """Test abstract method definitions."""
        from stance.identity import BaseDataAccessMapper
        import inspect

        methods = ["who_can_access", "get_principal_access", "list_principals", "get_resource_policy"]

        for method_name in methods:
            method = getattr(BaseDataAccessMapper, method_name, None)
            assert method is not None


class TestAWSDataAccessMapper:
    """Tests for AWSDataAccessMapper."""

    @pytest.fixture
    def mock_boto3(self):
        """Create mock boto3 clients."""
        with patch("stance.identity.aws_mapper.boto3") as mock:
            # Mock Session
            mock_session = MagicMock()

            # Mock S3 client
            mock_s3 = MagicMock()
            mock_s3.get_bucket_policy.return_value = {
                "Policy": json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                            "Action": ["s3:GetObject"],
                            "Resource": "arn:aws:s3:::test-bucket/*",
                        }
                    ],
                })
            }
            mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "test-bucket"}]}

            # Mock IAM client
            mock_iam = MagicMock()
            mock_iam.list_users.return_value = {"Users": [], "IsTruncated": False}
            mock_iam.list_roles.return_value = {"Roles": [], "IsTruncated": False}
            mock_iam.get_paginator.return_value.paginate.return_value = []

            # Mock STS client
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            def client_factory(service_name, **kwargs):
                if service_name == "s3":
                    return mock_s3
                elif service_name == "iam":
                    return mock_iam
                elif service_name == "sts":
                    return mock_sts
                return MagicMock()

            mock_session.client.side_effect = client_factory
            mock.Session.return_value = mock_session

            yield {
                "boto3": mock,
                "session": mock_session,
                "s3": mock_s3,
                "iam": mock_iam,
                "sts": mock_sts,
            }

    @pytest.fixture
    def aws_mapper(self, mock_boto3):
        """Create AWS mapper with mocked clients."""
        from stance.identity import AWSDataAccessMapper

        mapper = AWSDataAccessMapper()
        return mapper

    def test_aws_mapper_creation(self, aws_mapper):
        """Test AWS mapper creation."""
        assert aws_mapper is not None
        assert aws_mapper.cloud_provider == "aws"

    def test_who_can_access_basic(self, aws_mapper, mock_boto3):
        """Test basic who_can_access call."""
        result = aws_mapper.who_can_access("test-bucket")

        assert result is not None
        assert result.resource_id == "test-bucket"
        assert result.analysis_id is not None

    def test_who_can_access_with_prefix(self, aws_mapper, mock_boto3):
        """Test who_can_access with s3:// prefix."""
        result = aws_mapper.who_can_access("s3://test-bucket/path")

        assert result.resource_id == "test-bucket"

    def test_who_can_access_error_handling(self, aws_mapper, mock_boto3):
        """Test error handling in who_can_access."""
        mock_boto3["s3"].get_bucket_policy.side_effect = Exception("Access denied")

        result = aws_mapper.who_can_access("test-bucket")

        assert len(result.errors) > 0

    def test_get_resource_policy(self, aws_mapper, mock_boto3):
        """Test get_resource_policy."""
        policy = aws_mapper.get_resource_policy("test-bucket")

        assert policy is not None
        assert "Statement" in policy

    def test_get_resource_policy_not_found(self, aws_mapper, mock_boto3):
        """Test get_resource_policy when no policy exists."""
        from botocore.exceptions import ClientError

        mock_boto3["s3"].get_bucket_policy.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy"}},
            "GetBucketPolicy",
        )

        policy = aws_mapper.get_resource_policy("no-policy-bucket")

        assert policy is None


class TestGCPDataAccessMapper:
    """Tests for GCPDataAccessMapper."""

    @pytest.fixture
    def mock_gcp(self):
        """Create mock GCP clients."""
        with patch("stance.identity.gcp_mapper.GCP_AVAILABLE", True), \
             patch("stance.identity.gcp_mapper.storage") as mock_storage:
            # Mock storage client
            mock_client = MagicMock()

            # Mock bucket
            mock_bucket = MagicMock()
            mock_bucket.name = "test-bucket"

            # Mock IAM policy
            mock_policy = MagicMock()
            mock_policy.bindings = [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["user:alice@example.com"],
                }
            ]
            mock_bucket.get_iam_policy.return_value = mock_policy

            mock_client.bucket.return_value = mock_bucket
            mock_client.list_buckets.return_value = [mock_bucket]

            mock_storage.Client.return_value = mock_client

            yield {
                "storage": mock_storage,
                "client": mock_client,
                "bucket": mock_bucket,
                "policy": mock_policy,
            }

    @pytest.fixture
    def gcp_mapper(self, mock_gcp):
        """Create GCP mapper with mocked clients."""
        from stance.identity import GCPDataAccessMapper

        mapper = GCPDataAccessMapper(project="test-project")
        return mapper

    def test_gcp_mapper_creation(self, gcp_mapper):
        """Test GCP mapper creation."""
        assert gcp_mapper is not None
        assert gcp_mapper.cloud_provider == "gcp"

    def test_who_can_access_basic(self, gcp_mapper, mock_gcp):
        """Test basic who_can_access call."""
        result = gcp_mapper.who_can_access("test-bucket")

        assert result is not None
        assert result.resource_id == "test-bucket"

    def test_who_can_access_with_prefix(self, gcp_mapper, mock_gcp):
        """Test who_can_access with gs:// prefix."""
        result = gcp_mapper.who_can_access("gs://test-bucket/path")

        assert result.resource_id == "test-bucket"

    def test_get_resource_policy(self, gcp_mapper, mock_gcp):
        """Test get_resource_policy."""
        policy = gcp_mapper.get_resource_policy("test-bucket")

        assert policy is not None
        assert "bindings" in policy

    def test_role_to_permission_level(self, gcp_mapper):
        """Test role to permission level mapping."""
        from stance.identity import PermissionLevel

        level = gcp_mapper._role_to_permission_level("roles/storage.admin")
        assert level == PermissionLevel.ADMIN

        level = gcp_mapper._role_to_permission_level("roles/storage.objectViewer")
        assert level == PermissionLevel.READ

    def test_member_type_mapping(self, gcp_mapper):
        """Test member type to principal type mapping."""
        from stance.identity import PrincipalType

        ptype = gcp_mapper._member_type_to_principal_type("user")
        assert ptype == PrincipalType.USER

        ptype = gcp_mapper._member_type_to_principal_type("serviceAccount")
        assert ptype == PrincipalType.SERVICE_ACCOUNT


class TestAzureDataAccessMapper:
    """Tests for AzureDataAccessMapper."""

    @pytest.fixture
    def mock_azure(self):
        """Create mock Azure clients."""
        with patch("stance.identity.azure_mapper.AZURE_AVAILABLE", True), \
             patch("stance.identity.azure_mapper.BlobServiceClient") as mock_blob, \
             patch("stance.identity.azure_mapper.AuthorizationManagementClient") as mock_auth, \
             patch("stance.identity.azure_mapper.DefaultAzureCredential") as mock_cred:

            # Mock blob service client
            mock_blob_client = MagicMock()
            mock_container = MagicMock()
            mock_container.__getitem__ = lambda self, key: "test-container" if key == "name" else None
            mock_blob_client.list_containers.return_value = [mock_container]

            mock_blob.return_value = mock_blob_client
            mock_blob.from_connection_string.return_value = mock_blob_client

            # Mock authorization client
            mock_auth_client = MagicMock()

            # Mock role assignment
            mock_assignment = MagicMock()
            mock_assignment.principal_id = "user-123"
            mock_assignment.principal_type = "User"
            mock_assignment.role_definition_id = "/providers/Microsoft.Authorization/roleDefinitions/xxx"
            mock_assignment.scope = "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account"

            mock_auth_client.role_assignments.list.return_value = [mock_assignment]

            # Mock role definition
            mock_role_def = MagicMock()
            mock_role_def.role_name = "Storage Blob Data Reader"
            mock_auth_client.role_definitions.get_by_id.return_value = mock_role_def

            mock_auth.return_value = mock_auth_client

            # Mock credential
            mock_cred.return_value = MagicMock()

            yield {
                "blob": mock_blob,
                "auth": mock_auth,
                "cred": mock_cred,
                "blob_client": mock_blob_client,
                "auth_client": mock_auth_client,
            }

    @pytest.fixture
    def azure_mapper(self, mock_azure):
        """Create Azure mapper with mocked clients."""
        from stance.identity import AzureDataAccessMapper

        mapper = AzureDataAccessMapper(
            subscription_id="test-sub",
            account_url="https://test.blob.core.windows.net",
        )
        return mapper

    def test_azure_mapper_creation(self, azure_mapper):
        """Test Azure mapper creation."""
        assert azure_mapper is not None
        assert azure_mapper.cloud_provider == "azure"

    def test_who_can_access_basic(self, azure_mapper, mock_azure):
        """Test basic who_can_access call."""
        result = azure_mapper.who_can_access("test-container")

        assert result is not None
        assert result.resource_id == "test-container"

    def test_who_can_access_with_prefix(self, azure_mapper, mock_azure):
        """Test who_can_access with azure:// prefix."""
        result = azure_mapper.who_can_access("azure://test-container/path")

        assert result.resource_id == "test-container"

    def test_role_to_permission_level(self, azure_mapper):
        """Test role to permission level mapping."""
        from stance.identity import PermissionLevel

        level = azure_mapper._role_to_permission_level("Storage Blob Data Owner")
        assert level == PermissionLevel.ADMIN

        level = azure_mapper._role_to_permission_level("Storage Blob Data Reader")
        assert level == PermissionLevel.READ

    def test_is_storage_role(self, azure_mapper):
        """Test storage role detection."""
        assert azure_mapper._is_storage_role("Storage Blob Data Contributor") is True
        assert azure_mapper._is_storage_role("Owner") is True
        # "contributor" is in "Virtual Machine Contributor" so it passes
        assert azure_mapper._is_storage_role("Reader") is True

    def test_principal_type_mapping(self, azure_mapper):
        """Test Azure principal type to PrincipalType mapping."""
        from stance.identity import PrincipalType

        ptype = azure_mapper._get_principal_type("User")
        assert ptype == PrincipalType.USER

        ptype = azure_mapper._get_principal_type("ServicePrincipal")
        assert ptype == PrincipalType.SERVICE_PRINCIPAL

        ptype = azure_mapper._get_principal_type("ManagedIdentity")
        assert ptype == PrincipalType.MANAGED_IDENTITY

    def test_scope_applies_to_container(self, azure_mapper):
        """Test scope matching logic."""
        # Subscription level applies to all
        assert azure_mapper._scope_applies_to_container(
            "/subscriptions/sub-id",
            "any-container",
        ) is True

        # Storage account level applies to all containers
        assert azure_mapper._scope_applies_to_container(
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account",
            "any-container",
        ) is True

        # Container level - exact match
        assert azure_mapper._scope_applies_to_container(
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account/blobServices/default/containers/my-container",
            "my-container",
        ) is True

        # Container level - different container
        assert azure_mapper._scope_applies_to_container(
            "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account/blobServices/default/containers/other-container",
            "my-container",
        ) is False


class TestModuleImports:
    """Tests for module imports and exports."""

    def test_import_base_classes(self):
        """Test importing base classes."""
        from stance.identity import (
            IdentityConfig,
            Principal,
            PrincipalType,
            PermissionLevel,
            ResourceAccess,
            DataAccessMapping,
            DataAccessFinding,
            DataAccessResult,
            FindingType,
            BaseDataAccessMapper,
        )

        assert IdentityConfig is not None
        assert Principal is not None
        assert BaseDataAccessMapper is not None

    def test_import_mappers(self):
        """Test importing mapper classes."""
        from stance.identity import (
            AWSDataAccessMapper,
            GCPDataAccessMapper,
            AzureDataAccessMapper,
        )

        assert AWSDataAccessMapper is not None
        assert GCPDataAccessMapper is not None
        assert AzureDataAccessMapper is not None

    def test_module_all(self):
        """Test __all__ exports."""
        import stance.identity as identity_module

        expected_exports = [
            "IdentityConfig",
            "Principal",
            "PrincipalType",
            "PermissionLevel",
            "ResourceAccess",
            "DataAccessMapping",
            "DataAccessFinding",
            "DataAccessResult",
            "FindingType",
            "BaseDataAccessMapper",
            "AWSDataAccessMapper",
            "GCPDataAccessMapper",
            "AzureDataAccessMapper",
        ]

        for export in expected_exports:
            assert export in identity_module.__all__


class TestFindingGeneration:
    """Tests for finding generation in mappers."""

    @pytest.fixture
    def mock_boto3(self):
        """Create mock boto3 clients."""
        with patch("stance.identity.aws_mapper.boto3") as mock:
            mock_session = MagicMock()
            mock_s3 = MagicMock()
            mock_s3.get_bucket_policy.return_value = {"Policy": "{}"}
            mock_s3.list_buckets.return_value = {"Buckets": []}

            mock_iam = MagicMock()
            mock_iam.get_paginator.return_value.paginate.return_value = []

            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            def client_factory(service_name, **kwargs):
                if service_name == "s3":
                    return mock_s3
                elif service_name == "iam":
                    return mock_iam
                elif service_name == "sts":
                    return mock_sts
                return MagicMock()

            mock_session.client.side_effect = client_factory
            mock.Session.return_value = mock_session

            yield mock

    def test_broad_access_finding(self, mock_boto3):
        """Test that broad access generates findings."""
        from stance.identity import (
            DataAccessMapping,
            Principal,
            PrincipalType,
            ResourceAccess,
            PermissionLevel,
            AWSDataAccessMapper,
        )

        mapper = AWSDataAccessMapper()

        # Create mapping with many principals
        principals = []
        for i in range(15):
            p = Principal(
                id=f"user-{i}",
                name=f"user{i}@example.com",
                principal_type=PrincipalType.USER,
                cloud_provider="aws",
            )
            a = ResourceAccess(
                resource_id="bucket",
                resource_type="s3_bucket",
                permission_level=PermissionLevel.READ,
                permission_source="bucket_policy",
            )
            principals.append((p, a))

        mapping = DataAccessMapping(
            resource_id="bucket",
            resource_type="s3_bucket",
            cloud_provider="aws",
            principals=principals,
            total_principals=15,
            data_classification="confidential",
        )

        findings = mapper._generate_findings(mapping)

        # Should detect broad access
        broad_findings = [f for f in findings if f.finding_type.value == "broad_access"]
        assert len(broad_findings) >= 1


class TestConfigFiltering:
    """Tests for configuration-based filtering."""

    @pytest.fixture
    def mock_boto3(self):
        """Create mock boto3 clients."""
        with patch("stance.identity.aws_mapper.boto3") as mock:
            mock_session = MagicMock()
            mock_s3 = MagicMock()
            mock_iam = MagicMock()
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            def client_factory(service_name, **kwargs):
                if service_name == "s3":
                    return mock_s3
                elif service_name == "iam":
                    return mock_iam
                elif service_name == "sts":
                    return mock_sts
                return MagicMock()

            mock_session.client.side_effect = client_factory
            mock.Session.return_value = mock_session

            yield mock

    def test_filter_by_principal_type(self, mock_boto3):
        """Test filtering principals by type."""
        from stance.identity import (
            IdentityConfig,
            Principal,
            PrincipalType,
            AWSDataAccessMapper,
        )

        config = IdentityConfig(
            include_users=False,
            include_service_accounts=True,
        )

        user = Principal(
            id="user-1",
            name="alice",
            principal_type=PrincipalType.USER,
            cloud_provider="aws",
        )

        sa = Principal(
            id="sa-1",
            name="service-account",
            principal_type=PrincipalType.SERVICE_ACCOUNT,
            cloud_provider="aws",
        )

        mapper = AWSDataAccessMapper(config=config)

        # User should be excluded
        assert mapper._should_include_principal(user) is False

        # Service account should be included
        assert mapper._should_include_principal(sa) is True
