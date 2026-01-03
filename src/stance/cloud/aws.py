"""
AWS cloud provider implementation.

This module provides AWS-specific implementation of the CloudProvider
interface, wrapping boto3 functionality.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from stance.cloud.base import (
    CloudProvider,
    CloudCredentials,
    CloudAccount,
    CloudRegion,
    AuthenticationError,
    ConfigurationError,
)

if TYPE_CHECKING:
    from stance.collectors.base import BaseCollector
    from stance.storage.base import StorageBackend


class AWSProvider(CloudProvider):
    """
    AWS cloud provider implementation.

    Uses boto3 for all AWS API interactions. Supports multiple
    authentication methods including environment variables,
    IAM roles, and explicit credentials.
    """

    def __init__(
        self,
        credentials: CloudCredentials | None = None,
        region: str = "us-east-1",
        **kwargs: Any,
    ) -> None:
        """
        Initialize AWS provider.

        Args:
            credentials: Optional credentials. If None, uses boto3
                        default credential chain.
            region: Default AWS region.
            **kwargs: Additional configuration:
                - profile: AWS profile name
                - role_arn: IAM role to assume
        """
        super().__init__(credentials, **kwargs)
        self._region = region
        self._session = None
        self._account_id: str | None = None

    @property
    def provider_name(self) -> str:
        return "aws"

    @property
    def display_name(self) -> str:
        return "Amazon Web Services"

    @classmethod
    def is_available(cls) -> bool:
        """Check if boto3 is installed."""
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    @classmethod
    def get_required_packages(cls) -> list[str]:
        return ["boto3"]

    def initialize(self) -> None:
        """Initialize boto3 session."""
        if not self.is_available():
            raise ConfigurationError(
                "boto3 is not installed. Install with: pip install boto3"
            )

        import boto3

        session_kwargs: dict[str, Any] = {
            "region_name": self._region,
        }

        # Use profile if specified
        profile = self.get_config("profile") or self.credentials.aws_profile
        if profile:
            session_kwargs["profile_name"] = profile

        # Use explicit credentials if provided
        if self.credentials.aws_access_key_id:
            session_kwargs["aws_access_key_id"] = self.credentials.aws_access_key_id
            session_kwargs["aws_secret_access_key"] = (
                self.credentials.aws_secret_access_key
            )
            if self.credentials.aws_session_token:
                session_kwargs["aws_session_token"] = (
                    self.credentials.aws_session_token
                )

        try:
            self._session = boto3.Session(**session_kwargs)

            # Handle role assumption if specified
            role_arn = self.get_config("role_arn") or self.credentials.aws_role_arn
            if role_arn:
                self._assume_role(role_arn)

            # Validate by getting caller identity
            self._account_id = self._get_caller_identity()
            self._initialized = True

        except Exception as e:
            raise AuthenticationError(f"Failed to initialize AWS session: {e}")

    def _assume_role(self, role_arn: str) -> None:
        """Assume an IAM role."""
        import boto3

        sts = self._session.client("sts")
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="mantissa-stance",
            )
            creds = response["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self._region,
            )
        except Exception as e:
            raise AuthenticationError(f"Failed to assume role {role_arn}: {e}")

    def _get_caller_identity(self) -> str:
        """Get the AWS account ID from STS."""
        sts = self._session.client("sts")
        try:
            response = sts.get_caller_identity()
            return response["Account"]
        except Exception as e:
            raise AuthenticationError(f"Failed to get caller identity: {e}")

    def validate_credentials(self) -> bool:
        """Validate AWS credentials."""
        self._ensure_initialized()
        try:
            self._get_caller_identity()
            return True
        except Exception:
            return False

    def get_account(self) -> CloudAccount:
        """Get AWS account information."""
        self._ensure_initialized()

        # Try to get account alias
        display_name = None
        try:
            iam = self._session.client("iam")
            aliases = iam.list_account_aliases().get("AccountAliases", [])
            if aliases:
                display_name = aliases[0]
        except Exception:
            pass

        return CloudAccount(
            provider="aws",
            account_id=self._account_id,
            display_name=display_name,
            regions=self.list_regions(),
            metadata={"region": self._region},
        )

    def list_regions(self) -> list[CloudRegion]:
        """List available AWS regions."""
        self._ensure_initialized()

        try:
            ec2 = self._session.client("ec2", region_name="us-east-1")
            response = ec2.describe_regions()
            regions = []
            for r in response.get("Regions", []):
                regions.append(
                    CloudRegion(
                        provider="aws",
                        region_id=r["RegionName"],
                        display_name=r.get("RegionName", r["RegionName"]),
                        is_default=(r["RegionName"] == self._region),
                    )
                )
            return regions
        except Exception:
            # Return common regions if API call fails
            common_regions = [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            ]
            return [
                CloudRegion(
                    provider="aws",
                    region_id=r,
                    display_name=r,
                    is_default=(r == self._region),
                )
                for r in common_regions
            ]

    def get_collectors(self) -> list[BaseCollector]:
        """Get AWS collectors configured with this provider's session."""
        self._ensure_initialized()

        from stance.collectors.aws_iam import IAMCollector
        from stance.collectors.aws_s3 import S3Collector
        from stance.collectors.aws_ec2 import EC2Collector
        from stance.collectors.aws_security import SecurityCollector

        return [
            IAMCollector(session=self._session),
            S3Collector(session=self._session),
            EC2Collector(session=self._session),
            SecurityCollector(session=self._session),
        ]

    def get_storage_backend(
        self,
        storage_type: str = "s3",
        **kwargs: Any,
    ) -> StorageBackend:
        """Get AWS storage backend (S3)."""
        self._ensure_initialized()

        if storage_type == "local":
            from stance.storage.local import LocalStorage
            return LocalStorage(**kwargs)

        if storage_type in ("s3", "default"):
            from stance.storage.s3 import S3Storage

            bucket = kwargs.get("bucket")
            if not bucket:
                raise ConfigurationError("S3 storage requires 'bucket' parameter")

            return S3Storage(
                bucket=bucket,
                prefix=kwargs.get("prefix", "stance"),
                region=kwargs.get("region", self._region),
                session=self._session,
            )

        raise ConfigurationError(f"Unknown storage type for AWS: {storage_type}")

    def get_session(self):
        """Get the boto3 session for direct use."""
        self._ensure_initialized()
        return self._session

    def get_client(self, service: str, **kwargs: Any):
        """Get a boto3 client for a specific service."""
        self._ensure_initialized()
        return self._session.client(service, **kwargs)

    def get_resource(self, service: str, **kwargs: Any):
        """Get a boto3 resource for a specific service."""
        self._ensure_initialized()
        return self._session.resource(service, **kwargs)
