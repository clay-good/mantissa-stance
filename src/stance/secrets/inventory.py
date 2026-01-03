"""
Secret Inventory for Mantissa Stance.

Provides a unified inventory of secrets across cloud providers
including AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
HashiCorp Vault, and Kubernetes Secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SecretType(Enum):
    """Types of secrets tracked."""

    # Cloud Provider Credentials
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    AWS_SESSION_TOKEN = "aws_session_token"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    AZURE_STORAGE_KEY = "azure_storage_key"
    GCP_SERVICE_ACCOUNT_KEY = "gcp_service_account_key"
    GCP_API_KEY = "gcp_api_key"

    # Database Credentials
    DATABASE_PASSWORD = "database_password"
    DATABASE_CONNECTION_STRING = "database_connection_string"

    # API Keys and Tokens
    API_KEY = "api_key"
    API_TOKEN = "api_token"
    BEARER_TOKEN = "bearer_token"
    JWT_TOKEN = "jwt_token"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    OAUTH_REFRESH_TOKEN = "oauth_refresh_token"

    # Certificates and Keys
    TLS_CERTIFICATE = "tls_certificate"
    TLS_PRIVATE_KEY = "tls_private_key"
    SSH_PRIVATE_KEY = "ssh_private_key"
    SSH_PUBLIC_KEY = "ssh_public_key"
    PGP_PRIVATE_KEY = "pgp_private_key"
    ENCRYPTION_KEY = "encryption_key"
    SIGNING_KEY = "signing_key"

    # Service-Specific
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    DOCKER_REGISTRY_CREDENTIAL = "docker_registry_credential"
    NPM_TOKEN = "npm_token"
    SLACK_TOKEN = "slack_token"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"
    TWILIO_KEY = "twilio_key"

    # Generic
    PASSWORD = "password"
    SECRET = "secret"
    GENERIC_CREDENTIAL = "generic_credential"


class SecretSource(Enum):
    """Source systems for secrets."""

    # AWS
    AWS_SECRETS_MANAGER = "aws_secrets_manager"
    AWS_PARAMETER_STORE = "aws_parameter_store"
    AWS_IAM = "aws_iam"
    AWS_KMS = "aws_kms"

    # Azure
    AZURE_KEY_VAULT = "azure_key_vault"
    AZURE_APP_CONFIGURATION = "azure_app_configuration"
    AZURE_AD = "azure_ad"

    # GCP
    GCP_SECRET_MANAGER = "gcp_secret_manager"
    GCP_IAM = "gcp_iam"
    GCP_KMS = "gcp_kms"

    # Kubernetes
    KUBERNETES_SECRET = "kubernetes_secret"
    KUBERNETES_CONFIGMAP = "kubernetes_configmap"

    # External
    HASHICORP_VAULT = "hashicorp_vault"
    CYBERARK = "cyberark"

    # Code/Config
    ENVIRONMENT_VARIABLE = "environment_variable"
    CONFIG_FILE = "config_file"
    SOURCE_CODE = "source_code"

    # Unknown
    UNKNOWN = "unknown"


class SecretStatus(Enum):
    """Status of a secret."""

    ACTIVE = "active"
    EXPIRED = "expired"
    EXPIRING_SOON = "expiring_soon"
    ROTATION_REQUIRED = "rotation_required"
    ROTATION_IN_PROGRESS = "rotation_in_progress"
    DISABLED = "disabled"
    DELETED = "deleted"
    COMPROMISED = "compromised"
    UNKNOWN = "unknown"


@dataclass
class SecretMetadata:
    """Metadata associated with a secret."""

    # Creation and lifecycle
    created_at: datetime | None = None
    created_by: str | None = None
    last_rotated_at: datetime | None = None
    last_rotated_by: str | None = None
    expires_at: datetime | None = None

    # Access tracking
    last_accessed_at: datetime | None = None
    last_accessed_by: str | None = None
    access_count: int = 0

    # Version tracking
    version: str | None = None
    version_count: int = 1
    previous_versions: list[str] = field(default_factory=list)

    # Rotation settings
    rotation_enabled: bool = False
    rotation_schedule: str | None = None  # Cron expression
    rotation_lambda_arn: str | None = None  # AWS Secrets Manager
    next_rotation_date: datetime | None = None

    # Policy and compliance
    rotation_policy_id: str | None = None
    compliance_frameworks: list[str] = field(default_factory=list)
    last_audit_date: datetime | None = None

    # Custom metadata
    tags: dict[str, str] = field(default_factory=dict)
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
            "last_rotated_at": self.last_rotated_at.isoformat() if self.last_rotated_at else None,
            "last_rotated_by": self.last_rotated_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "last_accessed_by": self.last_accessed_by,
            "access_count": self.access_count,
            "version": self.version,
            "version_count": self.version_count,
            "rotation_enabled": self.rotation_enabled,
            "rotation_schedule": self.rotation_schedule,
            "next_rotation_date": self.next_rotation_date.isoformat() if self.next_rotation_date else None,
            "rotation_policy_id": self.rotation_policy_id,
            "compliance_frameworks": self.compliance_frameworks,
            "tags": self.tags,
            "description": self.description,
        }


@dataclass
class SecretInventoryItem:
    """A single secret in the inventory."""

    id: str
    name: str
    secret_type: SecretType
    source: SecretSource
    status: SecretStatus
    metadata: SecretMetadata

    # Location information
    account_id: str | None = None
    region: str | None = None
    resource_arn: str | None = None
    namespace: str | None = None  # For Kubernetes

    # Risk assessment
    risk_score: float = 0.0  # 0-100
    risk_factors: list[str] = field(default_factory=list)

    # Discovery
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def age_days(self) -> int | None:
        """Get age in days since creation."""
        if not self.metadata.created_at:
            return None
        now = datetime.now(timezone.utc)
        delta = now - self.metadata.created_at.replace(tzinfo=timezone.utc)
        return delta.days

    @property
    def days_since_rotation(self) -> int | None:
        """Get days since last rotation."""
        rotation_date = self.metadata.last_rotated_at or self.metadata.created_at
        if not rotation_date:
            return None
        now = datetime.now(timezone.utc)
        delta = now - rotation_date.replace(tzinfo=timezone.utc)
        return delta.days

    @property
    def days_until_expiration(self) -> int | None:
        """Get days until expiration (negative if expired)."""
        if not self.metadata.expires_at:
            return None
        now = datetime.now(timezone.utc)
        delta = self.metadata.expires_at.replace(tzinfo=timezone.utc) - now
        return delta.days

    @property
    def is_expired(self) -> bool:
        """Check if secret is expired."""
        if not self.metadata.expires_at:
            return False
        now = datetime.now(timezone.utc)
        return self.metadata.expires_at.replace(tzinfo=timezone.utc) < now

    @property
    def is_expiring_soon(self) -> bool:
        """Check if secret expires within 30 days."""
        days = self.days_until_expiration
        return days is not None and 0 < days <= 30

    @property
    def needs_rotation(self) -> bool:
        """Check if secret needs rotation based on common policies."""
        days = self.days_since_rotation
        if days is None:
            return False
        # Default: 90 days for most secrets
        return days > 90

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "secret_type": self.secret_type.value,
            "source": self.source.value,
            "status": self.status.value,
            "account_id": self.account_id,
            "region": self.region,
            "resource_arn": self.resource_arn,
            "namespace": self.namespace,
            "age_days": self.age_days,
            "days_since_rotation": self.days_since_rotation,
            "days_until_expiration": self.days_until_expiration,
            "is_expired": self.is_expired,
            "is_expiring_soon": self.is_expiring_soon,
            "needs_rotation": self.needs_rotation,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
            "discovered_at": self.discovered_at.isoformat(),
            "last_scanned_at": self.last_scanned_at.isoformat(),
            "metadata": self.metadata.to_dict(),
        }


@dataclass
class SecretInventory:
    """Complete inventory of secrets across all sources."""

    items: list[SecretInventoryItem] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sources_scanned: list[SecretSource] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        """Get total secret count."""
        return len(self.items)

    @property
    def active_count(self) -> int:
        """Get count of active secrets."""
        return sum(1 for s in self.items if s.status == SecretStatus.ACTIVE)

    @property
    def expired_count(self) -> int:
        """Get count of expired secrets."""
        return sum(1 for s in self.items if s.is_expired)

    @property
    def expiring_soon_count(self) -> int:
        """Get count of secrets expiring soon."""
        return sum(1 for s in self.items if s.is_expiring_soon)

    @property
    def rotation_required_count(self) -> int:
        """Get count of secrets needing rotation."""
        return sum(1 for s in self.items if s.needs_rotation)

    def get_by_source(self, source: SecretSource) -> list[SecretInventoryItem]:
        """Get secrets by source."""
        return [s for s in self.items if s.source == source]

    def get_by_type(self, secret_type: SecretType) -> list[SecretInventoryItem]:
        """Get secrets by type."""
        return [s for s in self.items if s.secret_type == secret_type]

    def get_by_status(self, status: SecretStatus) -> list[SecretInventoryItem]:
        """Get secrets by status."""
        return [s for s in self.items if s.status == status]

    def get_by_account(self, account_id: str) -> list[SecretInventoryItem]:
        """Get secrets by account."""
        return [s for s in self.items if s.account_id == account_id]

    def get_expired(self) -> list[SecretInventoryItem]:
        """Get expired secrets."""
        return [s for s in self.items if s.is_expired]

    def get_expiring_soon(self, days: int = 30) -> list[SecretInventoryItem]:
        """Get secrets expiring within specified days."""
        return [
            s for s in self.items
            if s.days_until_expiration is not None and 0 < s.days_until_expiration <= days
        ]

    def get_needing_rotation(self, max_age_days: int = 90) -> list[SecretInventoryItem]:
        """Get secrets that need rotation."""
        return [
            s for s in self.items
            if s.days_since_rotation is not None and s.days_since_rotation > max_age_days
        ]

    def get_high_risk(self, min_score: float = 70.0) -> list[SecretInventoryItem]:
        """Get high-risk secrets."""
        return [s for s in self.items if s.risk_score >= min_score]

    def get_by_compliance_framework(self, framework: str) -> list[SecretInventoryItem]:
        """Get secrets related to a compliance framework."""
        return [
            s for s in self.items
            if framework in s.metadata.compliance_frameworks
        ]

    def get_summary(self) -> dict[str, Any]:
        """Get inventory summary."""
        by_source: dict[str, int] = {}
        by_type: dict[str, int] = {}
        by_status: dict[str, int] = {}

        for item in self.items:
            source = item.source.value
            by_source[source] = by_source.get(source, 0) + 1

            stype = item.secret_type.value
            by_type[stype] = by_type.get(stype, 0) + 1

            status = item.status.value
            by_status[status] = by_status.get(status, 0) + 1

        return {
            "total_count": self.total_count,
            "active_count": self.active_count,
            "expired_count": self.expired_count,
            "expiring_soon_count": self.expiring_soon_count,
            "rotation_required_count": self.rotation_required_count,
            "by_source": by_source,
            "by_type": by_type,
            "by_status": by_status,
            "sources_scanned": [s.value for s in self.sources_scanned],
            "last_updated": self.last_updated.isoformat(),
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "items": [item.to_dict() for item in self.items],
            "summary": self.get_summary(),
        }


class SecretInventoryCollector:
    """
    Collects secret inventory from various sources.

    Supports AWS Secrets Manager, Azure Key Vault, GCP Secret Manager,
    Kubernetes Secrets, and more.
    """

    def __init__(self) -> None:
        """Initialize the collector."""
        self._inventory = SecretInventory()

    def collect_from_aws_secrets_manager(
        self,
        secrets_data: list[dict[str, Any]],
        account_id: str,
        region: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect secrets from AWS Secrets Manager response.

        Args:
            secrets_data: List of secrets from describe_secret API
            account_id: AWS account ID
            region: AWS region

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for secret in secrets_data:
            secret_name = secret.get("Name", "unknown")
            secret_arn = secret.get("ARN", "")

            # Parse creation and rotation dates
            created_at = secret.get("CreatedDate")
            last_rotated = secret.get("LastRotatedDate")
            last_accessed = secret.get("LastAccessedDate")
            next_rotation = secret.get("NextRotationDate")

            # Determine rotation status
            rotation_enabled = secret.get("RotationEnabled", False)
            rotation_lambda = secret.get("RotationLambdaARN")

            # Determine status
            if secret.get("DeletedDate"):
                status = SecretStatus.DELETED
            elif rotation_enabled and next_rotation:
                now = datetime.now(timezone.utc)
                if isinstance(next_rotation, datetime):
                    if next_rotation < now:
                        status = SecretStatus.ROTATION_REQUIRED
                    else:
                        status = SecretStatus.ACTIVE
                else:
                    status = SecretStatus.ACTIVE
            else:
                status = SecretStatus.ACTIVE

            # Determine secret type from name/tags
            secret_type = self._infer_secret_type(secret_name, secret.get("Tags", []))

            # Build metadata
            metadata = SecretMetadata(
                created_at=created_at if isinstance(created_at, datetime) else None,
                last_rotated_at=last_rotated if isinstance(last_rotated, datetime) else None,
                last_accessed_at=last_accessed if isinstance(last_accessed, datetime) else None,
                rotation_enabled=rotation_enabled,
                rotation_lambda_arn=rotation_lambda,
                next_rotation_date=next_rotation if isinstance(next_rotation, datetime) else None,
                version=secret.get("VersionIdsToStages", {}).get("AWSCURRENT", ["unknown"])[0] if secret.get("VersionIdsToStages") else None,
                description=secret.get("Description"),
                tags={t.get("Key", ""): t.get("Value", "") for t in secret.get("Tags", [])},
            )

            # Calculate risk score
            risk_score, risk_factors = self._calculate_risk(metadata, secret_type)

            item = SecretInventoryItem(
                id=f"aws-sm-{secret_arn.split(':')[-1]}" if secret_arn else f"aws-sm-{secret_name}",
                name=secret_name,
                secret_type=secret_type,
                source=SecretSource.AWS_SECRETS_MANAGER,
                status=status,
                metadata=metadata,
                account_id=account_id,
                region=region,
                resource_arn=secret_arn,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.AWS_SECRETS_MANAGER not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.AWS_SECRETS_MANAGER)

        return items

    def collect_from_aws_iam_access_keys(
        self,
        access_keys_data: list[dict[str, Any]],
        account_id: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect IAM access keys from credential report.

        Args:
            access_keys_data: List of access key data
            account_id: AWS account ID

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for key_data in access_keys_data:
            user_name = key_data.get("user_name", "unknown")
            access_key_id = key_data.get("access_key_id", "")
            created_date = key_data.get("create_date")
            last_used = key_data.get("last_used_date")
            status_str = key_data.get("status", "Active")

            # Determine status
            if status_str.lower() == "inactive":
                status = SecretStatus.DISABLED
            else:
                status = SecretStatus.ACTIVE

            # Check if rotation required
            if created_date:
                created_dt = created_date if isinstance(created_date, datetime) else None
                if created_dt:
                    age_days = (datetime.now(timezone.utc) - created_dt.replace(tzinfo=timezone.utc)).days
                    if age_days > 90:
                        status = SecretStatus.ROTATION_REQUIRED

            metadata = SecretMetadata(
                created_at=created_date if isinstance(created_date, datetime) else None,
                last_accessed_at=last_used if isinstance(last_used, datetime) else None,
                created_by=user_name,
                tags={"user": user_name},
            )

            risk_score, risk_factors = self._calculate_risk(metadata, SecretType.AWS_ACCESS_KEY)

            item = SecretInventoryItem(
                id=f"aws-iam-{access_key_id}",
                name=f"{user_name}/{access_key_id}",
                secret_type=SecretType.AWS_ACCESS_KEY,
                source=SecretSource.AWS_IAM,
                status=status,
                metadata=metadata,
                account_id=account_id,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.AWS_IAM not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.AWS_IAM)

        return items

    def collect_from_azure_key_vault(
        self,
        secrets_data: list[dict[str, Any]],
        subscription_id: str,
        vault_name: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect secrets from Azure Key Vault.

        Args:
            secrets_data: List of secrets from Key Vault
            subscription_id: Azure subscription ID
            vault_name: Key Vault name

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for secret in secrets_data:
            secret_id = secret.get("id", "")
            secret_name = secret_id.split("/")[-1] if secret_id else "unknown"

            attributes = secret.get("attributes", {})
            created = attributes.get("created")
            updated = attributes.get("updated")
            expires = attributes.get("expires")
            enabled = attributes.get("enabled", True)

            # Convert Unix timestamps
            created_dt = datetime.fromtimestamp(created, tz=timezone.utc) if created else None
            updated_dt = datetime.fromtimestamp(updated, tz=timezone.utc) if updated else None
            expires_dt = datetime.fromtimestamp(expires, tz=timezone.utc) if expires else None

            # Determine status
            if not enabled:
                status = SecretStatus.DISABLED
            elif expires_dt and expires_dt < datetime.now(timezone.utc):
                status = SecretStatus.EXPIRED
            elif expires_dt and (expires_dt - datetime.now(timezone.utc)).days <= 30:
                status = SecretStatus.EXPIRING_SOON
            else:
                status = SecretStatus.ACTIVE

            metadata = SecretMetadata(
                created_at=created_dt,
                last_rotated_at=updated_dt,
                expires_at=expires_dt,
                tags=secret.get("tags", {}),
                version=secret.get("version"),
            )

            secret_type = self._infer_secret_type(secret_name, secret.get("tags", {}))
            risk_score, risk_factors = self._calculate_risk(metadata, secret_type)

            item = SecretInventoryItem(
                id=f"azure-kv-{vault_name}-{secret_name}",
                name=f"{vault_name}/{secret_name}",
                secret_type=secret_type,
                source=SecretSource.AZURE_KEY_VAULT,
                status=status,
                metadata=metadata,
                account_id=subscription_id,
                resource_arn=secret_id,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.AZURE_KEY_VAULT not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.AZURE_KEY_VAULT)

        return items

    def collect_from_gcp_secret_manager(
        self,
        secrets_data: list[dict[str, Any]],
        project_id: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect secrets from GCP Secret Manager.

        Args:
            secrets_data: List of secrets from Secret Manager
            project_id: GCP project ID

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for secret in secrets_data:
            secret_name = secret.get("name", "").split("/")[-1]
            secret_id = secret.get("name", "")

            # Get replication and rotation info
            replication = secret.get("replication", {})
            rotation = secret.get("rotation", {})
            labels = secret.get("labels", {})

            # Parse dates
            create_time = secret.get("createTime")
            created_dt = None
            if create_time:
                try:
                    created_dt = datetime.fromisoformat(create_time.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            # Determine rotation info
            rotation_period = rotation.get("rotationPeriod")
            next_rotation = rotation.get("nextRotationTime")
            next_rotation_dt = None
            if next_rotation:
                try:
                    next_rotation_dt = datetime.fromisoformat(next_rotation.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            # Determine status
            status = SecretStatus.ACTIVE
            if next_rotation_dt and next_rotation_dt < datetime.now(timezone.utc):
                status = SecretStatus.ROTATION_REQUIRED

            metadata = SecretMetadata(
                created_at=created_dt,
                rotation_enabled=bool(rotation_period),
                rotation_schedule=rotation_period,
                next_rotation_date=next_rotation_dt,
                tags=labels,
            )

            secret_type = self._infer_secret_type(secret_name, labels)
            risk_score, risk_factors = self._calculate_risk(metadata, secret_type)

            item = SecretInventoryItem(
                id=f"gcp-sm-{project_id}-{secret_name}",
                name=secret_name,
                secret_type=secret_type,
                source=SecretSource.GCP_SECRET_MANAGER,
                status=status,
                metadata=metadata,
                account_id=project_id,
                resource_arn=secret_id,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.GCP_SECRET_MANAGER not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.GCP_SECRET_MANAGER)

        return items

    def collect_from_kubernetes_secrets(
        self,
        secrets_data: list[dict[str, Any]],
        cluster_name: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect secrets from Kubernetes cluster.

        Args:
            secrets_data: List of Kubernetes secrets
            cluster_name: Kubernetes cluster name

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for secret in secrets_data:
            metadata_obj = secret.get("metadata", {})
            secret_name = metadata_obj.get("name", "unknown")
            namespace = metadata_obj.get("namespace", "default")
            secret_uid = metadata_obj.get("uid", "")
            creation_timestamp = metadata_obj.get("creationTimestamp")
            annotations = metadata_obj.get("annotations", {})
            labels = metadata_obj.get("labels", {})

            secret_type_str = secret.get("type", "Opaque")

            # Parse creation time
            created_dt = None
            if creation_timestamp:
                try:
                    created_dt = datetime.fromisoformat(creation_timestamp.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            # Map K8s secret type
            k8s_type_mapping = {
                "Opaque": SecretType.GENERIC_CREDENTIAL,
                "kubernetes.io/service-account-token": SecretType.API_TOKEN,
                "kubernetes.io/dockerconfigjson": SecretType.DOCKER_REGISTRY_CREDENTIAL,
                "kubernetes.io/tls": SecretType.TLS_CERTIFICATE,
                "kubernetes.io/ssh-auth": SecretType.SSH_PRIVATE_KEY,
                "kubernetes.io/basic-auth": SecretType.PASSWORD,
            }
            secret_type = k8s_type_mapping.get(secret_type_str, SecretType.GENERIC_CREDENTIAL)

            # Count secret keys
            data = secret.get("data", {})
            key_count = len(data)

            metadata = SecretMetadata(
                created_at=created_dt,
                tags={**labels, **annotations},
                description=f"Kubernetes {secret_type_str} secret with {key_count} keys",
            )

            risk_score, risk_factors = self._calculate_risk(metadata, secret_type)

            # Add K8s-specific risk factors
            if namespace == "default":
                risk_factors.append("Secret in default namespace")
                risk_score = min(100, risk_score + 10)
            if "kube-system" in namespace:
                risk_factors.append("System namespace secret")

            item = SecretInventoryItem(
                id=f"k8s-{cluster_name}-{namespace}-{secret_name}",
                name=f"{namespace}/{secret_name}",
                secret_type=secret_type,
                source=SecretSource.KUBERNETES_SECRET,
                status=SecretStatus.ACTIVE,
                metadata=metadata,
                account_id=cluster_name,
                namespace=namespace,
                resource_arn=secret_uid,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.KUBERNETES_SECRET not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.KUBERNETES_SECRET)

        return items

    def collect_from_hashicorp_vault(
        self,
        secrets_data: list[dict[str, Any]],
        vault_addr: str,
    ) -> list[SecretInventoryItem]:
        """
        Collect secrets from HashiCorp Vault.

        Args:
            secrets_data: List of secrets from Vault
            vault_addr: Vault server address

        Returns:
            List of SecretInventoryItem
        """
        items = []

        for secret in secrets_data:
            path = secret.get("path", "unknown")
            secret_metadata = secret.get("metadata", {})

            created_time = secret_metadata.get("created_time")
            version = secret_metadata.get("version", 1)
            deletion_time = secret_metadata.get("deletion_time")
            destroyed = secret_metadata.get("destroyed", False)

            # Parse times
            created_dt = None
            if created_time:
                try:
                    created_dt = datetime.fromisoformat(created_time.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass

            # Determine status
            if destroyed:
                status = SecretStatus.DELETED
            elif deletion_time:
                status = SecretStatus.DISABLED
            else:
                status = SecretStatus.ACTIVE

            metadata = SecretMetadata(
                created_at=created_dt,
                version=str(version),
                version_count=version,
            )

            secret_type = self._infer_secret_type(path, {})
            risk_score, risk_factors = self._calculate_risk(metadata, secret_type)

            item = SecretInventoryItem(
                id=f"vault-{path.replace('/', '-')}",
                name=path,
                secret_type=secret_type,
                source=SecretSource.HASHICORP_VAULT,
                status=status,
                metadata=metadata,
                account_id=vault_addr,
                risk_score=risk_score,
                risk_factors=risk_factors,
            )

            items.append(item)

        self._inventory.items.extend(items)
        if SecretSource.HASHICORP_VAULT not in self._inventory.sources_scanned:
            self._inventory.sources_scanned.append(SecretSource.HASHICORP_VAULT)

        return items

    def _infer_secret_type(
        self,
        name: str,
        tags: dict[str, str] | list[dict[str, str]],
    ) -> SecretType:
        """Infer secret type from name and tags."""
        name_lower = name.lower()

        # Convert tags list to dict if needed
        if isinstance(tags, list):
            tags = {t.get("Key", ""): t.get("Value", "") for t in tags}

        # Check tags first
        type_tag = tags.get("secret-type", tags.get("SecretType", "")).lower()
        if type_tag:
            type_mapping = {
                "api-key": SecretType.API_KEY,
                "password": SecretType.PASSWORD,
                "database": SecretType.DATABASE_PASSWORD,
                "aws": SecretType.AWS_SECRET_KEY,
                "azure": SecretType.AZURE_CLIENT_SECRET,
                "gcp": SecretType.GCP_API_KEY,
                "ssh": SecretType.SSH_PRIVATE_KEY,
                "tls": SecretType.TLS_CERTIFICATE,
            }
            for key, value in type_mapping.items():
                if key in type_tag:
                    return value

        # Infer from name
        if any(x in name_lower for x in ["aws", "access-key"]):
            return SecretType.AWS_ACCESS_KEY
        if any(x in name_lower for x in ["azure", "client-secret"]):
            return SecretType.AZURE_CLIENT_SECRET
        if any(x in name_lower for x in ["gcp", "service-account"]):
            return SecretType.GCP_SERVICE_ACCOUNT_KEY
        if any(x in name_lower for x in ["database", "db", "mysql", "postgres", "mongo", "redis"]):
            return SecretType.DATABASE_PASSWORD
        if any(x in name_lower for x in ["api-key", "apikey"]):
            return SecretType.API_KEY
        if any(x in name_lower for x in ["token", "bearer"]):
            return SecretType.API_TOKEN
        if any(x in name_lower for x in ["ssh", "id_rsa"]):
            return SecretType.SSH_PRIVATE_KEY
        if any(x in name_lower for x in ["tls", "ssl", "cert"]):
            return SecretType.TLS_CERTIFICATE
        if any(x in name_lower for x in ["github"]):
            return SecretType.GITHUB_TOKEN
        if any(x in name_lower for x in ["gitlab"]):
            return SecretType.GITLAB_TOKEN
        if any(x in name_lower for x in ["slack"]):
            return SecretType.SLACK_TOKEN
        if any(x in name_lower for x in ["stripe"]):
            return SecretType.STRIPE_KEY
        if any(x in name_lower for x in ["password", "passwd", "pwd"]):
            return SecretType.PASSWORD

        return SecretType.GENERIC_CREDENTIAL

    def _calculate_risk(
        self,
        metadata: SecretMetadata,
        secret_type: SecretType,
    ) -> tuple[float, list[str]]:
        """Calculate risk score and factors."""
        risk_score = 0.0
        risk_factors = []

        # Age-based risk
        if metadata.created_at:
            age_days = (datetime.now(timezone.utc) - metadata.created_at.replace(tzinfo=timezone.utc)).days
            if age_days > 365:
                risk_score += 30
                risk_factors.append(f"Secret is {age_days} days old (>365 days)")
            elif age_days > 180:
                risk_score += 20
                risk_factors.append(f"Secret is {age_days} days old (>180 days)")
            elif age_days > 90:
                risk_score += 10
                risk_factors.append(f"Secret is {age_days} days old (>90 days)")

        # Rotation-based risk
        if not metadata.rotation_enabled:
            risk_score += 15
            risk_factors.append("Automatic rotation not enabled")

        rotation_date = metadata.last_rotated_at or metadata.created_at
        if rotation_date:
            days_since = (datetime.now(timezone.utc) - rotation_date.replace(tzinfo=timezone.utc)).days
            if days_since > 90:
                risk_score += 25
                risk_factors.append(f"Not rotated in {days_since} days")

        # Expiration-based risk
        if metadata.expires_at:
            days_until = (metadata.expires_at.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days
            if days_until < 0:
                risk_score += 40
                risk_factors.append("Secret has expired")
            elif days_until < 7:
                risk_score += 30
                risk_factors.append(f"Expires in {days_until} days")
            elif days_until < 30:
                risk_score += 15
                risk_factors.append(f"Expires in {days_until} days")

        # Type-based risk
        high_risk_types = [
            SecretType.AWS_ACCESS_KEY,
            SecretType.AWS_SECRET_KEY,
            SecretType.GCP_SERVICE_ACCOUNT_KEY,
            SecretType.AZURE_CLIENT_SECRET,
            SecretType.DATABASE_PASSWORD,
            SecretType.SSH_PRIVATE_KEY,
            SecretType.TLS_PRIVATE_KEY,
        ]
        if secret_type in high_risk_types:
            risk_score += 10
            risk_factors.append(f"High-sensitivity secret type: {secret_type.value}")

        # Access tracking
        if not metadata.last_accessed_at:
            risk_score += 5
            risk_factors.append("No access tracking available")

        return min(100, risk_score), risk_factors

    def get_inventory(self) -> SecretInventory:
        """Get the current inventory."""
        self._inventory.last_updated = datetime.now(timezone.utc)
        return self._inventory

    def clear_inventory(self) -> None:
        """Clear the inventory."""
        self._inventory = SecretInventory()
