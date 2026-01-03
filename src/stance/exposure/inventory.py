"""
Public Asset Inventory for Exposure Management.

Aggregates publicly accessible cloud resources from collector data
and correlates with DSPM classification results for risk assessment.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from stance.models.asset import Asset, AssetCollection, NETWORK_EXPOSURE_INTERNET
from stance.exposure.base import (
    ExposureConfig,
    ExposureType,
    ExposureSeverity,
    ExposureFindingType,
    PublicAsset,
    ExposureFinding,
    ExposureInventorySummary,
    ExposureInventoryResult,
    BaseExposureAnalyzer,
)

logger = logging.getLogger(__name__)


# Mapping from resource types to exposure types
RESOURCE_TYPE_TO_EXPOSURE: dict[str, ExposureType] = {
    # Storage
    "aws_s3_bucket": ExposureType.PUBLIC_BUCKET,
    "gcp_storage_bucket": ExposureType.PUBLIC_BUCKET,
    "azure_storage_container": ExposureType.PUBLIC_BUCKET,
    "azure_storage_account": ExposureType.PUBLIC_BUCKET,
    # Compute
    "aws_ec2_instance": ExposureType.PUBLIC_INSTANCE,
    "gcp_compute_instance": ExposureType.PUBLIC_INSTANCE,
    "azure_vm": ExposureType.PUBLIC_INSTANCE,
    # Serverless
    "aws_lambda_function": ExposureType.PUBLIC_FUNCTION,
    "gcp_cloud_function": ExposureType.PUBLIC_FUNCTION,
    "gcp_cloud_run_service": ExposureType.PUBLIC_FUNCTION,
    "azure_function": ExposureType.PUBLIC_FUNCTION,
    # Database
    "aws_rds_instance": ExposureType.PUBLIC_DATABASE,
    "aws_rds_cluster": ExposureType.PUBLIC_DATABASE,
    "gcp_sql_instance": ExposureType.PUBLIC_DATABASE,
    "azure_sql_server": ExposureType.PUBLIC_DATABASE,
    "azure_sql_database": ExposureType.PUBLIC_DATABASE,
    # Network
    "aws_elb": ExposureType.PUBLIC_LOAD_BALANCER,
    "aws_alb": ExposureType.PUBLIC_LOAD_BALANCER,
    "aws_nlb": ExposureType.PUBLIC_LOAD_BALANCER,
    "gcp_load_balancer": ExposureType.PUBLIC_LOAD_BALANCER,
    "azure_load_balancer": ExposureType.PUBLIC_LOAD_BALANCER,
    "aws_api_gateway": ExposureType.PUBLIC_API_GATEWAY,
    "gcp_api_gateway": ExposureType.PUBLIC_API_GATEWAY,
    "azure_api_management": ExposureType.PUBLIC_API_GATEWAY,
    # CDN
    "aws_cloudfront_distribution": ExposureType.PUBLIC_CDN,
    "gcp_cdn": ExposureType.PUBLIC_CDN,
    "azure_cdn": ExposureType.PUBLIC_CDN,
    # IP
    "aws_elastic_ip": ExposureType.PUBLIC_IP,
    "gcp_external_ip": ExposureType.PUBLIC_IP,
    "azure_public_ip": ExposureType.PUBLIC_IP,
    # Kubernetes
    "aws_eks_cluster": ExposureType.PUBLIC_SERVICE,
    "gcp_gke_cluster": ExposureType.PUBLIC_SERVICE,
    "azure_aks_cluster": ExposureType.PUBLIC_SERVICE,
}


@dataclass
class DSPMClassification:
    """
    Data classification from DSPM scan results.

    Attributes:
        resource_id: Resource identifier
        classification_level: Classification level (public, internal, etc.)
        data_categories: List of data categories found
        scan_date: When the scan was performed
    """

    resource_id: str
    classification_level: str
    data_categories: list[str] = field(default_factory=list)
    scan_date: datetime | None = None


class PublicAssetInventory(BaseExposureAnalyzer):
    """
    Aggregates and analyzes publicly accessible cloud resources.

    Discovers public assets from collector data (Asset objects) and
    correlates with DSPM classification results for comprehensive
    exposure analysis.
    """

    analyzer_name = "public_asset_inventory"

    def __init__(
        self,
        config: ExposureConfig | None = None,
        assets: AssetCollection | list[Asset] | None = None,
    ):
        """
        Initialize the public asset inventory.

        Args:
            config: Optional configuration for analysis
            assets: Collection of assets to analyze
        """
        super().__init__(config)
        if assets is None:
            self._assets: list[Asset] = []
        elif isinstance(assets, AssetCollection):
            self._assets = list(assets)
        else:
            self._assets = list(assets)
        self._dspm_classifications: dict[str, DSPMClassification] = {}
        self._finding_counter = 0

    def register_assets(self, assets: AssetCollection | list[Asset]) -> None:
        """
        Register assets for analysis.

        Args:
            assets: Assets to add to the inventory
        """
        if isinstance(assets, AssetCollection):
            self._assets.extend(list(assets))
        else:
            self._assets.extend(assets)

    def register_dspm_classification(
        self,
        resource_id: str,
        classification_level: str,
        data_categories: list[str] | None = None,
        scan_date: datetime | None = None,
    ) -> None:
        """
        Register DSPM classification for a resource.

        Args:
            resource_id: Resource identifier
            classification_level: Classification level
            data_categories: Data categories found
            scan_date: When the scan was performed
        """
        self._dspm_classifications[resource_id] = DSPMClassification(
            resource_id=resource_id,
            classification_level=classification_level,
            data_categories=data_categories or [],
            scan_date=scan_date,
        )

    def register_dspm_classifications(
        self,
        classifications: dict[str, DSPMClassification],
    ) -> None:
        """
        Register multiple DSPM classifications.

        Args:
            classifications: Dictionary mapping resource_id to classification
        """
        self._dspm_classifications.update(classifications)

    def discover_public_assets(self) -> Iterator[PublicAsset]:
        """
        Discover publicly accessible assets from registered assets.

        Filters assets to those with internet-facing network exposure
        and converts them to PublicAsset objects.

        Yields:
            Public assets found
        """
        for asset in self._assets:
            # Filter by configuration
            if not self._should_include_asset(asset):
                continue

            # Only include internet-facing assets
            if asset.network_exposure != NETWORK_EXPOSURE_INTERNET:
                continue

            # Convert to PublicAsset
            public_asset = self._asset_to_public_asset(asset)
            if public_asset:
                yield public_asset

    def analyze_asset(self, asset: PublicAsset) -> list[ExposureFinding]:
        """
        Analyze a public asset for exposure findings.

        Args:
            asset: Public asset to analyze

        Returns:
            List of findings for this asset
        """
        findings: list[ExposureFinding] = []

        # Check for sensitive data exposure
        if asset.has_sensitive_data:
            finding = self._create_sensitive_data_finding(asset)
            if finding:
                findings.append(finding)

        # Check for unrestricted access
        if asset.access_method in ("public_acl", "wildcard_policy", "anonymous"):
            findings.append(self._create_unrestricted_access_finding(asset))

        # Check for dangerous ports (compute resources)
        if asset.exposure_type == ExposureType.PUBLIC_INSTANCE:
            dangerous_ports = asset.metadata.get("dangerous_ports", [])
            if dangerous_ports:
                findings.append(self._create_dangerous_ports_finding(asset, dangerous_ports))

        # Check for unclassified public data
        if (
            asset.exposure_type == ExposureType.PUBLIC_BUCKET
            and not asset.data_classification
        ):
            findings.append(self._create_unclassified_finding(asset))

        return findings

    def run_inventory(self) -> ExposureInventoryResult:
        """
        Run the full public asset inventory analysis.

        Discovers all public assets, analyzes each for findings,
        and generates a comprehensive result.

        Returns:
            Complete inventory result
        """
        result = ExposureInventoryResult(
            inventory_id=f"exp-{uuid.uuid4().hex[:12]}",
            config=self._config,
            started_at=datetime.now(timezone.utc),
        )

        public_assets: list[PublicAsset] = []
        all_findings: list[ExposureFinding] = []

        try:
            # Discover public assets
            for public_asset in self.discover_public_assets():
                public_assets.append(public_asset)

                # Analyze each asset for findings
                asset_findings = self.analyze_asset(public_asset)
                all_findings.extend(asset_findings)

        except Exception as e:
            logger.error(f"Error during inventory analysis: {e}")
            result.errors.append(str(e))

        result.public_assets = public_assets
        result.findings = all_findings
        result.summary = self._build_summary(public_assets, all_findings)
        result.completed_at = datetime.now(timezone.utc)

        return result

    def get_public_assets_by_type(
        self,
        exposure_type: ExposureType,
    ) -> list[PublicAsset]:
        """
        Get public assets filtered by exposure type.

        Args:
            exposure_type: Type of exposure to filter by

        Returns:
            List of public assets of the specified type
        """
        return [
            asset for asset in self.discover_public_assets()
            if asset.exposure_type == exposure_type
        ]

    def get_public_assets_by_cloud(
        self,
        cloud_provider: str,
    ) -> list[PublicAsset]:
        """
        Get public assets filtered by cloud provider.

        Args:
            cloud_provider: Cloud provider to filter by

        Returns:
            List of public assets from the specified cloud
        """
        return [
            asset for asset in self.discover_public_assets()
            if asset.cloud_provider == cloud_provider
        ]

    def get_sensitive_public_assets(self) -> list[PublicAsset]:
        """
        Get public assets that contain sensitive data.

        Returns:
            List of public assets with sensitive data
        """
        return [
            asset for asset in self.discover_public_assets()
            if asset.has_sensitive_data
        ]

    def _should_include_asset(self, asset: Asset) -> bool:
        """Check if asset should be included based on configuration."""
        # Filter by cloud provider
        if self._config.cloud_providers:
            if asset.cloud_provider not in self._config.cloud_providers:
                return False

        # Filter by region
        if self._config.regions:
            if asset.region not in self._config.regions:
                return False

        # Filter by resource category
        exposure_type = RESOURCE_TYPE_TO_EXPOSURE.get(asset.resource_type)
        if exposure_type:
            if exposure_type in (ExposureType.PUBLIC_BUCKET,):
                if not self._config.include_storage:
                    return False
            elif exposure_type in (ExposureType.PUBLIC_INSTANCE, ExposureType.PUBLIC_FUNCTION):
                if not self._config.include_compute:
                    return False
            elif exposure_type in (ExposureType.PUBLIC_DATABASE,):
                if not self._config.include_database:
                    return False
            elif exposure_type in (
                ExposureType.PUBLIC_LOAD_BALANCER,
                ExposureType.PUBLIC_API_GATEWAY,
                ExposureType.PUBLIC_IP,
            ):
                if not self._config.include_network:
                    return False

        return True

    def _asset_to_public_asset(self, asset: Asset) -> PublicAsset | None:
        """Convert an Asset to a PublicAsset."""
        exposure_type = RESOURCE_TYPE_TO_EXPOSURE.get(asset.resource_type)
        if not exposure_type:
            # Default to bucket for storage, instance for compute
            if "bucket" in asset.resource_type.lower() or "storage" in asset.resource_type.lower():
                exposure_type = ExposureType.PUBLIC_BUCKET
            elif "instance" in asset.resource_type.lower() or "vm" in asset.resource_type.lower():
                exposure_type = ExposureType.PUBLIC_INSTANCE
            else:
                exposure_type = ExposureType.PUBLIC_IP  # Generic fallback

        # Extract public IPs from raw_config
        public_ips = self._extract_public_ips(asset.raw_config)

        # Extract public endpoint
        public_endpoint = self._extract_public_endpoint(asset)

        # Extract access method
        access_method = self._extract_access_method(asset.raw_config)

        # Get DSPM classification if available
        dspm = self._dspm_classifications.get(asset.id)
        data_classification = dspm.classification_level if dspm else None
        data_categories = dspm.data_categories if dspm else []

        # Check for sensitive data categories
        sensitive_categories = {"pii", "pci", "phi", "credentials", "financial"}
        has_sensitive_data = any(
            any(s in cat.lower() for s in sensitive_categories)
            for cat in data_categories
        )

        # Also check classification level
        if data_classification in ("confidential", "restricted", "top_secret"):
            has_sensitive_data = True

        # Calculate risk score
        risk_score = self.calculate_risk_score(
            exposure_type, data_classification, data_categories, access_method
        )

        return PublicAsset(
            asset_id=asset.id,
            name=asset.name,
            exposure_type=exposure_type,
            cloud_provider=asset.cloud_provider,
            account_id=asset.account_id,
            region=asset.region,
            resource_type=asset.resource_type,
            public_endpoint=public_endpoint,
            public_ips=public_ips,
            access_method=access_method,
            data_classification=data_classification,
            data_categories=data_categories,
            has_sensitive_data=has_sensitive_data,
            risk_score=risk_score,
            metadata=self._extract_metadata(asset.raw_config),
        )

    def _extract_public_ips(self, raw_config: dict[str, Any]) -> list[str]:
        """Extract public IP addresses from raw config."""
        public_ips: list[str] = []

        # AWS EC2
        if raw_config.get("public_ip_address"):
            public_ips.append(raw_config["public_ip_address"])

        # GCP Compute
        if raw_config.get("external_ips"):
            public_ips.extend(raw_config["external_ips"])

        # Azure VM
        if raw_config.get("public_ips"):
            public_ips.extend(raw_config["public_ips"])

        return public_ips

    def _extract_public_endpoint(self, asset: Asset) -> str | None:
        """Extract public endpoint URL from asset."""
        raw_config = asset.raw_config

        # S3 bucket website
        if raw_config.get("website_endpoint"):
            return raw_config["website_endpoint"]

        # API Gateway
        if raw_config.get("api_endpoint"):
            return raw_config["api_endpoint"]

        # Load balancer DNS
        if raw_config.get("dns_name"):
            return raw_config["dns_name"]

        # CloudFront
        if raw_config.get("domain_name"):
            return raw_config["domain_name"]

        # EC2 public DNS
        if raw_config.get("public_dns_name"):
            return raw_config["public_dns_name"]

        # Cloud Run URL
        if raw_config.get("url"):
            return raw_config["url"]

        # Azure public endpoints
        if raw_config.get("primary_endpoints"):
            endpoints = raw_config["primary_endpoints"]
            if isinstance(endpoints, dict):
                return endpoints.get("blob") or endpoints.get("web")

        return None

    def _extract_access_method(self, raw_config: dict[str, Any]) -> str:
        """Extract how public access is granted."""
        # AWS S3
        if raw_config.get("acl_allows_public"):
            return "public_acl"
        if raw_config.get("policy_allows_public"):
            return "wildcard_policy"

        # GCP GCS
        if raw_config.get("is_public"):
            iam_bindings = raw_config.get("iam_bindings", [])
            for binding in iam_bindings:
                members = binding.get("members", [])
                if "allUsers" in members:
                    return "public_acl"
                if "allAuthenticatedUsers" in members:
                    return "authenticated_users"
            return "policy"

        # Azure
        if raw_config.get("allow_blob_public_access"):
            return "public_access_enabled"
        if raw_config.get("public_access") == "container":
            return "container_public"
        if raw_config.get("public_access") == "blob":
            return "blob_public"

        # Network-based
        if raw_config.get("has_public_ip") or raw_config.get("public_ip_address"):
            return "public_ip"
        if raw_config.get("has_external_ip") or raw_config.get("external_ips"):
            return "external_ip"

        return "unknown"

    def _extract_metadata(self, raw_config: dict[str, Any]) -> dict[str, Any]:
        """Extract relevant metadata for findings."""
        metadata: dict[str, Any] = {}

        # Dangerous ports for security groups
        if raw_config.get("dangerous_ingress_rules"):
            metadata["dangerous_ports"] = raw_config["dangerous_ingress_rules"]

        # Security group info
        if raw_config.get("security_groups"):
            metadata["security_groups"] = raw_config["security_groups"]

        # Encryption status
        if raw_config.get("encryption_enabled") is not None:
            metadata["encrypted"] = raw_config["encryption_enabled"]

        # Versioning
        if raw_config.get("versioning_enabled") is not None:
            metadata["versioning"] = raw_config["versioning_enabled"]

        return metadata

    def _create_sensitive_data_finding(
        self,
        asset: PublicAsset,
    ) -> ExposureFinding | None:
        """Create a finding for sensitive data exposure."""
        self._finding_counter += 1

        # Determine finding type based on data categories
        finding_type = ExposureFindingType.SENSITIVE_DATA_PUBLIC
        categories_lower = [c.lower() for c in asset.data_categories]

        if any("pii" in c for c in categories_lower):
            finding_type = ExposureFindingType.PUBLIC_PII_EXPOSURE
        elif any("pci" in c for c in categories_lower):
            finding_type = ExposureFindingType.PUBLIC_PCI_EXPOSURE
        elif any("phi" in c for c in categories_lower):
            finding_type = ExposureFindingType.PUBLIC_PHI_EXPOSURE
        elif any("credential" in c or "secret" in c or "key" in c for c in categories_lower):
            finding_type = ExposureFindingType.PUBLIC_CREDENTIALS

        severity = self.calculate_severity(
            asset.exposure_type,
            asset.data_classification,
            asset.has_sensitive_data,
        )

        return ExposureFinding(
            finding_id=f"{asset.asset_id}-exp-{self._finding_counter:04d}",
            finding_type=finding_type,
            severity=severity,
            title=f"Sensitive data exposed publicly on {asset.name}",
            description=(
                f"Public resource '{asset.name}' contains sensitive data "
                f"classified as '{asset.data_classification}'. "
                f"Data categories: {', '.join(asset.data_categories)}."
            ),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            exposure_type=asset.exposure_type,
            cloud_provider=asset.cloud_provider,
            region=asset.region,
            data_classification=asset.data_classification,
            data_categories=asset.data_categories,
            recommended_action=(
                f"Remove public access from '{asset.name}' or relocate sensitive data "
                "to a private resource."
            ),
            risk_score=asset.risk_score,
        )

    def _create_unrestricted_access_finding(
        self,
        asset: PublicAsset,
    ) -> ExposureFinding:
        """Create a finding for unrestricted public access."""
        self._finding_counter += 1

        severity = ExposureSeverity.MEDIUM
        if asset.has_sensitive_data:
            severity = ExposureSeverity.HIGH

        return ExposureFinding(
            finding_id=f"{asset.asset_id}-exp-{self._finding_counter:04d}",
            finding_type=ExposureFindingType.UNRESTRICTED_ACCESS,
            severity=severity,
            title=f"Unrestricted public access on {asset.name}",
            description=(
                f"Resource '{asset.name}' has unrestricted public access via "
                f"'{asset.access_method}'. Consider implementing access controls."
            ),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            exposure_type=asset.exposure_type,
            cloud_provider=asset.cloud_provider,
            region=asset.region,
            data_classification=asset.data_classification,
            recommended_action=(
                f"Implement access controls on '{asset.name}'. Consider using "
                "IP allowlists, authentication, or private endpoints."
            ),
            risk_score=asset.risk_score,
        )

    def _create_dangerous_ports_finding(
        self,
        asset: PublicAsset,
        dangerous_ports: list[Any],
    ) -> ExposureFinding:
        """Create a finding for dangerous ports exposed."""
        self._finding_counter += 1

        return ExposureFinding(
            finding_id=f"{asset.asset_id}-exp-{self._finding_counter:04d}",
            finding_type=ExposureFindingType.DANGEROUS_PORTS_EXPOSED,
            severity=ExposureSeverity.HIGH,
            title=f"Dangerous ports exposed on {asset.name}",
            description=(
                f"Public instance '{asset.name}' has dangerous ports exposed to "
                f"the internet. This includes administrative or database ports that "
                "could be exploited by attackers."
            ),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            exposure_type=asset.exposure_type,
            cloud_provider=asset.cloud_provider,
            region=asset.region,
            recommended_action=(
                f"Restrict access to administrative ports on '{asset.name}'. "
                "Use VPN, bastion hosts, or IP allowlists instead of public access."
            ),
            risk_score=min(100.0, asset.risk_score + 20.0),
            metadata={"dangerous_ports": dangerous_ports},
        )

    def _create_unclassified_finding(
        self,
        asset: PublicAsset,
    ) -> ExposureFinding:
        """Create a finding for unclassified public data."""
        self._finding_counter += 1

        return ExposureFinding(
            finding_id=f"{asset.asset_id}-exp-{self._finding_counter:04d}",
            finding_type=ExposureFindingType.UNCLASSIFIED_PUBLIC,
            severity=ExposureSeverity.LOW,
            title=f"Unclassified data on public resource {asset.name}",
            description=(
                f"Public resource '{asset.name}' has not been scanned for data "
                "classification. Consider running a DSPM scan to identify any "
                "sensitive data that may be exposed."
            ),
            asset_id=asset.asset_id,
            asset_name=asset.name,
            exposure_type=asset.exposure_type,
            cloud_provider=asset.cloud_provider,
            region=asset.region,
            recommended_action=(
                f"Run a DSPM scan on '{asset.name}' to classify the data and "
                "determine if sensitive information is being exposed publicly."
            ),
            risk_score=asset.risk_score,
        )


def create_inventory_from_assets(
    assets: AssetCollection | list[Asset],
    dspm_results: dict[str, dict[str, Any]] | None = None,
    config: ExposureConfig | None = None,
) -> ExposureInventoryResult:
    """
    Convenience function to create an exposure inventory from assets.

    Args:
        assets: Collection of assets to analyze
        dspm_results: Optional DSPM scan results keyed by resource_id
        config: Optional configuration

    Returns:
        Complete inventory result
    """
    inventory = PublicAssetInventory(config=config, assets=assets)

    # Register DSPM classifications if provided
    if dspm_results:
        for resource_id, result in dspm_results.items():
            inventory.register_dspm_classification(
                resource_id=resource_id,
                classification_level=result.get("classification_level", "unknown"),
                data_categories=result.get("data_categories", []),
            )

    return inventory.run_inventory()
