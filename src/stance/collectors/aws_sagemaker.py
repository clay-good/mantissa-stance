"""
AWS SageMaker collector for Mantissa Stance.

Collects SageMaker notebook instances, endpoints, models, training jobs,
and their configurations for AI/ML security posture assessment.
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

# Deprecated or insecure instance types
DEPRECATED_INSTANCE_TYPES = {
    "ml.t2.medium",
    "ml.t2.large",
    "ml.t2.xlarge",
    "ml.t2.2xlarge",
    "ml.m4.xlarge",
    "ml.m4.2xlarge",
    "ml.m4.4xlarge",
}

# Minimum recommended instance types for production
PRODUCTION_INSTANCE_TYPES = {
    "ml.m5.xlarge",
    "ml.m5.2xlarge",
    "ml.m5.4xlarge",
    "ml.c5.xlarge",
    "ml.c5.2xlarge",
    "ml.p3.2xlarge",
    "ml.g4dn.xlarge",
}


class SageMakerCollector(BaseCollector):
    """
    Collects AWS SageMaker resources and configurations.

    Gathers SageMaker notebook instances, endpoints, models, training jobs,
    and domain configurations with their security settings including
    VPC configuration, encryption, IAM roles, and network access.
    All API calls are read-only.
    """

    collector_name = "aws_sagemaker"
    resource_types = [
        "aws_sagemaker_notebook",
        "aws_sagemaker_endpoint",
        "aws_sagemaker_endpoint_config",
        "aws_sagemaker_model",
        "aws_sagemaker_training_job",
        "aws_sagemaker_domain",
        "aws_sagemaker_user_profile",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all SageMaker resources.

        Returns:
            Collection of SageMaker assets
        """
        assets: list[Asset] = []

        # Collect notebook instances
        try:
            assets.extend(self._collect_notebook_instances())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker notebook instances: {e}")

        # Collect endpoints
        try:
            assets.extend(self._collect_endpoints())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker endpoints: {e}")

        # Collect endpoint configurations
        try:
            assets.extend(self._collect_endpoint_configs())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker endpoint configs: {e}")

        # Collect models
        try:
            assets.extend(self._collect_models())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker models: {e}")

        # Collect training jobs
        try:
            assets.extend(self._collect_training_jobs())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker training jobs: {e}")

        # Collect domains (SageMaker Studio)
        try:
            assets.extend(self._collect_domains())
        except Exception as e:
            logger.warning(f"Failed to collect SageMaker domains: {e}")

        return AssetCollection(assets)

    def _collect_notebook_instances(self) -> list[Asset]:
        """Collect SageMaker notebook instances with their configurations."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        for notebook in self._paginate(
            sm_client, "list_notebook_instances", "NotebookInstances"
        ):
            notebook_name = notebook["NotebookInstanceName"]
            notebook_arn = notebook["NotebookInstanceArn"]

            # Get detailed configuration
            try:
                details = sm_client.describe_notebook_instance(
                    NotebookInstanceName=notebook_name
                )
            except Exception as e:
                logger.warning(f"Failed to describe notebook {notebook_name}: {e}")
                details = notebook

            # Extract tags
            tags = self._get_notebook_tags(notebook_arn)

            # Check security configurations
            instance_type = details.get("InstanceType", "")
            is_deprecated_instance = instance_type in DEPRECATED_INSTANCE_TYPES
            direct_internet_access = details.get("DirectInternetAccess", "Enabled")
            has_internet_access = direct_internet_access == "Enabled"
            root_access = details.get("RootAccess", "Enabled")
            has_root_access = root_access == "Enabled"

            # VPC configuration
            subnet_id = details.get("SubnetId")
            security_groups = details.get("SecurityGroups", [])
            in_vpc = bool(subnet_id)

            # Encryption
            kms_key_id = details.get("KmsKeyId")
            has_kms_encryption = bool(kms_key_id)
            volume_size = details.get("VolumeSizeInGB", 5)

            # Lifecycle configuration
            lifecycle_config_name = details.get("NotebookInstanceLifecycleConfigName")

            # Determine network exposure
            if has_internet_access and not in_vpc:
                network_exposure = NETWORK_EXPOSURE_INTERNET
            else:
                network_exposure = NETWORK_EXPOSURE_INTERNAL

            raw_config: dict[str, Any] = {
                "notebook_instance_name": notebook_name,
                "notebook_instance_arn": notebook_arn,
                "instance_type": instance_type,
                "is_deprecated_instance": is_deprecated_instance,
                "status": details.get("NotebookInstanceStatus"),
                "creation_time": str(details.get("CreationTime", "")),
                "last_modified_time": str(details.get("LastModifiedTime", "")),
                # Security configurations
                "role_arn": details.get("RoleArn"),
                "direct_internet_access": direct_internet_access,
                "has_internet_access": has_internet_access,
                "root_access": root_access,
                "has_root_access": has_root_access,
                # VPC configuration
                "subnet_id": subnet_id,
                "security_groups": security_groups,
                "in_vpc": in_vpc,
                # Encryption
                "kms_key_id": kms_key_id,
                "has_kms_encryption": has_kms_encryption,
                "volume_size_gb": volume_size,
                # Lifecycle
                "lifecycle_config_name": lifecycle_config_name,
                "has_lifecycle_config": bool(lifecycle_config_name),
                # Additional settings
                "platform_identifier": details.get("PlatformIdentifier"),
                "accelerator_types": details.get("AcceleratorTypes", []),
                "default_code_repository": details.get("DefaultCodeRepository"),
                "additional_code_repositories": details.get("AdditionalCodeRepositories", []),
                "url": details.get("Url"),
            }

            asset = Asset(
                asset_id=notebook_arn,
                asset_type="aws_sagemaker_notebook",
                name=notebook_name,
                region=self.region,
                account_id=self.account_id,
                tags=tags,
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

        return assets

    def _collect_endpoints(self) -> list[Asset]:
        """Collect SageMaker inference endpoints."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        for endpoint in self._paginate(
            sm_client, "list_endpoints", "Endpoints"
        ):
            endpoint_name = endpoint["EndpointName"]
            endpoint_arn = endpoint["EndpointArn"]

            # Get detailed configuration
            try:
                details = sm_client.describe_endpoint(EndpointName=endpoint_name)
            except Exception as e:
                logger.warning(f"Failed to describe endpoint {endpoint_name}: {e}")
                details = endpoint

            # Extract tags
            tags = self._get_endpoint_tags(endpoint_arn)

            # Get endpoint config details for encryption info
            endpoint_config_name = details.get("EndpointConfigName", "")
            endpoint_config = self._get_endpoint_config(endpoint_config_name)

            # Check security configurations
            kms_key_id = endpoint_config.get("KmsKeyId") if endpoint_config else None
            has_kms_encryption = bool(kms_key_id)

            # Data capture configuration
            data_capture_config = details.get("DataCaptureConfig", {})
            data_capture_enabled = data_capture_config.get("EnableCapture", False)

            # Check for production variants
            production_variants = details.get("ProductionVariants", [])

            raw_config: dict[str, Any] = {
                "endpoint_name": endpoint_name,
                "endpoint_arn": endpoint_arn,
                "endpoint_config_name": endpoint_config_name,
                "status": details.get("EndpointStatus"),
                "creation_time": str(details.get("CreationTime", "")),
                "last_modified_time": str(details.get("LastModifiedTime", "")),
                # Security configurations
                "kms_key_id": kms_key_id,
                "has_kms_encryption": has_kms_encryption,
                # Data capture
                "data_capture_enabled": data_capture_enabled,
                "data_capture_config": data_capture_config,
                # Production variants
                "production_variants": [
                    {
                        "variant_name": v.get("VariantName"),
                        "model_name": v.get("CurrentDeployedModelArn", "").split("/")[-1] if v.get("CurrentDeployedModelArn") else None,
                        "instance_type": v.get("CurrentInstanceType", v.get("InstanceType")),
                        "initial_instance_count": v.get("InitialInstanceCount", v.get("CurrentInstanceCount")),
                        "current_instance_count": v.get("CurrentInstanceCount"),
                        "current_weight": v.get("CurrentWeight"),
                    }
                    for v in production_variants
                ],
                "variant_count": len(production_variants),
                # Failure reason if any
                "failure_reason": details.get("FailureReason"),
            }

            asset = Asset(
                asset_id=endpoint_arn,
                asset_type="aws_sagemaker_endpoint",
                name=endpoint_name,
                region=self.region,
                account_id=self.account_id,
                tags=tags,
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,  # Endpoints are internal by default
            )
            assets.append(asset)

        return assets

    def _collect_endpoint_configs(self) -> list[Asset]:
        """Collect SageMaker endpoint configurations."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        for config in self._paginate(
            sm_client, "list_endpoint_configs", "EndpointConfigs"
        ):
            config_name = config["EndpointConfigName"]
            config_arn = config["EndpointConfigArn"]

            # Get detailed configuration
            try:
                details = sm_client.describe_endpoint_config(
                    EndpointConfigName=config_name
                )
            except Exception as e:
                logger.warning(f"Failed to describe endpoint config {config_name}: {e}")
                details = config

            # Extract tags
            tags = self._get_endpoint_config_tags(config_arn)

            # Encryption
            kms_key_id = details.get("KmsKeyId")
            has_kms_encryption = bool(kms_key_id)

            # Production variants
            production_variants = details.get("ProductionVariants", [])

            # Check for async inference config
            async_inference_config = details.get("AsyncInferenceConfig")
            has_async_inference = bool(async_inference_config)

            # Data capture config
            data_capture_config = details.get("DataCaptureConfig", {})
            data_capture_enabled = data_capture_config.get("EnableCapture", False)

            raw_config: dict[str, Any] = {
                "endpoint_config_name": config_name,
                "endpoint_config_arn": config_arn,
                "creation_time": str(details.get("CreationTime", "")),
                # Security configurations
                "kms_key_id": kms_key_id,
                "has_kms_encryption": has_kms_encryption,
                # Production variants
                "production_variants": [
                    {
                        "variant_name": v.get("VariantName"),
                        "model_name": v.get("ModelName"),
                        "instance_type": v.get("InstanceType"),
                        "initial_instance_count": v.get("InitialInstanceCount"),
                        "initial_variant_weight": v.get("InitialVariantWeight"),
                        "accelerator_type": v.get("AcceleratorType"),
                        "serverless_config": v.get("ServerlessConfig"),
                    }
                    for v in production_variants
                ],
                "variant_count": len(production_variants),
                # Async inference
                "has_async_inference": has_async_inference,
                "async_inference_config": async_inference_config,
                # Data capture
                "data_capture_enabled": data_capture_enabled,
                "data_capture_config": data_capture_config,
            }

            asset = Asset(
                asset_id=config_arn,
                asset_type="aws_sagemaker_endpoint_config",
                name=config_name,
                region=self.region,
                account_id=self.account_id,
                tags=tags,
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_models(self) -> list[Asset]:
        """Collect SageMaker models."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        for model in self._paginate(sm_client, "list_models", "Models"):
            model_name = model["ModelName"]
            model_arn = model["ModelArn"]

            # Get detailed configuration
            try:
                details = sm_client.describe_model(ModelName=model_name)
            except Exception as e:
                logger.warning(f"Failed to describe model {model_name}: {e}")
                details = model

            # Extract tags
            tags = self._get_model_tags(model_arn)

            # Primary container
            primary_container = details.get("PrimaryContainer", {})
            container_image = primary_container.get("Image", "")
            model_data_url = primary_container.get("ModelDataUrl", "")

            # VPC configuration
            vpc_config = details.get("VpcConfig", {})
            in_vpc = bool(vpc_config.get("Subnets"))

            # Enable network isolation
            enable_network_isolation = details.get("EnableNetworkIsolation", False)

            # Inference execution config
            inference_execution_config = details.get("InferenceExecutionConfig", {})

            raw_config: dict[str, Any] = {
                "model_name": model_name,
                "model_arn": model_arn,
                "creation_time": str(details.get("CreationTime", "")),
                # Execution role
                "execution_role_arn": details.get("ExecutionRoleArn"),
                # Primary container
                "primary_container": {
                    "image": container_image,
                    "model_data_url": model_data_url,
                    "container_hostname": primary_container.get("ContainerHostname"),
                    "mode": primary_container.get("Mode"),
                    "environment": list(primary_container.get("Environment", {}).keys()),  # Keys only, not values
                    "model_package_name": primary_container.get("ModelPackageName"),
                },
                # VPC configuration
                "vpc_config": {
                    "subnets": vpc_config.get("Subnets", []),
                    "security_groups": vpc_config.get("SecurityGroupIds", []),
                },
                "in_vpc": in_vpc,
                # Network isolation
                "enable_network_isolation": enable_network_isolation,
                # Inference execution
                "inference_execution_config": inference_execution_config,
                # Containers (for multi-model)
                "containers": [
                    {
                        "image": c.get("Image"),
                        "container_hostname": c.get("ContainerHostname"),
                    }
                    for c in details.get("Containers", [])
                ],
            }

            asset = Asset(
                asset_id=model_arn,
                asset_type="aws_sagemaker_model",
                name=model_name,
                region=self.region,
                account_id=self.account_id,
                tags=tags,
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_training_jobs(self) -> list[Asset]:
        """Collect recent SageMaker training jobs."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        # Only collect recent training jobs (last 100)
        try:
            response = sm_client.list_training_jobs(
                MaxResults=100,
                SortBy="CreationTime",
                SortOrder="Descending",
            )
            training_jobs = response.get("TrainingJobSummaries", [])
        except Exception as e:
            logger.warning(f"Failed to list training jobs: {e}")
            return assets

        for job in training_jobs:
            job_name = job["TrainingJobName"]
            job_arn = job["TrainingJobArn"]

            # Get detailed configuration
            try:
                details = sm_client.describe_training_job(TrainingJobName=job_name)
            except Exception as e:
                logger.warning(f"Failed to describe training job {job_name}: {e}")
                details = job

            # Extract tags
            tags = self._get_training_job_tags(job_arn)

            # Resource config
            resource_config = details.get("ResourceConfig", {})
            instance_type = resource_config.get("InstanceType", "")
            instance_count = resource_config.get("InstanceCount", 1)
            volume_size_gb = resource_config.get("VolumeSizeInGB", 0)
            volume_kms_key = resource_config.get("VolumeKmsKeyId")

            # VPC configuration
            vpc_config = details.get("VpcConfig", {})
            in_vpc = bool(vpc_config.get("Subnets"))

            # Output data config
            output_config = details.get("OutputDataConfig", {})
            output_kms_key = output_config.get("KmsKeyId")

            # Enable network isolation
            enable_network_isolation = details.get("EnableNetworkIsolation", False)
            enable_inter_container_encryption = details.get("EnableInterContainerTrafficEncryption", False)

            raw_config: dict[str, Any] = {
                "training_job_name": job_name,
                "training_job_arn": job_arn,
                "training_job_status": details.get("TrainingJobStatus"),
                "secondary_status": details.get("SecondaryStatus"),
                "creation_time": str(details.get("CreationTime", "")),
                "training_start_time": str(details.get("TrainingStartTime", "")),
                "training_end_time": str(details.get("TrainingEndTime", "")),
                # Role
                "role_arn": details.get("RoleArn"),
                # Algorithm
                "algorithm_specification": {
                    "training_image": details.get("AlgorithmSpecification", {}).get("TrainingImage"),
                    "algorithm_name": details.get("AlgorithmSpecification", {}).get("AlgorithmName"),
                    "training_input_mode": details.get("AlgorithmSpecification", {}).get("TrainingInputMode"),
                    "enable_sage_maker_metrics_time_series": details.get("AlgorithmSpecification", {}).get("EnableSageMakerMetricsTimeSeries"),
                },
                # Resource configuration
                "resource_config": {
                    "instance_type": instance_type,
                    "instance_count": instance_count,
                    "volume_size_gb": volume_size_gb,
                    "volume_kms_key_id": volume_kms_key,
                    "has_volume_encryption": bool(volume_kms_key),
                },
                # VPC configuration
                "vpc_config": {
                    "subnets": vpc_config.get("Subnets", []),
                    "security_groups": vpc_config.get("SecurityGroupIds", []),
                },
                "in_vpc": in_vpc,
                # Output configuration
                "output_data_config": {
                    "s3_output_path": output_config.get("S3OutputPath"),
                    "kms_key_id": output_kms_key,
                    "has_output_encryption": bool(output_kms_key),
                },
                # Security settings
                "enable_network_isolation": enable_network_isolation,
                "enable_inter_container_traffic_encryption": enable_inter_container_encryption,
                # Input data (channel names only)
                "input_data_channels": [
                    c.get("ChannelName") for c in details.get("InputDataConfig", [])
                ],
                # Failure reason if any
                "failure_reason": details.get("FailureReason"),
            }

            asset = Asset(
                asset_id=job_arn,
                asset_type="aws_sagemaker_training_job",
                name=job_name,
                region=self.region,
                account_id=self.account_id,
                tags=tags,
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    def _collect_domains(self) -> list[Asset]:
        """Collect SageMaker Studio domains."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = sm_client.list_domains()
            domains = response.get("Domains", [])
        except Exception as e:
            logger.warning(f"Failed to list SageMaker domains: {e}")
            return assets

        for domain in domains:
            domain_id = domain["DomainId"]
            domain_name = domain.get("DomainName", domain_id)
            domain_arn = domain.get("DomainArn", f"arn:aws:sagemaker:{self.region}:{self.account_id}:domain/{domain_id}")

            # Get detailed configuration
            try:
                details = sm_client.describe_domain(DomainId=domain_id)
            except Exception as e:
                logger.warning(f"Failed to describe domain {domain_id}: {e}")
                details = domain

            # VPC configuration
            vpc_id = details.get("VpcId")
            subnet_ids = details.get("SubnetIds", [])
            in_vpc = bool(vpc_id)

            # App network access type
            app_network_access = details.get("AppNetworkAccessType", "PublicInternetOnly")
            has_public_access = app_network_access == "PublicInternetOnly"

            # Default user settings
            default_user_settings = details.get("DefaultUserSettings", {})

            # Security settings
            kms_key_id = details.get("KmsKeyId")
            has_kms_encryption = bool(kms_key_id)

            # Auth mode
            auth_mode = details.get("AuthMode", "IAM")

            # Home EFS file system
            home_efs_file_system_id = details.get("HomeEfsFileSystemId")

            raw_config: dict[str, Any] = {
                "domain_id": domain_id,
                "domain_name": domain_name,
                "domain_arn": domain_arn,
                "status": details.get("Status"),
                "creation_time": str(details.get("CreationTime", "")),
                "last_modified_time": str(details.get("LastModifiedTime", "")),
                # VPC configuration
                "vpc_id": vpc_id,
                "subnet_ids": subnet_ids,
                "in_vpc": in_vpc,
                # Network access
                "app_network_access_type": app_network_access,
                "has_public_access": has_public_access,
                # Authentication
                "auth_mode": auth_mode,
                # Encryption
                "kms_key_id": kms_key_id,
                "has_kms_encryption": has_kms_encryption,
                # Home file system
                "home_efs_file_system_id": home_efs_file_system_id,
                # Default user settings
                "default_user_settings": {
                    "execution_role": default_user_settings.get("ExecutionRole"),
                    "security_groups": default_user_settings.get("SecurityGroups", []),
                    "jupyter_server_app_settings": bool(default_user_settings.get("JupyterServerAppSettings")),
                    "kernel_gateway_app_settings": bool(default_user_settings.get("KernelGatewayAppSettings")),
                },
                # URL
                "url": details.get("Url"),
                # Failure reason if any
                "failure_reason": details.get("FailureReason"),
            }

            network_exposure = NETWORK_EXPOSURE_INTERNET if has_public_access else NETWORK_EXPOSURE_INTERNAL

            asset = Asset(
                asset_id=domain_arn,
                asset_type="aws_sagemaker_domain",
                name=domain_name,
                region=self.region,
                account_id=self.account_id,
                tags={},  # Domains don't support tags directly
                raw_config=raw_config,
                collected_at=now,
                network_exposure=network_exposure,
            )
            assets.append(asset)

            # Also collect user profiles for this domain
            assets.extend(self._collect_user_profiles(domain_id))

        return assets

    def _collect_user_profiles(self, domain_id: str) -> list[Asset]:
        """Collect user profiles for a SageMaker domain."""
        sm_client = self._get_client("sagemaker")
        assets: list[Asset] = []
        now = self._now()

        try:
            response = sm_client.list_user_profiles(DomainIdEquals=domain_id)
            user_profiles = response.get("UserProfiles", [])
        except Exception as e:
            logger.warning(f"Failed to list user profiles for domain {domain_id}: {e}")
            return assets

        for profile in user_profiles:
            profile_name = profile["UserProfileName"]
            domain_id = profile["DomainId"]

            # Get detailed configuration
            try:
                details = sm_client.describe_user_profile(
                    DomainId=domain_id,
                    UserProfileName=profile_name,
                )
            except Exception as e:
                logger.warning(f"Failed to describe user profile {profile_name}: {e}")
                details = profile

            user_settings = details.get("UserSettings", {})

            raw_config: dict[str, Any] = {
                "user_profile_name": profile_name,
                "domain_id": domain_id,
                "status": details.get("Status"),
                "creation_time": str(details.get("CreationTime", "")),
                "last_modified_time": str(details.get("LastModifiedTime", "")),
                # User settings
                "user_settings": {
                    "execution_role": user_settings.get("ExecutionRole"),
                    "security_groups": user_settings.get("SecurityGroups", []),
                    "sharing_settings": user_settings.get("SharingSettings", {}),
                },
                # SSO info (if using SSO auth)
                "single_sign_on_user_identifier": details.get("SingleSignOnUserIdentifier"),
                "single_sign_on_user_value": details.get("SingleSignOnUserValue"),
                # Failure reason if any
                "failure_reason": details.get("FailureReason"),
            }

            profile_arn = f"arn:aws:sagemaker:{self.region}:{self.account_id}:user-profile/{domain_id}/{profile_name}"

            asset = Asset(
                asset_id=profile_arn,
                asset_type="aws_sagemaker_user_profile",
                name=profile_name,
                region=self.region,
                account_id=self.account_id,
                tags={},
                raw_config=raw_config,
                collected_at=now,
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
            )
            assets.append(asset)

        return assets

    # Helper methods for getting tags
    def _get_notebook_tags(self, arn: str) -> dict[str, str]:
        """Get tags for a notebook instance."""
        return self._get_resource_tags(arn)

    def _get_endpoint_tags(self, arn: str) -> dict[str, str]:
        """Get tags for an endpoint."""
        return self._get_resource_tags(arn)

    def _get_endpoint_config_tags(self, arn: str) -> dict[str, str]:
        """Get tags for an endpoint config."""
        return self._get_resource_tags(arn)

    def _get_model_tags(self, arn: str) -> dict[str, str]:
        """Get tags for a model."""
        return self._get_resource_tags(arn)

    def _get_training_job_tags(self, arn: str) -> dict[str, str]:
        """Get tags for a training job."""
        return self._get_resource_tags(arn)

    def _get_resource_tags(self, arn: str) -> dict[str, str]:
        """Get tags for any SageMaker resource."""
        sm_client = self._get_client("sagemaker")
        try:
            response = sm_client.list_tags(ResourceArn=arn)
            return self._extract_tags(response.get("Tags", []))
        except Exception as e:
            logger.debug(f"Failed to get tags for {arn}: {e}")
            return {}

    def _get_endpoint_config(self, config_name: str) -> dict[str, Any] | None:
        """Get endpoint configuration details."""
        if not config_name:
            return None
        sm_client = self._get_client("sagemaker")
        try:
            return sm_client.describe_endpoint_config(EndpointConfigName=config_name)
        except Exception as e:
            logger.debug(f"Failed to get endpoint config {config_name}: {e}")
            return None

    def _now(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
