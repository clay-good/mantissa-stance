"""
AWS Lambda collector for Mantissa Stance.

Collects Lambda functions, layers, and their configurations
for security posture assessment.
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

# Deprecated runtimes that may have security implications
DEPRECATED_RUNTIMES = {
    "python2.7",
    "python3.6",
    "nodejs8.10",
    "nodejs10.x",
    "dotnetcore2.1",
    "ruby2.5",
    "java8",
}

# Runtimes approaching end of support (should be monitored)
EOL_APPROACHING_RUNTIMES = {
    "nodejs12.x",
    "nodejs14.x",
    "python3.7",
    "python3.8",
    "dotnetcore3.1",
    "ruby2.7",
}


class LambdaCollector(BaseCollector):
    """
    Collects AWS Lambda functions, layers, and configurations.

    Gathers Lambda functions with their security configurations including
    VPC settings, environment variables (names only, not values),
    execution roles, and resource policies. All API calls are read-only.
    """

    collector_name = "aws_lambda"
    resource_types = [
        "aws_lambda_function",
        "aws_lambda_layer",
        "aws_lambda_event_source_mapping",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all Lambda resources.

        Returns:
            Collection of Lambda assets
        """
        assets: list[Asset] = []

        # Collect Lambda functions
        try:
            assets.extend(self._collect_functions())
        except Exception as e:
            logger.warning(f"Failed to collect Lambda functions: {e}")

        # Collect Lambda layers
        try:
            assets.extend(self._collect_layers())
        except Exception as e:
            logger.warning(f"Failed to collect Lambda layers: {e}")

        # Collect event source mappings
        try:
            assets.extend(self._collect_event_source_mappings())
        except Exception as e:
            logger.warning(f"Failed to collect event source mappings: {e}")

        return AssetCollection(assets)

    def _collect_functions(self) -> list[Asset]:
        """Collect Lambda functions with their configurations."""
        lambda_client = self._get_client("lambda")
        assets: list[Asset] = []
        now = self._now()

        for func in self._paginate(
            lambda_client, "list_functions", "Functions"
        ):
            function_name = func["FunctionName"]
            function_arn = func["FunctionArn"]

            # Extract tags (requires separate API call)
            tags = self._get_function_tags(function_arn)

            # Get function policy (resource-based policy)
            resource_policy = self._get_function_policy(function_name)

            # Get function URL configuration if exists
            url_config = self._get_function_url_config(function_name)

            # Determine network exposure
            network_exposure = self._determine_function_network_exposure(
                func, resource_policy, url_config
            )

            # Check for deprecated runtime
            runtime = func.get("Runtime", "")
            runtime_deprecated = runtime in DEPRECATED_RUNTIMES
            runtime_eol_approaching = runtime in EOL_APPROACHING_RUNTIMES

            # Build raw config
            raw_config: dict[str, Any] = {
                "function_name": function_name,
                "function_arn": function_arn,
                "runtime": runtime,
                "runtime_deprecated": runtime_deprecated,
                "runtime_eol_approaching": runtime_eol_approaching,
                "handler": func.get("Handler"),
                "code_size": func.get("CodeSize"),
                "description": func.get("Description"),
                "timeout": func.get("Timeout"),
                "memory_size": func.get("MemorySize"),
                "last_modified": func.get("LastModified"),
                "code_sha256": func.get("CodeSha256"),
                "version": func.get("Version"),
                "package_type": func.get("PackageType", "Zip"),
                # Security-relevant configurations
                "role": func.get("Role"),
                "kms_key_arn": func.get("KMSKeyArn"),
                "has_kms_encryption": bool(func.get("KMSKeyArn")),
                # VPC configuration
                "vpc_config": self._extract_vpc_config(func),
                "in_vpc": bool(func.get("VpcConfig", {}).get("VpcId")),
                # Environment variables (names only, not values for security)
                "environment_variables": self._extract_env_var_names(func),
                "has_environment_variables": bool(
                    func.get("Environment", {}).get("Variables")
                ),
                # Tracing configuration
                "tracing_config": func.get("TracingConfig", {}),
                "xray_tracing_enabled": (
                    func.get("TracingConfig", {}).get("Mode") == "Active"
                ),
                # Layers
                "layers": [
                    {
                        "arn": layer.get("Arn"),
                        "code_size": layer.get("CodeSize"),
                    }
                    for layer in func.get("Layers", [])
                ],
                "layer_count": len(func.get("Layers", [])),
                # Dead letter config
                "dead_letter_config": func.get("DeadLetterConfig", {}),
                "has_dlq": bool(func.get("DeadLetterConfig", {}).get("TargetArn")),
                # Ephemeral storage
                "ephemeral_storage": func.get("EphemeralStorage", {}).get("Size", 512),
                # Architectures
                "architectures": func.get("Architectures", ["x86_64"]),
                # Snap start (for Java)
                "snap_start": func.get("SnapStart", {}),
                # Resource policy analysis
                "resource_policy": resource_policy,
                "has_resource_policy": bool(resource_policy),
                "is_publicly_invocable": self._is_publicly_invocable(resource_policy),
                # Function URL
                "function_url_config": url_config,
                "has_function_url": bool(url_config),
                "function_url_auth_type": (
                    url_config.get("auth_type") if url_config else None
                ),
                # Reserved concurrency
                "reserved_concurrent_executions": func.get(
                    "ReservedConcurrentExecutions"
                ),
                # State
                "state": func.get("State"),
                "state_reason": func.get("StateReason"),
                "state_reason_code": func.get("StateReasonCode"),
                # Last update status
                "last_update_status": func.get("LastUpdateStatus"),
                "last_update_status_reason": func.get("LastUpdateStatusReason"),
                # Signing configuration
                "signing_profile_version_arn": func.get("SigningProfileVersionArn"),
                "signing_job_arn": func.get("SigningJobArn"),
                "has_code_signing": bool(func.get("SigningProfileVersionArn")),
            }

            asset = Asset(
                id=function_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_lambda_function",
                name=function_name,
                tags=tags,
                network_exposure=network_exposure,
                created_at=now,  # Lambda doesn't expose creation time
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_layers(self) -> list[Asset]:
        """Collect Lambda layers."""
        lambda_client = self._get_client("lambda")
        assets: list[Asset] = []
        now = self._now()

        for layer in self._paginate(
            lambda_client, "list_layers", "Layers"
        ):
            layer_name = layer["LayerName"]
            layer_arn = layer["LayerArn"]
            latest_version = layer.get("LatestMatchingVersion", {})

            # Get layer version policy if exists
            layer_policy = None
            if latest_version.get("Version"):
                layer_policy = self._get_layer_policy(
                    layer_name, latest_version["Version"]
                )

            raw_config: dict[str, Any] = {
                "layer_name": layer_name,
                "layer_arn": layer_arn,
                "latest_version": latest_version.get("Version"),
                "latest_version_arn": latest_version.get("LayerVersionArn"),
                "description": latest_version.get("Description"),
                "created_date": latest_version.get("CreatedDate"),
                "compatible_runtimes": latest_version.get("CompatibleRuntimes", []),
                "compatible_architectures": latest_version.get(
                    "CompatibleArchitectures", []
                ),
                "license_info": latest_version.get("LicenseInfo"),
                # Policy analysis
                "layer_policy": layer_policy,
                "has_layer_policy": bool(layer_policy),
                "is_publicly_shared": self._is_layer_publicly_shared(layer_policy),
            }

            # Determine network exposure (layers shared publicly)
            network_exposure = (
                NETWORK_EXPOSURE_INTERNET
                if raw_config["is_publicly_shared"]
                else NETWORK_EXPOSURE_INTERNAL
            )

            asset = Asset(
                id=layer_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_lambda_layer",
                name=layer_name,
                tags={},  # Layers don't have tags
                network_exposure=network_exposure,
                created_at=now,
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _collect_event_source_mappings(self) -> list[Asset]:
        """Collect Lambda event source mappings."""
        lambda_client = self._get_client("lambda")
        assets: list[Asset] = []
        now = self._now()

        for mapping in self._paginate(
            lambda_client, "list_event_source_mappings", "EventSourceMappings"
        ):
            mapping_uuid = mapping["UUID"]
            event_source_arn = mapping.get("EventSourceArn", "")
            function_arn = mapping.get("FunctionArn", "")

            # Build a readable name
            source_type = self._determine_event_source_type(event_source_arn)
            name = f"{source_type}-{mapping_uuid[:8]}"

            raw_config: dict[str, Any] = {
                "uuid": mapping_uuid,
                "event_source_arn": event_source_arn,
                "event_source_type": source_type,
                "function_arn": function_arn,
                "batch_size": mapping.get("BatchSize"),
                "maximum_batching_window_in_seconds": mapping.get(
                    "MaximumBatchingWindowInSeconds"
                ),
                "parallelization_factor": mapping.get("ParallelizationFactor"),
                "starting_position": mapping.get("StartingPosition"),
                "starting_position_timestamp": mapping.get("StartingPositionTimestamp"),
                "last_modified": mapping.get("LastModified"),
                "last_processing_result": mapping.get("LastProcessingResult"),
                "state": mapping.get("State"),
                "state_transition_reason": mapping.get("StateTransitionReason"),
                # Error handling
                "destination_config": mapping.get("DestinationConfig", {}),
                "maximum_retry_attempts": mapping.get("MaximumRetryAttempts"),
                "maximum_record_age_in_seconds": mapping.get(
                    "MaximumRecordAgeInSeconds"
                ),
                "bisect_batch_on_function_error": mapping.get(
                    "BisectBatchOnFunctionError", False
                ),
                # Tumbling window
                "tumbling_window_in_seconds": mapping.get("TumblingWindowInSeconds"),
                # Filtering
                "filter_criteria": mapping.get("FilterCriteria", {}),
                "has_filter_criteria": bool(mapping.get("FilterCriteria")),
                # Self-managed event source
                "self_managed_event_source": mapping.get("SelfManagedEventSource"),
                "self_managed_kafka_event_source_config": mapping.get(
                    "SelfManagedKafkaEventSourceConfig"
                ),
                # Source access configuration (for secrets, VPC, etc.)
                "source_access_configurations": mapping.get(
                    "SourceAccessConfigurations", []
                ),
                # Scaling config
                "scaling_config": mapping.get("ScalingConfig", {}),
                # Document DB config
                "document_db_event_source_config": mapping.get(
                    "DocumentDBEventSourceConfig"
                ),
            }

            # Build ARN for the mapping
            mapping_arn = self._build_arn(
                "lambda",
                "event-source-mapping",
                mapping_uuid,
                region=self._region,
                account_id=self.account_id,
            )

            asset = Asset(
                id=mapping_arn,
                cloud_provider="aws",
                account_id=self.account_id,
                region=self._region,
                resource_type="aws_lambda_event_source_mapping",
                name=name,
                tags={},  # Event source mappings don't have tags
                network_exposure=NETWORK_EXPOSURE_INTERNAL,
                created_at=now,
                last_seen=now,
                raw_config=raw_config,
            )
            assets.append(asset)

        return assets

    def _get_function_tags(self, function_arn: str) -> dict[str, str]:
        """Get tags for a Lambda function."""
        lambda_client = self._get_client("lambda")
        try:
            response = lambda_client.list_tags(Resource=function_arn)
            return response.get("Tags", {})
        except Exception as e:
            logger.debug(f"Could not get tags for {function_arn}: {e}")
            return {}

    def _get_function_policy(self, function_name: str) -> dict[str, Any] | None:
        """Get resource-based policy for a Lambda function."""
        lambda_client = self._get_client("lambda")
        try:
            response = lambda_client.get_policy(FunctionName=function_name)
            import json
            return json.loads(response.get("Policy", "{}"))
        except lambda_client.exceptions.ResourceNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get policy for {function_name}: {e}")
            return None

    def _get_function_url_config(
        self, function_name: str
    ) -> dict[str, Any] | None:
        """Get function URL configuration if exists."""
        lambda_client = self._get_client("lambda")
        try:
            response = lambda_client.get_function_url_config(
                FunctionName=function_name
            )
            return {
                "function_url": response.get("FunctionUrl"),
                "function_arn": response.get("FunctionArn"),
                "auth_type": response.get("AuthType"),
                "cors": response.get("Cors", {}),
                "creation_time": response.get("CreationTime"),
                "last_modified_time": response.get("LastModifiedTime"),
                "invoke_mode": response.get("InvokeMode"),
            }
        except lambda_client.exceptions.ResourceNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get URL config for {function_name}: {e}")
            return None

    def _get_layer_policy(
        self, layer_name: str, version: int
    ) -> dict[str, Any] | None:
        """Get policy for a Lambda layer version."""
        lambda_client = self._get_client("lambda")
        try:
            response = lambda_client.get_layer_version_policy(
                LayerName=layer_name,
                VersionNumber=version,
            )
            import json
            return json.loads(response.get("Policy", "{}"))
        except lambda_client.exceptions.ResourceNotFoundException:
            return None
        except Exception as e:
            logger.debug(f"Could not get policy for layer {layer_name}: {e}")
            return None

    def _extract_vpc_config(self, func: dict[str, Any]) -> dict[str, Any]:
        """Extract VPC configuration from function."""
        vpc_config = func.get("VpcConfig", {})
        if not vpc_config.get("VpcId"):
            return {}

        return {
            "vpc_id": vpc_config.get("VpcId"),
            "subnet_ids": vpc_config.get("SubnetIds", []),
            "security_group_ids": vpc_config.get("SecurityGroupIds", []),
            "ipv6_allowed_for_dual_stack": vpc_config.get(
                "Ipv6AllowedForDualStack", False
            ),
        }

    def _extract_env_var_names(self, func: dict[str, Any]) -> list[str]:
        """
        Extract environment variable names (not values) for security analysis.

        We only collect names to identify potentially sensitive variables
        without exposing actual secret values.
        """
        env = func.get("Environment", {})
        variables = env.get("Variables", {})
        return list(variables.keys())

    def _determine_function_network_exposure(
        self,
        func: dict[str, Any],
        resource_policy: dict[str, Any] | None,
        url_config: dict[str, Any] | None,
    ) -> str:
        """Determine network exposure for a Lambda function."""
        # Function URL with no auth is internet-facing
        if url_config and url_config.get("auth_type") == "NONE":
            return NETWORK_EXPOSURE_INTERNET

        # Check if publicly invocable via resource policy
        if self._is_publicly_invocable(resource_policy):
            return NETWORK_EXPOSURE_INTERNET

        return NETWORK_EXPOSURE_INTERNAL

    def _is_publicly_invocable(
        self, resource_policy: dict[str, Any] | None
    ) -> bool:
        """Check if function can be invoked publicly based on resource policy."""
        if not resource_policy:
            return False

        statements = resource_policy.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect", "").upper()
            principal = statement.get("Principal", {})

            # Check for public access
            if effect == "ALLOW":
                if principal == "*":
                    return True
                if isinstance(principal, dict):
                    aws_principal = principal.get("AWS", "")
                    if aws_principal == "*":
                        return True
                    service_principal = principal.get("Service", "")
                    # Some service principals might make it publicly accessible
                    # depending on their configuration
                    if service_principal in [
                        "apigateway.amazonaws.com",
                        "elasticloadbalancing.amazonaws.com",
                    ]:
                        # These could be public depending on API/ALB config
                        # We mark conservatively as potentially public
                        # if no condition restricts it
                        condition = statement.get("Condition", {})
                        if not condition:
                            return True

        return False

    def _is_layer_publicly_shared(
        self, layer_policy: dict[str, Any] | None
    ) -> bool:
        """Check if layer is shared publicly."""
        if not layer_policy:
            return False

        statements = layer_policy.get("Statement", [])
        for statement in statements:
            effect = statement.get("Effect", "").upper()
            principal = statement.get("Principal")

            if effect == "ALLOW" and principal == "*":
                return True

        return False

    def _determine_event_source_type(self, event_source_arn: str) -> str:
        """Determine the type of event source from ARN."""
        if not event_source_arn:
            return "unknown"

        arn_lower = event_source_arn.lower()

        if ":sqs:" in arn_lower:
            return "sqs"
        elif ":kinesis:" in arn_lower:
            return "kinesis"
        elif ":dynamodb:" in arn_lower:
            return "dynamodb"
        elif ":kafka:" in arn_lower or "kafka" in arn_lower:
            return "kafka"
        elif ":mq:" in arn_lower:
            return "mq"
        elif ":docdb:" in arn_lower:
            return "documentdb"
        else:
            return "other"
