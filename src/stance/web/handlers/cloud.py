"""
Cloud handlers for the Stance web API.

This module handles all /api/cloud/* endpoints for cloud provider
management, credential validation, and account information.
"""

from __future__ import annotations

import logging
from typing import Any

from stance.web.handlers.base import HandlerResponse, HttpStatus
from stance.web.handlers.router import route, RoutedHandler

logger = logging.getLogger(__name__)


class CloudHandler(RoutedHandler):
    """
    Handler for cloud API endpoints.

    Handles:
    - Cloud provider listing
    - Credential validation
    - Account information
    - Region management
    """

    base_path = "/api/cloud/"

    # =========================================================================
    # GET endpoints
    # =========================================================================

    @route("list")
    def cloud_list(self, params: dict, body: dict | None) -> HandlerResponse:
        """List all cloud providers."""
        providers = self._get_cloud_provider_metadata()
        return HandlerResponse.success({
            "providers": providers,
            "total": len(providers),
        })

    @route("info")
    def cloud_info(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get info for a specific cloud provider.

        Query params:
            provider: Provider name (required)
        """
        provider_name = self.get_param(params, "provider", "")

        if not provider_name:
            return HandlerResponse.error("Missing required parameter: provider", HttpStatus.BAD_REQUEST)

        try:
            from stance.cloud import PROVIDERS, is_provider_available

            if provider_name not in PROVIDERS:
                return HandlerResponse.not_found("Provider")

            provider_class = PROVIDERS[provider_name]
            display_names = {
                "aws": "Amazon Web Services",
                "gcp": "Google Cloud Platform",
                "azure": "Microsoft Azure",
            }
            descriptions = {
                "aws": "AWS cloud services including IAM, S3, EC2, RDS, Lambda, and more",
                "gcp": "Google Cloud services including IAM, Cloud Storage, Compute Engine, and more",
                "azure": "Microsoft Azure services including IAM, Blob Storage, VMs, and more",
            }

            return HandlerResponse.success({
                "name": provider_name,
                "display_name": display_names.get(provider_name, provider_name.upper()),
                "available": is_provider_available(provider_name),
                "packages": provider_class.get_required_packages(),
                "description": descriptions.get(provider_name, "Cloud provider"),
                "credential_fields": self._get_credential_fields(provider_name),
                "default_region": self._get_default_region(provider_name),
            })
        except Exception as e:
            logger.warning(f"Error getting cloud info: {e}")
            return HandlerResponse.success({
                "name": provider_name,
                "display_name": provider_name.upper(),
                "available": False,
                "packages": [],
                "description": "Cloud provider",
            })

    @route("validate")
    def cloud_validate(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Validate cloud credentials.

        Query params:
            provider: Provider name (required)
            region: Region (optional)
            profile: AWS profile (optional)
            project: GCP project (optional)
            subscription: Azure subscription (optional)
        """
        provider_name = self.get_param(params, "provider", "")

        if not provider_name:
            return HandlerResponse.error("Missing required parameter: provider", HttpStatus.BAD_REQUEST)

        try:
            from stance.cloud import is_provider_available, get_cloud_provider

            if not is_provider_available(provider_name):
                return HandlerResponse.success({
                    "provider": provider_name,
                    "valid": False,
                    "error": "SDK not available. Install required packages.",
                })

            kwargs: dict[str, Any] = {}
            region = self.get_param(params, "region", "")
            profile = self.get_param(params, "profile", "")
            project = self.get_param(params, "project", "")
            subscription = self.get_param(params, "subscription", "")

            if region:
                kwargs["region"] = region
            if profile:
                kwargs["profile"] = profile
            if project:
                kwargs["project_id"] = project
            if subscription:
                kwargs["subscription_id"] = subscription

            provider = get_cloud_provider(provider_name, **kwargs)
            valid = provider.validate_credentials()

            return HandlerResponse.success({
                "provider": provider_name,
                "valid": valid,
                "account_id": getattr(provider, "_account_id", None),
            })
        except Exception as e:
            return HandlerResponse.success({
                "provider": provider_name,
                "valid": False,
                "error": str(e),
            })

    @route("account")
    def cloud_account(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get cloud account information.

        Query params:
            provider: Provider name (required)
        """
        provider_name = self.get_param(params, "provider", "")

        if not provider_name:
            return HandlerResponse.error("Missing required parameter: provider", HttpStatus.BAD_REQUEST)

        try:
            from stance.cloud import is_provider_available, get_cloud_provider

            if not is_provider_available(provider_name):
                return HandlerResponse.error(f"SDK not available for {provider_name}", HttpStatus.BAD_REQUEST)

            kwargs: dict[str, Any] = {}
            region = self.get_param(params, "region", "")
            if region:
                kwargs["region"] = region

            provider = get_cloud_provider(provider_name, **kwargs)
            account = provider.get_account()

            return HandlerResponse.success({
                "provider": account.provider,
                "account_id": account.account_id,
                "display_name": account.display_name,
                "region_count": len(account.regions),
                "metadata": account.metadata,
            })
        except Exception as e:
            return HandlerResponse.error(str(e), HttpStatus.BAD_REQUEST)

    @route("regions")
    def cloud_regions(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        List regions for a cloud provider.

        Query params:
            provider: Provider name (required)
        """
        provider_name = self.get_param(params, "provider", "")

        if not provider_name:
            return HandlerResponse.error("Missing required parameter: provider", HttpStatus.BAD_REQUEST)

        # Return demo region data
        regions_data = {
            "aws": [
                {"name": "us-east-1", "display_name": "US East (N. Virginia)"},
                {"name": "us-west-2", "display_name": "US West (Oregon)"},
                {"name": "eu-west-1", "display_name": "EU (Ireland)"},
                {"name": "ap-southeast-1", "display_name": "Asia Pacific (Singapore)"},
            ],
            "gcp": [
                {"name": "us-central1", "display_name": "Iowa"},
                {"name": "us-east1", "display_name": "South Carolina"},
                {"name": "europe-west1", "display_name": "Belgium"},
                {"name": "asia-east1", "display_name": "Taiwan"},
            ],
            "azure": [
                {"name": "eastus", "display_name": "East US"},
                {"name": "westus2", "display_name": "West US 2"},
                {"name": "westeurope", "display_name": "West Europe"},
                {"name": "southeastasia", "display_name": "Southeast Asia"},
            ],
        }

        regions = regions_data.get(provider_name, [])
        return HandlerResponse.success({
            "provider": provider_name,
            "regions": regions,
            "total": len(regions),
        })

    @route("availability")
    def cloud_availability(self, params: dict, body: dict | None) -> HandlerResponse:
        """Check cloud provider availability."""
        try:
            from stance.cloud import is_provider_available

            return HandlerResponse.success({
                "aws": is_provider_available("aws"),
                "gcp": is_provider_available("gcp"),
                "azure": is_provider_available("azure"),
            })
        except Exception:
            return HandlerResponse.success({
                "aws": False,
                "gcp": False,
                "azure": False,
            })

    @route("packages")
    def cloud_packages(self, params: dict, body: dict | None) -> HandlerResponse:
        """List required packages for cloud providers."""
        packages = {
            "aws": ["boto3"],
            "gcp": ["google-cloud-storage", "google-cloud-compute", "google-cloud-resource-manager"],
            "azure": ["azure-identity", "azure-mgmt-resource", "azure-mgmt-storage"],
        }
        return HandlerResponse.success({
            "packages": packages,
        })

    @route("credentials")
    def cloud_credentials(self, params: dict, body: dict | None) -> HandlerResponse:
        """
        Get credential configuration help.

        Query params:
            provider: Provider name (optional)
        """
        provider_name = self.get_param(params, "provider", "")

        credentials = {
            "aws": {
                "methods": ["environment", "profile", "iam_role"],
                "env_vars": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"],
                "config_file": "~/.aws/credentials",
            },
            "gcp": {
                "methods": ["service_account", "application_default"],
                "env_vars": ["GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"],
                "config_file": "~/.config/gcloud/application_default_credentials.json",
            },
            "azure": {
                "methods": ["service_principal", "managed_identity", "cli"],
                "env_vars": ["AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID"],
                "config_file": None,
            },
        }

        if provider_name:
            if provider_name in credentials:
                return HandlerResponse.success({
                    "provider": provider_name,
                    "credentials": credentials[provider_name],
                })
            return HandlerResponse.not_found("Provider")

        return HandlerResponse.success({
            "credentials": credentials,
        })

    @route("exceptions")
    def cloud_exceptions(self, params: dict, body: dict | None) -> HandlerResponse:
        """List cloud API exceptions and error handling."""
        exceptions = [
            {"name": "CredentialsError", "description": "Invalid or expired credentials"},
            {"name": "AccessDenied", "description": "Permission denied to resource"},
            {"name": "ResourceNotFound", "description": "Resource does not exist"},
            {"name": "QuotaExceeded", "description": "API quota or rate limit exceeded"},
            {"name": "NetworkError", "description": "Network connectivity issue"},
        ]
        return HandlerResponse.success({
            "exceptions": exceptions,
            "total": len(exceptions),
        })

    @route("status")
    def cloud_status(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get cloud module status."""
        try:
            from stance.cloud import is_provider_available

            return HandlerResponse.success({
                "module": "cloud",
                "version": "1.0.0",
                "status": "active",
                "providers": {
                    "aws": is_provider_available("aws"),
                    "gcp": is_provider_available("gcp"),
                    "azure": is_provider_available("azure"),
                },
                "capabilities": {
                    "credential_validation": True,
                    "multi_account": True,
                    "multi_region": True,
                    "assume_role": True,
                },
            })
        except Exception:
            return HandlerResponse.success({
                "module": "cloud",
                "version": "1.0.0",
                "status": "active",
                "providers": {"aws": False, "gcp": False, "azure": False},
            })

    @route("summary")
    def cloud_summary(self, params: dict, body: dict | None) -> HandlerResponse:
        """Get cloud summary."""
        return HandlerResponse.success({
            "total_providers": 3,
            "active_providers": 1,
            "configured_accounts": 0,
            "total_regions": 0,
        })

    # =========================================================================
    # Helper methods
    # =========================================================================

    def _get_cloud_provider_metadata(self) -> list[dict[str, Any]]:
        """Get cloud provider metadata."""
        try:
            from stance.cloud import is_provider_available

            return [
                {
                    "name": "aws",
                    "display_name": "Amazon Web Services",
                    "available": is_provider_available("aws"),
                },
                {
                    "name": "gcp",
                    "display_name": "Google Cloud Platform",
                    "available": is_provider_available("gcp"),
                },
                {
                    "name": "azure",
                    "display_name": "Microsoft Azure",
                    "available": is_provider_available("azure"),
                },
            ]
        except Exception:
            return [
                {"name": "aws", "display_name": "Amazon Web Services", "available": False},
                {"name": "gcp", "display_name": "Google Cloud Platform", "available": False},
                {"name": "azure", "display_name": "Microsoft Azure", "available": False},
            ]

    def _get_credential_fields(self, provider: str) -> list[str]:
        """Get credential fields for a provider."""
        fields = {
            "aws": ["access_key_id", "secret_access_key", "session_token", "profile", "region"],
            "gcp": ["project_id", "credentials_file", "region"],
            "azure": ["subscription_id", "tenant_id", "client_id", "client_secret"],
        }
        return fields.get(provider, [])

    def _get_default_region(self, provider: str) -> str:
        """Get default region for a provider."""
        defaults = {
            "aws": "us-east-1",
            "gcp": "us-central1",
            "azure": "eastus",
        }
        return defaults.get(provider, "")
