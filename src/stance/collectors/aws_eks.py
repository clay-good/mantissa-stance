"""
AWS EKS collector for Mantissa Stance.

Collects Elastic Kubernetes Service clusters, node groups, and their
security configurations for posture assessment.
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


class EKSCollector(BaseCollector):
    """
    Collects AWS EKS clusters, node groups, and security configurations.

    Gathers EKS cluster configurations including networking, logging,
    encryption, authentication, and node group settings.
    All API calls are read-only.
    """

    collector_name = "aws_eks"
    resource_types = [
        "aws_eks_cluster",
        "aws_eks_nodegroup",
        "aws_eks_fargate_profile",
        "aws_eks_addon",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all EKS resources.

        Returns:
            Collection of EKS assets
        """
        assets: list[Asset] = []

        # Collect EKS clusters
        try:
            assets.extend(self._collect_clusters())
        except Exception as e:
            logger.warning(f"Failed to collect EKS clusters: {e}")

        return AssetCollection(assets)

    def _collect_clusters(self) -> list[Asset]:
        """Collect EKS clusters with their configurations."""
        eks = self._get_client("eks")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List all cluster names
            cluster_names: list[str] = []
            for name in self._paginate(eks, "list_clusters", "clusters"):
                cluster_names.append(name)

            # Get detailed info for each cluster
            for cluster_name in cluster_names:
                try:
                    response = eks.describe_cluster(name=cluster_name)
                    cluster = response.get("cluster", {})

                    cluster_arn = cluster.get("arn", "")
                    cluster_endpoint = cluster.get("endpoint", "")

                    # Get cluster tags
                    tags = cluster.get("tags", {})

                    # VPC configuration
                    vpc_config = cluster.get("resourcesVpcConfig", {})
                    endpoint_public_access = vpc_config.get("endpointPublicAccess", True)
                    endpoint_private_access = vpc_config.get("endpointPrivateAccess", False)
                    public_access_cidrs = vpc_config.get("publicAccessCidrs", [])
                    security_group_ids = vpc_config.get("securityGroupIds", [])
                    subnet_ids = vpc_config.get("subnetIds", [])
                    cluster_security_group_id = vpc_config.get("clusterSecurityGroupId", "")

                    # Encryption configuration
                    encryption_config = cluster.get("encryptionConfig", [])
                    secrets_encryption_enabled = False
                    kms_key_arn = None
                    for enc in encryption_config:
                        if "secrets" in enc.get("resources", []):
                            secrets_encryption_enabled = True
                            provider = enc.get("provider", {})
                            kms_key_arn = provider.get("keyArn")
                            break

                    # Logging configuration
                    logging_config = cluster.get("logging", {})
                    cluster_logging = logging_config.get("clusterLogging", [])
                    enabled_log_types: list[str] = []
                    for log_group in cluster_logging:
                        if log_group.get("enabled"):
                            enabled_log_types.extend(log_group.get("types", []))

                    # Kubernetes network config
                    kubernetes_network_config = cluster.get("kubernetesNetworkConfig", {})
                    service_ipv4_cidr = kubernetes_network_config.get("serviceIpv4Cidr", "")
                    ip_family = kubernetes_network_config.get("ipFamily", "ipv4")

                    # Identity provider config
                    identity_provider = cluster.get("identity", {})
                    oidc_issuer = identity_provider.get("oidc", {}).get("issuer", "")

                    # OIDC provider configuration for IAM roles for service accounts
                    oidc_provider_config = self._get_oidc_provider_config(cluster_name, oidc_issuer)

                    # Build raw config
                    raw_config: dict[str, Any] = {
                        "cluster_name": cluster_name,
                        "cluster_arn": cluster_arn,
                        "endpoint": cluster_endpoint,
                        "status": cluster.get("status"),
                        "version": cluster.get("version"),
                        "platform_version": cluster.get("platformVersion"),
                        "role_arn": cluster.get("roleArn"),
                        "created_at": (
                            cluster["createdAt"].isoformat()
                            if cluster.get("createdAt")
                            else None
                        ),
                        # VPC configuration
                        "vpc_config": {
                            "vpc_id": vpc_config.get("vpcId"),
                            "subnet_ids": subnet_ids,
                            "security_group_ids": security_group_ids,
                            "cluster_security_group_id": cluster_security_group_id,
                            "endpoint_public_access": endpoint_public_access,
                            "endpoint_private_access": endpoint_private_access,
                            "public_access_cidrs": public_access_cidrs,
                        },
                        "endpoint_public_access": endpoint_public_access,
                        "endpoint_private_access": endpoint_private_access,
                        "public_access_cidrs": public_access_cidrs,
                        "public_access_unrestricted": "0.0.0.0/0" in public_access_cidrs,
                        # Encryption
                        "encryption_config": encryption_config,
                        "secrets_encryption_enabled": secrets_encryption_enabled,
                        "kms_key_arn": kms_key_arn,
                        # Logging
                        "logging": {
                            "enabled_log_types": enabled_log_types,
                            "all_logging_enabled": len(enabled_log_types) >= 5,
                        },
                        "enabled_log_types": enabled_log_types,
                        "api_logging_enabled": "api" in enabled_log_types,
                        "audit_logging_enabled": "audit" in enabled_log_types,
                        "authenticator_logging_enabled": "authenticator" in enabled_log_types,
                        "controller_manager_logging_enabled": "controllerManager" in enabled_log_types,
                        "scheduler_logging_enabled": "scheduler" in enabled_log_types,
                        # Kubernetes network
                        "kubernetes_network_config": {
                            "service_ipv4_cidr": service_ipv4_cidr,
                            "ip_family": ip_family,
                        },
                        # Identity
                        "identity": {
                            "oidc_issuer": oidc_issuer,
                        },
                        "oidc_issuer": oidc_issuer,
                        "oidc_provider_config": oidc_provider_config,
                        "irsa_enabled": bool(oidc_issuer),
                        # Access configuration
                        "access_config": cluster.get("accessConfig", {}),
                        # Upgrade policy
                        "upgrade_policy": cluster.get("upgradePolicy", {}),
                        # Health
                        "health": cluster.get("health", {}),
                        # Outpost config (for EKS on Outposts)
                        "outpost_config": cluster.get("outpostConfig"),
                    }

                    # Determine network exposure
                    network_exposure = self._determine_cluster_exposure(
                        endpoint_public_access, public_access_cidrs
                    )

                    # Get creation time
                    created_at = cluster.get("createdAt")
                    if created_at:
                        from datetime import timezone
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    asset = Asset(
                        id=cluster_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_eks_cluster",
                        name=cluster_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                    # Collect node groups for this cluster
                    try:
                        nodegroup_assets = self._collect_nodegroups(cluster_name, cluster_arn)
                        assets.extend(nodegroup_assets)
                    except Exception as e:
                        logger.debug(f"Could not collect node groups for {cluster_name}: {e}")

                    # Collect Fargate profiles for this cluster
                    try:
                        fargate_assets = self._collect_fargate_profiles(cluster_name, cluster_arn)
                        assets.extend(fargate_assets)
                    except Exception as e:
                        logger.debug(f"Could not collect Fargate profiles for {cluster_name}: {e}")

                    # Collect add-ons for this cluster
                    try:
                        addon_assets = self._collect_addons(cluster_name, cluster_arn)
                        assets.extend(addon_assets)
                    except Exception as e:
                        logger.debug(f"Could not collect add-ons for {cluster_name}: {e}")

                except Exception as e:
                    logger.warning(f"Failed to describe EKS cluster {cluster_name}: {e}")

        except Exception as e:
            logger.error(f"Error listing EKS clusters: {e}")
            raise

        return assets

    def _collect_nodegroups(self, cluster_name: str, cluster_arn: str) -> list[Asset]:
        """Collect EKS node groups for a cluster."""
        eks = self._get_client("eks")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List node groups
            nodegroup_names: list[str] = []
            for name in self._paginate(
                eks, "list_nodegroups", "nodegroups", clusterName=cluster_name
            ):
                nodegroup_names.append(name)

            # Get details for each node group
            for ng_name in nodegroup_names:
                try:
                    response = eks.describe_nodegroup(
                        clusterName=cluster_name, nodegroupName=ng_name
                    )
                    nodegroup = response.get("nodegroup", {})

                    ng_arn = nodegroup.get("nodegroupArn", "")
                    tags = nodegroup.get("tags", {})

                    # Scaling configuration
                    scaling_config = nodegroup.get("scalingConfig", {})

                    # Instance types
                    instance_types = nodegroup.get("instanceTypes", [])

                    # Remote access (SSH)
                    remote_access = nodegroup.get("remoteAccess", {})
                    ec2_ssh_key = remote_access.get("ec2SshKey", "")
                    source_security_groups = remote_access.get("sourceSecurityGroups", [])

                    # Launch template
                    launch_template = nodegroup.get("launchTemplate", {})

                    # Update config
                    update_config = nodegroup.get("updateConfig", {})

                    raw_config: dict[str, Any] = {
                        "cluster_name": cluster_name,
                        "cluster_arn": cluster_arn,
                        "nodegroup_name": ng_name,
                        "nodegroup_arn": ng_arn,
                        "status": nodegroup.get("status"),
                        "capacity_type": nodegroup.get("capacityType", "ON_DEMAND"),
                        "ami_type": nodegroup.get("amiType"),
                        "disk_size": nodegroup.get("diskSize"),
                        "node_role": nodegroup.get("nodeRole"),
                        "release_version": nodegroup.get("releaseVersion"),
                        "version": nodegroup.get("version"),
                        "created_at": (
                            nodegroup["createdAt"].isoformat()
                            if nodegroup.get("createdAt")
                            else None
                        ),
                        # Scaling
                        "scaling_config": scaling_config,
                        "min_size": scaling_config.get("minSize", 0),
                        "max_size": scaling_config.get("maxSize", 0),
                        "desired_size": scaling_config.get("desiredSize", 0),
                        # Instance types
                        "instance_types": instance_types,
                        # Network
                        "subnets": nodegroup.get("subnets", []),
                        # Remote access
                        "remote_access": remote_access,
                        "ssh_access_enabled": bool(ec2_ssh_key),
                        "ssh_key_name": ec2_ssh_key,
                        "ssh_source_security_groups": source_security_groups,
                        # Launch template
                        "launch_template": launch_template,
                        "uses_launch_template": bool(launch_template),
                        # Labels and taints
                        "labels": nodegroup.get("labels", {}),
                        "taints": nodegroup.get("taints", []),
                        # Update config
                        "update_config": update_config,
                        # Health
                        "health": nodegroup.get("health", {}),
                    }

                    # Network exposure - node groups are internal by default
                    network_exposure = NETWORK_EXPOSURE_INTERNAL

                    created_at = nodegroup.get("createdAt")
                    if created_at:
                        from datetime import timezone
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    asset = Asset(
                        id=ng_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_eks_nodegroup",
                        name=ng_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                except Exception as e:
                    logger.debug(f"Could not describe node group {ng_name}: {e}")

        except Exception as e:
            logger.debug(f"Error listing node groups for {cluster_name}: {e}")

        return assets

    def _collect_fargate_profiles(self, cluster_name: str, cluster_arn: str) -> list[Asset]:
        """Collect EKS Fargate profiles for a cluster."""
        eks = self._get_client("eks")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List Fargate profiles
            profile_names: list[str] = []
            for name in self._paginate(
                eks, "list_fargate_profiles", "fargateProfileNames", clusterName=cluster_name
            ):
                profile_names.append(name)

            # Get details for each profile
            for profile_name in profile_names:
                try:
                    response = eks.describe_fargate_profile(
                        clusterName=cluster_name, fargateProfileName=profile_name
                    )
                    profile = response.get("fargateProfile", {})

                    profile_arn = profile.get("fargateProfileArn", "")
                    tags = profile.get("tags", {})

                    # Selectors (namespace and labels)
                    selectors = profile.get("selectors", [])

                    raw_config: dict[str, Any] = {
                        "cluster_name": cluster_name,
                        "cluster_arn": cluster_arn,
                        "fargate_profile_name": profile_name,
                        "fargate_profile_arn": profile_arn,
                        "status": profile.get("status"),
                        "pod_execution_role_arn": profile.get("podExecutionRoleArn"),
                        "subnets": profile.get("subnets", []),
                        "selectors": selectors,
                        "selector_count": len(selectors),
                        "namespaces": [s.get("namespace") for s in selectors if s.get("namespace")],
                        "created_at": (
                            profile["createdAt"].isoformat()
                            if profile.get("createdAt")
                            else None
                        ),
                    }

                    # Fargate profiles are always internal
                    network_exposure = NETWORK_EXPOSURE_INTERNAL

                    created_at = profile.get("createdAt")
                    if created_at:
                        from datetime import timezone
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    asset = Asset(
                        id=profile_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_eks_fargate_profile",
                        name=profile_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                except Exception as e:
                    logger.debug(f"Could not describe Fargate profile {profile_name}: {e}")

        except Exception as e:
            logger.debug(f"Error listing Fargate profiles for {cluster_name}: {e}")

        return assets

    def _collect_addons(self, cluster_name: str, cluster_arn: str) -> list[Asset]:
        """Collect EKS add-ons for a cluster."""
        eks = self._get_client("eks")
        assets: list[Asset] = []
        now = self._now()

        try:
            # List add-ons
            addon_names: list[str] = []
            for name in self._paginate(
                eks, "list_addons", "addons", clusterName=cluster_name
            ):
                addon_names.append(name)

            # Get details for each add-on
            for addon_name in addon_names:
                try:
                    response = eks.describe_addon(
                        clusterName=cluster_name, addonName=addon_name
                    )
                    addon = response.get("addon", {})

                    addon_arn = addon.get("addonArn", "")
                    tags = addon.get("tags", {})

                    # Configuration values (may contain sensitive settings)
                    config_values = addon.get("configurationValues", "")

                    raw_config: dict[str, Any] = {
                        "cluster_name": cluster_name,
                        "cluster_arn": cluster_arn,
                        "addon_name": addon_name,
                        "addon_arn": addon_arn,
                        "addon_version": addon.get("addonVersion"),
                        "status": addon.get("status"),
                        "service_account_role_arn": addon.get("serviceAccountRoleArn"),
                        "has_service_account_role": bool(addon.get("serviceAccountRoleArn")),
                        "health": addon.get("health", {}),
                        "publisher": addon.get("publisher"),
                        "owner": addon.get("owner"),
                        "marketplace_information": addon.get("marketplaceInformation", {}),
                        "configuration_values": config_values,
                        "has_custom_configuration": bool(config_values),
                        "created_at": (
                            addon["createdAt"].isoformat()
                            if addon.get("createdAt")
                            else None
                        ),
                        "modified_at": (
                            addon["modifiedAt"].isoformat()
                            if addon.get("modifiedAt")
                            else None
                        ),
                    }

                    # Add-ons are internal by default
                    network_exposure = NETWORK_EXPOSURE_INTERNAL

                    created_at = addon.get("createdAt")
                    if created_at:
                        from datetime import timezone
                        created_at = created_at.replace(tzinfo=timezone.utc)

                    asset = Asset(
                        id=addon_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_eks_addon",
                        name=addon_name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                    assets.append(asset)

                except Exception as e:
                    logger.debug(f"Could not describe add-on {addon_name}: {e}")

        except Exception as e:
            logger.debug(f"Error listing add-ons for {cluster_name}: {e}")

        return assets

    def _get_oidc_provider_config(
        self, cluster_name: str, oidc_issuer: str
    ) -> dict[str, Any]:
        """
        Get OIDC provider configuration for IAM roles for service accounts.

        Args:
            cluster_name: EKS cluster name
            oidc_issuer: OIDC issuer URL from cluster

        Returns:
            Dictionary with OIDC provider configuration
        """
        if not oidc_issuer:
            return {"configured": False}

        try:
            iam = self._get_client("iam")

            # Extract provider ID from issuer URL
            # Example: https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE12345
            provider_id = oidc_issuer.replace("https://", "")

            # List OIDC providers and check if this one exists
            response = iam.list_open_id_connect_providers()
            providers = response.get("OpenIDConnectProviderList", [])

            for provider in providers:
                provider_arn = provider.get("Arn", "")
                if provider_id in provider_arn:
                    # Get provider details
                    try:
                        detail_response = iam.get_open_id_connect_provider(
                            OpenIDConnectProviderArn=provider_arn
                        )
                        return {
                            "configured": True,
                            "provider_arn": provider_arn,
                            "url": detail_response.get("Url"),
                            "client_id_list": detail_response.get("ClientIDList", []),
                            "thumbprint_list": detail_response.get("ThumbprintList", []),
                            "create_date": (
                                detail_response["CreateDate"].isoformat()
                                if detail_response.get("CreateDate")
                                else None
                            ),
                        }
                    except Exception as e:
                        logger.debug(f"Could not get OIDC provider details: {e}")

            return {"configured": False, "reason": "OIDC provider not found in IAM"}

        except Exception as e:
            logger.debug(f"Could not check OIDC provider for {cluster_name}: {e}")
            return {"configured": False, "error": str(e)}

    def _determine_cluster_exposure(
        self, endpoint_public_access: bool, public_access_cidrs: list[str]
    ) -> str:
        """
        Determine network exposure for an EKS cluster.

        Args:
            endpoint_public_access: Whether public access is enabled
            public_access_cidrs: List of CIDRs allowed public access

        Returns:
            Network exposure level string
        """
        if not endpoint_public_access:
            return NETWORK_EXPOSURE_INTERNAL

        # Public access enabled - check if unrestricted
        if "0.0.0.0/0" in public_access_cidrs:
            return NETWORK_EXPOSURE_INTERNET

        # Public access but restricted to specific CIDRs
        # Still considered internet-facing but more restricted
        return NETWORK_EXPOSURE_INTERNET
