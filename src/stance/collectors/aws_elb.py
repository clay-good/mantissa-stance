"""
AWS Elastic Load Balancer collector for Mantissa Stance.

Collects Application Load Balancers (ALBs), listeners, and their
configurations for security posture assessment.
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


class ELBCollector(BaseCollector):
    """
    Collects AWS Elastic Load Balancer resources.

    Gathers Application Load Balancers, listeners, and their
    security configurations. All API calls are read-only.
    """

    collector_name = "aws_elb"
    resource_types = [
        "aws_alb",
        "aws_alb_listener",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all ELB resources.

        Returns:
            Collection of ELB assets
        """
        assets: list[Asset] = []

        # Collect Application Load Balancers
        try:
            assets.extend(self._collect_albs())
        except Exception as e:
            logger.warning(f"Failed to collect ALBs: {e}")

        # Collect ALB listeners
        try:
            assets.extend(self._collect_listeners())
        except Exception as e:
            logger.warning(f"Failed to collect ALB listeners: {e}")

        return AssetCollection(assets)

    def _collect_albs(self) -> list[Asset]:
        """Collect Application Load Balancers with their configurations."""
        elbv2 = self._get_client("elbv2")
        wafv2 = self._get_client("wafv2")
        assets: list[Asset] = []
        now = self._now()

        try:
            # Get all load balancers
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    # Only process Application Load Balancers
                    if lb.get("Type") != "application":
                        continue

                    lb_arn = lb["LoadBalancerArn"]
                    lb_name = lb.get("LoadBalancerName", "")

                    # Get load balancer attributes
                    attributes = {}
                    try:
                        attrs_response = elbv2.describe_load_balancer_attributes(
                            LoadBalancerArn=lb_arn
                        )
                        for attr in attrs_response.get("Attributes", []):
                            key = attr.get("Key", "")
                            value = attr.get("Value", "")
                            attributes[key] = value
                    except Exception as e:
                        logger.debug(f"Could not get attributes for ALB {lb_name}: {e}")

                    # Check for WAF association
                    waf_acl_arn = None
                    try:
                        waf_response = wafv2.get_web_acl_for_resource(
                            ResourceArn=lb_arn
                        )
                        web_acl = waf_response.get("WebACL")
                        if web_acl:
                            waf_acl_arn = web_acl.get("ARN")
                    except wafv2.exceptions.WAFNonexistentItemException:
                        # No WAF ACL associated
                        pass
                    except Exception as e:
                        logger.debug(f"Could not get WAF ACL for ALB {lb_name}: {e}")

                    # Get tags
                    tags = {}
                    try:
                        tags_response = elbv2.describe_tags(
                            ResourceArns=[lb_arn]
                        )
                        for tag_desc in tags_response.get("TagDescriptions", []):
                            for tag in tag_desc.get("Tags", []):
                                tags[tag.get("Key", "")] = tag.get("Value", "")
                    except Exception as e:
                        logger.debug(f"Could not get tags for ALB {lb_name}: {e}")

                    # Parse attributes
                    access_logs_enabled = (
                        attributes.get("access_logs.s3.enabled", "false") == "true"
                    )
                    deletion_protection_enabled = (
                        attributes.get("deletion_protection.enabled", "false") == "true"
                    )
                    idle_timeout = int(
                        attributes.get("idle_timeout.timeout_seconds", "60")
                    )
                    http2_enabled = (
                        attributes.get("routing.http2.enabled", "true") == "true"
                    )
                    drop_invalid_header_fields = (
                        attributes.get(
                            "routing.http.drop_invalid_header_fields.enabled", "false"
                        ) == "true"
                    )
                    desync_mitigation_mode = attributes.get(
                        "routing.http.desync_mitigation_mode", "defensive"
                    )

                    raw_config: dict[str, Any] = {
                        "load_balancer_arn": lb_arn,
                        "load_balancer_name": lb_name,
                        "dns_name": lb.get("DNSName", ""),
                        "canonical_hosted_zone_id": lb.get("CanonicalHostedZoneId", ""),
                        "scheme": lb.get("Scheme", ""),
                        "vpc_id": lb.get("VpcId", ""),
                        "state": lb.get("State", {}).get("Code", ""),
                        "type": lb.get("Type", ""),
                        "availability_zones": [
                            {
                                "zone_name": az.get("ZoneName"),
                                "subnet_id": az.get("SubnetId"),
                            }
                            for az in lb.get("AvailabilityZones", [])
                        ],
                        "security_groups": lb.get("SecurityGroups", []),
                        "ip_address_type": lb.get("IpAddressType", ""),
                        "created_time": (
                            lb["CreatedTime"].isoformat()
                            if lb.get("CreatedTime")
                            else None
                        ),
                        # Attributes
                        "access_logs_enabled": access_logs_enabled,
                        "access_logs_s3_bucket": attributes.get(
                            "access_logs.s3.bucket", ""
                        ),
                        "access_logs_s3_prefix": attributes.get(
                            "access_logs.s3.prefix", ""
                        ),
                        "deletion_protection_enabled": deletion_protection_enabled,
                        "idle_timeout_seconds": idle_timeout,
                        "http2_enabled": http2_enabled,
                        "drop_invalid_header_fields": drop_invalid_header_fields,
                        "desync_mitigation_mode": desync_mitigation_mode,
                        # WAF
                        "waf_acl_arn": waf_acl_arn,
                        "has_waf_enabled": waf_acl_arn is not None,
                    }

                    # Determine network exposure
                    network_exposure = NETWORK_EXPOSURE_INTERNAL
                    if lb.get("Scheme") == "internet-facing":
                        network_exposure = NETWORK_EXPOSURE_INTERNET

                    assets.append(
                        Asset(
                            id=lb_arn,
                            cloud_provider="aws",
                            account_id=self.account_id,
                            region=self._region,
                            resource_type="aws_alb",
                            name=lb_name,
                            tags=tags,
                            network_exposure=network_exposure,
                            last_seen=now,
                            raw_config=raw_config,
                        )
                    )

        except Exception as e:
            logger.error(f"Error listing ALBs: {e}")
            raise

        return assets

    def _collect_listeners(self) -> list[Asset]:
        """Collect ALB listeners with their configurations."""
        elbv2 = self._get_client("elbv2")
        assets: list[Asset] = []
        now = self._now()

        try:
            # First get all ALBs
            albs = []
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page.get("LoadBalancers", []):
                    if lb.get("Type") == "application":
                        albs.append(lb)

            # Then get listeners for each ALB
            for alb in albs:
                lb_arn = alb["LoadBalancerArn"]
                lb_name = alb.get("LoadBalancerName", "")

                try:
                    listeners_response = elbv2.describe_listeners(
                        LoadBalancerArn=lb_arn
                    )

                    for listener in listeners_response.get("Listeners", []):
                        listener_arn = listener["ListenerArn"]
                        port = listener.get("Port", 0)
                        protocol = listener.get("Protocol", "")

                        # Check if this is HTTPS or redirects to HTTPS
                        is_https = protocol == "HTTPS"
                        redirects_to_https = False

                        # Check default actions for redirect to HTTPS
                        for action in listener.get("DefaultActions", []):
                            if action.get("Type") == "redirect":
                                redirect_config = action.get("RedirectConfig", {})
                                if redirect_config.get("Protocol") == "HTTPS":
                                    redirects_to_https = True
                                    break

                        # Get SSL certificate info
                        certificates = listener.get("Certificates", [])
                        ssl_policy = listener.get("SslPolicy", "")

                        raw_config: dict[str, Any] = {
                            "listener_arn": listener_arn,
                            "load_balancer_arn": lb_arn,
                            "load_balancer_name": lb_name,
                            "port": port,
                            "protocol": protocol,
                            "is_https": is_https,
                            "redirects_to_https": redirects_to_https,
                            "ssl_policy": ssl_policy,
                            "certificates": [
                                {"certificate_arn": cert.get("CertificateArn", "")}
                                for cert in certificates
                            ],
                            "default_actions": [
                                {
                                    "type": action.get("Type", ""),
                                    "target_group_arn": action.get("TargetGroupArn", ""),
                                    "order": action.get("Order", 0),
                                }
                                for action in listener.get("DefaultActions", [])
                            ],
                        }

                        # Determine network exposure based on ALB
                        network_exposure = NETWORK_EXPOSURE_INTERNAL
                        if alb.get("Scheme") == "internet-facing":
                            network_exposure = NETWORK_EXPOSURE_INTERNET

                        assets.append(
                            Asset(
                                id=listener_arn,
                                cloud_provider="aws",
                                account_id=self.account_id,
                                region=self._region,
                                resource_type="aws_alb_listener",
                                name=f"{lb_name}:{port}",
                                tags={},
                                network_exposure=network_exposure,
                                last_seen=now,
                                raw_config=raw_config,
                            )
                        )

                except Exception as e:
                    logger.debug(f"Could not get listeners for ALB {lb_name}: {e}")

        except Exception as e:
            logger.error(f"Error listing ALB listeners: {e}")
            raise

        return assets
