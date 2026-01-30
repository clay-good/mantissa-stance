"""
AWS EC2 collector for Mantissa Stance.

Collects EC2 instances, security groups, VPCs, and subnets
for security posture assessment.
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Any

from stance.collectors.base import BaseCollector
from stance.models import (
    Asset,
    AssetCollection,
    NETWORK_EXPOSURE_INTERNET,
    NETWORK_EXPOSURE_INTERNAL,
    NETWORK_EXPOSURE_ISOLATED,
)

logger = logging.getLogger(__name__)

# Sensitive ports that should not be exposed to the internet
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1434: "MSSQL Browser",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    5601: "Kibana",
    8080: "HTTP Alt",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
    139: "NetBIOS",
}


class EC2Collector(BaseCollector):
    """
    Collects AWS EC2 instances, security groups, and network configuration.

    Gathers EC2 instances, security groups, VPCs, and subnets.
    All API calls are read-only.
    """

    collector_name = "aws_ec2"
    resource_types = [
        "aws_ec2_instance",
        "aws_security_group",
        "aws_vpc",
        "aws_subnet",
        "aws_network_acl",
        "aws_vpc_endpoint",
    ]

    def collect(self) -> AssetCollection:
        """
        Collect all EC2 and network resources.

        Returns:
            Collection of EC2 and network assets
        """
        assets: list[Asset] = []

        # Collect instances
        try:
            assets.extend(self._collect_instances())
        except Exception as e:
            logger.warning(f"Failed to collect EC2 instances: {e}")

        # Collect security groups
        try:
            assets.extend(self._collect_security_groups())
        except Exception as e:
            logger.warning(f"Failed to collect security groups: {e}")

        # Collect VPCs
        try:
            assets.extend(self._collect_vpcs())
        except Exception as e:
            logger.warning(f"Failed to collect VPCs: {e}")

        # Collect subnets
        try:
            assets.extend(self._collect_subnets())
        except Exception as e:
            logger.warning(f"Failed to collect subnets: {e}")

        # Collect network ACLs
        try:
            assets.extend(self._collect_network_acls())
        except Exception as e:
            logger.warning(f"Failed to collect network ACLs: {e}")

        # Collect VPC endpoints
        try:
            assets.extend(self._collect_vpc_endpoints())
        except Exception as e:
            logger.warning(f"Failed to collect VPC endpoints: {e}")

        return AssetCollection(assets)

    def _collect_instances(self) -> list[Asset]:
        """Collect EC2 instances with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for reservation in self._paginate(
            ec2, "describe_instances", "Reservations"
        ):
            for instance in reservation.get("Instances", []):
                instance_id = instance["InstanceId"]

                # Build ARN
                instance_arn = self._build_arn(
                    "ec2",
                    "instance",
                    instance_id,
                    region=self._region,
                    account_id=self.account_id,
                )

                # Extract tags and name
                tags = self._extract_tags(instance.get("Tags"))
                name = self._get_name_from_tags(tags, instance_id)

                # Build raw config
                raw_config: dict[str, Any] = {
                    "instance_id": instance_id,
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "vpc_id": instance.get("VpcId"),
                    "subnet_id": instance.get("SubnetId"),
                    "private_ip_address": instance.get("PrivateIpAddress"),
                    "public_ip_address": instance.get("PublicIpAddress"),
                    "private_dns_name": instance.get("PrivateDnsName"),
                    "public_dns_name": instance.get("PublicDnsName"),
                    "image_id": instance.get("ImageId"),
                    "key_name": instance.get("KeyName"),
                    "launch_time": (
                        instance["LaunchTime"].isoformat()
                        if instance.get("LaunchTime")
                        else None
                    ),
                    "platform": instance.get("Platform", "linux"),
                    "architecture": instance.get("Architecture"),
                    "root_device_type": instance.get("RootDeviceType"),
                    "root_device_name": instance.get("RootDeviceName"),
                    "virtualization_type": instance.get("VirtualizationType"),
                    "hypervisor": instance.get("Hypervisor"),
                }

                # Get security groups
                security_groups = instance.get("SecurityGroups", [])
                raw_config["security_groups"] = [
                    {"id": sg["GroupId"], "name": sg.get("GroupName")}
                    for sg in security_groups
                ]
                raw_config["security_group_ids"] = [
                    sg["GroupId"] for sg in security_groups
                ]

                # Get IAM instance profile
                iam_profile = instance.get("IamInstanceProfile")
                if iam_profile:
                    raw_config["iam_instance_profile"] = {
                        "arn": iam_profile.get("Arn"),
                        "id": iam_profile.get("Id"),
                    }
                    raw_config["has_iam_role"] = True
                else:
                    raw_config["has_iam_role"] = False

                # Get EBS volumes encryption status
                block_devices = instance.get("BlockDeviceMappings", [])
                ebs_encrypted = True
                ebs_volumes = []
                for device in block_devices:
                    ebs = device.get("Ebs", {})
                    if ebs:
                        volume_id = ebs.get("VolumeId")
                        ebs_volumes.append({
                            "device_name": device.get("DeviceName"),
                            "volume_id": volume_id,
                            "delete_on_termination": ebs.get("DeleteOnTermination"),
                        })
                raw_config["ebs_volumes"] = ebs_volumes

                # Check EBS encryption (requires separate API call)
                try:
                    if ebs_volumes:
                        volume_ids = [v["volume_id"] for v in ebs_volumes if v.get("volume_id")]
                        if volume_ids:
                            volumes_response = ec2.describe_volumes(VolumeIds=volume_ids)
                            for volume in volumes_response.get("Volumes", []):
                                if not volume.get("Encrypted", False):
                                    ebs_encrypted = False
                                    break
                    raw_config["ebs_encrypted"] = ebs_encrypted
                except Exception as e:
                    logger.debug(f"Could not check EBS encryption for {instance_id}: {e}")

                # Get metadata options (IMDSv2)
                metadata_options = instance.get("MetadataOptions", {})
                raw_config["metadata_options"] = {
                    "http_tokens": metadata_options.get("HttpTokens", "optional"),
                    "http_put_response_hop_limit": metadata_options.get(
                        "HttpPutResponseHopLimit", 1
                    ),
                    "http_endpoint": metadata_options.get("HttpEndpoint", "enabled"),
                    "instance_metadata_tags": metadata_options.get(
                        "InstanceMetadataTags", "disabled"
                    ),
                }
                raw_config["imdsv2_required"] = (
                    metadata_options.get("HttpTokens") == "required"
                )

                # Get monitoring state
                monitoring = instance.get("Monitoring", {})
                raw_config["monitoring"] = {
                    "state": monitoring.get("State", "disabled"),
                }
                raw_config["detailed_monitoring_enabled"] = (
                    monitoring.get("State") == "enabled"
                )

                # Determine network exposure
                network_exposure = self._determine_instance_exposure(instance)

                # Get creation time
                created_at = instance.get("LaunchTime")
                if created_at:
                    created_at = created_at.replace(tzinfo=timezone.utc)

                assets.append(
                    Asset(
                        id=instance_arn,
                        cloud_provider="aws",
                        account_id=self.account_id,
                        region=self._region,
                        resource_type="aws_ec2_instance",
                        name=name,
                        tags=tags,
                        network_exposure=network_exposure,
                        created_at=created_at,
                        last_seen=now,
                        raw_config=raw_config,
                    )
                )

        return assets

    def _collect_security_groups(self) -> list[Asset]:
        """Collect security groups with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for sg in self._paginate(
            ec2, "describe_security_groups", "SecurityGroups"
        ):
            sg_id = sg["GroupId"]

            # Build ARN
            sg_arn = self._build_arn(
                "ec2",
                "security-group",
                sg_id,
                region=self._region,
                account_id=self.account_id,
            )

            # Extract tags and name
            tags = self._extract_tags(sg.get("Tags"))
            name = sg.get("GroupName", self._get_name_from_tags(tags, sg_id))

            # Process ingress rules
            ingress_rules = []
            dangerous_ingress = []
            ingress_cidrs = []

            for rule in sg.get("IpPermissions", []):
                processed_rule = self._process_security_rule(rule, "ingress")
                ingress_rules.append(processed_rule)

                # Track CIDRs
                ingress_cidrs.extend(processed_rule.get("cidr_blocks", []))

                # Check for dangerous rules
                if processed_rule.get("allows_all_traffic", False):
                    dangerous_ingress.append(processed_rule)

            # Process egress rules
            egress_rules = []
            for rule in sg.get("IpPermissionsEgress", []):
                processed_rule = self._process_security_rule(rule, "egress")
                egress_rules.append(processed_rule)

            raw_config: dict[str, Any] = {
                "group_id": sg_id,
                "group_name": sg.get("GroupName"),
                "description": sg.get("Description"),
                "vpc_id": sg.get("VpcId"),
                "owner_id": sg.get("OwnerId"),
                "ingress_rules": ingress_rules,
                "egress_rules": egress_rules,
                "ingress_cidrs": list(set(ingress_cidrs)),
                "dangerous_ingress_rules": dangerous_ingress,
                "has_dangerous_rules": len(dangerous_ingress) > 0,
                "allows_ssh_from_internet": self._allows_port_from_internet(
                    ingress_rules, 22
                ),
                "allows_rdp_from_internet": self._allows_port_from_internet(
                    ingress_rules, 3389
                ),
                "allows_mysql_from_internet": self._allows_port_from_internet(
                    ingress_rules, 3306
                ),
                "allows_postgres_from_internet": self._allows_port_from_internet(
                    ingress_rules, 5432
                ),
                "allows_mssql_from_internet": self._allows_port_from_internet(
                    ingress_rules, 1433
                ),
                "allows_mongodb_from_internet": self._allows_port_from_internet(
                    ingress_rules, 27017
                ),
                "allows_all_traffic_from_internet": any(
                    r.get("allows_all_traffic") for r in dangerous_ingress
                ),
                "has_unrestricted_egress": self._has_unrestricted_egress(
                    egress_rules
                ),
            }

            # Determine network exposure
            network_exposure = NETWORK_EXPOSURE_INTERNAL
            if raw_config["has_dangerous_rules"]:
                network_exposure = NETWORK_EXPOSURE_INTERNET

            assets.append(
                Asset(
                    id=sg_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_security_group",
                    name=name,
                    tags=tags,
                    network_exposure=network_exposure,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_vpcs(self) -> list[Asset]:
        """Collect VPCs with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for vpc in self._paginate(ec2, "describe_vpcs", "Vpcs"):
            vpc_id = vpc["VpcId"]

            # Build ARN
            vpc_arn = self._build_arn(
                "ec2",
                "vpc",
                vpc_id,
                region=self._region,
                account_id=self.account_id,
            )

            # Extract tags and name
            tags = self._extract_tags(vpc.get("Tags"))
            name = self._get_name_from_tags(tags, vpc_id)

            raw_config: dict[str, Any] = {
                "vpc_id": vpc_id,
                "cidr_block": vpc.get("CidrBlock"),
                "cidr_block_association_set": [
                    {
                        "cidr_block": assoc.get("CidrBlock"),
                        "state": assoc.get("CidrBlockState", {}).get("State"),
                    }
                    for assoc in vpc.get("CidrBlockAssociationSet", [])
                ],
                "dhcp_options_id": vpc.get("DhcpOptionsId"),
                "state": vpc.get("State"),
                "instance_tenancy": vpc.get("InstanceTenancy"),
                "is_default": vpc.get("IsDefault", False),
                "owner_id": vpc.get("OwnerId"),
            }

            # Get flow logs status
            try:
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                )
                raw_config["flow_logs_enabled"] = len(flow_logs.get("FlowLogs", [])) > 0
                raw_config["flow_logs"] = [
                    {
                        "id": fl.get("FlowLogId"),
                        "status": fl.get("FlowLogStatus"),
                        "traffic_type": fl.get("TrafficType"),
                        "log_destination_type": fl.get("LogDestinationType"),
                    }
                    for fl in flow_logs.get("FlowLogs", [])
                ]
            except Exception as e:
                logger.debug(f"Could not get flow logs for VPC {vpc_id}: {e}")

            assets.append(
                Asset(
                    id=vpc_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_vpc",
                    name=name,
                    tags=tags,
                    network_exposure=NETWORK_EXPOSURE_INTERNAL,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_subnets(self) -> list[Asset]:
        """Collect subnets with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for subnet in self._paginate(ec2, "describe_subnets", "Subnets"):
            subnet_id = subnet["SubnetId"]

            # Build ARN
            subnet_arn = self._build_arn(
                "ec2",
                "subnet",
                subnet_id,
                region=self._region,
                account_id=self.account_id,
            )

            # Extract tags and name
            tags = self._extract_tags(subnet.get("Tags"))
            name = self._get_name_from_tags(tags, subnet_id)

            raw_config: dict[str, Any] = {
                "subnet_id": subnet_id,
                "vpc_id": subnet.get("VpcId"),
                "cidr_block": subnet.get("CidrBlock"),
                "availability_zone": subnet.get("AvailabilityZone"),
                "availability_zone_id": subnet.get("AvailabilityZoneId"),
                "state": subnet.get("State"),
                "available_ip_address_count": subnet.get("AvailableIpAddressCount"),
                "map_public_ip_on_launch": subnet.get("MapPublicIpOnLaunch", False),
                "assign_ipv6_address_on_creation": subnet.get(
                    "AssignIpv6AddressOnCreation", False
                ),
                "default_for_az": subnet.get("DefaultForAz", False),
                "owner_id": subnet.get("OwnerId"),
            }

            # Determine if subnet is public (has route to internet gateway)
            try:
                # Get route tables associated with this subnet
                route_tables = ec2.describe_route_tables(
                    Filters=[
                        {"Name": "association.subnet-id", "Values": [subnet_id]}
                    ]
                )

                is_public = False
                for rt in route_tables.get("RouteTables", []):
                    for route in rt.get("Routes", []):
                        # Check for route to internet gateway
                        if route.get("GatewayId", "").startswith("igw-"):
                            destination = route.get("DestinationCidrBlock", "")
                            if destination == "0.0.0.0/0":
                                is_public = True
                                break

                raw_config["is_public_subnet"] = is_public
            except Exception as e:
                logger.debug(f"Could not determine if subnet {subnet_id} is public: {e}")
                raw_config["is_public_subnet"] = subnet.get("MapPublicIpOnLaunch", False)

            # Determine network exposure
            network_exposure = NETWORK_EXPOSURE_INTERNAL
            if raw_config.get("is_public_subnet"):
                network_exposure = NETWORK_EXPOSURE_INTERNET
            elif raw_config.get("map_public_ip_on_launch"):
                network_exposure = NETWORK_EXPOSURE_INTERNET

            assets.append(
                Asset(
                    id=subnet_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_subnet",
                    name=name,
                    tags=tags,
                    network_exposure=network_exposure,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _process_security_rule(
        self, rule: dict[str, Any], direction: str
    ) -> dict[str, Any]:
        """
        Process a security group rule into a normalized format.

        Args:
            rule: Raw security group rule from AWS
            direction: "ingress" or "egress"

        Returns:
            Normalized rule dictionary
        """
        processed: dict[str, Any] = {
            "direction": direction,
            "ip_protocol": rule.get("IpProtocol", "-1"),
            "from_port": rule.get("FromPort"),
            "to_port": rule.get("ToPort"),
            "cidr_blocks": [],
            "ipv6_cidr_blocks": [],
            "prefix_list_ids": [],
            "security_groups": [],
        }

        # Handle -1 protocol (all traffic)
        if processed["ip_protocol"] == "-1":
            processed["protocol_name"] = "all"
            processed["from_port"] = 0
            processed["to_port"] = 65535
        else:
            protocol_map = {"6": "tcp", "17": "udp", "1": "icmp"}
            processed["protocol_name"] = protocol_map.get(
                processed["ip_protocol"], processed["ip_protocol"]
            )

        # Extract CIDR blocks
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")
            if cidr:
                processed["cidr_blocks"].append(cidr)

        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6")
            if cidr:
                processed["ipv6_cidr_blocks"].append(cidr)

        # Extract prefix lists
        for prefix in rule.get("PrefixListIds", []):
            processed["prefix_list_ids"].append(prefix.get("PrefixListId"))

        # Extract security group references
        for sg_ref in rule.get("UserIdGroupPairs", []):
            processed["security_groups"].append({
                "group_id": sg_ref.get("GroupId"),
                "user_id": sg_ref.get("UserId"),
            })

        # Check if rule allows traffic from anywhere
        allows_all = (
            "0.0.0.0/0" in processed["cidr_blocks"]
            or "::/0" in processed["ipv6_cidr_blocks"]
        )
        processed["allows_all_traffic"] = allows_all

        # Identify exposed sensitive ports
        if allows_all and direction == "ingress":
            exposed_ports = []
            from_port = processed.get("from_port") or 0
            to_port = processed.get("to_port") or 65535

            for port, service in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    exposed_ports.append({"port": port, "service": service})

            processed["exposed_sensitive_ports"] = exposed_ports

        return processed

    def _allows_port_from_internet(
        self, rules: list[dict[str, Any]], port: int
    ) -> bool:
        """
        Check if any rule allows a specific port from the internet.

        Args:
            rules: List of processed security rules
            port: Port number to check

        Returns:
            True if port is accessible from internet
        """
        for rule in rules:
            if not rule.get("allows_all_traffic"):
                continue

            from_port = rule.get("from_port") or 0
            to_port = rule.get("to_port") or 65535

            if from_port <= port <= to_port:
                return True

        return False

    def _has_unrestricted_egress(
        self, egress_rules: list[dict[str, Any]]
    ) -> bool:
        """
        Check if any egress rule allows all traffic to 0.0.0.0/0.

        Args:
            egress_rules: List of processed egress security rules

        Returns:
            True if any egress rule allows all traffic to all destinations
        """
        for rule in egress_rules:
            cidr_blocks = rule.get("cidr_blocks", [])
            ip_protocol = rule.get("ip_protocol", "")
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")

            # Check for all-traffic rule (protocol -1 means all)
            is_all_traffic = (
                ip_protocol == "-1"
                or (from_port == 0 and to_port == 65535)
            )

            if is_all_traffic and ("0.0.0.0/0" in cidr_blocks or "::/0" in cidr_blocks):
                return True

        return False

    def _determine_instance_exposure(self, instance: dict[str, Any]) -> str:
        """
        Determine network exposure level for an EC2 instance.

        Args:
            instance: Instance data from AWS

        Returns:
            Network exposure level string
        """
        # If instance has public IP, it could be internet-facing
        if instance.get("PublicIpAddress"):
            return NETWORK_EXPOSURE_INTERNET

        # If instance has public DNS, it could be internet-facing
        if instance.get("PublicDnsName"):
            return NETWORK_EXPOSURE_INTERNET

        # Check if in a VPC
        if not instance.get("VpcId"):
            # EC2-Classic instances are treated as internet-facing
            return NETWORK_EXPOSURE_INTERNET

        return NETWORK_EXPOSURE_INTERNAL

    def _collect_network_acls(self) -> list[Asset]:
        """Collect Network ACLs with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for nacl in self._paginate(ec2, "describe_network_acls", "NetworkAcls"):
            nacl_id = nacl["NetworkAclId"]

            # Build ARN
            nacl_arn = self._build_arn(
                "ec2",
                "network-acl",
                nacl_id,
                region=self._region,
                account_id=self.account_id,
            )

            # Extract tags and name
            tags = self._extract_tags(nacl.get("Tags"))
            name = self._get_name_from_tags(tags, nacl_id)

            # Process entries (rules)
            inbound_rules = []
            outbound_rules = []
            allows_unrestricted_inbound_on_sensitive_ports = False

            for entry in nacl.get("Entries", []):
                rule = {
                    "rule_number": entry.get("RuleNumber"),
                    "protocol": entry.get("Protocol"),
                    "rule_action": entry.get("RuleAction"),
                    "cidr_block": entry.get("CidrBlock"),
                    "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
                    "port_range": entry.get("PortRange"),
                    "icmp_type_code": entry.get("IcmpTypeCode"),
                }

                if entry.get("Egress"):
                    outbound_rules.append(rule)
                else:
                    inbound_rules.append(rule)

                    # Check for unrestricted inbound on sensitive ports
                    if entry.get("RuleAction") == "allow":
                        cidr = entry.get("CidrBlock", "")
                        if cidr == "0.0.0.0/0":
                            port_range = entry.get("PortRange", {})
                            from_port = port_range.get("From", 0)
                            to_port = port_range.get("To", 65535)

                            # Check for sensitive ports
                            for port in SENSITIVE_PORTS.keys():
                                if from_port <= port <= to_port:
                                    allows_unrestricted_inbound_on_sensitive_ports = True
                                    break

            raw_config: dict[str, Any] = {
                "network_acl_id": nacl_id,
                "vpc_id": nacl.get("VpcId"),
                "is_default": nacl.get("IsDefault", False),
                "owner_id": nacl.get("OwnerId"),
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules,
                "associations": [
                    {
                        "association_id": assoc.get("NetworkAclAssociationId"),
                        "subnet_id": assoc.get("SubnetId"),
                    }
                    for assoc in nacl.get("Associations", [])
                ],
                "associated_subnet_count": len(nacl.get("Associations", [])),
                "allows_unrestricted_inbound_on_sensitive_ports": (
                    allows_unrestricted_inbound_on_sensitive_ports
                ),
            }

            assets.append(
                Asset(
                    id=nacl_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_network_acl",
                    name=name,
                    tags=tags,
                    network_exposure=NETWORK_EXPOSURE_INTERNAL,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets

    def _collect_vpc_endpoints(self) -> list[Asset]:
        """Collect VPC Endpoints with their configurations."""
        ec2 = self._get_client("ec2")
        assets: list[Asset] = []
        now = self._now()

        for endpoint in self._paginate(
            ec2, "describe_vpc_endpoints", "VpcEndpoints"
        ):
            endpoint_id = endpoint["VpcEndpointId"]

            # Build ARN
            endpoint_arn = self._build_arn(
                "ec2",
                "vpc-endpoint",
                endpoint_id,
                region=self._region,
                account_id=self.account_id,
            )

            # Extract tags and name
            tags = self._extract_tags(endpoint.get("Tags"))
            name = self._get_name_from_tags(tags, endpoint_id)

            # Analyze policy document
            policy_document = endpoint.get("PolicyDocument", "")
            has_restrictive_policy = True

            if policy_document:
                # Check if policy is overly permissive (allows all)
                if isinstance(policy_document, str):
                    if '"*"' in policy_document or "'*'" in policy_document:
                        # Check if it's a full-access policy
                        if (
                            '"Principal": "*"' in policy_document
                            or '"Principal":"*"' in policy_document
                        ):
                            if (
                                '"Action": "*"' in policy_document
                                or '"Action":"*"' in policy_document
                            ):
                                has_restrictive_policy = False
                        # Also check for Resource: *
                        if (
                            '"Resource": "*"' in policy_document
                            or '"Resource":"*"' in policy_document
                        ):
                            has_restrictive_policy = False

            raw_config: dict[str, Any] = {
                "vpc_endpoint_id": endpoint_id,
                "vpc_id": endpoint.get("VpcId"),
                "service_name": endpoint.get("ServiceName", ""),
                "state": endpoint.get("State", ""),
                "vpc_endpoint_type": endpoint.get("VpcEndpointType", ""),
                "policy_document": policy_document,
                "has_restrictive_policy": has_restrictive_policy,
                "route_table_ids": endpoint.get("RouteTableIds", []),
                "subnet_ids": endpoint.get("SubnetIds", []),
                "security_group_ids": [
                    sg.get("GroupId") for sg in endpoint.get("Groups", [])
                ],
                "private_dns_enabled": endpoint.get("PrivateDnsEnabled", False),
                "requester_managed": endpoint.get("RequesterManaged", False),
                "network_interface_ids": endpoint.get("NetworkInterfaceIds", []),
                "dns_entries": [
                    {
                        "dns_name": dns.get("DnsName", ""),
                        "hosted_zone_id": dns.get("HostedZoneId", ""),
                    }
                    for dns in endpoint.get("DnsEntries", [])
                ],
                "creation_timestamp": (
                    endpoint["CreationTimestamp"].isoformat()
                    if endpoint.get("CreationTimestamp")
                    else None
                ),
                "owner_id": endpoint.get("OwnerId"),
            }

            assets.append(
                Asset(
                    id=endpoint_arn,
                    cloud_provider="aws",
                    account_id=self.account_id,
                    region=self._region,
                    resource_type="aws_vpc_endpoint",
                    name=name,
                    tags=tags,
                    network_exposure=NETWORK_EXPOSURE_ISOLATED,
                    last_seen=now,
                    raw_config=raw_config,
                )
            )

        return assets
