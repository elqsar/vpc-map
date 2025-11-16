"""AWS VPC resource collector using boto3."""

from typing import Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from vpc_map.models import (
    InternetGateway,
    IpPermission,
    NatGateway,
    NetworkAcl,
    NetworkAclEntry,
    Route,
    RouteTable,
    SecurityGroup,
    Subnet,
    Tag,
    Vpc,
    VpcTopology,
)


class VpcCollector:
    """Collects VPC topology information from AWS."""

    def __init__(self, region: Optional[str] = None, profile: Optional[str] = None):
        """
        Initialize the VPC collector.

        Args:
            region: AWS region to use (defaults to configured region)
            profile: AWS profile to use (defaults to default profile)
        """
        self.session = boto3.Session(profile_name=profile, region_name=region)
        self.ec2_client = self.session.client("ec2")
        self.region = self.session.region_name or "us-east-1"

    def _parse_tags(self, tags_list: Optional[list]) -> list[Tag]:
        """Parse AWS tags into Tag models."""
        if not tags_list:
            return []
        return [Tag(key=tag["Key"], value=tag["Value"]) for tag in tags_list]

    def get_vpc(self, vpc_id: str) -> Vpc:
        """
        Get VPC details.

        Args:
            vpc_id: VPC ID to fetch

        Returns:
            Vpc model

        Raises:
            ValueError: If VPC not found
            ClientError: If AWS API call fails
        """
        try:
            response = self.ec2_client.describe_vpcs(VpcIds=[vpc_id])
            if not response["Vpcs"]:
                raise ValueError(f"VPC {vpc_id} not found")

            vpc_data = response["Vpcs"][0]

            # Get VPC attributes
            dns_support = self.ec2_client.describe_vpc_attribute(
                VpcId=vpc_id, Attribute="enableDnsSupport"
            )
            dns_hostnames = self.ec2_client.describe_vpc_attribute(
                VpcId=vpc_id, Attribute="enableDnsHostnames"
            )

            return Vpc(
                vpc_id=vpc_data["VpcId"],
                cidr_block=vpc_data["CidrBlock"],
                is_default=vpc_data.get("IsDefault", False),
                state=vpc_data["State"],
                tags=self._parse_tags(vpc_data.get("Tags")),
                enable_dns_support=dns_support["EnableDnsSupport"]["Value"],
                enable_dns_hostnames=dns_hostnames["EnableDnsHostnames"]["Value"],
            )
        except ClientError as e:
            raise ClientError(
                f"Failed to get VPC {vpc_id}: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_subnets(self, vpc_id: str) -> list[Subnet]:
        """Get all subnets in a VPC."""
        try:
            response = self.ec2_client.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            subnets = []
            for subnet_data in response["Subnets"]:
                subnets.append(
                    Subnet(
                        subnet_id=subnet_data["SubnetId"],
                        vpc_id=subnet_data["VpcId"],
                        cidr_block=subnet_data["CidrBlock"],
                        availability_zone=subnet_data["AvailabilityZone"],
                        available_ip_address_count=subnet_data["AvailableIpAddressCount"],
                        map_public_ip_on_launch=subnet_data.get("MapPublicIpOnLaunch", False),
                        state=subnet_data["State"],
                        tags=self._parse_tags(subnet_data.get("Tags")),
                    )
                )
            return subnets
        except ClientError as e:
            raise ClientError(
                f"Failed to get subnets: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_internet_gateways(self, vpc_id: str) -> list[InternetGateway]:
        """Get all internet gateways attached to a VPC."""
        try:
            response = self.ec2_client.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )

            igws = []
            for igw_data in response["InternetGateways"]:
                attachment = igw_data["Attachments"][0] if igw_data["Attachments"] else {}
                igws.append(
                    InternetGateway(
                        igw_id=igw_data["InternetGatewayId"],
                        vpc_id=attachment.get("VpcId"),
                        state=attachment.get("State", "detached"),
                        tags=self._parse_tags(igw_data.get("Tags")),
                    )
                )
            return igws
        except ClientError as e:
            raise ClientError(
                f"Failed to get internet gateways: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_nat_gateways(self, vpc_id: str) -> list[NatGateway]:
        """Get all NAT gateways in a VPC."""
        try:
            response = self.ec2_client.describe_nat_gateways(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            nat_gateways = []
            for nat_data in response["NatGateways"]:
                # Extract public and private IPs from addresses
                public_ip = None
                private_ip = None
                for addr in nat_data.get("NatGatewayAddresses", []):
                    if "PublicIp" in addr:
                        public_ip = addr["PublicIp"]
                    if "PrivateIp" in addr:
                        private_ip = addr["PrivateIp"]

                nat_gateways.append(
                    NatGateway(
                        nat_gateway_id=nat_data["NatGatewayId"],
                        vpc_id=nat_data["VpcId"],
                        subnet_id=nat_data["SubnetId"],
                        state=nat_data["State"],
                        public_ip=public_ip,
                        private_ip=private_ip,
                        tags=self._parse_tags(nat_data.get("Tags")),
                    )
                )
            return nat_gateways
        except ClientError as e:
            raise ClientError(
                f"Failed to get NAT gateways: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_route_tables(self, vpc_id: str) -> list[RouteTable]:
        """Get all route tables in a VPC."""
        try:
            response = self.ec2_client.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            route_tables = []
            for rt_data in response["RouteTables"]:
                # Parse routes
                routes = []
                for route_data in rt_data["Routes"]:
                    routes.append(
                        Route(
                            destination_cidr_block=route_data.get("DestinationCidrBlock"),
                            destination_ipv6_cidr_block=route_data.get("DestinationIpv6CidrBlock"),
                            gateway_id=route_data.get("GatewayId"),
                            nat_gateway_id=route_data.get("NatGatewayId"),
                            network_interface_id=route_data.get("NetworkInterfaceId"),
                            vpc_peering_connection_id=route_data.get("VpcPeeringConnectionId"),
                            instance_id=route_data.get("InstanceId"),
                            state=route_data.get("State", "active"),
                            origin=route_data.get("Origin", "CreateRouteTable"),
                        )
                    )

                # Parse subnet associations
                subnet_associations = []
                is_main = False
                for assoc in rt_data.get("Associations", []):
                    if assoc.get("Main", False):
                        is_main = True
                    if "SubnetId" in assoc:
                        subnet_associations.append(assoc["SubnetId"])

                route_tables.append(
                    RouteTable(
                        route_table_id=rt_data["RouteTableId"],
                        vpc_id=rt_data["VpcId"],
                        routes=routes,
                        subnet_associations=subnet_associations,
                        is_main=is_main,
                        tags=self._parse_tags(rt_data.get("Tags")),
                    )
                )
            return route_tables
        except ClientError as e:
            raise ClientError(
                f"Failed to get route tables: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_security_groups(self, vpc_id: str) -> list[SecurityGroup]:
        """Get all security groups in a VPC."""
        try:
            response = self.ec2_client.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            security_groups = []
            for sg_data in response["SecurityGroups"]:
                # Parse ingress rules
                ingress_rules = []
                for perm in sg_data.get("IpPermissions", []):
                    ingress_rules.append(
                        IpPermission(
                            ip_protocol=perm.get("IpProtocol", "-1"),
                            from_port=perm.get("FromPort"),
                            to_port=perm.get("ToPort"),
                            ip_ranges=[r["CidrIp"] for r in perm.get("IpRanges", [])],
                            ipv6_ranges=[r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])],
                            prefix_list_ids=[
                                p["PrefixListId"] for p in perm.get("PrefixListIds", [])
                            ],
                            user_id_group_pairs=[
                                g["GroupId"] for g in perm.get("UserIdGroupPairs", [])
                            ],
                        )
                    )

                # Parse egress rules
                egress_rules = []
                for perm in sg_data.get("IpPermissionsEgress", []):
                    egress_rules.append(
                        IpPermission(
                            ip_protocol=perm.get("IpProtocol", "-1"),
                            from_port=perm.get("FromPort"),
                            to_port=perm.get("ToPort"),
                            ip_ranges=[r["CidrIp"] for r in perm.get("IpRanges", [])],
                            ipv6_ranges=[r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])],
                            prefix_list_ids=[
                                p["PrefixListId"] for p in perm.get("PrefixListIds", [])
                            ],
                            user_id_group_pairs=[
                                g["GroupId"] for g in perm.get("UserIdGroupPairs", [])
                            ],
                        )
                    )

                security_groups.append(
                    SecurityGroup(
                        group_id=sg_data["GroupId"],
                        group_name=sg_data["GroupName"],
                        description=sg_data["Description"],
                        vpc_id=sg_data["VpcId"],
                        ingress_rules=ingress_rules,
                        egress_rules=egress_rules,
                        tags=self._parse_tags(sg_data.get("Tags")),
                    )
                )
            return security_groups
        except ClientError as e:
            raise ClientError(
                f"Failed to get security groups: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_network_acls(self, vpc_id: str) -> list[NetworkAcl]:
        """Get all network ACLs in a VPC."""
        try:
            response = self.ec2_client.describe_network_acls(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            network_acls = []
            for nacl_data in response["NetworkAcls"]:
                # Parse entries
                entries = []
                for entry in nacl_data.get("Entries", []):
                    entries.append(
                        NetworkAclEntry(
                            rule_number=entry["RuleNumber"],
                            protocol=entry.get("Protocol", "-1"),
                            rule_action=entry["RuleAction"],
                            egress=entry["Egress"],
                            cidr_block=entry.get("CidrBlock"),
                            ipv6_cidr_block=entry.get("Ipv6CidrBlock"),
                            icmp_type_code=entry.get("IcmpTypeCode"),
                            port_range=entry.get("PortRange"),
                        )
                    )

                # Parse subnet associations
                subnet_associations = []
                for assoc in nacl_data.get("Associations", []):
                    if "SubnetId" in assoc:
                        subnet_associations.append(assoc["SubnetId"])

                network_acls.append(
                    NetworkAcl(
                        nacl_id=nacl_data["NetworkAclId"],
                        vpc_id=nacl_data["VpcId"],
                        is_default=nacl_data.get("IsDefault", False),
                        entries=entries,
                        subnet_associations=subnet_associations,
                        tags=self._parse_tags(nacl_data.get("Tags")),
                    )
                )
            return network_acls
        except ClientError as e:
            raise ClientError(
                f"Failed to get network ACLs: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def get_security_group_usage(self, vpc_id: str) -> dict[str, list[str]]:
        """
        Get security group usage by querying network interfaces.

        Args:
            vpc_id: VPC ID to check

        Returns:
            Dictionary mapping security group IDs to list of ENI IDs using them
        """
        try:
            response = self.ec2_client.describe_network_interfaces(
                Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
            )

            usage = {}  # sg_id -> list of eni_ids
            for eni in response.get("NetworkInterfaces", []):
                eni_id = eni["NetworkInterfaceId"]
                for group in eni.get("Groups", []):
                    sg_id = group["GroupId"]
                    if sg_id not in usage:
                        usage[sg_id] = []
                    usage[sg_id].append(eni_id)

            return usage
        except ClientError as e:
            raise ClientError(
                f"Failed to get security group usage: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )

    def collect_vpc_topology(self, vpc_id: str) -> VpcTopology:
        """
        Collect complete VPC topology.

        Args:
            vpc_id: VPC ID to collect topology for

        Returns:
            VpcTopology with all resources

        Raises:
            ValueError: If VPC not found
            ClientError: If AWS API call fails
        """
        try:
            vpc = self.get_vpc(vpc_id)
            subnets = self.get_subnets(vpc_id)
            internet_gateways = self.get_internet_gateways(vpc_id)
            nat_gateways = self.get_nat_gateways(vpc_id)
            route_tables = self.get_route_tables(vpc_id)
            security_groups = self.get_security_groups(vpc_id)
            network_acls = self.get_network_acls(vpc_id)

            # Get security group usage information
            sg_usage = self.get_security_group_usage(vpc_id)

            # Populate usage information for each security group
            for sg in security_groups:
                if sg.group_id in sg_usage:
                    sg.attached_enis = sg_usage[sg.group_id]
                    sg.is_in_use = True
                else:
                    sg.attached_enis = []
                    sg.is_in_use = False

            return VpcTopology(
                vpc=vpc,
                subnets=subnets,
                internet_gateways=internet_gateways,
                nat_gateways=nat_gateways,
                route_tables=route_tables,
                security_groups=security_groups,
                network_acls=network_acls,
                region=self.region,
            )
        except Exception as e:
            raise Exception(f"Failed to collect VPC topology: {str(e)}")

    def list_vpcs(self) -> list[Vpc]:
        """List all VPCs in the region."""
        try:
            response = self.ec2_client.describe_vpcs()
            vpcs = []
            for vpc_data in response["Vpcs"]:
                vpcs.append(
                    Vpc(
                        vpc_id=vpc_data["VpcId"],
                        cidr_block=vpc_data["CidrBlock"],
                        is_default=vpc_data.get("IsDefault", False),
                        state=vpc_data["State"],
                        tags=self._parse_tags(vpc_data.get("Tags")),
                    )
                )
            return vpcs
        except ClientError as e:
            raise ClientError(
                f"Failed to list VPCs: {e.response['Error']['Message']}",
                e.response["Error"]["Code"],
            )
