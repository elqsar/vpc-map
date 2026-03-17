"""Tests for shared network analysis helpers."""

from vpc_map.models import (
    Ec2Instance,
    IpPermission,
    NetworkAcl,
    NetworkAclEntry,
    Route,
    RouteTable,
    SecurityGroup,
    Subnet,
    Vpc,
    VpcEndpoint,
    VpcTopology,
)
from vpc_map.network.analysis import analyze_instances, analyze_subnets, get_route_target_kind


def create_vpc() -> Vpc:
    """Create a base VPC fixture."""
    return Vpc(
        vpc_id="vpc-test123",
        cidr_block="10.0.0.0/16",
        is_default=False,
        state="available",
    )


def test_analyze_subnets_uses_main_route_table_and_endpoint_awareness():
    """Subnet classification should use one shared routing algorithm."""
    vpc = create_vpc()
    subnets = [
        Subnet(
            subnet_id="subnet-public",
            vpc_id=vpc.vpc_id,
            cidr_block="10.0.1.0/24",
            availability_zone="us-east-1a",
            available_ip_address_count=250,
            state="available",
        ),
        Subnet(
            subnet_id="subnet-private",
            vpc_id=vpc.vpc_id,
            cidr_block="10.0.2.0/24",
            availability_zone="us-east-1a",
            available_ip_address_count=250,
            state="available",
        ),
        Subnet(
            subnet_id="subnet-endpoint",
            vpc_id=vpc.vpc_id,
            cidr_block="10.0.3.0/24",
            availability_zone="us-east-1b",
            available_ip_address_count=250,
            state="available",
        ),
        Subnet(
            subnet_id="subnet-isolated",
            vpc_id=vpc.vpc_id,
            cidr_block="10.0.4.0/24",
            availability_zone="us-east-1b",
            available_ip_address_count=250,
            state="available",
        ),
    ]
    route_tables = [
        RouteTable(
            route_table_id="rtb-public",
            vpc_id=vpc.vpc_id,
            subnet_associations=["subnet-public"],
            routes=[
                Route(
                    destination_cidr_block="0.0.0.0/0",
                    gateway_id="igw-12345",
                    state="active",
                    origin="CreateRoute",
                )
            ],
        ),
        RouteTable(
            route_table_id="rtb-main",
            vpc_id=vpc.vpc_id,
            is_main=True,
            routes=[
                Route(
                    destination_cidr_block="0.0.0.0/0",
                    nat_gateway_id="nat-12345",
                    state="active",
                    origin="CreateRoute",
                )
            ],
        ),
        RouteTable(
            route_table_id="rtb-endpoint",
            vpc_id=vpc.vpc_id,
            subnet_associations=["subnet-endpoint"],
            routes=[],
        ),
        RouteTable(
            route_table_id="rtb-isolated",
            vpc_id=vpc.vpc_id,
            subnet_associations=["subnet-isolated"],
            routes=[],
        ),
    ]
    topology = VpcTopology(
        vpc=vpc,
        subnets=subnets,
        route_tables=route_tables,
        vpc_endpoints=[
            VpcEndpoint(
                vpc_endpoint_id="vpce-12345",
                vpc_id=vpc.vpc_id,
                service_name="com.amazonaws.us-east-1.s3",
                endpoint_type="Gateway",
                state="available",
                route_table_ids=["rtb-endpoint"],
            )
        ],
        region="us-east-1",
    )

    analysis = {item.subnet_id: item for item in analyze_subnets(topology)}

    assert analysis["subnet-public"].classification.value == "public"
    assert analysis["subnet-private"].classification.value == "private_with_nat"
    assert analysis["subnet-endpoint"].classification.value == "endpoint_only"
    assert analysis["subnet-isolated"].classification.value == "isolated"
    assert analysis["subnet-private"].route_table_id == "rtb-main"


def test_analyze_instances_detects_public_admin_exposure():
    """Instance exposure should reflect IGW route, public address, SG, and NACL."""
    vpc = create_vpc()
    instance = Ec2Instance(
        instance_id="i-12345",
        instance_type="t3.micro",
        state="running",
        subnet_id="subnet-public",
        vpc_id=vpc.vpc_id,
        availability_zone="us-east-1a",
        public_ip_address="198.51.100.10",
        security_groups=["sg-web"],
        ami_id="ami-12345",
    )
    topology = VpcTopology(
        vpc=vpc,
        subnets=[
            Subnet(
                subnet_id="subnet-public",
                vpc_id=vpc.vpc_id,
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                available_ip_address_count=250,
                state="available",
            )
        ],
        route_tables=[
            RouteTable(
                route_table_id="rtb-public",
                vpc_id=vpc.vpc_id,
                subnet_associations=["subnet-public"],
                routes=[
                    Route(
                        destination_cidr_block="0.0.0.0/0",
                        gateway_id="igw-12345",
                        state="active",
                        origin="CreateRoute",
                    )
                ],
            )
        ],
        security_groups=[
            SecurityGroup(
                group_id="sg-web",
                group_name="web",
                description="web",
                vpc_id=vpc.vpc_id,
                ingress_rules=[
                    IpPermission(
                        ip_protocol="tcp",
                        from_port=22,
                        to_port=22,
                        ip_ranges=["0.0.0.0/0"],
                    )
                ],
            )
        ],
        network_acls=[
            NetworkAcl(
                nacl_id="acl-12345",
                vpc_id=vpc.vpc_id,
                entries=[
                    NetworkAclEntry(
                        rule_number=100,
                        protocol="6",
                        rule_action="allow",
                        egress=False,
                        cidr_block="0.0.0.0/0",
                        port_range={"From": 22, "To": 22},
                    )
                ],
                subnet_associations=["subnet-public"],
            )
        ],
        ec2_instances=[instance],
        region="us-east-1",
    )

    exposure = analyze_instances(topology)[0]

    assert exposure.exposure_state.value == "publicly_reachable"
    assert exposure.open_admin_ports == [22]
    assert exposure.allowed_ports == [22]


def test_analyze_instances_detects_non_admin_public_service_exposure():
    """Public exposure should not be limited to a tiny built-in port list."""
    vpc = create_vpc()
    instance = Ec2Instance(
        instance_id="i-redis",
        instance_type="t3.micro",
        state="running",
        subnet_id="subnet-public",
        vpc_id=vpc.vpc_id,
        availability_zone="us-east-1a",
        public_ip_address="198.51.100.11",
        security_groups=["sg-redis"],
        ami_id="ami-12345",
    )
    topology = VpcTopology(
        vpc=vpc,
        subnets=[
            Subnet(
                subnet_id="subnet-public",
                vpc_id=vpc.vpc_id,
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                available_ip_address_count=250,
                state="available",
            )
        ],
        route_tables=[
            RouteTable(
                route_table_id="rtb-public",
                vpc_id=vpc.vpc_id,
                subnet_associations=["subnet-public"],
                routes=[
                    Route(
                        destination_cidr_block="0.0.0.0/0",
                        gateway_id="igw-12345",
                        state="active",
                        origin="CreateRoute",
                    )
                ],
            )
        ],
        security_groups=[
            SecurityGroup(
                group_id="sg-redis",
                group_name="redis",
                description="redis",
                vpc_id=vpc.vpc_id,
                ingress_rules=[
                    IpPermission(
                        ip_protocol="tcp",
                        from_port=6379,
                        to_port=6379,
                        ip_ranges=["0.0.0.0/0"],
                    )
                ],
            )
        ],
        network_acls=[
            NetworkAcl(
                nacl_id="acl-public",
                vpc_id=vpc.vpc_id,
                entries=[
                    NetworkAclEntry(
                        rule_number=100,
                        protocol="6",
                        rule_action="allow",
                        egress=False,
                        cidr_block="0.0.0.0/0",
                        port_range={"From": 6379, "To": 6379},
                    )
                ],
                subnet_associations=["subnet-public"],
            )
        ],
        ec2_instances=[instance],
        region="us-east-1",
    )

    exposure = analyze_instances(topology)[0]

    assert exposure.exposure_state.value == "publicly_reachable"
    assert exposure.open_admin_ports == []
    assert exposure.allowed_ports == [6379]


def test_get_route_target_kind_supports_expanded_targets():
    """Route target normalization should expose additional AWS route targets."""
    assert (
        get_route_target_kind(
            Route(
                destination_cidr_block="10.1.0.0/16",
                transit_gateway_id="tgw-12345",
                state="active",
                origin="CreateRoute",
            )
        )
        == "tgw"
    )
    assert (
        get_route_target_kind(
            Route(
                destination_ipv6_cidr_block="::/0",
                egress_only_internet_gateway_id="eigw-12345",
                state="active",
                origin="CreateRoute",
            )
        )
        == "eigw"
    )
