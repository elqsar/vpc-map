"""Tests for the diff engine."""

import copy

from vpc_map.diff.engine import diff_topologies
from vpc_map.models import (
    ChangeType,
    Ec2Instance,
    ElasticIp,
    InternetGateway,
    IpPermission,
    NatGateway,
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


def _create_topology() -> VpcTopology:
    """Create a base topology for diff testing."""
    return VpcTopology(
        vpc=Vpc(
            vpc_id="vpc-test",
            cidr_block="10.0.0.0/16",
            is_default=False,
            state="available",
            enable_dns_hostnames=True,
            enable_dns_support=True,
        ),
        subnets=[
            Subnet(
                subnet_id="subnet-1",
                vpc_id="vpc-test",
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                available_ip_address_count=250,
                state="available",
            ),
        ],
        internet_gateways=[
            InternetGateway(
                igw_id="igw-1",
                vpc_id="vpc-test",
                state="attached",
            ),
        ],
        route_tables=[
            RouteTable(
                route_table_id="rtb-1",
                vpc_id="vpc-test",
                subnet_associations=["subnet-1"],
                routes=[
                    Route(
                        destination_cidr_block="0.0.0.0/0",
                        gateway_id="igw-1",
                        state="active",
                        origin="CreateRoute",
                    ),
                    Route(
                        destination_cidr_block="10.0.0.0/16",
                        gateway_id="local",
                        state="active",
                        origin="CreateRouteTable",
                    ),
                ],
            ),
        ],
        security_groups=[
            SecurityGroup(
                group_id="sg-1",
                group_name="web",
                description="web sg",
                vpc_id="vpc-test",
                ingress_rules=[
                    IpPermission(
                        ip_protocol="tcp",
                        from_port=443,
                        to_port=443,
                        ip_ranges=["0.0.0.0/0"],
                    ),
                ],
                egress_rules=[
                    IpPermission(
                        ip_protocol="-1",
                        ip_ranges=["0.0.0.0/0"],
                    ),
                ],
            ),
        ],
        network_acls=[
            NetworkAcl(
                nacl_id="acl-1",
                vpc_id="vpc-test",
                entries=[
                    NetworkAclEntry(
                        rule_number=100,
                        protocol="6",
                        rule_action="allow",
                        egress=False,
                        cidr_block="0.0.0.0/0",
                        port_range={"From": 443, "To": 443},
                    ),
                ],
                subnet_associations=["subnet-1"],
            ),
        ],
        ec2_instances=[
            Ec2Instance(
                instance_id="i-1",
                instance_type="t3.micro",
                state="running",
                subnet_id="subnet-1",
                vpc_id="vpc-test",
                availability_zone="us-east-1a",
                public_ip_address="198.51.100.10",
                security_groups=["sg-1"],
                ami_id="ami-12345",
            ),
        ],
        region="us-east-1",
    )


def _deep_copy_topology(topology: VpcTopology) -> VpcTopology:
    """Deep copy a topology using model serialization."""
    return VpcTopology.model_validate(copy.deepcopy(topology.model_dump(mode="json")))


def test_identical_topologies_no_changes():
    """Empty diff for same topology."""
    topology = _create_topology()
    after = _deep_copy_topology(topology)
    report = diff_topologies(topology, after)
    assert report.resource_changes == []
    assert report.derived_changes == []


def test_added_resource_detected():
    """New subnet in 'after' -> ADDED change."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    after.subnets.append(
        Subnet(
            subnet_id="subnet-2",
            vpc_id="vpc-test",
            cidr_block="10.0.2.0/24",
            availability_zone="us-east-1b",
            available_ip_address_count=250,
            state="available",
        )
    )
    report = diff_topologies(before, after)
    added = [c for c in report.resource_changes if c.change_type == ChangeType.ADDED]
    assert len(added) == 1
    assert added[0].resource_type == "subnet"
    assert added[0].resource_id == "subnet-2"


def test_removed_resource_detected():
    """Missing subnet in 'after' -> REMOVED change."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    after.subnets = []
    report = diff_topologies(before, after)
    removed = [c for c in report.resource_changes if c.change_type == ChangeType.REMOVED]
    assert len(removed) == 1
    assert removed[0].resource_type == "subnet"
    assert removed[0].resource_id == "subnet-1"


def test_modified_security_group_rules():
    """Changed ingress_rules -> MODIFIED with field_changes."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    # Add SSH rule to security group
    after.security_groups[0].ingress_rules.append(
        IpPermission(
            ip_protocol="tcp",
            from_port=22,
            to_port=22,
            ip_ranges=["0.0.0.0/0"],
        )
    )
    report = diff_topologies(before, after)
    modified = [
        c for c in report.resource_changes
        if c.resource_type == "security_group" and c.change_type == ChangeType.MODIFIED
    ]
    assert len(modified) == 1
    assert modified[0].resource_id == "sg-1"
    fields = {fc.field for fc in modified[0].field_changes}
    assert "ingress_rules" in fields


def test_route_table_route_changes():
    """New route added -> route_table MODIFIED."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    after.route_tables[0].routes.append(
        Route(
            destination_cidr_block="10.1.0.0/16",
            gateway_id="vgw-12345",
            state="active",
            origin="CreateRoute",
        )
    )
    report = diff_topologies(before, after)
    modified = [
        c for c in report.resource_changes
        if c.resource_type == "route_table" and c.change_type == ChangeType.MODIFIED
    ]
    assert len(modified) == 1
    fields = {fc.field for fc in modified[0].field_changes}
    assert "routes" in fields


def test_vpc_field_change():
    """dns_hostnames toggle -> vpc-level change."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    after.vpc.enable_dns_hostnames = False
    report = diff_topologies(before, after)
    vpc_changes = [c for c in report.resource_changes if c.resource_type == "vpc"]
    assert len(vpc_changes) == 1
    assert vpc_changes[0].change_type == ChangeType.MODIFIED
    fields = {fc.field for fc in vpc_changes[0].field_changes}
    assert "enable_dns_hostnames" in fields


def test_derived_subnet_classification_change():
    """Route change -> classification drift."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    # Remove IGW route, add NAT route -> public -> private_with_nat
    after.route_tables[0].routes = [
        Route(
            destination_cidr_block="0.0.0.0/0",
            nat_gateway_id="nat-12345",
            state="active",
            origin="CreateRoute",
        ),
        Route(
            destination_cidr_block="10.0.0.0/16",
            gateway_id="local",
            state="active",
            origin="CreateRouteTable",
        ),
    ]
    after.nat_gateways = [
        NatGateway(
            nat_gateway_id="nat-12345",
            vpc_id="vpc-test",
            subnet_id="subnet-1",
            state="available",
        ),
    ]
    report = diff_topologies(before, after)
    classification_changes = [
        dc for dc in report.derived_changes
        if dc.analysis_type == "subnet_classification" and dc.field == "classification"
    ]
    assert len(classification_changes) == 1
    assert classification_changes[0].old_value == "public"
    assert classification_changes[0].new_value == "private_with_nat"


def test_derived_instance_exposure_change():
    """Public IP added -> exposure state drift."""
    before = _create_topology()
    # Remove public IP from before
    before.ec2_instances[0].public_ip_address = None
    # Remove IGW route so instance is privately reachable
    before.route_tables[0].routes = [
        Route(
            destination_cidr_block="10.0.0.0/16",
            gateway_id="local",
            state="active",
            origin="CreateRouteTable",
        ),
    ]
    before.internet_gateways = []

    after = _deep_copy_topology(before)
    # Add IGW route and public IP
    after.internet_gateways = [
        InternetGateway(igw_id="igw-1", vpc_id="vpc-test", state="attached"),
    ]
    after.route_tables[0].routes.append(
        Route(
            destination_cidr_block="0.0.0.0/0",
            gateway_id="igw-1",
            state="active",
            origin="CreateRoute",
        ),
    )
    after.ec2_instances[0].public_ip_address = "198.51.100.10"

    report = diff_topologies(before, after)
    exposure_changes = [
        dc for dc in report.derived_changes
        if dc.analysis_type == "instance_exposure" and dc.field == "exposure_state"
    ]
    assert len(exposure_changes) == 1
    assert exposure_changes[0].old_value == "privately_reachable_only"


def test_volatile_fields_excluded():
    """available_ip_address_count change -> no diff."""
    before = _create_topology()
    after = _deep_copy_topology(before)
    after.subnets[0].available_ip_address_count = 200
    report = diff_topologies(before, after)
    # Should have no resource changes since available_ip_address_count is volatile
    subnet_changes = [
        c for c in report.resource_changes if c.resource_type == "subnet"
    ]
    assert len(subnet_changes) == 0


def test_elastic_ip_fallback_key():
    """ElasticIp with no allocation_id uses public_ip as key."""
    before = _create_topology()
    before.elastic_ips = [
        ElasticIp(public_ip="203.0.113.1"),
    ]
    after = _deep_copy_topology(before)
    after.elastic_ips = []

    report = diff_topologies(before, after)
    removed = [
        c for c in report.resource_changes
        if c.resource_type == "elastic_ip" and c.change_type == ChangeType.REMOVED
    ]
    assert len(removed) == 1
    assert removed[0].resource_id == "203.0.113.1"
