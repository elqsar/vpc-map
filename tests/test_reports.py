"""Tests for report generators."""

from io import StringIO
import json

from rich.console import Console

from vpc_map.models import (
    AuditReport,
    Ec2Instance,
    ElasticIp,
    FlowLog,
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
from vpc_map.reports.html import HTMLReporter
from vpc_map.reports.json import JSONReporter
from vpc_map.reports.terminal import TerminalReporter


def _create_topology() -> VpcTopology:
    """Create a topology with Phase 1 resources populated."""
    return VpcTopology(
        vpc=Vpc(
            vpc_id="vpc-12345",
            cidr_block="10.0.0.0/16",
            is_default=False,
            state="available",
        ),
        flow_logs=[
            FlowLog(
                flow_log_id="fl-12345",
                resource_id="vpc-12345",
                resource_type="VPC",
                traffic_type="ALL",
                log_destination_type="cloud-watch-logs",
                flow_log_status="ACTIVE",
            )
        ],
        vpc_endpoints=[
            VpcEndpoint(
                vpc_endpoint_id="vpce-12345",
                vpc_id="vpc-12345",
                service_name="com.amazonaws.us-east-1.s3",
                endpoint_type="Gateway",
                state="available",
                route_table_ids=["rtb-12345"],
            )
        ],
        elastic_ips=[ElasticIp(allocation_id="eipalloc-123", public_ip="203.0.113.10")],
        subnets=[
            Subnet(
                subnet_id="subnet-12345",
                vpc_id="vpc-12345",
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                available_ip_address_count=250,
                state="available",
            )
        ],
        route_tables=[
            RouteTable(
                route_table_id="rtb-12345",
                vpc_id="vpc-12345",
                subnet_associations=["subnet-12345"],
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
                group_id="sg-12345",
                group_name="web",
                description="web",
                vpc_id="vpc-12345",
                ingress_rules=[
                    IpPermission(
                        ip_protocol="tcp",
                        from_port=443,
                        to_port=443,
                        ip_ranges=["0.0.0.0/0"],
                    )
                ],
            )
        ],
        network_acls=[
            NetworkAcl(
                nacl_id="acl-12345",
                vpc_id="vpc-12345",
                entries=[
                    NetworkAclEntry(
                        rule_number=100,
                        protocol="6",
                        rule_action="allow",
                        egress=False,
                        cidr_block="0.0.0.0/0",
                        port_range={"From": 443, "To": 443},
                    )
                ],
                subnet_associations=["subnet-12345"],
            )
        ],
        ec2_instances=[
            Ec2Instance(
                instance_id="i-12345",
                instance_type="t3.micro",
                state="running",
                subnet_id="subnet-12345",
                vpc_id="vpc-12345",
                availability_zone="us-east-1a",
                public_ip_address="203.0.113.10",
                security_groups=["sg-12345"],
                security_group_names=["web"],
                ami_id="ami-12345",
            )
        ],
        region="us-east-1",
    )


def test_json_report_includes_phase1_summary_counts(tmp_path):
    """Test combined JSON report summary counts for new resources."""
    topology = _create_topology()
    report = AuditReport(vpc_id=topology.vpc.vpc_id, region=topology.region)
    output_file = tmp_path / "report.json"

    JSONReporter().generate_combined_report(topology, report, output_file)

    content = json.loads(output_file.read_text())
    counts = content["summary"]["resource_counts"]
    assert counts["flow_logs"] == 1
    assert counts["vpc_endpoints"] == 1
    assert counts["elastic_ips"] == 1
    assert counts["elastic_ips_unassociated"] == 1
    assert "network_analysis" in content
    assert "subnets" in content["network_analysis"]
    assert "instances" in content["network_analysis"]


def test_html_report_renders_phase1_sections(tmp_path):
    """Test HTML report includes Phase 1 inventory sections."""
    topology = _create_topology()
    report = AuditReport(vpc_id=topology.vpc.vpc_id, region=topology.region)
    output_file = tmp_path / "report.html"

    HTMLReporter().generate_report(topology, report, output_file)

    content = output_file.read_text()
    assert "Flow Logs (1)" in content
    assert "VPC Endpoints (1)" in content
    assert "Elastic IPs (1)" in content


def test_terminal_report_prints_phase1_tables():
    """Test terminal reporter prints Phase 1 sections."""
    topology = _create_topology()
    report = AuditReport(vpc_id=topology.vpc.vpc_id, region=topology.region)
    stream = StringIO()
    reporter = TerminalReporter()
    reporter.console = Console(file=stream, force_terminal=False, width=120)

    reporter.print_summary(topology, report)

    output = stream.getvalue()
    assert "Flow Logs" in output
    assert "VPC Endpoints" in output
    assert "Elastic IPs" in output
    assert "Instance Exposure" in output
