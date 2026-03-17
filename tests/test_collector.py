"""Tests for AWS collector parsing logic."""

from unittest.mock import MagicMock, patch

from vpc_map.aws.collector import VpcCollector
from vpc_map.models import Ec2Instance, NatGateway


def _make_collector(mock_ec2_client):
    """Create a collector with a mocked boto3 session."""
    session = MagicMock()
    session.client.return_value = mock_ec2_client
    session.region_name = "us-east-1"

    with patch("vpc_map.aws.collector.boto3.Session", return_value=session):
        return VpcCollector(region="us-east-1")


def test_get_flow_logs_parses_vpc_and_subnet_logs():
    """Test flow log parsing."""
    mock_ec2_client = MagicMock()
    mock_ec2_client.describe_flow_logs.return_value = {
        "FlowLogs": [
            {
                "FlowLogId": "fl-12345",
                "ResourceId": "vpc-12345",
                "ResourceType": "VPC",
                "TrafficType": "ALL",
                "LogDestinationType": "cloud-watch-logs",
                "LogDestination": "arn:aws:logs:us-east-1:123456789012:log-group:test",
                "DeliverLogsStatus": "SUCCESS",
                "FlowLogStatus": "ACTIVE",
            },
            {
                "FlowLogId": "fl-67890",
                "ResourceId": "subnet-12345",
                "ResourceType": "Subnet",
                "TrafficType": "REJECT",
                "LogDestinationType": "s3",
                "FlowLogStatus": "ACTIVE",
            },
        ]
    }
    collector = _make_collector(mock_ec2_client)

    flow_logs = collector.get_flow_logs("vpc-12345", ["subnet-12345"])

    assert len(flow_logs) == 2
    assert flow_logs[0].resource_type == "VPC"
    assert flow_logs[1].traffic_type == "REJECT"


def test_get_vpc_endpoints_parses_gateway_and_interface():
    """Test VPC endpoint parsing."""
    mock_ec2_client = MagicMock()
    mock_ec2_client.describe_vpc_endpoints.return_value = {
        "VpcEndpoints": [
            {
                "VpcEndpointId": "vpce-12345",
                "VpcId": "vpc-12345",
                "ServiceName": "com.amazonaws.us-east-1.s3",
                "VpcEndpointType": "Gateway",
                "State": "available",
                "RouteTableIds": ["rtb-12345"],
            },
            {
                "VpcEndpointId": "vpce-67890",
                "VpcId": "vpc-12345",
                "ServiceName": "com.amazonaws.us-east-1.ssm",
                "VpcEndpointType": "Interface",
                "State": "available",
                "PrivateDnsEnabled": True,
                "SubnetIds": ["subnet-12345"],
                "Groups": [{"GroupId": "sg-12345"}],
                "NetworkInterfaceIds": ["eni-12345"],
            },
        ]
    }
    collector = _make_collector(mock_ec2_client)

    endpoints = collector.get_vpc_endpoints("vpc-12345")

    assert len(endpoints) == 2
    assert endpoints[0].endpoint_type == "Gateway"
    assert endpoints[1].security_group_ids == ["sg-12345"]
    assert endpoints[1].private_dns_enabled is True


def test_get_elastic_ips_filters_to_vpc_resources_and_unassociated():
    """Test Elastic IP scoping for VPC resources plus unattached EIPs."""
    mock_ec2_client = MagicMock()
    mock_ec2_client.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-1",
                "PublicIp": "203.0.113.10",
                "Domain": "vpc",
            },
            {
                "AllocationId": "eipalloc-2",
                "AssociationId": "eipassoc-2",
                "PublicIp": "203.0.113.20",
                "InstanceId": "i-12345",
                "Domain": "vpc",
            },
            {
                "AllocationId": "eipalloc-3",
                "AssociationId": "eipassoc-3",
                "PublicIp": "203.0.113.30",
                "InstanceId": "i-outside",
                "Domain": "vpc",
            },
        ]
    }
    mock_ec2_client.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [{"NetworkInterfaceId": "eni-12345"}]
    }
    collector = _make_collector(mock_ec2_client)

    elastic_ips = collector.get_elastic_ips(
        "vpc-12345",
        nat_gateways=[
            NatGateway(
                nat_gateway_id="nat-12345",
                vpc_id="vpc-12345",
                subnet_id="subnet-12345",
                state="available",
                public_ip="198.51.100.1",
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
                ami_id="ami-12345",
            )
        ],
    )

    assert [elastic_ip.public_ip for elastic_ip in elastic_ips] == [
        "203.0.113.10",
        "203.0.113.20",
    ]
