"""Tests for the snapshot loader."""

import json

import pytest

from vpc_map.diff.loader import load_topology_from_file
from vpc_map.models import (
    Route,
    RouteTable,
    Subnet,
    Vpc,
    VpcTopology,
)


def _make_topology() -> VpcTopology:
    return VpcTopology(
        vpc=Vpc(
            vpc_id="vpc-loader",
            cidr_block="10.0.0.0/16",
            state="available",
        ),
        subnets=[
            Subnet(
                subnet_id="subnet-1",
                vpc_id="vpc-loader",
                cidr_block="10.0.1.0/24",
                availability_zone="us-east-1a",
                available_ip_address_count=250,
                state="available",
            ),
        ],
        route_tables=[
            RouteTable(
                route_table_id="rtb-1",
                vpc_id="vpc-loader",
                routes=[
                    Route(
                        destination_cidr_block="10.0.0.0/16",
                        gateway_id="local",
                        state="active",
                        origin="CreateRouteTable",
                    ),
                ],
            ),
        ],
        region="us-east-1",
    )


def test_load_from_standalone_report(tmp_path):
    """Loads topology-only JSON."""
    topology = _make_topology()
    path = tmp_path / "standalone.json"
    data = topology.model_dump(mode="json")
    path.write_text(json.dumps(data))

    loaded = load_topology_from_file(path)
    assert loaded.vpc.vpc_id == "vpc-loader"
    assert len(loaded.subnets) == 1
    assert loaded.region == "us-east-1"


def test_load_from_combined_report(tmp_path):
    """Extracts topology from combined JSON."""
    topology = _make_topology()
    combined = {
        "topology": topology.model_dump(mode="json"),
        "audit": {"findings": []},
        "summary": {},
    }
    path = tmp_path / "combined.json"
    path.write_text(json.dumps(combined))

    loaded = load_topology_from_file(path)
    assert loaded.vpc.vpc_id == "vpc-loader"
    assert len(loaded.subnets) == 1


def test_load_invalid_json_raises(tmp_path):
    """Error handling on bad input."""
    path = tmp_path / "bad.json"
    path.write_text("not json")

    with pytest.raises(json.JSONDecodeError):
        load_topology_from_file(path)


def test_load_invalid_topology_raises(tmp_path):
    """Error handling on valid JSON but invalid topology."""
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"foo": "bar"}))

    with pytest.raises(Exception):
        load_topology_from_file(path)
