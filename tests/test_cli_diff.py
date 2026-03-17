"""Tests for CLI diff and baseline commands."""

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vpc_map.cli import main
from vpc_map.models import (
    Route,
    RouteTable,
    Subnet,
    Vpc,
    VpcTopology,
)


def _make_topology_dict(**overrides) -> dict:
    """Create a topology dict suitable for JSON serialization."""
    topology = VpcTopology(
        vpc=Vpc(
            vpc_id=overrides.get("vpc_id", "vpc-cli-test"),
            cidr_block="10.0.0.0/16",
            state="available",
        ),
        subnets=overrides.get(
            "subnets",
            [
                Subnet(
                    subnet_id="subnet-1",
                    vpc_id="vpc-cli-test",
                    cidr_block="10.0.1.0/24",
                    availability_zone="us-east-1a",
                    available_ip_address_count=250,
                    state="available",
                ),
            ],
        ),
        route_tables=overrides.get(
            "route_tables",
            [
                RouteTable(
                    route_table_id="rtb-1",
                    vpc_id="vpc-cli-test",
                    subnet_associations=["subnet-1"],
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
        ),
        region="us-east-1",
    )
    return topology.model_dump(mode="json")


def test_diff_identical_files(tmp_path):
    """diff command with identical files -> 'no drift' output."""
    data = _make_topology_dict()
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    before_file.write_text(json.dumps(data))
    after_file.write_text(json.dumps(data))

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(before_file), str(after_file)])
    assert result.exit_code == 0
    assert "No drift detected" in result.output


def test_diff_with_changes(tmp_path):
    """diff command with changes -> change summary."""
    before_data = _make_topology_dict()
    after_data = _make_topology_dict()
    # Add a subnet to after
    after_data["subnets"].append(
        {
            "subnet_id": "subnet-2",
            "vpc_id": "vpc-cli-test",
            "cidr_block": "10.0.2.0/24",
            "availability_zone": "us-east-1b",
            "available_ip_address_count": 250,
            "map_public_ip_on_launch": False,
            "state": "available",
            "tags": [],
        }
    )

    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    before_file.write_text(json.dumps(before_data))
    after_file.write_text(json.dumps(after_data))

    runner = CliRunner()
    result = runner.invoke(main, ["diff", str(before_file), str(after_file)])
    assert result.exit_code == 0
    assert "subnet-2" in result.output


def test_diff_json_output(tmp_path):
    """diff command with --format json produces output file."""
    data = _make_topology_dict()
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    before_file.write_text(json.dumps(data))
    after_file.write_text(json.dumps(data))

    output_dir = tmp_path / "output"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["diff", str(before_file), str(after_file), "-f", "json", "-o", str(output_dir)],
    )
    assert result.exit_code == 0
    assert (output_dir / "vpc_diff.json").exists()


def test_diff_html_output(tmp_path):
    """diff command with --format html produces output file."""
    data = _make_topology_dict()
    before_file = tmp_path / "before.json"
    after_file = tmp_path / "after.json"
    before_file.write_text(json.dumps(data))
    after_file.write_text(json.dumps(data))

    output_dir = tmp_path / "output"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["diff", str(before_file), str(after_file), "-f", "html", "-o", str(output_dir)],
    )
    assert result.exit_code == 0
    assert (output_dir / "vpc_diff.html").exists()


def test_baseline_create_with_mocked_collector(tmp_path):
    """baseline create with mocked collector -> file written."""
    topology = VpcTopology(
        vpc=Vpc(
            vpc_id="vpc-baseline",
            cidr_block="10.0.0.0/16",
            state="available",
        ),
        region="us-east-1",
    )

    mock_collector = MagicMock()
    mock_collector.collect_vpc_topology.return_value = topology

    output_file = tmp_path / "baseline.json"

    with patch("vpc_map.cli.VpcCollector", return_value=mock_collector):
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["baseline", "create", "vpc-baseline", "-o", str(output_file)],
        )

    assert result.exit_code == 0
    assert output_file.exists()
    content = json.loads(output_file.read_text())
    assert content["vpc"]["vpc_id"] == "vpc-baseline"
