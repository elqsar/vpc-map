"""Tests for diff report generators."""

import json
from datetime import datetime
from io import StringIO

from rich.console import Console

from vpc_map.models import (
    ChangeType,
    DerivedChange,
    DiffReport,
    FieldChange,
    ResourceChange,
)
from vpc_map.reports.html import HTMLReporter
from vpc_map.reports.json import JSONReporter
from vpc_map.reports.terminal import TerminalReporter


def _create_diff_report() -> DiffReport:
    """Create a sample diff report for testing."""
    return DiffReport(
        vpc_id="vpc-test",
        region="us-east-1",
        before_collected_at=datetime(2026, 1, 1, 12, 0, 0),
        after_collected_at=datetime(2026, 1, 2, 12, 0, 0),
        resource_changes=[
            ResourceChange(
                resource_type="subnet",
                resource_id="subnet-new",
                change_type=ChangeType.ADDED,
            ),
            ResourceChange(
                resource_type="subnet",
                resource_id="subnet-old",
                change_type=ChangeType.REMOVED,
            ),
            ResourceChange(
                resource_type="security_group",
                resource_id="sg-1",
                change_type=ChangeType.MODIFIED,
                field_changes=[
                    FieldChange(
                        field="ingress_rules",
                        old_value=[{"ip_protocol": "tcp", "from_port": 443, "to_port": 443}],
                        new_value=[
                            {"ip_protocol": "tcp", "from_port": 443, "to_port": 443},
                            {"ip_protocol": "tcp", "from_port": 22, "to_port": 22},
                        ],
                    ),
                ],
            ),
        ],
        derived_changes=[
            DerivedChange(
                analysis_type="subnet_classification",
                resource_id="subnet-1",
                field="classification",
                old_value="public",
                new_value="private_with_nat",
            ),
        ],
    )


def _create_empty_diff_report() -> DiffReport:
    """Create an empty diff report (no changes)."""
    return DiffReport(
        vpc_id="vpc-test",
        region="us-east-1",
        before_collected_at=datetime(2026, 1, 1, 12, 0, 0),
        after_collected_at=datetime(2026, 1, 2, 12, 0, 0),
    )


def test_json_diff_report_structure(tmp_path):
    """JSON diff report has correct structure."""
    report = _create_diff_report()
    output = tmp_path / "diff.json"
    JSONReporter().generate_diff_report(report, output)

    content = json.loads(output.read_text())
    assert "diff" in content
    assert "summary" in content
    summary = content["summary"]
    assert summary["vpc_id"] == "vpc-test"
    assert summary["resources_added"] == 1
    assert summary["resources_removed"] == 1
    assert summary["resources_modified"] == 1
    assert summary["derived_changes"] == 1
    assert "subnet" in summary["changes_by_resource_type"]
    assert "security_group" in summary["changes_by_resource_type"]


def test_json_diff_report_empty(tmp_path):
    """JSON diff report with no changes."""
    report = _create_empty_diff_report()
    output = tmp_path / "diff.json"
    JSONReporter().generate_diff_report(report, output)

    content = json.loads(output.read_text())
    assert content["summary"]["resources_added"] == 0
    assert content["summary"]["resources_removed"] == 0
    assert content["summary"]["resources_modified"] == 0


def test_terminal_diff_report_shows_changes():
    """Terminal output includes key sections for changes."""
    report = _create_diff_report()
    stream = StringIO()
    reporter = TerminalReporter()
    reporter.console = Console(file=stream, force_terminal=False, width=120)
    reporter.print_diff_report(report)

    output = stream.getvalue()
    assert "Snapshot Diff" in output
    assert "subnet-new" in output
    assert "subnet-old" in output
    assert "sg-1" in output
    assert "Derived Analysis Changes" in output
    assert "subnet_classification" in output


def test_terminal_diff_report_no_drift():
    """Terminal output shows 'No drift detected' when empty."""
    report = _create_empty_diff_report()
    stream = StringIO()
    reporter = TerminalReporter()
    reporter.console = Console(file=stream, force_terminal=False, width=120)
    reporter.print_diff_report(report)

    output = stream.getvalue()
    assert "No drift detected" in output


def test_html_diff_report_sections(tmp_path):
    """HTML diff report includes key sections."""
    report = _create_diff_report()
    output = tmp_path / "diff.html"
    HTMLReporter().generate_diff_report(report, output)

    content = output.read_text()
    assert "VPC Snapshot Diff Report" in content
    assert "vpc-test" in content
    assert "subnet-new" in content
    assert "subnet-old" in content
    assert "sg-1" in content
    assert "Derived Analysis Changes" in content
    assert "subnet_classification" in content


def test_html_diff_report_no_drift(tmp_path):
    """HTML diff report shows no drift message."""
    report = _create_empty_diff_report()
    output = tmp_path / "diff.html"
    HTMLReporter().generate_diff_report(report, output)

    content = output.read_text()
    assert "No drift detected" in content
