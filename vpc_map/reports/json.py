"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from vpc_map.models import AuditReport, ChangeType, DiffReport, VpcTopology
from vpc_map.network.analysis import build_network_analysis


class JSONReporter:
    """Generate JSON format reports."""

    @staticmethod
    def _serialize_datetime(obj: Any) -> Any:
        """Serialize datetime objects to ISO format."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def generate_topology_report(self, topology: VpcTopology, output_file: Path) -> None:
        """
        Generate JSON topology report.

        Args:
            topology: VPC topology to export
            output_file: Output file path
        """
        # Convert to dict using Pydantic's model_dump
        topology_dict = topology.model_dump()

        with open(output_file, "w") as f:
            json.dump(topology_dict, f, indent=2, default=self._serialize_datetime)

    def generate_audit_report(self, report: AuditReport, output_file: Path) -> None:
        """
        Generate JSON audit report.

        Args:
            report: Audit report to export
            output_file: Output file path
        """
        # Convert to dict using Pydantic's model_dump
        report_dict = report.model_dump()

        with open(output_file, "w") as f:
            json.dump(report_dict, f, indent=2, default=self._serialize_datetime)

    def generate_combined_report(
        self, topology: VpcTopology, report: AuditReport, output_file: Path
    ) -> None:
        """
        Generate combined JSON report with topology and audit data.

        Args:
            topology: VPC topology
            report: Audit report
            output_file: Output file path
        """
        combined = {
            "topology": topology.model_dump(),
            "audit": report.model_dump(),
            "network_analysis": build_network_analysis(topology),
            "summary": {
                "vpc_id": topology.vpc.vpc_id,
                "region": topology.region,
                "resource_counts": {
                    "subnets": len(topology.subnets),
                    "internet_gateways": len(topology.internet_gateways),
                    "nat_gateways": len(topology.nat_gateways),
                    "flow_logs": len(topology.flow_logs),
                    "vpc_endpoints": len(topology.vpc_endpoints),
                    "elastic_ips": len(topology.elastic_ips),
                    "elastic_ips_unassociated": len(
                        [elastic_ip for elastic_ip in topology.elastic_ips if not elastic_ip.is_associated]
                    ),
                    "route_tables": len(topology.route_tables),
                    "security_groups": len(topology.security_groups),
                    "security_groups_in_use": len(
                        [sg for sg in topology.security_groups if sg.is_in_use]
                    ),
                    "security_groups_unused": len(
                        [sg for sg in topology.security_groups if not sg.is_in_use]
                    ),
                    "network_acls": len(topology.network_acls),
                    "ec2_instances": len(topology.ec2_instances),
                    "ec2_instances_running": len(
                        [i for i in topology.ec2_instances if i.is_running]
                    ),
                    "ec2_instances_stopped": len(
                        [i for i in topology.ec2_instances if i.state == "stopped"]
                    ),
                    "ec2_instances_with_public_ip": len(
                        [i for i in topology.ec2_instances if i.has_public_ip]
                    ),
                    "ec2_spot_instances": len(
                        [i for i in topology.ec2_instances if i.is_spot]
                    ),
                    "ebs_volumes": len(topology.ebs_volumes),
                    "ebs_volumes_encrypted": len(
                        [vol for vol in topology.ebs_volumes if vol.encrypted]
                    ),
                    "ebs_volumes_unencrypted": len(
                        [vol for vol in topology.ebs_volumes if not vol.encrypted]
                    ),
                    "ebs_total_size_gib": sum(vol.size for vol in topology.ebs_volumes),
                },
                "audit_summary": {
                    "total_checks": report.total_checks,
                    "passed": report.passed_checks,
                    "failed": report.failed_checks,
                    "warnings": report.warnings,
                },
                "findings_by_severity": {
                    "critical": len([f for f in report.findings if f.severity == "critical"]),
                    "high": len([f for f in report.findings if f.severity == "high"]),
                    "medium": len([f for f in report.findings if f.severity == "medium"]),
                    "low": len([f for f in report.findings if f.severity == "low"]),
                    "info": len([f for f in report.findings if f.severity == "info"]),
                },
                "findings_by_category": {
                    "security": len([f for f in report.findings if f.category == "security"]),
                    "cost": len([f for f in report.findings if f.category == "cost"]),
                    "reliability": len([f for f in report.findings if f.category == "reliability"]),
                    "performance": len([f for f in report.findings if f.category == "performance"]),
                    "operations": len([f for f in report.findings if f.category == "operations"]),
                },
            },
        }

        with open(output_file, "w") as f:
            json.dump(combined, f, indent=2, default=self._serialize_datetime)

    def generate_diff_report(self, diff_report: DiffReport, output_file: Path) -> None:
        """Generate JSON diff report."""
        # Build summary counts
        changes_by_type: dict[str, dict[str, int]] = {}
        for change in diff_report.resource_changes:
            counts = changes_by_type.setdefault(
                change.resource_type, {"added": 0, "removed": 0, "modified": 0}
            )
            counts[change.change_type.value] += 1

        added = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.ADDED)
        removed = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.REMOVED)
        modified = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.MODIFIED)

        output = {
            "diff": diff_report.model_dump(mode="json"),
            "summary": {
                "vpc_id": diff_report.vpc_id,
                "before_collected_at": diff_report.before_collected_at.isoformat(),
                "after_collected_at": diff_report.after_collected_at.isoformat(),
                "resources_added": added,
                "resources_removed": removed,
                "resources_modified": modified,
                "derived_changes": len(diff_report.derived_changes),
                "changes_by_resource_type": changes_by_type,
            },
        }

        with open(output_file, "w") as f:
            json.dump(output, f, indent=2, default=self._serialize_datetime)
