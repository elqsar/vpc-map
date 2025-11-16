"""JSON report generator."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from vpc_map.models import AuditReport, VpcTopology


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
            "summary": {
                "vpc_id": topology.vpc.vpc_id,
                "region": topology.region,
                "resource_counts": {
                    "subnets": len(topology.subnets),
                    "internet_gateways": len(topology.internet_gateways),
                    "nat_gateways": len(topology.nat_gateways),
                    "route_tables": len(topology.route_tables),
                    "security_groups": len(topology.security_groups),
                    "security_groups_in_use": len(
                        [sg for sg in topology.security_groups if sg.is_in_use]
                    ),
                    "security_groups_unused": len(
                        [sg for sg in topology.security_groups if not sg.is_in_use]
                    ),
                    "network_acls": len(topology.network_acls),
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
