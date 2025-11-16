"""Audit engine orchestration."""

from vpc_map.models import AuditReport, VpcTopology

from .aws_waf import AWSWellArchitectedAuditor
from .cis import CISBenchmarkAuditor
from .custom import CustomSecurityAuditor


class AuditEngine:
    """Orchestrates security and best practice audits."""

    def __init__(self, topology: VpcTopology):
        """
        Initialize the audit engine.

        Args:
            topology: VPC topology to audit
        """
        self.topology = topology
        self.auditors = [
            AWSWellArchitectedAuditor(topology),
            CISBenchmarkAuditor(topology),
            CustomSecurityAuditor(topology),
        ]

    def run_audit(self) -> AuditReport:
        """
        Run all audits and generate a comprehensive report.

        Returns:
            Complete audit report with findings from all auditors
        """
        report = AuditReport(
            vpc_id=self.topology.vpc.vpc_id,
            region=self.topology.region,
        )

        # Run each auditor
        for auditor in self.auditors:
            findings = auditor.audit()
            for finding in findings:
                report.add_finding(finding)

        return report
