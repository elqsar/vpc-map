"""Terminal report generator using Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from vpc_map.models import AuditReport, Severity, VpcTopology


class TerminalReporter:
    """Generate formatted terminal reports using Rich."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "cyan",
    }

    SEVERITY_EMOJI = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "ℹ️ ",
    }

    def __init__(self):
        """Initialize the terminal reporter."""
        self.console = Console()

    def print_topology(self, topology: VpcTopology) -> None:
        """
        Print VPC topology summary to terminal.

        Args:
            topology: VPC topology to display
        """
        # VPC header
        vpc_name = topology.vpc.get_tag("Name") or topology.vpc.vpc_id
        self.console.print(
            Panel.fit(
                f"[bold cyan]VPC:[/bold cyan] {vpc_name}\n"
                f"[bold]ID:[/bold] {topology.vpc.vpc_id}\n"
                f"[bold]CIDR:[/bold] {topology.vpc.cidr_block}\n"
                f"[bold]Region:[/bold] {topology.region}\n"
                f"[bold]DNS Support:[/bold] {'✓' if topology.vpc.enable_dns_support else '✗'}\n"
                f"[bold]DNS Hostnames:[/bold] {'✓' if topology.vpc.enable_dns_hostnames else '✗'}",
                title="VPC Information",
                border_style="cyan",
            )
        )

        # Resource summary table
        summary_table = Table(title="Resource Summary", show_header=True)
        summary_table.add_column("Resource Type", style="cyan")
        summary_table.add_column("Count", justify="right", style="green")

        summary_table.add_row("Subnets", str(len(topology.subnets)))
        summary_table.add_row("Internet Gateways", str(len(topology.internet_gateways)))
        summary_table.add_row("NAT Gateways", str(len(topology.nat_gateways)))
        summary_table.add_row("Route Tables", str(len(topology.route_tables)))
        summary_table.add_row("Security Groups", str(len(topology.security_groups)))
        summary_table.add_row("Network ACLs", str(len(topology.network_acls)))
        summary_table.add_row("EBS Volumes", str(len(topology.ebs_volumes)))

        self.console.print(summary_table)

        # Subnets tree
        subnet_tree = Tree("[bold cyan]Subnets", guide_style="cyan")
        for subnet in topology.subnets:
            subnet_name = subnet.get_tag("Name") or subnet.subnet_id
            subnet_node = subnet_tree.add(
                f"[yellow]{subnet_name}[/yellow] ({subnet.cidr_block}) - {subnet.availability_zone}"
            )
            subnet_node.add(f"Available IPs: {subnet.available_ip_address_count}")
            subnet_node.add(
                f"Auto-assign Public IP: {'Yes' if subnet.map_public_ip_on_launch else 'No'}"
            )

        self.console.print(subnet_tree)

        # Internet Gateways
        if topology.internet_gateways:
            igw_table = Table(title="Internet Gateways", show_header=True)
            igw_table.add_column("ID", style="cyan")
            igw_table.add_column("Name", style="yellow")
            igw_table.add_column("State", style="green")

            for igw in topology.internet_gateways:
                igw_name = igw.get_tag("Name") or "-"
                igw_table.add_row(igw.igw_id, igw_name, igw.state)

            self.console.print(igw_table)

        # NAT Gateways
        if topology.nat_gateways:
            nat_table = Table(title="NAT Gateways", show_header=True)
            nat_table.add_column("ID", style="cyan")
            nat_table.add_column("Name", style="yellow")
            nat_table.add_column("Subnet", style="magenta")
            nat_table.add_column("Public IP", style="green")
            nat_table.add_column("State", style="blue")

            for nat in topology.nat_gateways:
                nat_name = nat.get_tag("Name") or "-"
                nat_table.add_row(
                    nat.nat_gateway_id,
                    nat_name,
                    nat.subnet_id,
                    nat.public_ip or "-",
                    nat.state,
                )

            self.console.print(nat_table)

        # Security Groups summary
        sg_table = Table(title="Security Groups", show_header=True)
        sg_table.add_column("Name", style="cyan")
        sg_table.add_column("ID", style="yellow")
        sg_table.add_column("Ingress Rules", justify="right", style="green")
        sg_table.add_column("Egress Rules", justify="right", style="blue")
        sg_table.add_column("In Use", justify="center", style="magenta")
        sg_table.add_column("Attached ENIs", justify="right", style="blue")

        for sg in topology.security_groups:
            in_use_indicator = "✓" if sg.is_in_use else "✗"
            in_use_style = "green" if sg.is_in_use else "red"
            sg_table.add_row(
                sg.group_name,
                sg.group_id,
                str(len(sg.ingress_rules)),
                str(len(sg.egress_rules)),
                f"[{in_use_style}]{in_use_indicator}[/{in_use_style}]",
                str(len(sg.attached_enis)),
            )

        self.console.print(sg_table)

        # EBS Volumes
        if topology.ebs_volumes:
            ebs_table = Table(title="EBS Volumes", show_header=True)
            ebs_table.add_column("Volume ID", style="cyan")
            ebs_table.add_column("Name", style="yellow")
            ebs_table.add_column("Size (GiB)", justify="right", style="green")
            ebs_table.add_column("Type", style="blue")
            ebs_table.add_column("State", style="magenta")
            ebs_table.add_column("Encrypted", justify="center", style="cyan")
            ebs_table.add_column("Attached To", style="green")

            for vol in topology.ebs_volumes:
                vol_name = vol.get_tag("Name") or "-"
                encrypted_indicator = "✓" if vol.encrypted else "✗"
                encrypted_style = "green" if vol.encrypted else "red"

                # Get instance IDs this volume is attached to
                instance_ids = ", ".join(vol.instance_ids) if vol.instance_ids else "-"

                ebs_table.add_row(
                    vol.volume_id,
                    vol_name,
                    str(vol.size),
                    vol.volume_type,
                    vol.state,
                    f"[{encrypted_style}]{encrypted_indicator}[/{encrypted_style}]",
                    instance_ids,
                )

            self.console.print(ebs_table)

    def print_audit_report(self, report: AuditReport) -> None:
        """
        Print audit report to terminal.

        Args:
            report: Audit report to display
        """
        # Summary panel
        total_issues = report.failed_checks + report.warnings
        status_color = "green" if total_issues == 0 else "yellow" if total_issues < 5 else "red"

        summary_text = (
            f"[bold]Total Checks:[/bold] {report.total_checks}\n"
            f"[bold green]Passed:[/bold green] {report.passed_checks}\n"
            f"[bold red]Failed:[/bold red] {report.failed_checks}\n"
            f"[bold yellow]Warnings:[/bold yellow] {report.warnings}"
        )

        self.console.print(
            Panel.fit(
                summary_text,
                title=f"[{status_color}]Audit Summary - {report.vpc_id}[/{status_color}]",
                border_style=status_color,
            )
        )

        # Severity breakdown
        severity_table = Table(title="Findings by Severity", show_header=True)
        severity_table.add_column("Severity", style="bold")
        severity_table.add_column("Count", justify="right")

        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            count = len(report.get_findings_by_severity(severity))
            if count > 0:
                emoji = self.SEVERITY_EMOJI.get(severity, "")
                color = self.SEVERITY_COLORS.get(severity, "white")
                severity_table.add_row(
                    f"[{color}]{emoji} {severity.value.upper()}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                )

        self.console.print(severity_table)

        # Detailed findings
        if report.findings:
            self.console.print("\n[bold cyan]Detailed Findings:[/bold cyan]\n")

            # Group by severity
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                findings = report.get_findings_by_severity(severity)
                if not findings:
                    continue

                color = self.SEVERITY_COLORS.get(severity, "white")
                emoji = self.SEVERITY_EMOJI.get(severity, "")

                for finding in findings:
                    finding_panel = Panel(
                        f"[bold]Resource:[/bold] {finding.resource_type} - {finding.resource_id}\n"
                        f"[bold]Category:[/bold] {finding.category.value}\n"
                        f"[bold]Framework:[/bold] {finding.framework} ({finding.rule_id})\n\n"
                        f"{finding.description}\n\n"
                        f"[bold cyan]Recommendation:[/bold cyan]\n{finding.recommendation}",
                        title=f"[{color}]{emoji} {finding.title}[/{color}]",
                        border_style=color,
                        expand=False,
                    )
                    self.console.print(finding_panel)

        else:
            self.console.print("[bold green]No issues found! 🎉[/bold green]")

    def print_summary(self, topology: VpcTopology, report: AuditReport) -> None:
        """
        Print combined summary of topology and audit.

        Args:
            topology: VPC topology
            report: Audit report
        """
        self.console.rule("[bold cyan]VPC Analysis Report", style="cyan")
        self.console.print()
        self.print_topology(topology)
        self.console.print()
        self.console.rule("[bold yellow]Security Audit", style="yellow")
        self.console.print()
        self.print_audit_report(report)
        self.console.print()
        self.console.rule(style="cyan")
