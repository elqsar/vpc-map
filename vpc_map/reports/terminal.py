"""Terminal report generator using Rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from vpc_map.models import AuditReport, ChangeType, DiffReport, Severity, VpcTopology
from vpc_map.network.analysis import analyze_instances, analyze_subnets


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

    @staticmethod
    def _describe_eip_attachment(elastic_ip) -> str:
        """Describe the resource attached to an Elastic IP."""
        if elastic_ip.instance_id:
            return f"Instance {elastic_ip.instance_id}"
        if elastic_ip.network_interface_id:
            return f"ENI {elastic_ip.network_interface_id}"
        return "Unassociated"

    def print_topology(self, topology: VpcTopology) -> None:
        """
        Print VPC topology summary to terminal.

        Args:
            topology: VPC topology to display
        """
        subnet_analysis = {
            analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
        }
        instance_exposure = {
            exposure.instance_id: exposure for exposure in analyze_instances(topology)
        }

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
        summary_table.add_row("Flow Logs", str(len(topology.flow_logs)))
        summary_table.add_row("VPC Endpoints", str(len(topology.vpc_endpoints)))
        summary_table.add_row("Elastic IPs", str(len(topology.elastic_ips)))
        summary_table.add_row("Route Tables", str(len(topology.route_tables)))
        summary_table.add_row("Security Groups", str(len(topology.security_groups)))
        summary_table.add_row("Network ACLs", str(len(topology.network_acls)))
        summary_table.add_row("EC2 Instances", str(len(topology.ec2_instances)))
        summary_table.add_row("EBS Volumes", str(len(topology.ebs_volumes)))

        self.console.print(summary_table)

        # Subnets tree
        subnet_tree = Tree("[bold cyan]Subnets", guide_style="cyan")
        for subnet in topology.subnets:
            subnet_name = subnet.get_tag("Name") or subnet.subnet_id
            classification = subnet_analysis[subnet.subnet_id].classification.value
            subnet_node = subnet_tree.add(
                f"[yellow]{subnet_name}[/yellow] ({subnet.cidr_block}) - "
                f"{subnet.availability_zone} - {classification}"
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

        # Flow Logs
        if topology.flow_logs:
            flow_log_table = Table(title="Flow Logs", show_header=True)
            flow_log_table.add_column("ID", style="cyan")
            flow_log_table.add_column("Resource", style="yellow")
            flow_log_table.add_column("Traffic", style="magenta")
            flow_log_table.add_column("Destination", style="green")
            flow_log_table.add_column("Status", style="blue")

            for flow_log in topology.flow_logs:
                destination = flow_log.log_destination_type or flow_log.log_destination or "-"
                status = flow_log.flow_log_status or flow_log.deliver_logs_status or "-"
                flow_log_table.add_row(
                    flow_log.flow_log_id,
                    flow_log.resource_id,
                    flow_log.traffic_type,
                    destination,
                    status,
                )

            self.console.print(flow_log_table)

        # VPC Endpoints
        if topology.vpc_endpoints:
            endpoint_table = Table(title="VPC Endpoints", show_header=True)
            endpoint_table.add_column("ID", style="cyan")
            endpoint_table.add_column("Service", style="yellow")
            endpoint_table.add_column("Type", style="magenta")
            endpoint_table.add_column("State", style="green")
            endpoint_table.add_column("Private DNS", style="blue")
            endpoint_table.add_column("Attachments", style="cyan")

            for endpoint in topology.vpc_endpoints:
                attachments = []
                if endpoint.subnet_ids:
                    attachments.append(f"{len(endpoint.subnet_ids)} subnet(s)")
                if endpoint.route_table_ids:
                    attachments.append(f"{len(endpoint.route_table_ids)} route table(s)")
                if endpoint.security_group_ids:
                    attachments.append(f"{len(endpoint.security_group_ids)} SG(s)")

                endpoint_table.add_row(
                    endpoint.vpc_endpoint_id,
                    endpoint.service_name.split(".")[-1],
                    endpoint.endpoint_type,
                    endpoint.state,
                    "Yes" if endpoint.private_dns_enabled else "No",
                    ", ".join(attachments) if attachments else "-",
                )

            self.console.print(endpoint_table)

        # Elastic IPs
        if topology.elastic_ips:
            eip_table = Table(title="Elastic IPs", show_header=True)
            eip_table.add_column("Public IP", style="cyan")
            eip_table.add_column("Allocation ID", style="yellow")
            eip_table.add_column("Private IP", style="magenta")
            eip_table.add_column("Attached To", style="green")
            eip_table.add_column("Domain", style="blue")

            for elastic_ip in topology.elastic_ips:
                eip_table.add_row(
                    elastic_ip.public_ip,
                    elastic_ip.allocation_id or "-",
                    elastic_ip.private_ip_address or "-",
                    self._describe_eip_attachment(elastic_ip),
                    elastic_ip.domain or "-",
                )

            self.console.print(eip_table)

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

        # EC2 Instances
        if topology.ec2_instances:
            ec2_table = Table(title="EC2 Instances", show_header=True)
            ec2_table.add_column("Instance ID", style="cyan")
            ec2_table.add_column("Name", style="yellow")
            ec2_table.add_column("Type", style="blue")
            ec2_table.add_column("State", style="magenta")
            ec2_table.add_column("AZ", style="cyan")
            ec2_table.add_column("Private IP", style="green")
            ec2_table.add_column("Public IP", style="green")
            ec2_table.add_column("Security Groups", style="blue")
            ec2_table.add_column("Launched", style="yellow")

            for instance in topology.ec2_instances:
                instance_name = instance.get_tag("Name") or "-"

                # Format state with color
                state_style = "green" if instance.is_running else "red"
                state_display = f"[{state_style}]{instance.state}[/{state_style}]"

                # Format launch time
                launch_time_str = "-"
                if instance.launch_time:
                    launch_time_str = instance.launch_time.strftime("%Y-%m-%d")

                # Format security groups (show count and first name)
                sg_display = "-"
                if instance.security_group_names:
                    if len(instance.security_group_names) == 1:
                        sg_display = instance.security_group_names[0]
                    else:
                        sg_display = f"{instance.security_group_names[0]} (+{len(instance.security_group_names)-1})"

                ec2_table.add_row(
                    instance.instance_id,
                    instance_name,
                    instance.instance_type,
                    state_display,
                    instance.availability_zone,
                    instance.private_ip_address or "-",
                    instance.public_ip_address or "-",
                    sg_display,
                    launch_time_str,
                )

            self.console.print(ec2_table)

            exposure_table = Table(title="Instance Exposure", show_header=True)
            exposure_table.add_column("Instance ID", style="cyan")
            exposure_table.add_column("Subnet Type", style="yellow")
            exposure_table.add_column("Public Address", style="green")
            exposure_table.add_column("Exposure", style="magenta")
            exposure_table.add_column("Tracked Ports", style="blue")

            for instance in topology.ec2_instances:
                exposure = instance_exposure[instance.instance_id]
                exposure_table.add_row(
                    instance.instance_id,
                    exposure.subnet_classification.value,
                    exposure.public_address_source or "-",
                    exposure.exposure_state.value,
                    ", ".join(map(str, exposure.allowed_ports)) if exposure.allowed_ports else "-",
                )

            self.console.print(exposure_table)

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

    def print_diff_report(self, diff_report: DiffReport) -> None:
        """Print diff report to terminal."""
        # Header
        added = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.ADDED)
        removed = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.REMOVED)
        modified = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.MODIFIED)
        derived = len(diff_report.derived_changes)

        self.console.print(
            Panel.fit(
                f"[bold cyan]VPC:[/bold cyan] {diff_report.vpc_id}\n"
                f"[bold]Region:[/bold] {diff_report.region}\n"
                f"[bold]Before:[/bold] {diff_report.before_collected_at}\n"
                f"[bold]After:[/bold] {diff_report.after_collected_at}\n"
                f"[bold]Changes:[/bold] {added} added, {removed} removed, "
                f"{modified} modified, {derived} derived",
                title="Snapshot Diff",
                border_style="cyan",
            )
        )

        if not diff_report.resource_changes and not diff_report.derived_changes:
            self.console.print(
                Panel.fit(
                    "[bold green]No drift detected[/bold green]",
                    border_style="green",
                )
            )
            return

        # Summary table by resource type
        type_counts: dict[str, dict[str, int]] = {}
        for change in diff_report.resource_changes:
            counts = type_counts.setdefault(change.resource_type, {"added": 0, "removed": 0, "modified": 0})
            counts[change.change_type.value] += 1

        if type_counts:
            summary_table = Table(title="Changes by Resource Type", show_header=True)
            summary_table.add_column("Resource Type", style="cyan")
            summary_table.add_column("Added", justify="right", style="green")
            summary_table.add_column("Removed", justify="right", style="red")
            summary_table.add_column("Modified", justify="right", style="yellow")

            for rtype in sorted(type_counts):
                counts = type_counts[rtype]
                summary_table.add_row(
                    rtype,
                    str(counts["added"]) if counts["added"] else "-",
                    str(counts["removed"]) if counts["removed"] else "-",
                    str(counts["modified"]) if counts["modified"] else "-",
                )

            self.console.print(summary_table)

        # Detail sections grouped by resource type
        current_type = None
        for change in sorted(diff_report.resource_changes, key=lambda c: (c.resource_type, c.change_type.value)):
            if change.resource_type != current_type:
                current_type = change.resource_type
                self.console.print(f"\n[bold cyan]{current_type.upper()}[/bold cyan]")

            if change.change_type == ChangeType.ADDED:
                self.console.print(f"  [green]+ {change.resource_id}[/green]")
            elif change.change_type == ChangeType.REMOVED:
                self.console.print(f"  [red]- {change.resource_id}[/red]")
            elif change.change_type == ChangeType.MODIFIED:
                self.console.print(f"  [yellow]~ {change.resource_id}[/yellow]")
                if change.field_changes:
                    detail_table = Table(show_header=True, padding=(0, 1))
                    detail_table.add_column("Field", style="cyan")
                    detail_table.add_column("Old Value", style="red")
                    detail_table.add_column("New Value", style="green")
                    for fc in change.field_changes:
                        detail_table.add_row(
                            fc.field,
                            str(fc.old_value) if fc.old_value is not None else "-",
                            str(fc.new_value) if fc.new_value is not None else "-",
                        )
                    self.console.print(detail_table)

        # Derived analysis section
        if diff_report.derived_changes:
            self.console.print()
            derived_table = Table(title="Derived Analysis Changes", show_header=True)
            derived_table.add_column("Type", style="cyan")
            derived_table.add_column("Resource", style="yellow")
            derived_table.add_column("Field", style="magenta")
            derived_table.add_column("Old Value", style="red")
            derived_table.add_column("New Value", style="green")

            for dc in diff_report.derived_changes:
                derived_table.add_row(
                    dc.analysis_type,
                    dc.resource_id,
                    dc.field,
                    str(dc.old_value) if dc.old_value is not None else "-",
                    str(dc.new_value) if dc.new_value is not None else "-",
                )

            self.console.print(derived_table)

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
