"""CLI interface for VPC Map."""

from pathlib import Path

import click
from rich.console import Console

from vpc_map.audit.engine import AuditEngine
from vpc_map.aws.collector import VpcCollector
from vpc_map.reports.html import HTMLReporter
from vpc_map.reports.json import JSONReporter
from vpc_map.reports.terminal import TerminalReporter
from vpc_map.visualization.graphviz import VpcVisualizer

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """AWS VPC topology mapper and security auditor."""
    pass


@main.command()
@click.option(
    "--region",
    "-r",
    help="AWS region to use (defaults to configured region)",
    default=None,
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile to use (defaults to default profile)",
    default=None,
)
def list_vpcs(region, profile):
    """List all VPCs in the region."""
    try:
        collector = VpcCollector(region=region, profile=profile)
        vpcs = collector.list_vpcs()

        if not vpcs:
            console.print("[yellow]No VPCs found in the region.[/yellow]")
            return

        console.print(f"\n[bold cyan]VPCs in {collector.region}:[/bold cyan]\n")
        for vpc in vpcs:
            vpc_name = vpc.get_tag("Name") or "-"
            default = " [yellow](default)[/yellow]" if vpc.is_default else ""
            console.print(f"  • {vpc.vpc_id} - {vpc_name} - {vpc.cidr_block}{default}")

    except Exception as e:
        console.print(f"[red]Error listing VPCs: {str(e)}[/red]")
        raise click.Abort()


@main.command()
@click.argument("vpc_id")
@click.option(
    "--region",
    "-r",
    help="AWS region to use (defaults to configured region)",
    default=None,
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile to use (defaults to default profile)",
    default=None,
)
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for reports and diagrams",
    default="./vpc-map-output",
    type=click.Path(path_type=Path),
)
@click.option(
    "--format",
    "-f",
    help="Output format(s) for reports",
    type=click.Choice(["terminal", "json", "html", "all"], case_sensitive=False),
    default="terminal",
)
@click.option(
    "--diagram-format",
    help="Diagram format",
    type=click.Choice(["png", "svg"], case_sensitive=False),
    default="png",
)
@click.option(
    "--no-diagram",
    is_flag=True,
    help="Skip diagram generation",
)
@click.option(
    "--no-audit",
    is_flag=True,
    help="Skip security audit",
)
def analyze(vpc_id, region, profile, output_dir, format, diagram_format, no_diagram, no_audit):
    """Analyze a VPC and generate topology diagram and security audit report."""
    try:
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Collect VPC topology
        console.print(f"[cyan]Collecting VPC topology for {vpc_id}...[/cyan]")
        collector = VpcCollector(region=region, profile=profile)
        topology = collector.collect_vpc_topology(vpc_id)
        console.print("[green]✓[/green] Topology collected")

        # Generate diagram
        diagram_path = None
        if not no_diagram:
            console.print("[cyan]Generating topology diagram...[/cyan]")
            visualizer = VpcVisualizer(topology)
            diagram_path = visualizer.create_diagram(
                output_file=str(output_dir / "vpc_topology"),
                format=diagram_format,
            )
            console.print(f"[green]✓[/green] Diagram saved to {diagram_path}")

            # Generate security diagram
            security_diagram_path = visualizer.create_security_diagram(
                output_file=str(output_dir / "vpc_security"),
                format=diagram_format,
            )
            console.print(f"[green]✓[/green] Security diagram saved to {security_diagram_path}")

        # Run audit
        audit_report = None
        if not no_audit:
            console.print("[cyan]Running security audit...[/cyan]")
            audit_engine = AuditEngine(topology)
            audit_report = audit_engine.run_audit()
            console.print(f"[green]✓[/green] Audit completed ({audit_report.total_checks} checks)")

        # Generate reports
        if format == "terminal" or format == "all":
            console.print("\n")
            reporter = TerminalReporter()
            reporter.print_summary(topology, audit_report)

        if format == "json" or format == "all":
            console.print("[cyan]Generating JSON report...[/cyan]")
            json_reporter = JSONReporter()
            json_output = output_dir / "vpc_report.json"
            json_reporter.generate_combined_report(topology, audit_report, json_output)
            console.print(f"[green]✓[/green] JSON report saved to {json_output}")

        if format == "html" or format == "all":
            console.print("[cyan]Generating HTML report...[/cyan]")
            html_reporter = HTMLReporter()
            html_output = output_dir / "vpc_report.html"
            html_reporter.generate_report(topology, audit_report, html_output, diagram_path)
            console.print(f"[green]✓[/green] HTML report saved to {html_output}")

        console.print("\n[bold green]Analysis complete![/bold green]")
        console.print(f"Output directory: {output_dir.absolute()}")

    except ValueError as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
        import traceback

        traceback.print_exc()
        raise click.Abort()


@main.command()
@click.argument("vpc_id")
@click.option(
    "--region",
    "-r",
    help="AWS region to use (defaults to configured region)",
    default=None,
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile to use (defaults to default profile)",
    default=None,
)
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for diagrams",
    default="./vpc-map-output",
    type=click.Path(path_type=Path),
)
@click.option(
    "--format",
    "-f",
    help="Diagram format",
    type=click.Choice(["png", "svg"], case_sensitive=False),
    default="png",
)
def diagram_only(vpc_id, region, profile, output_dir, format):
    """Generate only the VPC topology diagram without audit."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        console.print(f"[cyan]Collecting VPC topology for {vpc_id}...[/cyan]")
        collector = VpcCollector(region=region, profile=profile)
        topology = collector.collect_vpc_topology(vpc_id)

        console.print("[cyan]Generating diagrams...[/cyan]")
        visualizer = VpcVisualizer(topology)

        # Topology diagram
        topology_path = visualizer.create_diagram(
            output_file=str(output_dir / "vpc_topology"),
            format=format,
        )
        console.print(f"[green]✓[/green] Topology diagram: {topology_path}")

        # Security diagram
        security_path = visualizer.create_security_diagram(
            output_file=str(output_dir / "vpc_security"),
            format=format,
        )
        console.print(f"[green]✓[/green] Security diagram: {security_path}")

        console.print("\n[bold green]Diagrams generated![/bold green]")

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()


@main.command()
@click.argument("vpc_id")
@click.option(
    "--region",
    "-r",
    help="AWS region to use (defaults to configured region)",
    default=None,
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile to use (defaults to default profile)",
    default=None,
)
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for audit report",
    default="./vpc-map-output",
    type=click.Path(path_type=Path),
)
@click.option(
    "--format",
    "-f",
    help="Output format for audit report",
    type=click.Choice(["terminal", "json", "html", "all"], case_sensitive=False),
    default="terminal",
)
def audit_only(vpc_id, region, profile, output_dir, format):
    """Run only the security audit without generating diagrams."""
    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        console.print(f"[cyan]Collecting VPC topology for {vpc_id}...[/cyan]")
        collector = VpcCollector(region=region, profile=profile)
        topology = collector.collect_vpc_topology(vpc_id)

        console.print("[cyan]Running security audit...[/cyan]")
        audit_engine = AuditEngine(topology)
        report = audit_engine.run_audit()

        if format == "terminal" or format == "all":
            console.print("\n")
            reporter = TerminalReporter()
            reporter.print_audit_report(report)

        if format == "json" or format == "all":
            json_reporter = JSONReporter()
            json_output = output_dir / "audit_report.json"
            json_reporter.generate_audit_report(report, json_output)
            console.print(f"\n[green]✓[/green] JSON report: {json_output}")

        if format == "html" or format == "all":
            html_reporter = HTMLReporter()
            html_output = output_dir / "audit_report.html"
            html_reporter.generate_report(topology, report, html_output)
            console.print(f"[green]✓[/green] HTML report: {html_output}")

        console.print("\n[bold green]Audit complete![/bold green]")

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()


if __name__ == "__main__":
    main()
