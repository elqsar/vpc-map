"""CLI interface for VPC Map."""

from pathlib import Path

import click
from rich.console import Console

from vpc_map.audit.engine import AuditEngine
from vpc_map.aws.collector import VpcCollector
from vpc_map.diff import diff_topologies, load_topology_from_file
from vpc_map.reports.html import HTMLReporter
from vpc_map.reports.json import JSONReporter
from vpc_map.reports.terminal import TerminalReporter
from vpc_map.visualization.ascii import AsciiVisualizer
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
    type=click.Choice(["png", "svg", "ascii"], case_sensitive=False),
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
            if diagram_format == "ascii":
                console.print("[cyan]Generating ASCII routing diagram...[/cyan]")
                ascii_visualizer = AsciiVisualizer(topology)

                # Full routing diagram
                routing_path = str(output_dir / "vpc_routing.txt")
                ascii_visualizer.save_routing_diagram(routing_path, compact=False)
                console.print(f"[green]✓[/green] ASCII routing diagram saved to {routing_path}")

                # Compact routing diagram
                compact_path = str(output_dir / "vpc_routing_compact.txt")
                ascii_visualizer.save_routing_diagram(compact_path, compact=True)
                console.print(f"[green]✓[/green] Compact ASCII diagram saved to {compact_path}")

                diagram_path = routing_path
            else:
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
    type=click.Choice(["png", "svg", "ascii"], case_sensitive=False),
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

        if format == "ascii":
            ascii_visualizer = AsciiVisualizer(topology)

            # Full routing diagram
            routing_path = str(output_dir / "vpc_routing.txt")
            ascii_visualizer.save_routing_diagram(routing_path, compact=False)
            console.print(f"[green]✓[/green] ASCII routing diagram: {routing_path}")

            # Compact routing diagram
            compact_path = str(output_dir / "vpc_routing_compact.txt")
            ascii_visualizer.save_routing_diagram(compact_path, compact=True)
            console.print(f"[green]✓[/green] Compact ASCII diagram: {compact_path}")
        else:
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


@main.command()
@click.argument("before_file", type=click.Path(exists=True, path_type=Path))
@click.argument("after_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "-f",
    "fmt",
    help="Output format for diff report",
    type=click.Choice(["terminal", "json", "html", "all"], case_sensitive=False),
    default="terminal",
)
@click.option(
    "--output-dir",
    "-o",
    help="Output directory for reports",
    default="./vpc-map-output",
    type=click.Path(path_type=Path),
)
def diff(before_file, after_file, fmt, output_dir):
    """Compare two VPC topology snapshots and report changes."""
    try:
        console.print("[cyan]Loading snapshots...[/cyan]")
        before = load_topology_from_file(before_file)
        after = load_topology_from_file(after_file)

        if before.vpc.vpc_id != after.vpc.vpc_id:
            console.print(
                f"[yellow]Warning: VPC IDs differ ({before.vpc.vpc_id} vs {after.vpc.vpc_id})[/yellow]"
            )

        console.print("[cyan]Computing diff...[/cyan]")
        diff_report = diff_topologies(before, after)

        if fmt == "terminal" or fmt == "all":
            console.print()
            reporter = TerminalReporter()
            reporter.print_diff_report(diff_report)

        if fmt == "json" or fmt == "all":
            output_dir.mkdir(parents=True, exist_ok=True)
            json_output = output_dir / "vpc_diff.json"
            JSONReporter().generate_diff_report(diff_report, json_output)
            console.print(f"[green]✓[/green] JSON diff report saved to {json_output}")

        if fmt == "html" or fmt == "all":
            output_dir.mkdir(parents=True, exist_ok=True)
            html_output = output_dir / "vpc_diff.html"
            HTMLReporter().generate_diff_report(diff_report, html_output)
            console.print(f"[green]✓[/green] HTML diff report saved to {html_output}")

        console.print("\n[bold green]Diff complete![/bold green]")

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()


@main.group()
def baseline():
    """Manage VPC topology baselines."""
    pass


@baseline.command("create")
@click.argument("vpc_id")
@click.option(
    "--region",
    "-r",
    help="AWS region to use",
    default=None,
)
@click.option(
    "--profile",
    "-p",
    help="AWS profile to use",
    default=None,
)
@click.option(
    "--output-file",
    "-o",
    help="Output file path for baseline",
    default=None,
    type=click.Path(path_type=Path),
)
def baseline_create(vpc_id, region, profile, output_file):
    """Create a baseline snapshot of a VPC topology."""
    try:
        console.print(f"[cyan]Collecting VPC topology for {vpc_id}...[/cyan]")
        collector = VpcCollector(region=region, profile=profile)
        topology = collector.collect_vpc_topology(vpc_id)
        console.print("[green]✓[/green] Topology collected")

        if output_file is None:
            output_file = Path(f"vpc-map-baseline-{vpc_id}.json")

        output_file.parent.mkdir(parents=True, exist_ok=True)
        JSONReporter().generate_topology_report(topology, output_file)
        console.print(f"[green]✓[/green] Baseline saved to {output_file}")

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()


if __name__ == "__main__":
    main()
