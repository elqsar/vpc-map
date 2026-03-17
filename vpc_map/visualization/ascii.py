"""ASCII art network diagrams showing VPC routing topology."""

from typing import Dict, List

from vpc_map.models import VpcTopology
from vpc_map.network.analysis import (
    analyze_subnets,
    format_route_target,
    get_route_destination,
    get_route_table_for_subnet,
    get_route_target_kind,
)


class AsciiVisualizer:
    """Creates ASCII art network diagrams showing routing paths."""

    def __init__(self, topology: VpcTopology):
        """
        Initialize the ASCII visualizer.

        Args:
            topology: VPC topology to visualize
        """
        self.topology = topology
        self.subnet_analysis = {
            analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
        }

    def _get_subnet_type(self, subnet_id: str) -> str:
        """Get the shared subnet classification label."""
        return self.subnet_analysis[subnet_id].classification.value.upper()

    def _get_route_table_for_subnet(self, subnet_id: str) -> str:
        """Get the route table ID associated with a subnet."""
        route_table = get_route_table_for_subnet(self.topology, subnet_id)
        return route_table.route_table_id if route_table else "N/A"

    def _format_box(self, content: str, width: int = 70, title: str = "") -> str:
        """Create a box around content with optional title."""
        lines = content.split("\n")
        result = []

        # Top border
        if title:
            title_text = f" {title} "
            padding = (width - len(title_text) - 2) // 2
            result.append(f"┌{'─' * padding}{title_text}{'─' * (width - padding - len(title_text) - 2)}┐")
        else:
            result.append(f"┌{'─' * (width - 2)}┐")

        # Content
        for line in lines:
            padding = width - len(line) - 4
            result.append(f"│ {line}{' ' * padding} │")

        # Bottom border
        result.append(f"└{'─' * (width - 2)}┘")

        return "\n".join(result)

    def _create_subnet_box(self, subnet_id: str, width: int = 30) -> List[str]:
        """Create ASCII box for a subnet."""
        subnet = next((s for s in self.topology.subnets if s.subnet_id == subnet_id), None)
        if not subnet:
            return []

        subnet_name = subnet.get_tag("Name") or subnet.subnet_id
        subnet_type = self._get_subnet_type(subnet_id)

        lines = [
            "┌" + "─" * (width - 2) + "┐",
            f"│ {subnet_type:<{width-4}} │",
            f"│ {subnet_name:<{width-4}} │",
            f"│ {subnet.cidr_block:<{width-4}} │",
            f"│ AZ: {subnet.availability_zone:<{width-8}} │",
            "└" + "─" * (width - 2) + "┘",
        ]
        return lines

    def create_routing_diagram(self) -> str:
        """
        Create ASCII art diagram showing VPC routing topology.

        Returns:
            ASCII art string representation of the VPC routing
        """
        output = []

        # VPC Header
        vpc_name = self.topology.vpc.get_tag("Name") or self.topology.vpc.vpc_id
        output.append("=" * 80)
        output.append(f"VPC ROUTING TOPOLOGY: {vpc_name}")
        output.append(f"VPC ID: {self.topology.vpc.vpc_id}")
        output.append(f"CIDR: {self.topology.vpc.cidr_block}")
        output.append(f"Region: {self.topology.region}")
        output.append("=" * 80)
        output.append("")

        # Internet Gateway section
        if self.topology.internet_gateways:
            output.append("INTERNET CONNECTIVITY")
            output.append("-" * 80)
            for igw in self.topology.internet_gateways:
                igw_name = igw.get_tag("Name") or igw.igw_id
                output.append("")
                output.append("                    ┌─────────────┐")
                output.append("                    │  INTERNET   │")
                output.append("                    └──────┬──────┘")
                output.append("                           │")
                output.append("                           ▼")
                output.append("                    ┌──────────────────────┐")
                output.append("                    │ Internet Gateway     │")
                output.append(f"                    │ {igw_name:<20} │")
                output.append(f"                    │ {igw.igw_id:<20} │")
                output.append("                    └──────────────────────┘")
                output.append("")
            output.append("-" * 80)
            output.append("")

        # Subnets grouped by AZ
        output.append("SUBNETS BY AVAILABILITY ZONE")
        output.append("-" * 80)

        # Group subnets by AZ
        subnets_by_az: Dict[str, List] = {}
        for subnet in self.topology.subnets:
            az = subnet.availability_zone
            if az not in subnets_by_az:
                subnets_by_az[az] = []
            subnets_by_az[az].append(subnet)

        for az, subnets in sorted(subnets_by_az.items()):
            output.append(f"\n┌─ Availability Zone: {az} " + "─" * (80 - len(az) - 26) + "┐")

            for subnet in subnets:
                subnet_name = subnet.get_tag("Name") or subnet.subnet_id
                subnet_type = self._get_subnet_type(subnet.subnet_id)
                rt_id = self._get_route_table_for_subnet(subnet.subnet_id)

                output.append("│")
                type_marker = "🌐" if subnet_type == "PUBLIC" else "🔒"
                output.append(f"│  {type_marker} {subnet_type} SUBNET")
                output.append(f"│     Name: {subnet_name}")
                output.append(f"│     ID: {subnet.subnet_id}")
                output.append(f"│     CIDR: {subnet.cidr_block}")
                output.append(f"│     Available IPs: {subnet.available_ip_address_count}")
                output.append(f"│     Route Table: {rt_id}")

                # Check for NAT gateway in this subnet
                nat_in_subnet = [nat for nat in self.topology.nat_gateways if nat.subnet_id == subnet.subnet_id]
                if nat_in_subnet:
                    for nat in nat_in_subnet:
                        nat_name = nat.get_tag("Name") or nat.nat_gateway_id
                        output.append("│")
                        output.append(f"│     ├─ NAT Gateway: {nat_name}")
                        output.append(f"│     │  ID: {nat.nat_gateway_id}")
                        output.append(f"│     │  Public IP: {nat.public_ip or 'N/A'}")
                        output.append(f"│     │  Private IP: {nat.private_ip or 'N/A'}")

                interface_endpoints = [
                    endpoint
                    for endpoint in self.topology.vpc_endpoints
                    if endpoint.endpoint_type.lower() == "interface"
                    and subnet.subnet_id in endpoint.subnet_ids
                ]
                if interface_endpoints:
                    for endpoint in interface_endpoints:
                        output.append("│")
                        output.append(f"│     ├─ Interface Endpoint: {endpoint.service_name}")
                        output.append(f"│     │  ID: {endpoint.vpc_endpoint_id}")
                        output.append(f"│     │  State: {endpoint.state}")

                output.append("│")

            output.append("└" + "─" * 78 + "┘")

        output.append("")

        # Route Tables section
        output.append("\nROUTE TABLES & ROUTING CONFIGURATION")
        output.append("=" * 80)

        for rt in self.topology.route_tables:
            rt_name = rt.get_tag("Name") or rt.route_table_id
            main_marker = " (MAIN)" if rt.is_main else ""

            output.append("")
            output.append(f"┌─ Route Table: {rt_name}{main_marker} " + "─" * (80 - len(rt_name) - len(main_marker) - 18) + "┐")
            output.append(f"│ ID: {rt.route_table_id:<73} │")

            # Associated subnets
            if rt.subnet_associations:
                output.append("│" + " " * 78 + "│")
                output.append("│ Associated Subnets:" + " " * 58 + "│")
                for subnet_id in rt.subnet_associations:
                    subnet = next((s for s in self.topology.subnets if s.subnet_id == subnet_id), None)
                    if subnet:
                        subnet_name = subnet.get_tag("Name") or subnet_id
                        subnet_type = self._get_subnet_type(subnet_id)
                        marker = "🌐" if subnet_type == "PUBLIC" else "🔒"
                        output.append(f"│   {marker} {subnet_name:<70} │")
                        output.append(f"│      {subnet_id} ({subnet.cidr_block})" + " " * (80 - len(subnet_id) - len(subnet.cidr_block) - 12) + "│")
            elif rt.is_main:
                output.append("│" + " " * 78 + "│")
                output.append("│ Associated Subnets: All subnets without explicit association" + " " * 16 + "│")

            # Routes
            output.append("│" + " " * 78 + "│")
            output.append("│ Routes:" + " " * 70 + "│")
            output.append("│ " + "─" * 76 + " │")
            output.append("│  Destination          Target                    Status" + " " * 17 + "│")
            output.append("│ " + "─" * 76 + " │")

            for route in rt.routes:
                dest = get_route_destination(route)
                target = format_route_target(route)

                # Format route entry
                dest_str = f"{dest:<20}"
                target_str = f"{target:<28}"
                status_str = f"{route.state:<6}"

                output.append(f"│  {dest_str}  {target_str}  {status_str}" + " " * (78 - len(dest_str) - len(target_str) - len(status_str) - 6) + "│")

            output.append("└" + "─" * 78 + "┘")

        output.append("")

        # Routing Flow Visualization
        output.append("\nROUTING FLOW DIAGRAM")
        output.append("=" * 80)
        output.append("")

        # Find public and private subnets
        public_subnets = [
            subnet
            for subnet in self.topology.subnets
            if self._get_subnet_type(subnet.subnet_id) == "PUBLIC"
        ]
        private_subnets = [
            subnet
            for subnet in self.topology.subnets
            if self._get_subnet_type(subnet.subnet_id) == "PRIVATE_WITH_NAT"
        ]
        endpoint_only_subnets = [
            subnet
            for subnet in self.topology.subnets
            if self._get_subnet_type(subnet.subnet_id) == "ENDPOINT_ONLY"
        ]
        isolated_subnets = [
            subnet
            for subnet in self.topology.subnets
            if self._get_subnet_type(subnet.subnet_id) == "ISOLATED"
        ]

        if public_subnets and self.topology.internet_gateways:
            output.append("PUBLIC SUBNET INTERNET ACCESS:")
            output.append("")
            output.append("  Internet")
            output.append("      │")
            output.append("      ▼")
            output.append("  [Internet Gateway]")
            output.append("      │")
            output.append("      ▼")
            for subnet in public_subnets[:3]:  # Show first 3
                subnet_name = subnet.get_tag("Name") or subnet.subnet_id
                output.append(f"  {subnet_name} ({subnet.cidr_block})")
            if len(public_subnets) > 3:
                output.append(f"  ... and {len(public_subnets) - 3} more public subnets")
            output.append("")

        if private_subnets and self.topology.nat_gateways:
            output.append("PRIVATE SUBNET INTERNET ACCESS (via NAT):")
            output.append("")
            for nat in self.topology.nat_gateways[:2]:  # Show first 2 NAT gateways
                nat_name = nat.get_tag("Name") or nat.nat_gateway_id
                output.append(f"  Private Subnets → [{nat_name}] → Internet Gateway → Internet")

                # Find subnets that route to this NAT
                for rt in self.topology.route_tables:
                    for route in rt.routes:
                        if route.nat_gateway_id == nat.nat_gateway_id:
                            for subnet_id in rt.subnet_associations:
                                subnet = next((s for s in self.topology.subnets if s.subnet_id == subnet_id), None)
                                if subnet:
                                    subnet_name = subnet.get_tag("Name") or subnet_id
                                    output.append(f"    • {subnet_name} ({subnet.cidr_block})")
                output.append("")

        # Summary statistics
        output.append("")
        output.append("SUMMARY")
        output.append("=" * 80)
        output.append(f"Total Subnets: {len(self.topology.subnets)}")
        output.append(f"  Public: {len(public_subnets)}")
        output.append(f"  Private With NAT: {len(private_subnets)}")
        output.append(f"  Endpoint Only: {len(endpoint_only_subnets)}")
        output.append(f"  Isolated: {len(isolated_subnets)}")
        output.append(f"Internet Gateways: {len(self.topology.internet_gateways)}")
        output.append(f"NAT Gateways: {len(self.topology.nat_gateways)}")
        output.append(f"Route Tables: {len(self.topology.route_tables)}")
        output.append("=" * 80)

        return "\n".join(output)

    def create_compact_routing_diagram(self) -> str:
        """
        Create a compact ASCII art diagram showing key routing paths.

        Returns:
            Compact ASCII art string representation
        """
        output = []

        vpc_name = self.topology.vpc.get_tag("Name") or self.topology.vpc.vpc_id

        # Compact header
        output.append("╔" + "═" * 78 + "╗")
        output.append(f"║ VPC: {vpc_name:<70} ║")
        output.append(f"║ {self.topology.vpc.vpc_id} - {self.topology.vpc.cidr_block:<54} ║")
        output.append("╚" + "═" * 78 + "╝")
        output.append("")

        # Routing summary for each route table
        for rt in self.topology.route_tables:
            rt_name = rt.get_tag("Name") or rt.route_table_id
            main = " [MAIN]" if rt.is_main else ""

            output.append(f"┌─ {rt_name}{main}")
            output.append("│")

            # Show key routes
            for route in rt.routes:
                dest = get_route_destination(route)
                target_kind = get_route_target_kind(route)

                if target_kind == "igw":
                    output.append(f"│  {dest} ──→ Internet Gateway")
                elif target_kind == "nat":
                    output.append(f"│  {dest} ──→ NAT Gateway")
                elif target_kind == "local":
                    output.append(f"│  {dest} ──→ Local (VPC)")
                else:
                    output.append(f"│  {dest} ──→ {format_route_target(route)}")

            # Show associated subnets
            if rt.subnet_associations:
                output.append("│")
                output.append(f"│  Subnets ({len(rt.subnet_associations)}):")
                for subnet_id in rt.subnet_associations[:3]:
                    subnet = next((s for s in self.topology.subnets if s.subnet_id == subnet_id), None)
                    if subnet:
                        name = subnet.get_tag("Name") or subnet_id
                        output.append(f"│    • {name}")
                if len(rt.subnet_associations) > 3:
                    output.append(f"│    • ... {len(rt.subnet_associations) - 3} more")

            output.append("└" + "─" * 40)
            output.append("")

        return "\n".join(output)

    def save_routing_diagram(self, output_file: str, compact: bool = False) -> str:
        """
        Save ASCII routing diagram to a text file.

        Args:
            output_file: Path to output file
            compact: If True, generate compact version

        Returns:
            Path to saved file
        """
        if compact:
            content = self.create_compact_routing_diagram()
        else:
            content = self.create_routing_diagram()

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)

        return output_file
