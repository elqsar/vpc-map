"""VPC topology visualization using Graphviz."""

from pathlib import Path

import graphviz

from vpc_map.models import VpcTopology
from vpc_map.network.analysis import (
    analyze_subnets,
    get_route_destination,
    get_route_target_kind,
)


class VpcVisualizer:
    """Creates visual diagrams of VPC topology using Graphviz."""

    # Color scheme
    COLORS = {
        "vpc": "#E8F4F8",
        "subnet_public": "#B8E6B8",
        "subnet_private": "#FFE6B8",
        "subnet_endpoint_only": "#CFE8F6",
        "subnet_isolated": "#E6E6E6",
        "igw": "#FFB6C1",
        "nat": "#DDA0DD",
        "endpoint": "#C7E9C0",
        "route_table": "#F0E68C",
        "security_group": "#87CEEB",
        "nacl": "#FFA07A",
    }

    def __init__(self, topology: VpcTopology):
        """
        Initialize the visualizer.

        Args:
            topology: VPC topology to visualize
        """
        self.topology = topology
        self.subnet_analysis = {
            analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
        }

    def _get_subnet_type(self, subnet_id: str) -> str:
        """Get the shared subnet classification label."""
        return self.subnet_analysis[subnet_id].classification.value

    def _format_cidr(self, cidr: str) -> str:
        """Format CIDR block for display."""
        return cidr.replace("/", "/\\n")

    def _truncate_id(self, resource_id: str) -> str:
        """Truncate resource ID for cleaner display."""
        if "-" in resource_id:
            prefix, suffix = resource_id.split("-", 1)
            return f"{prefix}-{suffix[:8]}..."
        return resource_id

    def _endpoint_label(self, endpoint) -> str:
        """Format a compact label for a VPC endpoint."""
        service_name = endpoint.service_name.split(".")[-1]
        return (
            f"VPC Endpoint\\n"
            f"{service_name}\\n"
            f"{endpoint.endpoint_type}\\n"
            f"{endpoint.state}"
        )

    def _add_route_target_node(self, dot: graphviz.Digraph, target_kind: str, target_id: str) -> None:
        """Add a labeled node for expanded route targets not otherwise rendered."""
        labels = {
            "tgw": "Transit Gateway",
            "vgw": "VPN Gateway",
            "eigw": "Egress-Only IGW",
            "pcx": "VPC Peering",
            "eni": "ENI",
            "instance": "Instance",
            "carrier_gw": "Carrier Gateway",
            "local_gw": "Local Gateway",
        }
        shapes = {
            "tgw": "octagon",
            "vgw": "octagon",
            "eigw": "box",
            "pcx": "hexagon",
            "eni": "ellipse",
            "instance": "ellipse",
            "carrier_gw": "hexagon",
            "local_gw": "hexagon",
        }
        colors = {
            "tgw": "#E7D7F7",
            "vgw": "#F7DFC6",
            "eigw": "#DCEBFA",
            "pcx": "#FBE6B8",
            "eni": "#EFEFEF",
            "instance": "#EFEFEF",
            "carrier_gw": "#F7E2C6",
            "local_gw": "#D9DEF8",
        }
        if target_kind not in labels:
            return

        dot.node(
            target_id,
            label=f"{labels[target_kind]}\\n{target_id}",
            shape=shapes[target_kind],
            style="filled,rounded",
            fillcolor=colors[target_kind],
            fontsize="9",
        )

    def create_diagram(self, output_file: str = "vpc_topology", format: str = "png") -> Path:
        """
        Create VPC topology diagram.

        Args:
            output_file: Output file name (without extension)
            format: Output format (png, svg, pdf)

        Returns:
            Path to generated diagram file
        """
        # Create main graph
        dot = graphviz.Digraph(
            name="VPC Topology",
            comment=f"VPC {self.topology.vpc.vpc_id} Topology",
            format=format,
        )
        dot.attr(
            rankdir="TB",
            splines="ortho",
            nodesep="0.8",
            ranksep="1.0",
            fontname="Arial",
        )

        # VPC container
        vpc_name = self.topology.vpc.get_tag("Name") or self.topology.vpc.vpc_id
        with dot.subgraph(name=f"cluster_{self.topology.vpc.vpc_id}") as vpc_cluster:
            vpc_cluster.attr(
                style="filled,rounded",
                fillcolor=self.COLORS["vpc"],
                label=f"VPC: {vpc_name}\\n{self.topology.vpc.cidr_block}\\n({self.topology.region})",
                fontsize="16",
                fontname="Arial Bold",
            )

            # Add subnets
            for subnet in self.topology.subnets:
                subnet_type = self._get_subnet_type(subnet.subnet_id)
                subnet_name = subnet.get_tag("Name") or subnet.subnet_id
                color = {
                    "public": self.COLORS["subnet_public"],
                    "private_with_nat": self.COLORS["subnet_private"],
                    "endpoint_only": self.COLORS["subnet_endpoint_only"],
                    "isolated": self.COLORS["subnet_isolated"],
                }.get(subnet_type, self.COLORS["subnet_private"])

                label = (
                    f"{subnet_name}\\n"
                    f"{subnet.cidr_block}\\n"
                    f"AZ: {subnet.availability_zone}\\n"
                    f"Type: {subnet_type.upper()}"
                )

                vpc_cluster.node(
                    subnet.subnet_id,
                    label=label,
                    shape="box",
                    style="filled,rounded",
                    fillcolor=color,
                    fontsize="11",
                )

                # Add NAT gateways in subnets
                for nat in self.topology.nat_gateways:
                    if nat.subnet_id == subnet.subnet_id:
                        nat_name = nat.get_tag("Name") or nat.nat_gateway_id
                        nat_label = f"NAT Gateway\\n{nat_name}"
                        if nat.public_ip:
                            nat_label += f"\\n{nat.public_ip}"

                        vpc_cluster.node(
                            nat.nat_gateway_id,
                            label=nat_label,
                            shape="diamond",
                            style="filled",
                            fillcolor=self.COLORS["nat"],
                            fontsize="10",
                        )
                        vpc_cluster.edge(
                            subnet.subnet_id,
                            nat.nat_gateway_id,
                            style="dashed",
                            color="gray",
                        )

                # Add interface endpoints in subnets
                for endpoint in self.topology.vpc_endpoints:
                    if endpoint.endpoint_type.lower() != "interface":
                        continue
                    if subnet.subnet_id not in endpoint.subnet_ids:
                        continue

                    vpc_cluster.node(
                        endpoint.vpc_endpoint_id,
                        label=self._endpoint_label(endpoint),
                        shape="hexagon",
                        style="filled,rounded",
                        fillcolor=self.COLORS["endpoint"],
                        fontsize="10",
                    )
                    vpc_cluster.edge(
                        subnet.subnet_id,
                        endpoint.vpc_endpoint_id,
                        style="dashed",
                        color="darkgreen",
                    )

            # Add gateway endpoints once at VPC scope
            for endpoint in self.topology.vpc_endpoints:
                if endpoint.endpoint_type.lower() != "gateway":
                    continue

                vpc_cluster.node(
                    endpoint.vpc_endpoint_id,
                    label=self._endpoint_label(endpoint),
                    shape="hexagon",
                    style="filled,rounded",
                    fillcolor=self.COLORS["endpoint"],
                    fontsize="10",
                )

        # Add Internet Gateways (outside VPC cluster)
        for igw in self.topology.internet_gateways:
            igw_name = igw.get_tag("Name") or igw.igw_id
            dot.node(
                igw.igw_id,
                label=f"Internet Gateway\\n{igw_name}",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["igw"],
                fontsize="11",
            )
            # Connect IGW to VPC
            dot.edge(
                igw.igw_id,
                self.topology.vpc.vpc_id,
                label="attached",
                style="bold",
                color="darkgreen",
            )

        # Add Internet node
        if self.topology.internet_gateways:
            dot.node(
                "internet",
                label="Internet",
                shape="cloud",
                style="filled",
                fillcolor="lightblue",
                fontsize="12",
            )
            for igw in self.topology.internet_gateways:
                dot.edge("internet", igw.igw_id, style="bold", color="blue")

        # Add route table connections
        for rt in self.topology.route_tables:
            rt_name = rt.get_tag("Name") or rt.route_table_id
            rt_label = f"Route Table\\n{rt_name}"
            if rt.is_main:
                rt_label += "\\n(Main)"

            # Create route table node
            dot.node(
                rt.route_table_id,
                label=rt_label,
                shape="folder",
                style="filled",
                fillcolor=self.COLORS["route_table"],
                fontsize="9",
            )

            # Connect route table to associated subnets
            for subnet_id in rt.subnet_associations:
                dot.edge(
                    rt.route_table_id,
                    subnet_id,
                    label="routes",
                    style="dotted",
                    color="orange",
                    arrowhead="none",
                )

            # Show routes to NAT gateways and IGWs
            for route in rt.routes:
                target_kind = get_route_target_kind(route)
                target_id = (
                    route.nat_gateway_id
                    or route.gateway_id
                    or route.vpc_endpoint_id
                    or route.transit_gateway_id
                    or route.egress_only_internet_gateway_id
                    or route.vpn_gateway_id
                    or route.carrier_gateway_id
                    or route.local_gateway_id
                    or route.vpc_peering_connection_id
                    or route.network_interface_id
                    or route.instance_id
                )
                edge_color = {
                    "nat": "purple",
                    "igw": "green",
                    "vpce": "darkgreen",
                    "tgw": "brown",
                    "vgw": "sienna",
                    "eigw": "darkblue",
                    "pcx": "darkorange",
                    "eni": "gray40",
                    "instance": "gray40",
                    "carrier_gw": "goldenrod4",
                    "local_gw": "slateblue4",
                }.get(target_kind)

                if edge_color and target_id:
                    self._add_route_target_node(dot, target_kind, target_id)
                    dot.edge(
                        rt.route_table_id,
                        target_id,
                        label=f"→ {get_route_destination(route)}",
                        style="dashed",
                        color=edge_color,
                        fontsize="8",
                    )

        for endpoint in self.topology.vpc_endpoints:
            if endpoint.endpoint_type.lower() != "gateway":
                continue
            for route_table_id in endpoint.route_table_ids:
                dot.edge(
                    route_table_id,
                    endpoint.vpc_endpoint_id,
                    label="endpoint",
                    style="dotted",
                    color="darkgreen",
                    fontsize="8",
                )

        # Add legend
        with dot.subgraph(name="cluster_legend") as legend:
            legend.attr(
                label="Legend",
                style="filled",
                fillcolor="white",
                fontsize="12",
            )
            legend.node(
                "legend_public",
                label="Public Subnet",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["subnet_public"],
            )
            legend.node(
                "legend_private",
                label="Private With NAT",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["subnet_private"],
            )
            legend.node(
                "legend_endpoint_only",
                label="Endpoint-Only Subnet",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["subnet_endpoint_only"],
            )
            legend.node(
                "legend_isolated",
                label="Isolated Subnet",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["subnet_isolated"],
            )
            legend.node(
                "legend_nat",
                label="NAT Gateway",
                shape="diamond",
                style="filled",
                fillcolor=self.COLORS["nat"],
            )
            legend.node(
                "legend_endpoint",
                label="VPC Endpoint",
                shape="hexagon",
                style="filled,rounded",
                fillcolor=self.COLORS["endpoint"],
            )
            legend.node(
                "legend_igw",
                label="Internet Gateway",
                shape="box",
                style="filled,rounded",
                fillcolor=self.COLORS["igw"],
            )

        # Render diagram
        output_path = Path(output_file)
        dot.render(str(output_path), cleanup=True, format=format)

        return output_path.with_suffix(f".{format}")

    def create_security_diagram(
        self, output_file: str = "vpc_security", format: str = "png"
    ) -> Path:
        """
        Create security groups and NACLs diagram.

        Args:
            output_file: Output file name (without extension)
            format: Output format (png, svg, pdf)

        Returns:
            Path to generated diagram file
        """
        dot = graphviz.Digraph(
            name="VPC Security",
            comment=f"VPC {self.topology.vpc.vpc_id} Security Configuration",
            format=format,
        )
        dot.attr(rankdir="LR", splines="true", nodesep="0.5", ranksep="1.0")

        # Add security groups
        with dot.subgraph(name="cluster_security_groups") as sg_cluster:
            sg_cluster.attr(
                label="Security Groups",
                style="filled,rounded",
                fillcolor="lightgray",
            )

            for sg in self.topology.security_groups:
                sg_label = (
                    f"{sg.group_name}\\n"
                    f"{sg.group_id}\\n"
                    f"Ingress: {len(sg.ingress_rules)} rules\\n"
                    f"Egress: {len(sg.egress_rules)} rules"
                )

                sg_cluster.node(
                    sg.group_id,
                    label=sg_label,
                    shape="box",
                    style="filled,rounded",
                    fillcolor=self.COLORS["security_group"],
                )

        # Add NACLs
        with dot.subgraph(name="cluster_nacls") as nacl_cluster:
            nacl_cluster.attr(
                label="Network ACLs",
                style="filled,rounded",
                fillcolor="lightgray",
            )

            for nacl in self.topology.network_acls:
                nacl_name = nacl.get_tag("Name") or nacl.nacl_id
                nacl_label = (
                    f"{nacl_name}\\n"
                    f"Rules: {len(nacl.entries)}\\n"
                    f"Subnets: {len(nacl.subnet_associations)}"
                )
                if nacl.is_default:
                    nacl_label += "\\n(Default)"

                nacl_cluster.node(
                    nacl.nacl_id,
                    label=nacl_label,
                    shape="box",
                    style="filled,rounded",
                    fillcolor=self.COLORS["nacl"],
                )

                # Connect NACLs to associated subnets
                for subnet_id in nacl.subnet_associations:
                    subnet_name = next(
                        (
                            s.get_tag("Name") or s.subnet_id
                            for s in self.topology.subnets
                            if s.subnet_id == subnet_id
                        ),
                        subnet_id,
                    )
                    dot.edge(
                        nacl.nacl_id,
                        f"subnet_{subnet_id}",
                        label="protects",
                        style="dotted",
                    )

                    # Add subnet reference nodes
                    dot.node(
                        f"subnet_{subnet_id}",
                        label=f"Subnet\\n{subnet_name}",
                        shape="ellipse",
                        style="filled",
                        fillcolor=self.COLORS["subnet_public"],
                    )

        # Render diagram
        output_path = Path(output_file)
        dot.render(str(output_path), cleanup=True, format=format)

        return output_path.with_suffix(f".{format}")
