"""Shared derived network analysis for topology, audits, and reports."""

from __future__ import annotations

from typing import Optional

from vpc_map.models import (
    Ec2Instance,
    ExposureState,
    InstanceExposure,
    IpPermission,
    NetworkAcl,
    NetworkAclEntry,
    Route,
    RouteTable,
    SecurityGroup,
    SubnetAnalysis,
    SubnetClassification,
    VpcTopology,
)

INTERESTING_PORTS = (22, 80, 443, 1433, 3306, 3389, 5432, 5984, 6379, 8080, 8443, 9200, 27017)
ADMIN_PORTS = {22, 3389}


def get_route_table_for_subnet(topology: VpcTopology, subnet_id: str) -> Optional[RouteTable]:
    """Get the explicit or main route table for a subnet."""
    for route_table in topology.route_tables:
        if subnet_id in route_table.subnet_associations:
            return route_table

    for route_table in topology.route_tables:
        if route_table.is_main:
            return route_table

    return None


def get_network_acl_for_subnet(topology: VpcTopology, subnet_id: str) -> Optional[NetworkAcl]:
    """Get the network ACL associated with a subnet."""
    for network_acl in topology.network_acls:
        if subnet_id in network_acl.subnet_associations:
            return network_acl

    for network_acl in topology.network_acls:
        if network_acl.is_default:
            return network_acl

    return None


def get_route_destination(route: Route) -> str:
    """Get the most relevant route destination for display."""
    return route.destination_cidr_block or route.destination_ipv6_cidr_block or "local"


def get_route_target_kind(route: Route) -> str:
    """Normalize route target kinds for rendering and audit logic."""
    if route.vpc_endpoint_id or _id_has_prefix(route.gateway_id, "vpce-"):
        return "vpce"
    if route.transit_gateway_id or _id_has_prefix(route.gateway_id, "tgw-"):
        return "tgw"
    if route.nat_gateway_id:
        return "nat"
    if route.egress_only_internet_gateway_id or _id_has_prefix(route.gateway_id, "eigw-"):
        return "eigw"
    if route.vpn_gateway_id or _id_has_prefix(route.gateway_id, "vgw-"):
        return "vgw"
    if route.carrier_gateway_id or _id_has_prefix(route.gateway_id, "cagw-"):
        return "carrier_gw"
    if route.local_gateway_id or _id_has_prefix(route.gateway_id, "lgw-"):
        return "local_gw"
    if route.vpc_peering_connection_id:
        return "pcx"
    if route.network_interface_id:
        return "eni"
    if route.instance_id:
        return "instance"
    if route.gateway_id == "local":
        return "local"
    if _id_has_prefix(route.gateway_id, "igw-"):
        return "igw"
    if route.gateway_id:
        return "gateway"
    return "unknown"


def format_route_target(route: Route) -> str:
    """Format route targets consistently across reports and diagrams."""
    target_kind = get_route_target_kind(route)
    target_id = _get_route_target_id(route)

    labels = {
        "igw": "Internet Gateway",
        "nat": "NAT Gateway",
        "vpce": "VPC Endpoint",
        "tgw": "Transit Gateway",
        "vgw": "VPN Gateway",
        "eigw": "Egress-Only IGW",
        "pcx": "VPC Peering",
        "eni": "ENI",
        "instance": "Instance",
        "carrier_gw": "Carrier Gateway",
        "local_gw": "Local Gateway",
        "local": "Local (VPC)",
        "gateway": "Gateway",
        "unknown": "Unknown",
    }
    if target_id and target_kind not in {"local", "unknown"}:
        return f"{labels[target_kind]} ({target_id})"
    return labels[target_kind]


def analyze_subnet(topology: VpcTopology, subnet_id: str) -> SubnetAnalysis:
    """Derive routing-based connectivity facts for a subnet."""
    route_table = get_route_table_for_subnet(topology, subnet_id)
    has_internet_gateway_route = False
    has_nat_route = False
    has_endpoint_access = False

    if route_table:
        for route in route_table.routes:
            if not _is_default_route(route):
                continue

            target_kind = get_route_target_kind(route)
            if target_kind == "igw":
                has_internet_gateway_route = True
            elif target_kind == "nat":
                has_nat_route = True

        has_endpoint_access = _has_endpoint_access(topology, subnet_id, route_table.route_table_id)
    else:
        has_endpoint_access = _has_endpoint_access(topology, subnet_id, None)

    if has_internet_gateway_route:
        classification = SubnetClassification.PUBLIC
    elif has_nat_route:
        classification = SubnetClassification.PRIVATE_WITH_NAT
    elif has_endpoint_access:
        classification = SubnetClassification.ENDPOINT_ONLY
    else:
        classification = SubnetClassification.ISOLATED

    return SubnetAnalysis(
        subnet_id=subnet_id,
        route_table_id=route_table.route_table_id if route_table else None,
        classification=classification,
        has_internet_gateway_route=has_internet_gateway_route,
        has_nat_route=has_nat_route,
        has_endpoint_access=has_endpoint_access,
    )


def analyze_subnets(topology: VpcTopology) -> list[SubnetAnalysis]:
    """Analyze all subnets in topology order."""
    return [analyze_subnet(topology, subnet.subnet_id) for subnet in topology.subnets]


def analyze_instance_exposure(
    topology: VpcTopology,
    instance: Ec2Instance,
    subnet_analysis_map: Optional[dict[str, SubnetAnalysis]] = None,
) -> InstanceExposure:
    """Derive externally reachable posture for an EC2 instance."""
    subnet_analysis_map = subnet_analysis_map or {
        analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
    }
    subnet_analysis = subnet_analysis_map.get(instance.subnet_id)
    if subnet_analysis is None:
        subnet_analysis = analyze_subnet(topology, instance.subnet_id)

    public_address_source = _get_public_address_source(topology, instance)
    has_public_address = public_address_source is not None
    internet_route = subnet_analysis.has_internet_gateway_route

    security_groups = {
        security_group.group_id: security_group for security_group in topology.security_groups
    }
    internet_open_rules = [
        rule
        for group_id in instance.security_groups
        for rule in _get_internet_open_rules(security_groups.get(group_id))
    ]
    allowed_ports = sorted(
        {port for rule in internet_open_rules for port in _sample_ports_for_rule(rule)}
    )
    open_admin_ports = [port for port in allowed_ports if port in ADMIN_PORTS]
    security_group_exposure = bool(internet_open_rules)

    network_acl = get_network_acl_for_subnet(topology, instance.subnet_id)
    nacl_allowed_ports = sorted(
        port for port in allowed_ports if _network_acl_allows_port(network_acl, port)
    )
    blocked_ports = sorted(port for port in allowed_ports if port not in nacl_allowed_ports)
    nacl_exposure = any(_network_acl_allows_rule(network_acl, rule) for rule in internet_open_rules)

    explanations = []
    if not internet_route:
        explanations.append("No default route to an internet gateway.")
    if not has_public_address:
        explanations.append("No public IPv4 address or associated Elastic IP.")
    if allowed_ports:
        explanations.append(f"Security groups allow internet ingress on ports {', '.join(map(str, allowed_ports))}.")
    else:
        explanations.append("No internet-open security group rule found.")
    if blocked_ports:
        explanations.append(f"Network ACL blocks tracked ports {', '.join(map(str, blocked_ports))}.")

    if internet_route and has_public_address and security_group_exposure and nacl_exposure:
        exposure_state = ExposureState.PUBLICLY_REACHABLE
    elif internet_route and has_public_address:
        exposure_state = ExposureState.POTENTIALLY_REACHABLE
    else:
        exposure_state = ExposureState.PRIVATELY_REACHABLE_ONLY

    return InstanceExposure(
        instance_id=instance.instance_id,
        subnet_id=instance.subnet_id,
        subnet_classification=subnet_analysis.classification,
        public_address_source=public_address_source,
        has_public_address=has_public_address,
        internet_route=internet_route,
        security_group_exposure=security_group_exposure,
        nacl_exposure=nacl_exposure,
        exposure_state=exposure_state,
        allowed_ports=allowed_ports,
        open_admin_ports=open_admin_ports,
        blocked_ports=blocked_ports,
        explanations=explanations,
    )


def analyze_instances(topology: VpcTopology) -> list[InstanceExposure]:
    """Analyze exposure posture for all instances in topology order."""
    subnet_analysis = analyze_subnets(topology)
    subnet_analysis_map = {analysis.subnet_id: analysis for analysis in subnet_analysis}
    return [
        analyze_instance_exposure(topology, instance, subnet_analysis_map)
        for instance in topology.ec2_instances
    ]


def build_network_analysis(topology: VpcTopology) -> dict[str, list[dict]]:
    """Build a JSON-serializable network analysis section."""
    subnet_analysis = analyze_subnets(topology)
    instance_analysis = analyze_instances(topology)
    return {
        "subnets": [analysis.model_dump(mode="json") for analysis in subnet_analysis],
        "instances": [analysis.model_dump(mode="json") for analysis in instance_analysis],
    }


def _id_has_prefix(value: Optional[str], prefix: str) -> bool:
    return bool(value and value.startswith(prefix))


def _get_route_target_id(route: Route) -> Optional[str]:
    for target_id in (
        route.vpc_endpoint_id,
        route.transit_gateway_id,
        route.nat_gateway_id,
        route.egress_only_internet_gateway_id,
        route.vpn_gateway_id,
        route.carrier_gateway_id,
        route.local_gateway_id,
        route.vpc_peering_connection_id,
        route.network_interface_id,
        route.instance_id,
        route.gateway_id,
    ):
        if target_id and target_id != "local":
            return target_id
    return None


def _is_default_route(route: Route) -> bool:
    return route.destination_cidr_block == "0.0.0.0/0" or route.destination_ipv6_cidr_block == "::/0"


def _has_endpoint_access(
    topology: VpcTopology, subnet_id: str, route_table_id: Optional[str]
) -> bool:
    for endpoint in topology.vpc_endpoints:
        if subnet_id in endpoint.subnet_ids:
            return True
        if route_table_id and route_table_id in endpoint.route_table_ids:
            return True
    return False


def _get_public_address_source(topology: VpcTopology, instance: Ec2Instance) -> Optional[str]:
    for elastic_ip in topology.elastic_ips:
        if elastic_ip.instance_id == instance.instance_id:
            return "elastic_ip"
        if elastic_ip.public_ip and instance.public_ip_address == elastic_ip.public_ip:
            return "elastic_ip"

    if instance.public_ip_address:
        return "public_ip"

    return None


def _get_internet_open_rules(security_group: Optional[SecurityGroup]) -> list[IpPermission]:
    if security_group is None:
        return []

    return [rule for rule in security_group.ingress_rules if _is_internet_rule(rule)]


def _sample_ports_for_rule(rule: IpPermission) -> set[int]:
    """Return representative ports for reporting and NACL overlap checks."""
    if rule.ip_protocol in {"-1", "all"} or rule.from_port is None or rule.to_port is None:
        return set(INTERESTING_PORTS)

    if rule.from_port == rule.to_port:
        return {rule.from_port}

    sampled_ports = {rule.from_port, rule.to_port}
    sampled_ports.update(port for port in INTERESTING_PORTS if _rule_matches_port(rule, port))
    return sampled_ports


def _is_internet_rule(rule: IpPermission) -> bool:
    return "0.0.0.0/0" in rule.ip_ranges or "::/0" in rule.ipv6_ranges


def _rule_matches_port(rule: IpPermission, port: int) -> bool:
    if rule.ip_protocol in {"-1", "all"}:
        return True
    if rule.ip_protocol not in {"6", "17", "tcp", "udp"}:
        return False
    if rule.from_port is None or rule.to_port is None:
        return True
    return rule.from_port <= port <= rule.to_port


def _network_acl_allows_port(network_acl: Optional[NetworkAcl], port: int) -> bool:
    if network_acl is None:
        return False

    inbound_entries = sorted(
        (
            entry
            for entry in network_acl.entries
            if not entry.egress and _entry_matches_internet(entry) and _entry_matches_port(entry, port)
        ),
        key=lambda entry: entry.rule_number,
    )
    if not inbound_entries:
        return False

    return inbound_entries[0].rule_action == "allow"


def _network_acl_allows_rule(network_acl: Optional[NetworkAcl], rule: IpPermission) -> bool:
    """Check whether the subnet NACL allows any representative port from the SG rule."""
    if network_acl is None:
        return False

    sample_ports = _sample_ports_for_rule(rule)
    return any(_network_acl_allows_port(network_acl, port) for port in sample_ports)


def _entry_matches_internet(entry: NetworkAclEntry) -> bool:
    return entry.cidr_block == "0.0.0.0/0" or entry.ipv6_cidr_block == "::/0"


def _entry_matches_port(entry: NetworkAclEntry, port: int) -> bool:
    if entry.protocol in {"-1", "all"}:
        return True
    if entry.protocol not in {"6", "17", "tcp", "udp"}:
        return False
    if not entry.port_range:
        return True

    from_port = entry.port_range.get("From", 0)
    to_port = entry.port_range.get("To", 65535)
    return from_port <= port <= to_port
