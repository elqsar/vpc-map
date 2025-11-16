"""AWS Well-Architected Framework audit rules."""

from vpc_map.models import AuditCategory, AuditFinding, Severity, VpcTopology


class AWSWellArchitectedAuditor:
    """Implements AWS Well-Architected Framework best practices."""

    def __init__(self, topology: VpcTopology):
        """Initialize the auditor with VPC topology."""
        self.topology = topology
        self.framework = "AWS Well-Architected"

    def audit(self) -> list[AuditFinding]:
        """Run all AWS Well-Architected checks."""
        findings = []
        findings.extend(self._check_vpc_flow_logs())
        findings.extend(self._check_dns_settings())
        findings.extend(self._check_subnet_availability())
        findings.extend(self._check_nat_gateway_redundancy())
        findings.extend(self._check_unused_resources())
        findings.extend(self._check_default_security_group())
        findings.extend(self._check_network_segmentation())
        return findings

    def _check_vpc_flow_logs(self) -> list[AuditFinding]:
        """Check if VPC Flow Logs are enabled (simulated - requires additional API call)."""
        # Note: This would require describe_flow_logs API call in production
        # For now, we'll create an informational finding
        return [
            AuditFinding(
                severity=Severity.INFO,
                category=AuditCategory.SECURITY,
                title="VPC Flow Logs Check",
                description="Ensure VPC Flow Logs are enabled for network monitoring and security analysis.",
                resource_id=self.topology.vpc.vpc_id,
                resource_type="VPC",
                recommendation="Enable VPC Flow Logs to capture IP traffic information. "
                "This helps with security analysis, troubleshooting, and compliance.",
                framework=self.framework,
                rule_id="WAF-SEC-001",
                compliance_status="WARNING",
            )
        ]

    def _check_dns_settings(self) -> list[AuditFinding]:
        """Check DNS resolution and hostname settings."""
        findings = []

        if not self.topology.vpc.enable_dns_support:
            findings.append(
                AuditFinding(
                    severity=Severity.MEDIUM,
                    category=AuditCategory.RELIABILITY,
                    title="DNS Support Disabled",
                    description="DNS resolution is disabled in the VPC, which may cause issues with resource connectivity.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Enable DNS support in the VPC to allow proper DNS resolution for resources.",
                    framework=self.framework,
                    rule_id="WAF-REL-001",
                )
            )

        if not self.topology.vpc.enable_dns_hostnames:
            findings.append(
                AuditFinding(
                    severity=Severity.LOW,
                    category=AuditCategory.OPERATIONS,
                    title="DNS Hostnames Disabled",
                    description="DNS hostnames are disabled, which prevents automatic hostname assignment to instances.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Enable DNS hostnames for easier resource identification and management.",
                    framework=self.framework,
                    rule_id="WAF-OPS-001",
                )
            )

        return findings

    def _check_subnet_availability(self) -> list[AuditFinding]:
        """Check subnet distribution across availability zones."""
        findings = []

        # Count subnets per AZ
        az_distribution = {}
        for subnet in self.topology.subnets:
            az = subnet.availability_zone
            az_distribution[az] = az_distribution.get(az, 0) + 1

        # Check if subnets span multiple AZs
        if len(az_distribution) < 2:
            findings.append(
                AuditFinding(
                    severity=Severity.HIGH,
                    category=AuditCategory.RELIABILITY,
                    title="Single Availability Zone",
                    description=f"All subnets are in a single AZ ({list(az_distribution.keys())[0]}), creating a single point of failure.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Deploy subnets across multiple Availability Zones (at least 2) for high availability and fault tolerance.",
                    framework=self.framework,
                    rule_id="WAF-REL-002",
                )
            )

        # Check for low IP availability
        for subnet in self.topology.subnets:
            if subnet.available_ip_address_count < 10:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.OPERATIONS,
                        title="Low IP Address Availability",
                        description=f"Subnet has only {subnet.available_ip_address_count} available IP addresses.",
                        resource_id=subnet.subnet_id,
                        resource_type="Subnet",
                        recommendation="Monitor IP usage and consider expanding the subnet CIDR or creating additional subnets.",
                        framework=self.framework,
                        rule_id="WAF-OPS-002",
                    )
                )

        return findings

    def _check_nat_gateway_redundancy(self) -> list[AuditFinding]:
        """Check NAT Gateway redundancy across AZs."""
        findings = []

        # Get NAT gateways that are active
        active_nats = [
            nat for nat in self.topology.nat_gateways if nat.state in ["available", "pending"]
        ]

        if not active_nats:
            # No NAT gateways, check if there are private subnets that might need them
            has_private_subnets = False
            for subnet in self.topology.subnets:
                # Check if subnet has no direct route to IGW
                has_igw_route = False
                for rt in self.topology.route_tables:
                    if subnet.subnet_id in rt.subnet_associations:
                        for route in rt.routes:
                            if route.gateway_id and route.gateway_id.startswith("igw-"):
                                has_igw_route = True
                                break
                if not has_igw_route:
                    has_private_subnets = True
                    break

            if has_private_subnets:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.RELIABILITY,
                        title="No NAT Gateways Found",
                        description="Private subnets detected but no NAT Gateways configured for outbound internet access.",
                        resource_id=self.topology.vpc.vpc_id,
                        resource_type="VPC",
                        recommendation="Deploy NAT Gateways in public subnets to enable outbound internet access for private subnets.",
                        framework=self.framework,
                        rule_id="WAF-REL-003",
                    )
                )
        else:
            # Check NAT gateway distribution across AZs
            nat_azs = set()
            for nat in active_nats:
                for subnet in self.topology.subnets:
                    if subnet.subnet_id == nat.subnet_id:
                        nat_azs.add(subnet.availability_zone)
                        break

            if len(nat_azs) < 2 and len(self.topology.subnets) > 1:
                findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        category=AuditCategory.RELIABILITY,
                        title="Single NAT Gateway AZ",
                        description="All NAT Gateways are in a single AZ, creating a single point of failure.",
                        resource_id=self.topology.vpc.vpc_id,
                        resource_type="VPC",
                        recommendation="Deploy NAT Gateways in multiple AZs for high availability.",
                        framework=self.framework,
                        rule_id="WAF-REL-004",
                    )
                )

        return findings

    def _check_unused_resources(self) -> list[AuditFinding]:
        """Check for unused resources that incur costs."""
        findings = []

        # Check for NAT gateways in failed/deleted state
        for nat in self.topology.nat_gateways:
            if nat.state in ["failed", "deleting", "deleted"]:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Inactive NAT Gateway",
                        description=f"NAT Gateway is in '{nat.state}' state but may still incur charges.",
                        resource_id=nat.nat_gateway_id,
                        resource_type="NAT Gateway",
                        recommendation="Review and delete failed or unused NAT Gateways to avoid unnecessary costs.",
                        framework=self.framework,
                        rule_id="WAF-COST-001",
                    )
                )

        # Check for unassociated route tables
        associated_rts = set()
        for rt in self.topology.route_tables:
            if rt.subnet_associations or rt.is_main:
                associated_rts.add(rt.route_table_id)

        for rt in self.topology.route_tables:
            if rt.route_table_id not in associated_rts:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Unassociated Route Table",
                        description="Route table is not associated with any subnets.",
                        resource_id=rt.route_table_id,
                        resource_type="Route Table",
                        recommendation="Remove unused route tables to reduce clutter and potential confusion.",
                        framework=self.framework,
                        rule_id="WAF-COST-002",
                    )
                )

        return findings

    def _check_default_security_group(self) -> list[AuditFinding]:
        """Check if default security group is being used."""
        findings = []

        for sg in self.topology.security_groups:
            if sg.group_name == "default":
                # Check if it has permissive rules
                if sg.ingress_rules or len(sg.egress_rules) > 0:
                    has_permissive_ingress = False
                    for rule in sg.ingress_rules:
                        if "0.0.0.0/0" in rule.ip_ranges or "::/0" in rule.ipv6_ranges:
                            has_permissive_ingress = True
                            break

                    if has_permissive_ingress:
                        findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                category=AuditCategory.SECURITY,
                                title="Default Security Group Has Permissive Rules",
                                description="Default security group allows inbound traffic from anywhere.",
                                resource_id=sg.group_id,
                                resource_type="Security Group",
                                recommendation="Remove all rules from the default security group and use custom security groups instead.",
                                framework=self.framework,
                                rule_id="WAF-SEC-002",
                            )
                        )

        return findings

    def _check_network_segmentation(self) -> list[AuditFinding]:
        """Check for proper network segmentation."""
        findings = []

        # Check if VPC has both public and private subnets
        has_public = False
        has_private = False

        for subnet in self.topology.subnets:
            # Determine subnet type by checking route tables
            is_public = False
            for rt in self.topology.route_tables:
                if subnet.subnet_id in rt.subnet_associations or rt.is_main:
                    for route in rt.routes:
                        if route.gateway_id and route.gateway_id.startswith("igw-"):
                            is_public = True
                            break

            if is_public:
                has_public = True
            else:
                has_private = True

        if has_public and not has_private:
            findings.append(
                AuditFinding(
                    severity=Severity.MEDIUM,
                    category=AuditCategory.SECURITY,
                    title="No Private Subnets",
                    description="VPC only has public subnets, exposing all resources to the internet.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Create private subnets for application and database tiers to improve security through network segmentation.",
                    framework=self.framework,
                    rule_id="WAF-SEC-003",
                )
            )

        return findings
