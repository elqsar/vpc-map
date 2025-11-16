"""Custom security and best practice audit rules."""

from vpc_map.models import AuditCategory, AuditFinding, Severity, VpcTopology


class CustomSecurityAuditor:
    """Implements custom security and operational best practices."""

    def __init__(self, topology: VpcTopology):
        """Initialize the auditor with VPC topology."""
        self.topology = topology
        self.framework = "Custom Security Checks"

    def audit(self) -> list[AuditFinding]:
        """Run all custom security checks."""
        findings = []
        findings.extend(self._check_resource_tagging())
        findings.extend(self._check_subnet_naming())
        findings.extend(self._check_security_group_descriptions())
        findings.extend(self._check_unused_security_groups())
        findings.extend(self._check_overlapping_security_rules())
        findings.extend(self._check_nacl_ephemeral_ports())
        findings.extend(self._check_route_table_complexity())
        findings.extend(self._check_public_subnet_auto_assign())
        return findings

    def _check_resource_tagging(self) -> list[AuditFinding]:
        """Check if resources are properly tagged."""
        findings = []
        required_tags = ["Name", "Environment"]

        # Check VPC tags
        vpc_tags = {tag.key for tag in self.topology.vpc.tags}
        missing_vpc_tags = set(required_tags) - vpc_tags
        if missing_vpc_tags:
            findings.append(
                AuditFinding(
                    severity=Severity.LOW,
                    category=AuditCategory.OPERATIONS,
                    title="VPC Missing Required Tags",
                    description=f"VPC is missing recommended tags: {', '.join(missing_vpc_tags)}",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Add 'Name' and 'Environment' tags to VPC for better resource management and cost allocation.",
                    framework=self.framework,
                    rule_id="CUSTOM-OPS-001",
                )
            )

        # Check subnet tags
        for subnet in self.topology.subnets:
            subnet_tags = {tag.key for tag in subnet.tags}
            if "Name" not in subnet_tags:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.OPERATIONS,
                        title="Subnet Missing Name Tag",
                        description=f"Subnet {subnet.subnet_id} has no 'Name' tag, making it harder to identify.",
                        resource_id=subnet.subnet_id,
                        resource_type="Subnet",
                        recommendation="Add descriptive 'Name' tag to subnet (e.g., 'public-subnet-1a', 'private-db-subnet-1b').",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-002",
                    )
                )

        # Check security group tags
        for sg in self.topology.security_groups:
            if sg.group_name != "default" and not sg.tags:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.OPERATIONS,
                        title="Security Group Has No Tags",
                        description=f"Security group '{sg.group_name}' has no tags.",
                        resource_id=sg.group_id,
                        resource_type="Security Group",
                        recommendation="Add tags to security groups for better organization and tracking.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-003",
                    )
                )

        return findings

    def _check_subnet_naming(self) -> list[AuditFinding]:
        """Check subnet naming conventions."""
        findings = []

        for subnet in self.topology.subnets:
            name = subnet.get_tag("Name")
            if name:
                # Check if name indicates public/private
                name_lower = name.lower()
                has_type_indicator = any(
                    indicator in name_lower
                    for indicator in ["public", "private", "dmz", "internal"]
                )

                if not has_type_indicator:
                    findings.append(
                        AuditFinding(
                            severity=Severity.INFO,
                            category=AuditCategory.OPERATIONS,
                            title="Subnet Name Doesn't Indicate Type",
                            description=f"Subnet name '{name}' doesn't clearly indicate if it's public or private.",
                            resource_id=subnet.subnet_id,
                            resource_type="Subnet",
                            recommendation="Use naming convention that indicates subnet type (e.g., 'public-web-1a', 'private-app-1b').",
                            framework=self.framework,
                            rule_id="CUSTOM-OPS-004",
                            compliance_status="WARNING",
                        )
                    )

        return findings

    def _check_security_group_descriptions(self) -> list[AuditFinding]:
        """Check if security groups have meaningful descriptions."""
        findings = []

        for sg in self.topology.security_groups:
            if sg.group_name == "default":
                continue

            # Check for generic or empty descriptions
            desc_lower = sg.description.lower()
            generic_phrases = [
                "security group",
                "sg for",
                "default",
                "created by",
                "managed by terraform",
            ]

            is_generic = any(phrase in desc_lower for phrase in generic_phrases)
            is_short = len(sg.description) < 10

            if is_generic or is_short:
                findings.append(
                    AuditFinding(
                        severity=Severity.INFO,
                        category=AuditCategory.OPERATIONS,
                        title="Security Group Has Generic Description",
                        description=f"Security group '{sg.group_name}' has a generic description: '{sg.description}'",
                        resource_id=sg.group_id,
                        resource_type="Security Group",
                        recommendation="Provide meaningful descriptions that explain the security group's purpose and the resources it protects.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-005",
                        compliance_status="WARNING",
                    )
                )

        return findings

    def _check_unused_security_groups(self) -> list[AuditFinding]:
        """Check for security groups with no rules (potential unused)."""
        findings = []

        for sg in self.topology.security_groups:
            if sg.group_name == "default":
                continue

            # Security group with no ingress rules might be unused
            if not sg.ingress_rules and len(sg.egress_rules) <= 1:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Potentially Unused Security Group",
                        description=f"Security group '{sg.group_name}' has no ingress rules and minimal egress rules.",
                        resource_id=sg.group_id,
                        resource_type="Security Group",
                        recommendation="Review if this security group is in use. Delete unused security groups to reduce clutter.",
                        framework=self.framework,
                        rule_id="CUSTOM-COST-001",
                    )
                )

        return findings

    def _check_overlapping_security_rules(self) -> list[AuditFinding]:
        """Check for overlapping or redundant security group rules."""
        findings = []

        for sg in self.topology.security_groups:
            # Check for duplicate-like ingress rules
            seen_rules = set()
            for rule in sg.ingress_rules:
                rule_key = (
                    rule.ip_protocol,
                    rule.from_port,
                    rule.to_port,
                    tuple(sorted(rule.ip_ranges)),
                )
                if rule_key in seen_rules:
                    findings.append(
                        AuditFinding(
                            severity=Severity.MEDIUM,
                            category=AuditCategory.OPERATIONS,
                            title="Duplicate Security Group Rules",
                            description=f"Security group '{sg.group_name}' has duplicate or overlapping ingress rules.",
                            resource_id=sg.group_id,
                            resource_type="Security Group",
                            recommendation="Remove duplicate rules to simplify security group management.",
                            framework=self.framework,
                            rule_id="CUSTOM-OPS-006",
                        )
                    )
                    break
                seen_rules.add(rule_key)

        return findings

    def _check_nacl_ephemeral_ports(self) -> list[AuditFinding]:
        """Check if NACLs properly allow ephemeral ports for return traffic."""
        findings = []

        for nacl in self.topology.network_acls:
            if nacl.is_default:
                continue

            # Check for egress rules that might block return traffic
            has_ephemeral_allow = False
            for entry in nacl.entries:
                if entry.egress and entry.rule_action == "allow":
                    if entry.port_range:
                        from_port = entry.port_range.get("From", 0)
                        to_port = entry.port_range.get("To", 65535)
                        # Ephemeral ports are typically 1024-65535 or 32768-65535
                        if from_port <= 1024 and to_port >= 65535:
                            has_ephemeral_allow = True
                            break

            if not has_ephemeral_allow and nacl.subnet_associations:
                findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        category=AuditCategory.OPERATIONS,
                        title="NACL May Block Ephemeral Ports",
                        description="Network ACL may not allow ephemeral ports for return traffic, which could break connectivity.",
                        resource_id=nacl.nacl_id,
                        resource_type="Network ACL",
                        recommendation="Ensure NACL allows ephemeral ports (1024-65535) for egress to enable return traffic. "
                        "Add rule allowing TCP/UDP ports 1024-65535 for proper stateless firewall operation.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-007",
                    )
                )

        return findings

    def _check_route_table_complexity(self) -> list[AuditFinding]:
        """Check for overly complex route tables."""
        findings = []

        for rt in self.topology.route_tables:
            if len(rt.routes) > 20:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.OPERATIONS,
                        title="Complex Route Table",
                        description=f"Route table has {len(rt.routes)} routes, which may be difficult to manage.",
                        resource_id=rt.route_table_id,
                        resource_type="Route Table",
                        recommendation="Consider simplifying route table or splitting into multiple tables for better management.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-008",
                    )
                )

        return findings

    def _check_public_subnet_auto_assign(self) -> list[AuditFinding]:
        """Check if public subnets have auto-assign public IP enabled."""
        findings = []

        for subnet in self.topology.subnets:
            # Determine if subnet is public
            is_public = False
            for rt in self.topology.route_tables:
                if subnet.subnet_id in rt.subnet_associations or rt.is_main:
                    for route in rt.routes:
                        if route.gateway_id and route.gateway_id.startswith("igw-"):
                            is_public = True
                            break

            # Public subnet should have auto-assign enabled
            if is_public and not subnet.map_public_ip_on_launch:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.OPERATIONS,
                        title="Public Subnet Auto-Assign Disabled",
                        description=f"Public subnet {subnet.get_tag('Name') or subnet.subnet_id} doesn't auto-assign public IPs.",
                        resource_id=subnet.subnet_id,
                        resource_type="Subnet",
                        recommendation="Enable auto-assign public IPv4 address for public subnets to simplify instance deployment.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-009",
                    )
                )

            # Private subnet should NOT have auto-assign enabled
            if not is_public and subnet.map_public_ip_on_launch:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.SECURITY,
                        title="Private Subnet Auto-Assigns Public IPs",
                        description=f"Private subnet {subnet.get_tag('Name') or subnet.subnet_id} auto-assigns public IPs.",
                        resource_id=subnet.subnet_id,
                        resource_type="Subnet",
                        recommendation="Disable auto-assign public IP for private subnets to prevent accidental internet exposure.",
                        framework=self.framework,
                        rule_id="CUSTOM-SEC-001",
                    )
                )

        return findings
