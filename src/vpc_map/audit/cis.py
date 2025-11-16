"""CIS AWS Foundations Benchmark audit rules."""

from vpc_map.models import AuditCategory, AuditFinding, Severity, VpcTopology


class CISBenchmarkAuditor:
    """Implements CIS AWS Foundations Benchmark network security checks."""

    def __init__(self, topology: VpcTopology):
        """Initialize the auditor with VPC topology."""
        self.topology = topology
        self.framework = "CIS AWS Foundations Benchmark"

    def audit(self) -> list[AuditFinding]:
        """Run all CIS benchmark checks."""
        findings = []
        findings.extend(self._check_default_security_group())
        findings.extend(self._check_security_group_rules())
        findings.extend(self._check_nacl_rules())
        findings.extend(self._check_vpc_peering())
        findings.extend(self._check_unrestricted_access())
        return findings

    def _check_default_security_group(self) -> list[AuditFinding]:
        """CIS 5.3: Ensure the default security group restricts all traffic."""
        findings = []

        for sg in self.topology.security_groups:
            if sg.group_name == "default":
                # Default SG should have no inbound or outbound rules
                if sg.ingress_rules:
                    findings.append(
                        AuditFinding(
                            severity=Severity.CRITICAL,
                            category=AuditCategory.SECURITY,
                            title="Default Security Group Has Ingress Rules",
                            description=f"Default security group has {len(sg.ingress_rules)} ingress rule(s). "
                            "CIS recommends default security groups restrict all traffic.",
                            resource_id=sg.group_id,
                            resource_type="Security Group",
                            recommendation="Remove all ingress rules from the default security group. "
                            "Use custom security groups with least-privilege rules instead.",
                            framework=self.framework,
                            rule_id="CIS-5.3-001",
                        )
                    )

                # Check egress rules (default has allow all)
                for egress in sg.egress_rules:
                    if egress.ip_protocol == "-1" and (
                        "0.0.0.0/0" in egress.ip_ranges or "::/0" in egress.ipv6_ranges
                    ):
                        findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                category=AuditCategory.SECURITY,
                                title="Default Security Group Allows All Egress",
                                description="Default security group allows all outbound traffic.",
                                resource_id=sg.group_id,
                                resource_type="Security Group",
                                recommendation="Remove the 'allow all' egress rule from the default security group.",
                                framework=self.framework,
                                rule_id="CIS-5.3-002",
                            )
                        )
                        break

        return findings

    def _check_security_group_rules(self) -> list[AuditFinding]:
        """Check for overly permissive security group rules."""
        findings = []

        dangerous_ports = {
            22: "SSH",
            3389: "RDP",
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            5984: "CouchDB",
            9200: "Elasticsearch",
        }

        for sg in self.topology.security_groups:
            # Check ingress rules
            for rule in sg.ingress_rules:
                # Check for 0.0.0.0/0 access
                if "0.0.0.0/0" in rule.ip_ranges or "::/0" in rule.ipv6_ranges:
                    # All ports open
                    if rule.ip_protocol == "-1":
                        findings.append(
                            AuditFinding(
                                severity=Severity.CRITICAL,
                                category=AuditCategory.SECURITY,
                                title="Security Group Allows All Protocols from Anywhere",
                                description=f"Security group '{sg.group_name}' allows all protocols and ports from 0.0.0.0/0.",
                                resource_id=sg.group_id,
                                resource_type="Security Group",
                                recommendation="Restrict ingress rules to specific protocols, ports, and source IPs. "
                                "Never allow all traffic from the internet.",
                                framework=self.framework,
                                rule_id="CIS-5.1-001",
                            )
                        )

                    # Check for dangerous ports open to internet
                    if rule.from_port in dangerous_ports:
                        findings.append(
                            AuditFinding(
                                severity=Severity.CRITICAL,
                                category=AuditCategory.SECURITY,
                                title=f"{dangerous_ports[rule.from_port]} Port Open to Internet",
                                description=f"Security group '{sg.group_name}' allows {dangerous_ports[rule.from_port]} "
                                f"(port {rule.from_port}) from 0.0.0.0/0.",
                                resource_id=sg.group_id,
                                resource_type="Security Group",
                                recommendation=f"Restrict {dangerous_ports[rule.from_port]} access to specific IP ranges. "
                                "Use VPN or bastion hosts for administrative access.",
                                framework=self.framework,
                                rule_id=f"CIS-5.2-{rule.from_port:03d}",
                            )
                        )

                    # Check for port ranges
                    if rule.from_port and rule.to_port and rule.to_port - rule.from_port > 100:
                        findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                category=AuditCategory.SECURITY,
                                title="Wide Port Range Open to Internet",
                                description=f"Security group '{sg.group_name}' allows ports {rule.from_port}-{rule.to_port} from 0.0.0.0/0.",
                                resource_id=sg.group_id,
                                resource_type="Security Group",
                                recommendation="Limit port ranges to only what is necessary. "
                                "Define specific rules for each required service.",
                                framework=self.framework,
                                rule_id="CIS-5.1-002",
                            )
                        )

        return findings

    def _check_nacl_rules(self) -> list[AuditFinding]:
        """Check Network ACL rules for security issues."""
        findings = []

        for nacl in self.topology.network_acls:
            # Skip default NACLs as they typically allow all
            if nacl.is_default:
                continue

            # Check for overly permissive allow rules
            for entry in nacl.entries:
                if entry.rule_action == "allow" and entry.rule_number < 32767:
                    # Check for allow all from anywhere
                    if (
                        entry.cidr_block == "0.0.0.0/0" or entry.ipv6_cidr_block == "::/0"
                    ) and entry.protocol == "-1":
                        rule_type = "Egress" if entry.egress else "Ingress"
                        findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                category=AuditCategory.SECURITY,
                                title=f"NACL Allows All {rule_type} Traffic",
                                description=f"Network ACL has a rule (#{entry.rule_number}) that allows all {rule_type.lower()} traffic.",
                                resource_id=nacl.nacl_id,
                                resource_type="Network ACL",
                                recommendation="Review NACL rules and apply principle of least privilege. "
                                "Only allow necessary protocols and ports.",
                                framework=self.framework,
                                rule_id="CIS-5.4-001",
                            )
                        )

            # Check for deny rules that might be too broad
            deny_all_rules = [
                entry
                for entry in nacl.entries
                if entry.rule_action == "deny"
                and (entry.cidr_block == "0.0.0.0/0" or entry.ipv6_cidr_block == "::/0")
                and entry.rule_number < 100
            ]

            if deny_all_rules and len(nacl.subnet_associations) > 0:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.OPERATIONS,
                        title="NACL Has Early Deny All Rule",
                        description="Network ACL has a broad deny rule with low rule number, which may block legitimate traffic.",
                        resource_id=nacl.nacl_id,
                        resource_type="Network ACL",
                        recommendation="Review NACL rule ordering. Ensure deny rules don't inadvertently block required traffic.",
                        framework=self.framework,
                        rule_id="CIS-5.4-002",
                    )
                )

        return findings

    def _check_vpc_peering(self) -> list[AuditFinding]:
        """Check for VPC peering connections in route tables."""
        findings = []

        for rt in self.topology.route_tables:
            for route in rt.routes:
                if route.vpc_peering_connection_id:
                    # VPC peering found - this is informational
                    findings.append(
                        AuditFinding(
                            severity=Severity.INFO,
                            category=AuditCategory.SECURITY,
                            title="VPC Peering Connection Detected",
                            description=f"Route table has a route to VPC peering connection {route.vpc_peering_connection_id}.",
                            resource_id=rt.route_table_id,
                            resource_type="Route Table",
                            recommendation="Ensure VPC peering connections are properly secured and only exist with trusted VPCs. "
                            "Review and audit peering connections regularly.",
                            framework=self.framework,
                            rule_id="CIS-5.5-001",
                            compliance_status="WARNING",
                        )
                    )

        return findings

    def _check_unrestricted_access(self) -> list[AuditFinding]:
        """CIS 5.1: Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports."""
        findings = []

        admin_ports = {
            22: "SSH",
            3389: "RDP",
        }

        for nacl in self.topology.network_acls:
            for entry in nacl.entries:
                if (
                    not entry.egress
                    and entry.rule_action == "allow"
                    and entry.cidr_block == "0.0.0.0/0"
                ):
                    # Check if it covers admin ports
                    if entry.port_range:
                        from_port = entry.port_range.get("From", 0)
                        to_port = entry.port_range.get("To", 65535)

                        for port, service in admin_ports.items():
                            if from_port <= port <= to_port:
                                findings.append(
                                    AuditFinding(
                                        severity=Severity.CRITICAL,
                                        category=AuditCategory.SECURITY,
                                        title=f"NACL Allows {service} from Internet",
                                        description=f"Network ACL allows {service} (port {port}) ingress from 0.0.0.0/0 in rule #{entry.rule_number}.",
                                        resource_id=nacl.nacl_id,
                                        resource_type="Network ACL",
                                        recommendation=f"Restrict {service} access to specific IP ranges. "
                                        "Use VPN or bastion hosts for administrative access.",
                                        framework=self.framework,
                                        rule_id=f"CIS-5.1-{port:03d}",
                                    )
                                )

        return findings
