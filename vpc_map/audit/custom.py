"""Custom security and best practice audit rules."""

from vpc_map.models import (
    AuditCategory,
    AuditFinding,
    ExposureState,
    Severity,
    SubnetClassification,
    VpcTopology,
)
from vpc_map.network.analysis import analyze_instances, analyze_subnets


class CustomSecurityAuditor:
    """Implements custom security and operational best practices."""

    def __init__(self, topology: VpcTopology):
        """Initialize the auditor with VPC topology."""
        self.topology = topology
        self.framework = "Custom Security Checks"
        self.subnet_analysis = {
            analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
        }
        self.instance_exposure = {
            exposure.instance_id: exposure for exposure in analyze_instances(topology)
        }

    def audit(self) -> list[AuditFinding]:
        """Run all custom security checks."""
        findings = []
        findings.extend(self._check_resource_tagging())
        findings.extend(self._check_subnet_naming())
        findings.extend(self._check_security_group_descriptions())
        findings.extend(self._check_unused_security_groups())
        findings.extend(self._check_overlapping_security_rules())
        findings.extend(self._check_vpc_endpoint_security_groups())
        findings.extend(self._check_nacl_ephemeral_ports())
        findings.extend(self._check_route_table_complexity())
        findings.extend(self._check_public_subnet_auto_assign())
        findings.extend(self._check_elastic_ips())
        findings.extend(self._check_instance_reachability())
        findings.extend(self._check_public_ip_in_non_public_subnet())
        findings.extend(self._check_internet_path_controls())
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

            if not sg.is_in_use:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Potentially Unused Security Group",
                        description=f"Security group '{sg.group_name}' is not attached to any network interfaces.",
                        resource_id=sg.group_id,
                        resource_type="Security Group",
                        recommendation="Review whether this security group is still needed. Delete unused groups to reduce clutter and tighten rule management.",
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

    def _check_vpc_endpoint_security_groups(self) -> list[AuditFinding]:
        """Check whether interface endpoint security groups are exposed too broadly."""
        findings = []
        security_groups = {sg.group_id: sg for sg in self.topology.security_groups}

        for endpoint in self.topology.vpc_endpoints:
            if endpoint.endpoint_type.lower() != "interface":
                continue

            for group_id in endpoint.security_group_ids:
                security_group = security_groups.get(group_id)
                if not security_group:
                    continue

                for rule in security_group.ingress_rules:
                    if "0.0.0.0/0" in rule.ip_ranges or "::/0" in rule.ipv6_ranges:
                        findings.append(
                            AuditFinding(
                                severity=Severity.HIGH,
                                category=AuditCategory.SECURITY,
                                title="Interface Endpoint Security Group Open Broadly",
                                description=f"Security group '{security_group.group_name}' attached to endpoint {endpoint.vpc_endpoint_id} allows ingress from anywhere.",
                                resource_id=security_group.group_id,
                                resource_type="Security Group",
                                recommendation="Restrict interface endpoint security groups to the specific client subnets or application security groups that need private service access.",
                                framework=self.framework,
                                rule_id="CUSTOM-SEC-002",
                            )
                        )
                        break

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
                        # Ephemeral ranges commonly include 1024-65535 or 32768-65535.
                        if from_port <= 32768 and to_port >= 65535:
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
            is_public = (
                self.subnet_analysis[subnet.subnet_id].classification
                == SubnetClassification.PUBLIC
            )

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

    def _check_elastic_ips(self) -> list[AuditFinding]:
        """Check Elastic IP associations for waste and unexpected exposure."""
        findings = []
        instances = {instance.instance_id: instance for instance in self.topology.ec2_instances}

        for elastic_ip in self.topology.elastic_ips:
            if not elastic_ip.is_associated:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Unassociated Elastic IP",
                        description=f"Elastic IP {elastic_ip.public_ip} is allocated but not associated with any resource.",
                        resource_id=elastic_ip.allocation_id or elastic_ip.public_ip,
                        resource_type="Elastic IP",
                        recommendation="Release unused Elastic IPs to avoid unnecessary charges and reduce public-IP sprawl.",
                        framework=self.framework,
                        rule_id="CUSTOM-COST-002",
                    )
                )
                continue

            if elastic_ip.instance_id:
                instance = instances.get(elastic_ip.instance_id)
                if (
                    instance
                    and self.subnet_analysis[instance.subnet_id].classification
                    != SubnetClassification.PUBLIC
                ):
                    findings.append(
                        AuditFinding(
                            severity=Severity.HIGH,
                            category=AuditCategory.SECURITY,
                            title="Elastic IP Attached To Instance In Private Subnet",
                            description=f"Elastic IP {elastic_ip.public_ip} is attached to instance {instance.instance_id} in subnet {instance.subnet_id}, which does not have direct internet gateway routing.",
                            resource_id=elastic_ip.allocation_id or elastic_ip.public_ip,
                            resource_type="Elastic IP",
                            recommendation="Review whether the instance should be publicly addressable. Remove the Elastic IP or move the workload to an intentionally public subnet.",
                            framework=self.framework,
                            rule_id="CUSTOM-SEC-003",
                        )
                    )

        return findings

    def _check_instance_reachability(self) -> list[AuditFinding]:
        """Check whether instances are directly reachable on admin ports."""
        findings = []

        for instance in self.topology.ec2_instances:
            exposure = self.instance_exposure[instance.instance_id]
            if (
                exposure.exposure_state == ExposureState.PUBLICLY_REACHABLE
                and exposure.open_admin_ports
            ):
                findings.append(
                    AuditFinding(
                        severity=Severity.CRITICAL,
                        category=AuditCategory.SECURITY,
                        title="Instance Reachable From Internet On Admin Port",
                        description=(
                            f"Instance {instance.instance_id} is publicly reachable on "
                            f"admin port(s) {', '.join(map(str, exposure.open_admin_ports))}."
                        ),
                        resource_id=instance.instance_id,
                        resource_type="EC2 Instance",
                        recommendation="Restrict internet ingress on admin ports by removing public addressing, moving the workload behind controlled access paths, or tightening security groups and NACLs.",
                        framework=self.framework,
                        rule_id="CUSTOM-SEC-004",
                    )
                )

        return findings

    def _check_public_ip_in_non_public_subnet(self) -> list[AuditFinding]:
        """Check for public addressing on instances outside public subnets."""
        findings = []

        for instance in self.topology.ec2_instances:
            exposure = self.instance_exposure[instance.instance_id]
            if (
                exposure.has_public_address
                and exposure.subnet_classification != SubnetClassification.PUBLIC
            ):
                findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        category=AuditCategory.SECURITY,
                        title="Public IP Attached To Instance In Non-Public Subnet",
                        description=(
                            f"Instance {instance.instance_id} has public address source "
                            f"'{exposure.public_address_source}' in a "
                            f"{exposure.subnet_classification.value} subnet."
                        ),
                        resource_id=instance.instance_id,
                        resource_type="EC2 Instance",
                        recommendation="Remove public addressing from workloads outside intentionally public subnets, or correct the subnet routing design if the subnet should be public.",
                        framework=self.framework,
                        rule_id="CUSTOM-SEC-005",
                    )
                )

        return findings

    def _check_internet_path_controls(self) -> list[AuditFinding]:
        """Check for internet paths that are inconsistent with SG or NACL controls."""
        findings = []

        for instance in self.topology.ec2_instances:
            exposure = self.instance_exposure[instance.instance_id]
            if not exposure.internet_route or not exposure.has_public_address:
                continue

            if exposure.allowed_ports and exposure.blocked_ports:
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.OPERATIONS,
                        title="Internet Path Present But NACL Blocks Tracked Traffic",
                        description=(
                            f"Instance {instance.instance_id} has an internet route and public "
                            f"addressing, but the subnet NACL blocks tracked port(s) "
                            f"{', '.join(map(str, exposure.blocked_ports))}."
                        ),
                        resource_id=instance.instance_id,
                        resource_type="EC2 Instance",
                        recommendation="Align NACL rules with the intended internet-facing ports, or remove the public route/public address if the workload is not meant to be reachable.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-010",
                        compliance_status="WARNING",
                    )
                )
            elif not exposure.security_group_exposure:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.OPERATIONS,
                        title="Internet Path Present But Security Groups Block Tracked Traffic",
                        description=(
                            f"Instance {instance.instance_id} has an internet route and public "
                            "addressing, but no tracked security group ingress rule is open to the internet."
                        ),
                        resource_id=instance.instance_id,
                        resource_type="EC2 Instance",
                        recommendation="Either remove unnecessary public routing/public addressing or document that the workload is intentionally non-public despite having an internet path.",
                        framework=self.framework,
                        rule_id="CUSTOM-OPS-011",
                        compliance_status="WARNING",
                    )
                )

        return findings
