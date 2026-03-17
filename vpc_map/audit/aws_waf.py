"""AWS Well-Architected Framework audit rules."""

from vpc_map.models import (
    AuditCategory,
    AuditFinding,
    Severity,
    SubnetClassification,
    VpcTopology,
)
from vpc_map.network.analysis import analyze_subnets


class AWSWellArchitectedAuditor:
    """Implements AWS Well-Architected Framework best practices."""

    APPROVED_FLOW_LOG_DESTINATIONS = {"cloud-watch-logs", "s3"}
    ACTIVE_ENDPOINT_STATES = {"available", "pending"}

    def __init__(self, topology: VpcTopology):
        """Initialize the auditor with VPC topology."""
        self.topology = topology
        self.framework = "AWS Well-Architected"
        self.subnet_analysis = {
            analysis.subnet_id: analysis for analysis in analyze_subnets(topology)
        }

    def audit(self) -> list[AuditFinding]:
        """Run all AWS Well-Architected checks."""
        findings = []
        findings.extend(self._check_vpc_flow_logs())
        findings.extend(self._check_dns_settings())
        findings.extend(self._check_subnet_availability())
        findings.extend(self._check_nat_gateway_redundancy())
        findings.extend(self._check_vpc_endpoints())
        findings.extend(self._check_unused_resources())
        findings.extend(self._check_default_security_group())
        findings.extend(self._check_network_segmentation())
        return findings

    def _check_vpc_flow_logs(self) -> list[AuditFinding]:
        """Check whether real VPC Flow Logs are enabled and healthy."""
        findings = []
        vpc_flow_logs = [
            flow_log
            for flow_log in self.topology.flow_logs
            if flow_log.resource_id == self.topology.vpc.vpc_id
        ]
        subnet_flow_logs = [
            flow_log
            for flow_log in self.topology.flow_logs
            if flow_log.resource_type.lower() == "subnet"
        ]

        if not self.topology.flow_logs:
            findings.append(
                AuditFinding(
                    severity=Severity.MEDIUM,
                    category=AuditCategory.SECURITY,
                    title="VPC Flow Logs Not Enabled",
                    description="No VPC or subnet flow logs were found for this VPC.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Enable VPC Flow Logs for the VPC or all subnets to capture network telemetry for security analysis, troubleshooting, and compliance.",
                    framework=self.framework,
                    rule_id="WAF-SEC-001",
                )
            )
            return findings

        if not vpc_flow_logs and subnet_flow_logs:
            findings.append(
                AuditFinding(
                    severity=Severity.LOW,
                    category=AuditCategory.OPERATIONS,
                    title="Flow Logs Enabled Only At Subnet Scope",
                    description="Subnet flow logs exist, but there is no VPC-level flow log covering the entire VPC.",
                    resource_id=self.topology.vpc.vpc_id,
                    resource_type="VPC",
                    recommendation="Add a VPC-level flow log or ensure every subnet is intentionally covered and managed consistently.",
                    framework=self.framework,
                    rule_id="WAF-OPS-010",
                    compliance_status="WARNING",
                )
            )

        for flow_log in self.topology.flow_logs:
            flow_log_status = (flow_log.flow_log_status or "").lower()
            deliver_status = (flow_log.deliver_logs_status or "").lower()
            if flow_log_status and flow_log_status != "active":
                findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        category=AuditCategory.SECURITY,
                        title="Flow Log Is Not Active",
                        description=f"Flow log {flow_log.flow_log_id} for {flow_log.resource_id} is in '{flow_log.flow_log_status}' state.",
                        resource_id=flow_log.flow_log_id,
                        resource_type="Flow Log",
                        recommendation="Investigate the flow log configuration and reactivate or recreate the flow log so network events are delivered reliably.",
                        framework=self.framework,
                        rule_id="WAF-SEC-002",
                    )
                )
            elif deliver_status and deliver_status not in {"success"}:
                findings.append(
                    AuditFinding(
                        severity=Severity.HIGH,
                        category=AuditCategory.OPERATIONS,
                        title="Flow Log Delivery Is Failing",
                        description=f"Flow log {flow_log.flow_log_id} reports delivery status '{flow_log.deliver_logs_status}'.",
                        resource_id=flow_log.flow_log_id,
                        resource_type="Flow Log",
                        recommendation="Review IAM permissions and destination configuration to restore successful log delivery.",
                        framework=self.framework,
                        rule_id="WAF-OPS-011",
                    )
                )

            if flow_log.traffic_type.upper() != "ALL":
                findings.append(
                    AuditFinding(
                        severity=Severity.MEDIUM,
                        category=AuditCategory.SECURITY,
                        title="Flow Log Does Not Capture All Traffic",
                        description=f"Flow log {flow_log.flow_log_id} captures only '{flow_log.traffic_type}' traffic.",
                        resource_id=flow_log.flow_log_id,
                        resource_type="Flow Log",
                        recommendation="Use traffic type 'ALL' when comprehensive network monitoring or compliance coverage is required.",
                        framework=self.framework,
                        rule_id="WAF-SEC-003",
                        compliance_status="WARNING",
                    )
                )

            destination_type = (flow_log.log_destination_type or "").lower()
            if destination_type and destination_type not in self.APPROVED_FLOW_LOG_DESTINATIONS:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.OPERATIONS,
                        title="Flow Log Uses Non-Standard Destination",
                        description=f"Flow log {flow_log.flow_log_id} delivers to destination type '{flow_log.log_destination_type}'.",
                        resource_id=flow_log.flow_log_id,
                        resource_type="Flow Log",
                        recommendation="Prefer CloudWatch Logs or S3 unless a different destination is explicitly required and governed.",
                        framework=self.framework,
                        rule_id="WAF-OPS-012",
                        compliance_status="WARNING",
                    )
                )

        return findings

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
                if (
                    self.subnet_analysis[subnet.subnet_id].classification
                    != SubnetClassification.PUBLIC
                ):
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

    def _check_vpc_endpoints(self) -> list[AuditFinding]:
        """Check VPC endpoint health and private-service access posture."""
        findings = []
        active_endpoints = [
            endpoint
            for endpoint in self.topology.vpc_endpoints
            if endpoint.state.lower() in self.ACTIVE_ENDPOINT_STATES
        ]

        for endpoint in self.topology.vpc_endpoints:
            endpoint_type = endpoint.endpoint_type.lower()
            endpoint_state = endpoint.state.lower()
            if endpoint_state in {"rejected", "failed", "deleted", "deleting", "pendingacceptance"}:
                findings.append(
                    AuditFinding(
                        severity=Severity.LOW,
                        category=AuditCategory.COST,
                        title="Inactive Or Rejected VPC Endpoint",
                        description=f"VPC endpoint {endpoint.vpc_endpoint_id} for {endpoint.service_name} is in '{endpoint.state}' state.",
                        resource_id=endpoint.vpc_endpoint_id,
                        resource_type="VPC Endpoint",
                        recommendation="Remove unused endpoints or resolve the endpoint state so the configuration reflects intended service access.",
                        framework=self.framework,
                        rule_id="WAF-COST-003",
                        compliance_status="WARNING",
                    )
                )

            if endpoint_type == "interface" and endpoint_state in self.ACTIVE_ENDPOINT_STATES:
                if not endpoint.private_dns_enabled:
                    findings.append(
                        AuditFinding(
                            severity=Severity.LOW,
                            category=AuditCategory.OPERATIONS,
                            title="Interface Endpoint Private DNS Disabled",
                            description=f"Interface endpoint {endpoint.vpc_endpoint_id} for {endpoint.service_name} has private DNS disabled.",
                            resource_id=endpoint.vpc_endpoint_id,
                            resource_type="VPC Endpoint",
                            recommendation="Enable private DNS unless clients are expected to use explicit VPC endpoint DNS names.",
                            framework=self.framework,
                            rule_id="WAF-OPS-013",
                            compliance_status="WARNING",
                        )
                    )

        active_nats = [
            nat for nat in self.topology.nat_gateways if nat.state.lower() in {"available", "pending"}
        ]
        private_subnets = [
            subnet
            for subnet in self.topology.subnets
            if self.subnet_analysis[subnet.subnet_id].classification
            != SubnetClassification.PUBLIC
        ]
        gateway_services = {
            endpoint.service_name.lower(): endpoint
            for endpoint in active_endpoints
            if endpoint.endpoint_type.lower() == "gateway"
        }
        if active_nats and private_subnets:
            for service_suffix, service_name in {
                ".s3": "S3",
                ".dynamodb": "DynamoDB",
            }.items():
                if not any(name.endswith(service_suffix) for name in gateway_services):
                    findings.append(
                        AuditFinding(
                            severity=Severity.LOW,
                            category=AuditCategory.COST,
                            title=f"Missing {service_name} Gateway Endpoint",
                            description=f"Private subnets use NAT gateways, but no active {service_name} gateway endpoint was found.",
                            resource_id=self.topology.vpc.vpc_id,
                            resource_type="VPC",
                            recommendation=f"Consider adding a {service_name} gateway endpoint to reduce NAT traffic and keep AWS service access private.",
                            framework=self.framework,
                            rule_id=f"WAF-COST-{service_name.upper()}-001",
                            compliance_status="WARNING",
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
            if self.subnet_analysis[subnet.subnet_id].classification == SubnetClassification.PUBLIC:
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
