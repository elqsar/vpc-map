"""Tests for data models."""

from vpc_map.models import (
    AuditCategory,
    AuditFinding,
    AuditReport,
    ElasticIp,
    FlowLog,
    IpPermission,
    SecurityGroup,
    Severity,
    Subnet,
    Tag,
    Vpc,
    VpcEndpoint,
    VpcTopology,
)


def test_vpc_model():
    """Test VPC model creation and tag retrieval."""
    vpc = Vpc(
        vpc_id="vpc-12345",
        cidr_block="10.0.0.0/16",
        is_default=False,
        state="available",
        tags=[Tag(key="Name", value="test-vpc"), Tag(key="Environment", value="dev")],
        enable_dns_support=True,
        enable_dns_hostnames=True,
    )

    assert vpc.vpc_id == "vpc-12345"
    assert vpc.get_tag("Name") == "test-vpc"
    assert vpc.get_tag("Environment") == "dev"
    assert vpc.get_tag("NonExistent") is None


def test_subnet_model():
    """Test Subnet model creation."""
    subnet = Subnet(
        subnet_id="subnet-12345",
        vpc_id="vpc-12345",
        cidr_block="10.0.1.0/24",
        availability_zone="us-east-1a",
        available_ip_address_count=251,
        map_public_ip_on_launch=True,
        state="available",
    )

    assert subnet.subnet_id == "subnet-12345"
    assert subnet.available_ip_address_count == 251
    assert subnet.map_public_ip_on_launch is True


def test_security_group_model():
    """Test Security Group model with rules."""
    ingress_rule = IpPermission(
        ip_protocol="tcp",
        from_port=80,
        to_port=80,
        ip_ranges=["0.0.0.0/0"],
    )

    egress_rule = IpPermission(
        ip_protocol="-1",
        ip_ranges=["0.0.0.0/0"],
    )

    sg = SecurityGroup(
        group_id="sg-12345",
        group_name="web-sg",
        description="Web server security group",
        vpc_id="vpc-12345",
        ingress_rules=[ingress_rule],
        egress_rules=[egress_rule],
    )

    assert sg.group_id == "sg-12345"
    assert len(sg.ingress_rules) == 1
    assert sg.ingress_rules[0].from_port == 80
    assert "0.0.0.0/0" in sg.ingress_rules[0].ip_ranges


def test_audit_finding_model():
    """Test Audit Finding model creation."""
    finding = AuditFinding(
        severity=Severity.HIGH,
        category=AuditCategory.SECURITY,
        title="Test Finding",
        description="This is a test security finding",
        resource_id="sg-12345",
        resource_type="Security Group",
        recommendation="Fix the issue",
        framework="Test Framework",
        rule_id="TEST-001",
    )

    assert finding.severity == Severity.HIGH
    assert finding.category == AuditCategory.SECURITY
    assert finding.compliance_status == "FAILED"


def test_audit_report():
    """Test Audit Report model and finding management."""
    report = AuditReport(
        vpc_id="vpc-12345",
        region="us-east-1",
    )

    # Add findings
    finding1 = AuditFinding(
        severity=Severity.HIGH,
        category=AuditCategory.SECURITY,
        title="Finding 1",
        description="Test",
        resource_id="sg-1",
        resource_type="SG",
        recommendation="Fix it",
        framework="Test",
        rule_id="T-001",
        compliance_status="FAILED",
    )

    finding2 = AuditFinding(
        severity=Severity.MEDIUM,
        category=AuditCategory.COST,
        title="Finding 2",
        description="Test",
        resource_id="sg-2",
        resource_type="SG",
        recommendation="Fix it",
        framework="Test",
        rule_id="T-002",
        compliance_status="PASSED",
    )

    report.add_finding(finding1)
    report.add_finding(finding2)

    assert report.total_checks == 2
    assert report.failed_checks == 1
    assert report.passed_checks == 1

    # Test filtering
    high_findings = report.get_findings_by_severity(Severity.HIGH)
    assert len(high_findings) == 1
    assert high_findings[0].title == "Finding 1"

    security_findings = report.get_findings_by_category(AuditCategory.SECURITY)
    assert len(security_findings) == 1


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_audit_category_enum():
    """Test AuditCategory enum values."""
    assert AuditCategory.SECURITY.value == "security"
    assert AuditCategory.COST.value == "cost"
    assert AuditCategory.RELIABILITY.value == "reliability"
    assert AuditCategory.PERFORMANCE.value == "performance"
    assert AuditCategory.OPERATIONS.value == "operations"


def test_flow_log_model():
    """Test Flow Log model creation."""
    flow_log = FlowLog(
        flow_log_id="fl-12345",
        resource_id="vpc-12345",
        resource_type="VPC",
        traffic_type="ALL",
        log_destination_type="cloud-watch-logs",
        log_destination="arn:aws:logs:us-east-1:123456789012:log-group:test",
        deliver_logs_status="SUCCESS",
        flow_log_status="ACTIVE",
        log_format="${srcaddr} ${dstaddr}",
    )

    assert flow_log.flow_log_id == "fl-12345"
    assert flow_log.resource_type == "VPC"
    assert flow_log.traffic_type == "ALL"


def test_vpc_endpoint_model():
    """Test VPC endpoint model creation."""
    endpoint = VpcEndpoint(
        vpc_endpoint_id="vpce-12345",
        vpc_id="vpc-12345",
        service_name="com.amazonaws.us-east-1.s3",
        endpoint_type="Gateway",
        state="available",
        route_table_ids=["rtb-12345"],
    )

    assert endpoint.vpc_endpoint_id == "vpce-12345"
    assert endpoint.endpoint_type == "Gateway"
    assert endpoint.route_table_ids == ["rtb-12345"]


def test_elastic_ip_model_association():
    """Test Elastic IP association helper."""
    elastic_ip = ElasticIp(
        allocation_id="eipalloc-12345",
        association_id="eipassoc-12345",
        public_ip="203.0.113.10",
        instance_id="i-12345",
    )

    assert elastic_ip.is_associated is True


def test_vpc_topology_new_resource_defaults():
    """Test topology defaults for Phase 1 resource collections."""
    topology = VpcTopology(
        vpc=Vpc(
            vpc_id="vpc-12345",
            cidr_block="10.0.0.0/16",
            is_default=False,
            state="available",
        ),
        region="us-east-1",
    )

    assert topology.flow_logs == []
    assert topology.vpc_endpoints == []
    assert topology.elastic_ips == []
