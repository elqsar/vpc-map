"""Data models for VPC components and audit findings."""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for audit findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AuditCategory(str, Enum):
    """Categories for audit findings."""

    SECURITY = "security"
    COST = "cost"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    OPERATIONS = "operations"


class SubnetClassification(str, Enum):
    """Derived subnet connectivity classifications."""

    PUBLIC = "public"
    PRIVATE_WITH_NAT = "private_with_nat"
    ISOLATED = "isolated"
    ENDPOINT_ONLY = "endpoint_only"


class ExposureState(str, Enum):
    """Derived external exposure states."""

    PUBLICLY_REACHABLE = "publicly_reachable"
    POTENTIALLY_REACHABLE = "potentially_reachable"
    PRIVATELY_REACHABLE_ONLY = "privately_reachable_only"


class Tag(BaseModel):
    """AWS resource tag."""

    key: str
    value: str


class Vpc(BaseModel):
    """VPC resource model."""

    vpc_id: str
    cidr_block: str
    is_default: bool = False
    state: str
    tags: list[Tag] = Field(default_factory=list)
    enable_dns_hostnames: bool = False
    enable_dns_support: bool = True

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class Subnet(BaseModel):
    """Subnet resource model."""

    subnet_id: str
    vpc_id: str
    cidr_block: str
    availability_zone: str
    available_ip_address_count: int
    map_public_ip_on_launch: bool = False
    state: str
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class InternetGateway(BaseModel):
    """Internet Gateway resource model."""

    igw_id: str
    vpc_id: Optional[str] = None
    state: str
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class NatGateway(BaseModel):
    """NAT Gateway resource model."""

    nat_gateway_id: str
    vpc_id: str
    subnet_id: str
    state: str
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class FlowLog(BaseModel):
    """VPC Flow Log resource model."""

    flow_log_id: str
    resource_id: str
    resource_type: str
    traffic_type: str
    log_destination_type: Optional[str] = None
    log_destination: Optional[str] = None
    deliver_logs_status: Optional[str] = None
    flow_log_status: Optional[str] = None
    log_format: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class VpcEndpoint(BaseModel):
    """VPC Endpoint resource model."""

    vpc_endpoint_id: str
    vpc_id: str
    service_name: str
    endpoint_type: str
    state: str
    private_dns_enabled: bool = False
    subnet_ids: list[str] = Field(default_factory=list)
    route_table_ids: list[str] = Field(default_factory=list)
    security_group_ids: list[str] = Field(default_factory=list)
    network_interface_ids: list[str] = Field(default_factory=list)
    policy_document: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class ElasticIp(BaseModel):
    """Elastic IP resource model."""

    allocation_id: Optional[str] = None
    association_id: Optional[str] = None
    public_ip: str
    private_ip_address: Optional[str] = None
    instance_id: Optional[str] = None
    network_interface_id: Optional[str] = None
    network_interface_owner_id: Optional[str] = None
    domain: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None

    @property
    def is_associated(self) -> bool:
        """Check if the Elastic IP is currently associated."""
        return bool(self.association_id or self.instance_id or self.network_interface_id)


class EbsVolume(BaseModel):
    """EBS Volume resource model."""

    volume_id: str
    size: int  # Size in GiB
    volume_type: str  # gp2, gp3, io1, io2, st1, sc1, standard
    state: str  # creating, available, in-use, deleting, deleted, error
    availability_zone: str
    encrypted: bool = False
    kms_key_id: Optional[str] = None
    iops: Optional[int] = None  # Provisioned IOPS
    throughput: Optional[int] = None  # Throughput in MiB/s (gp3, io2)
    multi_attach_enabled: bool = False
    snapshot_id: Optional[str] = None  # Source snapshot
    attachments: list[dict] = Field(default_factory=list)  # Attachment info
    create_time: Optional[datetime] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None

    @property
    def is_attached(self) -> bool:
        """Check if volume is attached to any instance."""
        return len(self.attachments) > 0

    @property
    def instance_ids(self) -> list[str]:
        """Get list of instance IDs this volume is attached to."""
        return [att.get("InstanceId") for att in self.attachments if att.get("InstanceId")]


class Ec2Instance(BaseModel):
    """EC2 Instance resource model."""

    instance_id: str
    instance_type: str  # t2.micro, m5.large, etc.
    state: str  # pending, running, stopping, stopped, shutting-down, terminated
    subnet_id: str
    vpc_id: str
    availability_zone: str
    private_ip_address: Optional[str] = None
    public_ip_address: Optional[str] = None
    private_dns_name: Optional[str] = None
    public_dns_name: Optional[str] = None
    security_groups: list[str] = Field(default_factory=list)  # List of security group IDs
    security_group_names: list[str] = Field(default_factory=list)  # List of security group names
    ami_id: str
    launch_time: Optional[datetime] = None
    platform: Optional[str] = None  # windows or None for Linux
    architecture: Optional[str] = None  # i386, x86_64, arm64, x86_64_mac, arm64_mac
    monitoring_state: str = "disabled"  # enabled or disabled
    iam_instance_profile: Optional[str] = None  # IAM role ARN
    ebs_optimized: bool = False
    root_device_type: str = "ebs"  # ebs or instance-store
    root_device_name: Optional[str] = None
    instance_lifecycle: Optional[str] = None  # spot, scheduled, or None for normal
    spot_instance_request_id: Optional[str] = None
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None

    @property
    def is_running(self) -> bool:
        """Check if instance is in running state."""
        return self.state == "running"

    @property
    def is_spot(self) -> bool:
        """Check if instance is a spot instance."""
        return self.instance_lifecycle == "spot"

    @property
    def has_public_ip(self) -> bool:
        """Check if instance has a public IP address."""
        return self.public_ip_address is not None


class Route(BaseModel):
    """Route in a route table."""

    destination_cidr_block: Optional[str] = None
    destination_ipv6_cidr_block: Optional[str] = None
    gateway_id: Optional[str] = None
    nat_gateway_id: Optional[str] = None
    vpc_endpoint_id: Optional[str] = None
    transit_gateway_id: Optional[str] = None
    egress_only_internet_gateway_id: Optional[str] = None
    vpn_gateway_id: Optional[str] = None
    carrier_gateway_id: Optional[str] = None
    local_gateway_id: Optional[str] = None
    network_interface_id: Optional[str] = None
    vpc_peering_connection_id: Optional[str] = None
    instance_id: Optional[str] = None
    state: str
    origin: str  # CreateRouteTable, CreateRoute, EnableVgwRoutePropagation


class RouteTable(BaseModel):
    """Route Table resource model."""

    route_table_id: str
    vpc_id: str
    routes: list[Route] = Field(default_factory=list)
    subnet_associations: list[str] = Field(default_factory=list)  # List of subnet IDs
    is_main: bool = False
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class IpPermission(BaseModel):
    """IP permission (ingress/egress rule)."""

    ip_protocol: str  # tcp, udp, icmp, or -1 for all
    from_port: Optional[int] = None
    to_port: Optional[int] = None
    ip_ranges: list[str] = Field(default_factory=list)  # CIDR blocks
    ipv6_ranges: list[str] = Field(default_factory=list)  # IPv6 CIDR blocks
    prefix_list_ids: list[str] = Field(default_factory=list)
    user_id_group_pairs: list[str] = Field(default_factory=list)  # Referenced security group IDs


class SecurityGroup(BaseModel):
    """Security Group resource model."""

    group_id: str
    group_name: str
    description: str
    vpc_id: str
    ingress_rules: list[IpPermission] = Field(default_factory=list)
    egress_rules: list[IpPermission] = Field(default_factory=list)
    tags: list[Tag] = Field(default_factory=list)
    attached_enis: list[str] = Field(default_factory=list)  # Network interface IDs using this SG
    is_in_use: bool = False  # Whether any resource uses this security group

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class NetworkAclEntry(BaseModel):
    """Network ACL entry (rule)."""

    rule_number: int
    protocol: str  # tcp, udp, icmp, or -1 for all
    rule_action: str  # allow or deny
    egress: bool  # True for egress, False for ingress
    cidr_block: Optional[str] = None
    ipv6_cidr_block: Optional[str] = None
    icmp_type_code: Optional[dict] = None
    port_range: Optional[dict] = None  # {"From": 80, "To": 80}


class NetworkAcl(BaseModel):
    """Network ACL resource model."""

    nacl_id: str
    vpc_id: str
    is_default: bool = False
    entries: list[NetworkAclEntry] = Field(default_factory=list)
    subnet_associations: list[str] = Field(default_factory=list)  # List of subnet IDs
    tags: list[Tag] = Field(default_factory=list)

    def get_tag(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None


class AuditFinding(BaseModel):
    """Security or best practice audit finding."""

    severity: Severity
    category: AuditCategory
    title: str
    description: str
    resource_id: str
    resource_type: str
    recommendation: str
    framework: str  # "AWS Well-Architected", "CIS", "Custom"
    rule_id: str
    compliance_status: str = "FAILED"  # PASSED, FAILED, WARNING
    discovered_at: datetime = Field(default_factory=datetime.now)


class VpcTopology(BaseModel):
    """Complete VPC topology with all resources."""

    vpc: Vpc
    subnets: list[Subnet] = Field(default_factory=list)
    internet_gateways: list[InternetGateway] = Field(default_factory=list)
    nat_gateways: list[NatGateway] = Field(default_factory=list)
    flow_logs: list[FlowLog] = Field(default_factory=list)
    vpc_endpoints: list[VpcEndpoint] = Field(default_factory=list)
    elastic_ips: list[ElasticIp] = Field(default_factory=list)
    route_tables: list[RouteTable] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(default_factory=list)
    network_acls: list[NetworkAcl] = Field(default_factory=list)
    ec2_instances: list[Ec2Instance] = Field(default_factory=list)
    ebs_volumes: list[EbsVolume] = Field(default_factory=list)
    region: str
    collected_at: datetime = Field(default_factory=datetime.now)


class SubnetAnalysis(BaseModel):
    """Derived network analysis for a subnet."""

    subnet_id: str
    route_table_id: Optional[str] = None
    classification: SubnetClassification
    has_internet_gateway_route: bool = False
    has_nat_route: bool = False
    has_endpoint_access: bool = False


class InstanceExposure(BaseModel):
    """Derived network exposure analysis for an EC2 instance."""

    instance_id: str
    subnet_id: str
    subnet_classification: SubnetClassification
    public_address_source: Optional[str] = None
    has_public_address: bool = False
    internet_route: bool = False
    security_group_exposure: bool = False
    nacl_exposure: bool = False
    exposure_state: ExposureState
    allowed_ports: list[int] = Field(default_factory=list)
    open_admin_ports: list[int] = Field(default_factory=list)
    blocked_ports: list[int] = Field(default_factory=list)
    explanations: list[str] = Field(default_factory=list)


class AuditReport(BaseModel):
    """Complete audit report with all findings."""

    vpc_id: str
    region: str
    findings: list[AuditFinding] = Field(default_factory=list)
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0
    warnings: int = 0
    generated_at: datetime = Field(default_factory=datetime.now)

    def add_finding(self, finding: AuditFinding) -> None:
        """Add a finding to the report and update counters."""
        self.findings.append(finding)
        self.total_checks += 1
        if finding.compliance_status == "PASSED":
            self.passed_checks += 1
        elif finding.compliance_status == "FAILED":
            self.failed_checks += 1
        elif finding.compliance_status == "WARNING":
            self.warnings += 1

    def get_findings_by_severity(self, severity: Severity) -> list[AuditFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: AuditCategory) -> list[AuditFinding]:
        """Get findings filtered by category."""
        return [f for f in self.findings if f.category == category]


class ChangeType(str, Enum):
    """Types of resource changes between snapshots."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"


class FieldChange(BaseModel):
    """A single field-level change within a resource."""

    field: str
    old_value: Any = None
    new_value: Any = None


class ResourceChange(BaseModel):
    """A change to a specific resource between snapshots."""

    resource_type: str
    resource_id: str
    change_type: ChangeType
    field_changes: list[FieldChange] = Field(default_factory=list)


class DerivedChange(BaseModel):
    """A change in derived analysis (subnet classification or instance exposure)."""

    analysis_type: str
    resource_id: str
    field: str
    old_value: Any = None
    new_value: Any = None


class DiffReport(BaseModel):
    """Complete diff report comparing two topology snapshots."""

    vpc_id: str
    region: str
    before_collected_at: datetime
    after_collected_at: datetime
    resource_changes: list[ResourceChange] = Field(default_factory=list)
    derived_changes: list[DerivedChange] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.now)
