"""Data models for VPC components and audit findings."""

from datetime import datetime
from enum import Enum
from typing import Optional

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


class Route(BaseModel):
    """Route in a route table."""

    destination_cidr_block: Optional[str] = None
    destination_ipv6_cidr_block: Optional[str] = None
    gateway_id: Optional[str] = None
    nat_gateway_id: Optional[str] = None
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
    route_tables: list[RouteTable] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(default_factory=list)
    network_acls: list[NetworkAcl] = Field(default_factory=list)
    ebs_volumes: list[EbsVolume] = Field(default_factory=list)
    region: str
    collected_at: datetime = Field(default_factory=datetime.now)


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
