"""HTML report generator."""

import base64
from pathlib import Path

from jinja2 import Template

from vpc_map.models import AuditReport, ChangeType, DiffReport, VpcTopology

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPC Analysis Report - {{ vpc_id }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-left: 10px;
            border-left: 4px solid #3498db;
        }
        h3 {
            color: #34495e;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .meta {
            color: #7f8c8d;
            margin-bottom: 20px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .summary-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }
        .summary-card h3 {
            margin: 0;
            font-size: 14px;
            color: #7f8c8d;
            text-transform: uppercase;
        }
        .summary-card .value {
            font-size: 32px;
            font-weight: bold;
            margin-top: 10px;
        }
        .summary-card.passed .value { color: #27ae60; }
        .summary-card.failed .value { color: #e74c3c; }
        .summary-card.warnings .value { color: #f39c12; }
        .diagram {
            text-align: center;
            margin: 30px 0;
            padding: 20px;
            background: #fafafa;
            border-radius: 6px;
        }
        .diagram img {
            max-width: 100%;
            height: auto;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
            font-weight: 600;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .finding {
            margin: 20px 0;
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid;
        }
        .finding.critical {
            background-color: #fee;
            border-left-color: #c0392b;
        }
        .finding.high {
            background-color: #fef5e7;
            border-left-color: #e74c3c;
        }
        .finding.medium {
            background-color: #fef9e7;
            border-left-color: #f39c12;
        }
        .finding.low {
            background-color: #e8f8f5;
            border-left-color: #3498db;
        }
        .finding.info {
            background-color: #ebf5fb;
            border-left-color: #5dade2;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .finding-title {
            font-size: 18px;
            font-weight: 600;
        }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }
        .severity-badge.critical { background-color: #c0392b; }
        .severity-badge.high { background-color: #e74c3c; }
        .severity-badge.medium { background-color: #f39c12; }
        .severity-badge.low { background-color: #3498db; }
        .severity-badge.info { background-color: #5dade2; }
        .finding-meta {
            color: #7f8c8d;
            font-size: 14px;
            margin: 10px 0;
        }
        .finding-description {
            margin: 15px 0;
            line-height: 1.8;
        }
        .recommendation {
            background-color: rgba(52, 152, 219, 0.1);
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
        }
        .recommendation-title {
            font-weight: 600;
            color: #2980b9;
            margin-bottom: 8px;
        }
        .tag {
            display: inline-block;
            background-color: #ecf0f1;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            margin-right: 5px;
            color: #34495e;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            text-align: center;
            color: #7f8c8d;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>VPC Analysis Report</h1>
        <div class="meta">
            <strong>VPC ID:</strong> {{ vpc_id }}<br>
            <strong>Region:</strong> {{ region }}<br>
            <strong>Generated:</strong> {{ generated_at }}<br>
            <strong>CIDR:</strong> {{ vpc_cidr }}
        </div>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Resources</h3>
                <div class="value">{{ total_resources }}</div>
            </div>
            <div class="summary-card">
                <h3>Total Checks</h3>
                <div class="value">{{ total_checks }}</div>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <div class="value">{{ passed_checks }}</div>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <div class="value">{{ failed_checks }}</div>
            </div>
            <div class="summary-card warnings">
                <h3>Warnings</h3>
                <div class="value">{{ warnings }}</div>
            </div>
        </div>

        {% if diagram_data %}
        <h2>VPC Topology Diagram</h2>
        <div class="diagram">
            <img src="data:image/png;base64,{{ diagram_data }}" alt="VPC Topology Diagram">
        </div>
        {% endif %}

        <h2>Resource Inventory</h2>
        <h3>Subnets ({{ subnets|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>ID</th>
                    <th>CIDR</th>
                    <th>AZ</th>
                    <th>Available IPs</th>
                </tr>
            </thead>
            <tbody>
                {% for subnet in subnets %}
                <tr>
                    <td>{{ subnet.name }}</td>
                    <td><code>{{ subnet.subnet_id }}</code></td>
                    <td>{{ subnet.cidr_block }}</td>
                    <td>{{ subnet.availability_zone }}</td>
                    <td>{{ subnet.available_ip_address_count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if nat_gateways %}
        <h3>NAT Gateways ({{ nat_gateways|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>ID</th>
                    <th>Public IP</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
                {% for nat in nat_gateways %}
                <tr>
                    <td>{{ nat.name }}</td>
                    <td><code>{{ nat.nat_gateway_id }}</code></td>
                    <td>{{ nat.public_ip or '-' }}</td>
                    <td>{{ nat.state }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if flow_logs %}
        <h3>Flow Logs ({{ flow_logs|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Resource</th>
                    <th>Traffic</th>
                    <th>Destination Type</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for flow_log in flow_logs %}
                <tr>
                    <td><code>{{ flow_log.flow_log_id }}</code></td>
                    <td>{{ flow_log.resource_id }}</td>
                    <td>{{ flow_log.traffic_type }}</td>
                    <td>{{ flow_log.log_destination_type or '-' }}</td>
                    <td>{{ flow_log.status }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if vpc_endpoints %}
        <h3>VPC Endpoints ({{ vpc_endpoints|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Service</th>
                    <th>ID</th>
                    <th>Type</th>
                    <th>State</th>
                    <th>Private DNS</th>
                    <th>Attachments</th>
                </tr>
            </thead>
            <tbody>
                {% for endpoint in vpc_endpoints %}
                <tr>
                    <td>{{ endpoint.service_name }}</td>
                    <td><code>{{ endpoint.vpc_endpoint_id }}</code></td>
                    <td>{{ endpoint.endpoint_type }}</td>
                    <td>{{ endpoint.state }}</td>
                    <td>{{ endpoint.private_dns_enabled }}</td>
                    <td>{{ endpoint.attachments }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if elastic_ips %}
        <h3>Elastic IPs ({{ elastic_ips|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Public IP</th>
                    <th>Allocation ID</th>
                    <th>Private IP</th>
                    <th>Attached To</th>
                    <th>Domain</th>
                </tr>
            </thead>
            <tbody>
                {% for elastic_ip in elastic_ips %}
                <tr>
                    <td>{{ elastic_ip.public_ip }}</td>
                    <td><code>{{ elastic_ip.allocation_id or '-' }}</code></td>
                    <td>{{ elastic_ip.private_ip_address or '-' }}</td>
                    <td>{{ elastic_ip.attachment }}</td>
                    <td>{{ elastic_ip.domain or '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <h3>Security Groups ({{ security_groups|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>ID</th>
                    <th>Ingress Rules</th>
                    <th>Egress Rules</th>
                    <th>In Use</th>
                    <th>Attached ENIs</th>
                </tr>
            </thead>
            <tbody>
                {% for sg in security_groups %}
                <tr>
                    <td>{{ sg.group_name }}</td>
                    <td><code>{{ sg.group_id }}</code></td>
                    <td>{{ sg.ingress_count }}</td>
                    <td>{{ sg.egress_count }}</td>
                    <td style="text-align: center;">
                        {% if sg.is_in_use %}
                            <span style="color: #27ae60; font-weight: bold;">✓</span>
                        {% else %}
                            <span style="color: #e74c3c; font-weight: bold;">✗</span>
                        {% endif %}
                    </td>
                    <td style="text-align: center;">{{ sg.attached_enis_count }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        {% if ec2_instances %}
        <h3>EC2 Instances ({{ ec2_instances|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Instance ID</th>
                    <th>Type</th>
                    <th>State</th>
                    <th>AZ</th>
                    <th>Private IP</th>
                    <th>Public IP</th>
                    <th>Launch Time</th>
                </tr>
            </thead>
            <tbody>
                {% for instance in ec2_instances %}
                <tr>
                    <td>{{ instance.name }}</td>
                    <td><code>{{ instance.instance_id }}</code></td>
                    <td>{{ instance.instance_type }}</td>
                    <td>
                        {% if instance.state == 'running' %}
                            <span style="color: #27ae60; font-weight: bold;">{{ instance.state }}</span>
                        {% elif instance.state == 'stopped' %}
                            <span style="color: #e74c3c; font-weight: bold;">{{ instance.state }}</span>
                        {% else %}
                            <span style="color: #f39c12; font-weight: bold;">{{ instance.state }}</span>
                        {% endif %}
                    </td>
                    <td>{{ instance.availability_zone }}</td>
                    <td>{{ instance.private_ip or '-' }}</td>
                    <td>{{ instance.public_ip or '-' }}</td>
                    <td>{{ instance.launch_time }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        {% if ebs_volumes %}
        <h3>EBS Volumes ({{ ebs_volumes|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Volume ID</th>
                    <th>Size (GB)</th>
                    <th>Type</th>
                    <th>State</th>
                    <th>AZ</th>
                    <th>Encrypted</th>
                    <th>Attached To</th>
                </tr>
            </thead>
            <tbody>
                {% for volume in ebs_volumes %}
                <tr>
                    <td>{{ volume.name }}</td>
                    <td><code>{{ volume.volume_id }}</code></td>
                    <td>{{ volume.size }}</td>
                    <td>{{ volume.volume_type }}</td>
                    <td>
                        {% if volume.state == 'in-use' %}
                            <span style="color: #27ae60; font-weight: bold;">{{ volume.state }}</span>
                        {% elif volume.state == 'available' %}
                            <span style="color: #3498db; font-weight: bold;">{{ volume.state }}</span>
                        {% else %}
                            <span style="color: #f39c12; font-weight: bold;">{{ volume.state }}</span>
                        {% endif %}
                    </td>
                    <td>{{ volume.availability_zone }}</td>
                    <td style="text-align: center;">
                        {% if volume.encrypted %}
                            <span style="color: #27ae60; font-weight: bold;">✓</span>
                        {% else %}
                            <span style="color: #e74c3c; font-weight: bold;">✗</span>
                        {% endif %}
                    </td>
                    <td>{{ volume.attachments }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <h2>Security Audit Findings</h2>

        {% if findings %}
            {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
                {% set severity_findings = findings|selectattr('severity', 'equalto', severity)|list %}
                {% if severity_findings %}
                    <h3>{{ severity|upper }} Severity ({{ severity_findings|length }})</h3>
                    {% for finding in severity_findings %}
                    <div class="finding {{ severity }}">
                        <div class="finding-header">
                            <div class="finding-title">{{ finding.title }}</div>
                            <span class="severity-badge {{ severity }}">{{ severity }}</span>
                        </div>
                        <div class="finding-meta">
                            <span class="tag">{{ finding.category }}</span>
                            <span class="tag">{{ finding.framework }}</span>
                            <span class="tag">{{ finding.resource_type }}: {{ finding.resource_id }}</span>
                        </div>
                        <div class="finding-description">
                            {{ finding.description }}
                        </div>
                        <div class="recommendation">
                            <div class="recommendation-title">📋 Recommendation</div>
                            {{ finding.recommendation }}
                        </div>
                    </div>
                    {% endfor %}
                {% endif %}
            {% endfor %}
        {% else %}
            <p style="color: #27ae60; font-size: 18px;">✅ No security issues found! Your VPC configuration looks good.</p>
        {% endif %}

        <div class="footer">
            Generated by VPC Map - AWS VPC Topology Mapper and Security Auditor
        </div>
    </div>
</body>
</html>
"""


DIFF_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VPC Diff Report - {{ vpc_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6; color: #333; background-color: #f5f5f5; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-bottom: 10px; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 15px; padding-left: 10px; border-left: 4px solid #3498db; }
        h3 { color: #34495e; margin-top: 20px; margin-bottom: 10px; }
        .meta { color: #7f8c8d; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }
        .summary-card h3 { margin: 0; font-size: 14px; color: #7f8c8d; text-transform: uppercase; }
        .summary-card .value { font-size: 32px; font-weight: bold; margin-top: 10px; }
        .summary-card.added .value { color: #27ae60; }
        .summary-card.removed .value { color: #e74c3c; }
        .summary-card.modified .value { color: #f39c12; }
        .summary-card.derived .value { color: #8e44ad; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; font-weight: 600; }
        tr:hover { background-color: #f5f5f5; }
        .change-added { color: #27ae60; font-weight: 600; }
        .change-removed { color: #e74c3c; font-weight: 600; }
        .change-modified { color: #f39c12; font-weight: 600; }
        .old-value { color: #e74c3c; }
        .new-value { color: #27ae60; }
        .no-drift { color: #27ae60; font-size: 18px; margin: 20px 0; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #7f8c8d; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>VPC Snapshot Diff Report</h1>
        <div class="meta">
            <strong>VPC ID:</strong> {{ vpc_id }}<br>
            <strong>Region:</strong> {{ region }}<br>
            <strong>Before:</strong> {{ before_collected_at }}<br>
            <strong>After:</strong> {{ after_collected_at }}<br>
            <strong>Generated:</strong> {{ generated_at }}
        </div>

        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card added">
                <h3>Added</h3>
                <div class="value">{{ added_count }}</div>
            </div>
            <div class="summary-card removed">
                <h3>Removed</h3>
                <div class="value">{{ removed_count }}</div>
            </div>
            <div class="summary-card modified">
                <h3>Modified</h3>
                <div class="value">{{ modified_count }}</div>
            </div>
            <div class="summary-card derived">
                <h3>Derived</h3>
                <div class="value">{{ derived_count }}</div>
            </div>
        </div>

        {% if not resource_changes and not derived_changes %}
        <p class="no-drift">No drift detected between snapshots.</p>
        {% endif %}

        {% if resource_changes %}
        <h2>Resource Changes</h2>
        {% for rtype, changes in grouped_changes.items() %}
        <h3>{{ rtype }} ({{ changes|length }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Resource ID</th>
                    <th>Change</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {% for change in changes %}
                <tr>
                    <td><code>{{ change.resource_id }}</code></td>
                    <td><span class="change-{{ change.change_type }}">{{ change.change_type }}</span></td>
                    <td>
                        {% if change.field_changes %}
                        <table>
                            <tr><th>Field</th><th>Old</th><th>New</th></tr>
                            {% for fc in change.field_changes %}
                            <tr>
                                <td>{{ fc.field }}</td>
                                <td class="old-value">{{ fc.old_value if fc.old_value is not none else '-' }}</td>
                                <td class="new-value">{{ fc.new_value if fc.new_value is not none else '-' }}</td>
                            </tr>
                            {% endfor %}
                        </table>
                        {% else %}
                        -
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endfor %}
        {% endif %}

        {% if derived_changes %}
        <h2>Derived Analysis Changes</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Resource</th>
                    <th>Field</th>
                    <th>Old Value</th>
                    <th>New Value</th>
                </tr>
            </thead>
            <tbody>
                {% for dc in derived_changes %}
                <tr>
                    <td>{{ dc.analysis_type }}</td>
                    <td><code>{{ dc.resource_id }}</code></td>
                    <td>{{ dc.field }}</td>
                    <td class="old-value">{{ dc.old_value if dc.old_value is not none else '-' }}</td>
                    <td class="new-value">{{ dc.new_value if dc.new_value is not none else '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <div class="footer">
            Generated by VPC Map - AWS VPC Topology Mapper and Security Auditor
        </div>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Generate HTML format reports."""

    def generate_report(
        self,
        topology: VpcTopology,
        report: AuditReport,
        output_file: Path,
        diagram_path: Path = None,
    ) -> None:
        """
        Generate HTML report.

        Args:
            topology: VPC topology
            report: Audit report
            output_file: Output HTML file path
            diagram_path: Optional path to diagram image to embed
        """
        # Read and encode diagram if provided
        diagram_data = None
        if diagram_path and diagram_path.exists():
            with open(diagram_path, "rb") as f:
                diagram_data = base64.b64encode(f.read()).decode("utf-8")

        # Prepare template data
        template_data = {
            "vpc_id": topology.vpc.vpc_id,
            "region": topology.region,
            "vpc_cidr": topology.vpc.cidr_block,
            "generated_at": report.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "total_resources": (
                len(topology.subnets)
                + len(topology.internet_gateways)
                + len(topology.nat_gateways)
                + len(topology.flow_logs)
                + len(topology.vpc_endpoints)
                + len(topology.elastic_ips)
                + len(topology.route_tables)
                + len(topology.security_groups)
                + len(topology.network_acls)
                + len(topology.ec2_instances)
                + len(topology.ebs_volumes)
            ),
            "total_checks": report.total_checks,
            "passed_checks": report.passed_checks,
            "failed_checks": report.failed_checks,
            "warnings": report.warnings,
            "diagram_data": diagram_data,
            "subnets": [
                {
                    "name": s.get_tag("Name") or "-",
                    "subnet_id": s.subnet_id,
                    "cidr_block": s.cidr_block,
                    "availability_zone": s.availability_zone,
                    "available_ip_address_count": s.available_ip_address_count,
                }
                for s in topology.subnets
            ],
            "nat_gateways": [
                {
                    "name": n.get_tag("Name") or "-",
                    "nat_gateway_id": n.nat_gateway_id,
                    "public_ip": n.public_ip,
                    "state": n.state,
                }
                for n in topology.nat_gateways
            ],
            "flow_logs": [
                {
                    "flow_log_id": flow_log.flow_log_id,
                    "resource_id": flow_log.resource_id,
                    "traffic_type": flow_log.traffic_type,
                    "log_destination_type": flow_log.log_destination_type,
                    "status": flow_log.flow_log_status or flow_log.deliver_logs_status or "-",
                }
                for flow_log in topology.flow_logs
            ],
            "vpc_endpoints": [
                {
                    "vpc_endpoint_id": endpoint.vpc_endpoint_id,
                    "service_name": endpoint.service_name,
                    "endpoint_type": endpoint.endpoint_type,
                    "state": endpoint.state,
                    "private_dns_enabled": "Yes" if endpoint.private_dns_enabled else "No",
                    "attachments": ", ".join(
                        part
                        for part in [
                            f"{len(endpoint.subnet_ids)} subnet(s)" if endpoint.subnet_ids else "",
                            (
                                f"{len(endpoint.route_table_ids)} route table(s)"
                                if endpoint.route_table_ids
                                else ""
                            ),
                            (
                                f"{len(endpoint.security_group_ids)} SG(s)"
                                if endpoint.security_group_ids
                                else ""
                            ),
                        ]
                        if part
                    )
                    or "-",
                }
                for endpoint in topology.vpc_endpoints
            ],
            "elastic_ips": [
                {
                    "public_ip": elastic_ip.public_ip,
                    "allocation_id": elastic_ip.allocation_id,
                    "private_ip_address": elastic_ip.private_ip_address,
                    "attachment": (
                        f"Instance {elastic_ip.instance_id}"
                        if elastic_ip.instance_id
                        else (
                            f"ENI {elastic_ip.network_interface_id}"
                            if elastic_ip.network_interface_id
                            else "Unassociated"
                        )
                    ),
                    "domain": elastic_ip.domain,
                }
                for elastic_ip in topology.elastic_ips
            ],
            "security_groups": [
                {
                    "group_name": sg.group_name,
                    "group_id": sg.group_id,
                    "ingress_count": len(sg.ingress_rules),
                    "egress_count": len(sg.egress_rules),
                    "is_in_use": sg.is_in_use,
                    "attached_enis_count": len(sg.attached_enis),
                }
                for sg in topology.security_groups
            ],
            "ec2_instances": [
                {
                    "name": instance.get_tag("Name") or "-",
                    "instance_id": instance.instance_id,
                    "instance_type": instance.instance_type,
                    "state": instance.state,
                    "availability_zone": instance.availability_zone,
                    "private_ip": instance.private_ip_address,
                    "public_ip": instance.public_ip_address,
                    "launch_time": instance.launch_time.strftime("%Y-%m-%d %H:%M:%S")
                    if instance.launch_time
                    else "-",
                }
                for instance in topology.ec2_instances
            ],
            "ebs_volumes": [
                {
                    "name": volume.get_tag("Name") or "-",
                    "volume_id": volume.volume_id,
                    "size": volume.size,
                    "volume_type": volume.volume_type,
                    "state": volume.state,
                    "availability_zone": volume.availability_zone,
                    "encrypted": volume.encrypted,
                    "attachments": ", ".join(volume.instance_ids)
                    if volume.instance_ids
                    else "-",
                }
                for volume in topology.ebs_volumes
            ],
            "findings": [
                {
                    "severity": f.severity.value,
                    "category": f.category.value.upper(),
                    "title": f.title,
                    "description": f.description,
                    "resource_type": f.resource_type,
                    "resource_id": f.resource_id,
                    "recommendation": f.recommendation,
                    "framework": f.framework,
                    "rule_id": f.rule_id,
                }
                for f in report.findings
            ],
        }

        # Render template
        template = Template(HTML_TEMPLATE)
        html_content = template.render(**template_data)

        # Write to file
        with open(output_file, "w") as f:
            f.write(html_content)

    def generate_diff_report(
        self,
        diff_report: DiffReport,
        output_file: Path,
    ) -> None:
        """Generate HTML diff report."""
        added = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.ADDED)
        removed = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.REMOVED)
        modified = sum(1 for c in diff_report.resource_changes if c.change_type == ChangeType.MODIFIED)

        # Group changes by resource type
        grouped: dict[str, list[dict]] = {}
        for change in diff_report.resource_changes:
            entry = {
                "resource_id": change.resource_id,
                "change_type": change.change_type.value,
                "field_changes": [
                    {
                        "field": fc.field,
                        "old_value": fc.old_value,
                        "new_value": fc.new_value,
                    }
                    for fc in change.field_changes
                ],
            }
            grouped.setdefault(change.resource_type, []).append(entry)

        derived = [
            {
                "analysis_type": dc.analysis_type,
                "resource_id": dc.resource_id,
                "field": dc.field,
                "old_value": dc.old_value,
                "new_value": dc.new_value,
            }
            for dc in diff_report.derived_changes
        ]

        template_data = {
            "vpc_id": diff_report.vpc_id,
            "region": diff_report.region,
            "before_collected_at": diff_report.before_collected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "after_collected_at": diff_report.after_collected_at.strftime("%Y-%m-%d %H:%M:%S"),
            "generated_at": diff_report.generated_at.strftime("%Y-%m-%d %H:%M:%S"),
            "added_count": added,
            "removed_count": removed,
            "modified_count": modified,
            "derived_count": len(diff_report.derived_changes),
            "resource_changes": diff_report.resource_changes,
            "grouped_changes": grouped,
            "derived_changes": derived,
        }

        template = Template(DIFF_HTML_TEMPLATE)
        html_content = template.render(**template_data)

        with open(output_file, "w") as f:
            f.write(html_content)
