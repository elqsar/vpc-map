"""HTML report generator."""

import base64
from pathlib import Path

from jinja2 import Template

from vpc_map.models import AuditReport, VpcTopology

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
                + len(topology.route_tables)
                + len(topology.security_groups)
                + len(topology.network_acls)
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
