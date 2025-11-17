# VPC Map

AWS VPC topology mapper and security auditor - a comprehensive CLI tool for visualizing and auditing your AWS VPC infrastructure.

## Features

- **VPC Topology Visualization**: Generate clear, visual diagrams of your VPC infrastructure showing:
  - VPC, subnets, and availability zones
  - Internet Gateways and NAT Gateways
  - Route tables and their associations
  - Network connections and routing paths

- **Comprehensive Security Audit**: Automated security and best practice checks based on:
  - AWS Well-Architected Framework
  - CIS AWS Foundations Benchmark
  - Custom security best practices

- **Multiple Output Formats**:
  - Rich terminal output with colors and tables
  - JSON for automation and integration
  - HTML reports with embedded diagrams
  - PNG/SVG diagrams for documentation
  - ASCII art network diagrams showing routing topology

- **Resource Discovery**: Automatically discovers and analyzes:
  - Subnets
  - NAT Gateways
  - Internet Gateways
  - Route Tables
  - Security Groups
  - Network ACLs

## Installation

### Prerequisites

- Python 3.12 or higher
- AWS credentials configured (via `aws configure` or environment variables)
- Graphviz (for diagram generation)

### Install Graphviz

**macOS:**
```bash
brew install graphviz
```

**Ubuntu/Debian:**
```bash
sudo apt-get install graphviz
```

**Windows:**
Download from https://graphviz.org/download/

### Install VPC Map

```bash
# Clone the repository
cd vpc-map

# Install with uv (recommended)
uv pip install -e .

# Or install with pip
pip install -e .
```

## Usage

### List Available VPCs

```bash
vpc-map list-vpcs
```

**Options:**
- `-r, --region`: Specify AWS region
- `-p, --profile`: Specify AWS profile

**Example:**
```bash
vpc-map list-vpcs --region us-west-2 --profile production
```

### Analyze a VPC

Perform complete analysis with topology diagram and security audit:

```bash
vpc-map analyze vpc-12345678
```

**Options:**
- `-r, --region`: AWS region (defaults to configured region)
- `-p, --profile`: AWS profile (defaults to default profile)
- `-o, --output-dir`: Output directory (default: `./vpc-map-output`)
- `-f, --format`: Output format: `terminal`, `json`, `html`, `all` (default: `terminal`)
- `--diagram-format`: Diagram format: `png`, `svg`, `ascii` (default: `png`)
- `--no-diagram`: Skip diagram generation
- `--no-audit`: Skip security audit

**Examples:**

```bash
# Basic analysis with terminal output
vpc-map analyze vpc-12345678

# Generate all output formats
vpc-map analyze vpc-12345678 --format all

# Generate SVG diagrams instead of PNG
vpc-map analyze vpc-12345678 --diagram-format svg

# Generate ASCII art routing diagrams
vpc-map analyze vpc-12345678 --diagram-format ascii

# Custom output directory
vpc-map analyze vpc-12345678 -o ./my-vpc-reports

# Skip diagram, audit only
vpc-map analyze vpc-12345678 --no-diagram

# Different AWS profile and region
vpc-map analyze vpc-12345678 --region eu-west-1 --profile prod
```

### Generate Diagrams Only

```bash
vpc-map diagram-only vpc-12345678
```

**Options:**
- `-r, --region`: AWS region
- `-p, --profile`: AWS profile
- `-o, --output-dir`: Output directory
- `-f, --format`: Diagram format (`png`, `svg`, or `ascii`)

**Examples:**
```bash
# Generate SVG diagrams
vpc-map diagram-only vpc-12345678 --format svg -o ./diagrams

# Generate ASCII art routing diagrams
vpc-map diagram-only vpc-12345678 --format ascii -o ./diagrams
```

### Run Audit Only

```bash
vpc-map audit-only vpc-12345678
```

**Options:**
- `-r, --region`: AWS region
- `-p, --profile`: AWS profile
- `-o, --output-dir`: Output directory
- `-f, --format`: Output format (`terminal`, `json`, `html`, `all`)

**Example:**
```bash
vpc-map audit-only vpc-12345678 --format json
```

## Output Examples

### Terminal Output

The terminal output provides:
- VPC information and DNS settings
- Resource summary table
- Subnet details tree
- Security audit findings organized by severity
- Color-coded findings with recommendations

### JSON Output

Machine-readable format including:
- Complete topology data
- All audit findings
- Summary statistics
- Findings grouped by severity and category

```json
{
  "topology": { ... },
  "audit": { ... },
  "summary": {
    "vpc_id": "vpc-12345678",
    "resource_counts": { ... },
    "findings_by_severity": { ... }
  }
}
```

### HTML Report

Self-contained HTML file with:
- Executive summary with statistics
- Embedded topology diagrams
- Resource inventory tables
- Detailed findings with recommendations
- Professional styling and formatting

### ASCII Art Diagrams

Text-based network diagrams showing:
- Complete VPC routing topology with all routes
- Subnets organized by availability zone
- Route tables with detailed routing information
- Internet and NAT gateway connections
- Routing flow visualization
- Compact summary view option

## Security Audit Checks

### AWS Well-Architected Framework

- VPC Flow Logs monitoring
- DNS configuration
- Multi-AZ subnet distribution
- NAT Gateway redundancy
- Unused resource detection
- Default security group configuration
- Network segmentation

### CIS AWS Foundations Benchmark

- Default security group restrictions
- Security group rule validation
- Network ACL configuration
- Unrestricted access to critical ports (SSH, RDP, databases)
- Wide port range exposure

### Custom Security Checks

- Resource tagging compliance
- Subnet naming conventions
- Security group descriptions
- Unused security groups
- Overlapping security rules
- NACL ephemeral port configuration
- Route table complexity
- Public/private subnet auto-assign IP settings

## AWS Permissions Required

The tool requires read-only permissions for:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcAttribute"
      ],
      "Resource": "*"
    }
  ]
}
```

## Development

### Running Tests

```bash
# Run all tests
uv run pytest -v

# Run with coverage
uv run pytest --cov=vpc_map --cov-report=html

# Run specific test file
uv run pytest tests/test_models.py
```

### Code Formatting

```bash
# Format code
uv run black vpc_map/

# Lint code
uv run ruff check vpc_map/
```

## Project Structure

```
vpc-map/
├── src/vpc_map/
│   ├── __init__.py
│   ├── cli.py              # CLI commands
│   ├── models.py           # Data models
│   ├── aws/
│   │   └── collector.py    # AWS resource collection
│   ├── visualization/
│   │   └── graphviz.py     # Diagram generation
│   ├── audit/
│   │   ├── engine.py       # Audit orchestration
│   │   ├── aws_waf.py      # AWS Well-Architected rules
│   │   ├── cis.py          # CIS benchmark rules
│   │   └── custom.py       # Custom security rules
│   └── reports/
│       ├── terminal.py     # Terminal output
│       ├── json.py         # JSON reports
│       └── html.py         # HTML reports
├── tests/
├── pyproject.toml
└── README.md
```

## Troubleshooting

### Graphviz Not Found

If you get an error about Graphviz not being installed:

```bash
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Verify installation
dot -V
```

### AWS Credentials

Ensure your AWS credentials are configured:

```bash
# Configure default profile
aws configure

# Or use environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Permission Denied Errors

If you encounter permission errors, ensure your AWS user/role has the required EC2 read permissions listed above.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.

## Version

Current version: 0.1.0
