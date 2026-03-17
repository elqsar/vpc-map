"""Load VpcTopology from saved JSON snapshot files."""

import json
from pathlib import Path

from vpc_map.models import VpcTopology


def load_topology_from_file(path: Path) -> VpcTopology:
    """Load a VpcTopology from a JSON file.

    Supports both standalone topology JSON (from generate_topology_report)
    and combined report JSON (from generate_combined_report, which nests
    topology under a "topology" key).
    """
    with open(path) as f:
        data = json.load(f)

    if "topology" in data and "vpc" in data["topology"]:
        data = data["topology"]

    return VpcTopology.model_validate(data)
