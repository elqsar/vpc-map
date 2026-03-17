"""Snapshot diff and drift detection for VPC topologies."""

from vpc_map.diff.engine import diff_topologies
from vpc_map.diff.loader import load_topology_from_file

__all__ = ["diff_topologies", "load_topology_from_file"]
