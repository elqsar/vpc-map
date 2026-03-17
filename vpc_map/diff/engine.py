"""Core diff engine for comparing two VpcTopology snapshots."""

from __future__ import annotations

import warnings
from typing import Any

from vpc_map.models import (
    ChangeType,
    DerivedChange,
    DiffReport,
    FieldChange,
    ResourceChange,
    VpcTopology,
)
from vpc_map.network.analysis import analyze_instances, analyze_subnets

VOLATILE_FIELDS = frozenset({
    "collected_at",
    "available_ip_address_count",
    "discovered_at",
    "generated_at",
})

RESOURCE_COLLECTIONS: list[tuple[str, str, str]] = [
    ("subnets", "subnet", "subnet_id"),
    ("internet_gateways", "internet_gateway", "igw_id"),
    ("nat_gateways", "nat_gateway", "nat_gateway_id"),
    ("flow_logs", "flow_log", "flow_log_id"),
    ("vpc_endpoints", "vpc_endpoint", "vpc_endpoint_id"),
    ("elastic_ips", "elastic_ip", "allocation_id"),
    ("route_tables", "route_table", "route_table_id"),
    ("security_groups", "security_group", "group_id"),
    ("network_acls", "network_acl", "nacl_id"),
    ("ec2_instances", "ec2_instance", "instance_id"),
    ("ebs_volumes", "ebs_volume", "volume_id"),
]


def diff_topologies(before: VpcTopology, after: VpcTopology) -> DiffReport:
    """Compare two topology snapshots and produce a structured diff report."""
    if before.vpc.vpc_id != after.vpc.vpc_id:
        warnings.warn(
            f"VPC IDs differ: {before.vpc.vpc_id} vs {after.vpc.vpc_id}. "
            "Proceeding with cross-VPC comparison.",
            stacklevel=2,
        )

    resource_changes = _diff_vpc(before, after)
    derived_changes = _diff_derived_analysis(before, after)

    return DiffReport(
        vpc_id=after.vpc.vpc_id,
        region=after.region,
        before_collected_at=before.collected_at,
        after_collected_at=after.collected_at,
        resource_changes=resource_changes,
        derived_changes=derived_changes,
    )


def _diff_vpc(before: VpcTopology, after: VpcTopology) -> list[ResourceChange]:
    """Compare all resource collections between two topologies."""
    changes: list[ResourceChange] = []

    # Compare VPC-level fields
    before_vpc_dict = before.vpc.model_dump(mode="json")
    after_vpc_dict = after.vpc.model_dump(mode="json")
    vpc_field_changes = _diff_dicts(before_vpc_dict, after_vpc_dict)
    if vpc_field_changes:
        changes.append(
            ResourceChange(
                resource_type="vpc",
                resource_id=after.vpc.vpc_id,
                change_type=ChangeType.MODIFIED,
                field_changes=vpc_field_changes,
            )
        )

    # Compare each resource collection
    for field_name, resource_type, key_field in RESOURCE_COLLECTIONS:
        before_list = getattr(before, field_name)
        after_list = getattr(after, field_name)
        changes.extend(
            _diff_collection(before_list, after_list, resource_type, key_field)
        )

    return changes


def _get_resource_key(resource_dict: dict, key_field: str, resource_type: str) -> str:
    """Extract primary key from a resource dict, with fallback for ElasticIp."""
    key = resource_dict.get(key_field)
    if key is not None:
        return str(key)
    if resource_type == "elastic_ip":
        return resource_dict.get("public_ip", "unknown")
    return "unknown"


def _diff_collection(
    before_list: list,
    after_list: list,
    resource_type: str,
    key_field: str,
) -> list[ResourceChange]:
    """Compare two lists of resources by primary key."""
    before_index: dict[str, dict] = {}
    for item in before_list:
        d = item.model_dump(mode="json")
        key = _get_resource_key(d, key_field, resource_type)
        before_index[key] = d

    after_index: dict[str, dict] = {}
    for item in after_list:
        d = item.model_dump(mode="json")
        key = _get_resource_key(d, key_field, resource_type)
        after_index[key] = d

    before_keys = set(before_index.keys())
    after_keys = set(after_index.keys())

    changes: list[ResourceChange] = []

    # Added resources
    for key in sorted(after_keys - before_keys):
        changes.append(
            ResourceChange(
                resource_type=resource_type,
                resource_id=key,
                change_type=ChangeType.ADDED,
            )
        )

    # Removed resources
    for key in sorted(before_keys - after_keys):
        changes.append(
            ResourceChange(
                resource_type=resource_type,
                resource_id=key,
                change_type=ChangeType.REMOVED,
            )
        )

    # Modified resources
    for key in sorted(before_keys & after_keys):
        field_changes = _diff_dicts(before_index[key], after_index[key])
        if field_changes:
            changes.append(
                ResourceChange(
                    resource_type=resource_type,
                    resource_id=key,
                    change_type=ChangeType.MODIFIED,
                    field_changes=field_changes,
                )
            )

    return changes


def _diff_dicts(
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str = "",
) -> list[FieldChange]:
    """Recursively compare two dicts and return field-level changes."""
    changes: list[FieldChange] = []
    all_keys = set(before.keys()) | set(after.keys())

    for key in sorted(all_keys):
        if key in VOLATILE_FIELDS:
            continue

        full_key = f"{prefix}{key}" if not prefix else f"{prefix}.{key}"
        old_val = before.get(key)
        new_val = after.get(key)

        if old_val == new_val:
            continue

        if isinstance(old_val, dict) and isinstance(new_val, dict):
            changes.extend(_diff_dicts(old_val, new_val, full_key))
        elif isinstance(old_val, list) and isinstance(new_val, list):
            if _lists_differ(old_val, new_val):
                changes.append(
                    FieldChange(field=full_key, old_value=old_val, new_value=new_val)
                )
        else:
            changes.append(
                FieldChange(field=full_key, old_value=old_val, new_value=new_val)
            )

    return changes


def _lists_differ(a: list, b: list) -> bool:
    """Check if two lists differ, sorting simple lists for comparison."""
    if len(a) != len(b):
        return True

    # Try sorting for simple (non-dict) lists
    if a and not isinstance(a[0], dict) and not isinstance(a[0], list):
        try:
            return sorted(a) != sorted(b)
        except TypeError:
            pass

    return a != b


def _diff_derived_analysis(
    before: VpcTopology,
    after: VpcTopology,
) -> list[DerivedChange]:
    """Compare derived subnet classifications and instance exposure."""
    changes: list[DerivedChange] = []

    # Subnet classification changes
    before_subnets = {a.subnet_id: a for a in analyze_subnets(before)}
    after_subnets = {a.subnet_id: a for a in analyze_subnets(after)}

    subnet_fields = [
        "classification",
        "has_internet_gateway_route",
        "has_nat_route",
        "has_endpoint_access",
    ]

    for subnet_id in sorted(set(before_subnets) | set(after_subnets)):
        before_analysis = before_subnets.get(subnet_id)
        after_analysis = after_subnets.get(subnet_id)

        if before_analysis is None:
            changes.append(
                DerivedChange(
                    analysis_type="subnet_classification",
                    resource_id=subnet_id,
                    field="classification",
                    old_value=None,
                    new_value=after_analysis.classification.value,
                )
            )
            continue

        if after_analysis is None:
            changes.append(
                DerivedChange(
                    analysis_type="subnet_classification",
                    resource_id=subnet_id,
                    field="classification",
                    old_value=before_analysis.classification.value,
                    new_value=None,
                )
            )
            continue

        for field in subnet_fields:
            old_val = getattr(before_analysis, field)
            new_val = getattr(after_analysis, field)
            if hasattr(old_val, "value"):
                old_val = old_val.value
            if hasattr(new_val, "value"):
                new_val = new_val.value
            if old_val != new_val:
                changes.append(
                    DerivedChange(
                        analysis_type="subnet_classification",
                        resource_id=subnet_id,
                        field=field,
                        old_value=old_val,
                        new_value=new_val,
                    )
                )

    # Instance exposure changes
    before_instances = {e.instance_id: e for e in analyze_instances(before)}
    after_instances = {e.instance_id: e for e in analyze_instances(after)}

    instance_fields = [
        "exposure_state",
        "subnet_classification",
        "allowed_ports",
        "open_admin_ports",
        "has_public_address",
    ]

    for instance_id in sorted(set(before_instances) | set(after_instances)):
        before_exposure = before_instances.get(instance_id)
        after_exposure = after_instances.get(instance_id)

        if before_exposure is None:
            changes.append(
                DerivedChange(
                    analysis_type="instance_exposure",
                    resource_id=instance_id,
                    field="exposure_state",
                    old_value=None,
                    new_value=after_exposure.exposure_state.value,
                )
            )
            continue

        if after_exposure is None:
            changes.append(
                DerivedChange(
                    analysis_type="instance_exposure",
                    resource_id=instance_id,
                    field="exposure_state",
                    old_value=before_exposure.exposure_state.value,
                    new_value=None,
                )
            )
            continue

        for field in instance_fields:
            old_val = getattr(before_exposure, field)
            new_val = getattr(after_exposure, field)
            if hasattr(old_val, "value"):
                old_val = old_val.value
            if hasattr(new_val, "value"):
                new_val = new_val.value
            if old_val != new_val:
                changes.append(
                    DerivedChange(
                        analysis_type="instance_exposure",
                        resource_id=instance_id,
                        field=field,
                        old_value=old_val,
                        new_value=new_val,
                    )
                )

    return changes
