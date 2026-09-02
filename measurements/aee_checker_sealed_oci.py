"""AEE probe vocabulary over the shared contained-OCI envelope."""

from __future__ import annotations

import os
from pathlib import Path
import contained_oci as contained

from contained_oci import (
    DEFAULT_MOUNT_SPEC,
    INERT_RESOURCE_PROFILE,
    DockerUnavailable,
    PrepareError,
    _require_mount_spec,
    classify_inspect_status,
    container_exists,
    docker_bounded,
    docker_create_argv,
    docker_ok,
    docker_run_capped,
    image_platform,
    inspect_lookup,
    parse_inspect_payload,
    require_container_absent,
    require_docker_ready,
    require_image_id,
    require_local_image,
    validate_inspect_contract,
)
from aee_checker_sealed_common import exact_object

INSPECT_SNAPSHOT_KEYS = (
    "cap_drop", "memory", "memory_swap", "network_mode",
    "no_new_privileges", "offline_env", "pids", "read_only_root",
    "readonly_mounts", "tmpfs", "user",
)
PROBE_MECHANISMS = (
    "deadline", "disk", "file-count", "network-off", "output", "protocol-exit",
)
EXPECTED_REFUSALS = {
    "deadline": "deadline",
    "disk": "abnormal",
    "file-count": "abnormal",
    "network-off": "abnormal",
    "output": "output_cap",
    "protocol-exit": "abnormal",
}
PROBE_ROW_KEYS = ("control", "inspect", "mechanism", "refusal")
def build_inert_image(context: Path) -> str:
    os.environ.setdefault("DOCKER_BUILDKIT", "1")
    raw = docker_bounded(
        ["build", "-q", "-f", "Containerfile", "."],
        cwd=Path(context), timeout=300)
    return require_image_id(raw.decode("utf-8").strip())


def require_live_oci_capability(context: Path) -> str:
    require_docker_ready()
    return build_inert_image(Path(context))


def classify_container_result(returncode, raw: bytes) -> dict:
    if type(returncode) is not int:
        return {"state": "harness_failure", "parsed": None}
    if returncode == 0:
        return {"state": "completed", "parsed": None}
    return {"state": "abnormal", "parsed": None}


def record_probe_pair(mechanism: str, control: dict, refusal: dict) -> dict:
    expected = EXPECTED_REFUSALS.get(mechanism)
    if expected is None:
        raise PrepareError("unknown probe mechanism")
    if control.get("state") != "completed":
        raise PrepareError("probe pair missing control")
    if refusal.get("state") != expected:
        raise PrepareError("probe refusal must be %s" % expected)
    if type(control.get("contract")) is not dict or type(refusal.get("contract")) is not dict:
        raise PrepareError("probe pair missing inspect")
    return {
        "control": "completed",
        "inspect": {"control": control["contract"], "refusal": refusal["contract"]},
        "mechanism": mechanism,
        "refusal": expected,
    }


def require_probe_evidence(rows) -> None:
    if type(rows) is not list or len(rows) != len(PROBE_MECHANISMS):
        raise PrepareError("probe evidence must pair every required mechanism")
    for expected, row in zip(PROBE_MECHANISMS, rows):
        exact_object(row, PROBE_ROW_KEYS, "probe evidence")
        if row["mechanism"] != expected or row["control"] != "completed":
            raise PrepareError("probe pair missing control")
        want = EXPECTED_REFUSALS[expected]
        if row["refusal"] != want:
            raise PrepareError("%s refusal must be %s" % (expected, want))
        exact_object(row["inspect"], ("control", "refusal"), "probe inspect")
        for side in row["inspect"].values():
            exact_object(side, INSPECT_SNAPSHOT_KEYS, "inspect snapshot")


def defense_in_depth_from_inspect(inspect) -> dict:
    row = inspect[0] if isinstance(inspect, list) and inspect else inspect
    snap = validate_inspect_contract(row, sealed=True)
    return {
        "claim": "inspect-verified; not efficacy-tested",
        "memory": snap["memory"],
        "memory_swap": snap["memory_swap"],
        "pids": snap["pids"],
    }


def run_inert_probe(
        *, image_id: str, mode: str, mounts: dict, name_prefix: str,
        sealed: bool = True, mount_spec=DEFAULT_MOUNT_SPEC) -> dict:
    raw = contained.run_contained(
        image_id=image_id,
        mounts=mounts,
        command=[mode],
        entrypoint="/probe",
        mount_spec=mount_spec,
        resource_profile=INERT_RESOURCE_PROFILE,
        sealed=sealed,
        name_prefix="%s%s-" % (name_prefix, mode.replace("-", "")),
        cleanup_label="container",
    )
    if raw["state"] == "timeout":
        state = "deadline"
    elif raw["state"] == "output-cap":
        state = "output_cap"
    else:
        state = classify_container_result(raw["process"].returncode, b"")["state"]
    return {
        "state": state,
        "name": raw["name"],
        "inspect": raw["inspect"],
        "contract": raw["contract"],
        "container_absent_after": raw["container_absent_after"],
        "parsed": None,
    }
