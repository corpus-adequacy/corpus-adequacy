"""Sibling execution-envelope record for `contained-oci-v0` (#106).

One observation-only projector reads Docker output; one comparator holds the
observation against the requested declaration; one builder closes the state
model and computes publication permission. Nothing here scores, publishes, or
authorizes publication: `publication_permission` is a recorded fact and its
enforcement is owned by #107.

The record is a sibling artifact. `report.v0`, `prepare.v1`, `survivors.v0`
and every published byte are unchanged; the binding direction is envelope to
an optional report digest, never the reverse.
"""

from __future__ import annotations

import json

import corpus_adequacy as ca
import contained_oci as contained

ENVELOPE_SCHEMA = "corpus-adequacy.execution-envelope.v0"
CONTAINED_PROFILE = "contained-oci-v0"
CONTAINED_USER = contained.CONTAINED_USER
OFFLINE_ENV_NAME = "CARGO_NET_OFFLINE"

SETUP_STATUSES = ("ready", "unavailable", "refused")
# No `degraded`: contained-oci-v0 has no optional containment axis, so a
# missing or contradicted required field is `unverified` and the run is
# withheld. A third member here would be a state the engine cannot produce.
ENVELOPE_STATUSES = ("verified", "unverified")
CANDIDATE_OUTCOMES = ("completed", "timeout", "output-cap", "unproved", "not-run")
CLEANUP_RESULTS = ("removed-and-absent", "remove-failed", "absence-unproved")
PUBLICATION_PERMISSIONS = ("permitted", "withheld")

EFFECTIVE_KEYS = (
    "cap_add", "cap_drop", "devices", "env_names", "image", "image_env_names",
    "memory", "memory_swap", "mounts", "network_mode", "no_new_privileges",
    "pid_mode", "pids_limit", "privileged", "read_only_root",
    "runtime_version", "tmpfs", "user", "userns_mode",
)
REQUESTED_KEYS = (
    "execution_profile", "image_id", "mount_spec", "resource_profile", "sealed",
)
ENVELOPE_KEYS = (
    "candidate_outcome", "cleanup", "effective", "envelope_status",
    "execution_commit", "non_claims", "prepare_sha256",
    "publication_permission", "report_sha256", "requested", "schema",
    "setup_status", "unverified_field", "withheld_reason",
)
NON_CLAIMS = (
    "States the envelope one Docker daemon reported for one container on one "
    "host at one time.",
    "Does not prove kernel or runtime escape resistance.",
    "Does not prove the absence of side channels.",
    "Does not prove an uncompromised daemon or operator.",
    "Does not authenticate the candidate author or prove candidate correctness.",
    "Not a sandbox-completeness claim, not a score, not an audit, not a "
    "certification, and not publication authorization.",
)


class EnvelopeError(contained.PrepareError):
    """An observation was missing, contradicted, or outside the closed model."""


def _observed(doc, *path):
    """Read one observation. Absence is unverified; it is never a value.

    A key that is present with a JSON `null` is an observation the daemon
    made. A key that is absent is an observation it did not make, and the
    two must not collapse into the same answer.
    """
    node = doc
    for depth, key in enumerate(path):
        if type(node) is not dict or key not in node:
            raise EnvelopeError(".".join(path))
        node = node[key]
    return node


def _observed_list(doc, *path) -> tuple:
    """Docker emits JSON null for an empty list; absence still refuses."""
    value = _observed(doc, *path)
    if value is None:
        return ()
    if type(value) is not list:
        raise EnvelopeError(".".join(path))
    return tuple(value)


def _observed_str(doc, *path) -> str:
    value = _observed(doc, *path)
    if not isinstance(value, str):
        raise EnvelopeError(".".join(path))
    return value


def _observed_int(doc, *path) -> int:
    value = _observed(doc, *path)
    if type(value) is not int:
        raise EnvelopeError(".".join(path))
    return value


def _observed_bool(doc, *path) -> bool:
    value = _observed(doc, *path)
    if type(value) is not bool:
        raise EnvelopeError(".".join(path))
    return value


def _observed_tmpfs(spec: str, where: str) -> dict:
    """Parse one tmpfs option string into observed numbers only."""
    if not isinstance(spec, str):
        raise EnvelopeError(where)
    parts = spec.split(",")
    size = inodes = None
    try:
        for part in parts:
            if part.startswith("size="):
                size = int(part[5:])
            elif part.startswith("nr_inodes="):
                inodes = int(part[10:])
    except ValueError as exc:
        raise EnvelopeError(where) from exc
    if type(size) is not int or type(inodes) is not int:
        raise EnvelopeError(where)
    return {"exec": "exec" in parts, "nr_inodes": inodes, "size": size}


def project_effective_envelope(inspect, *, image_env_names, runtime_version) -> dict:
    """Read the effective envelope from Docker output and nothing else.

    Every value is read from `inspect` or from the runtime version observed
    for this run. No requested or declared value reaches this function, and
    no accessor here supplies a default: an observation the daemon did not
    make raises with the observation path as its name.
    """
    if type(inspect) is not dict:
        raise EnvelopeError("inspect")
    if not isinstance(runtime_version, str) or not runtime_version.strip():
        raise EnvelopeError("runtime_version")
    if type(image_env_names) not in (list, tuple):
        raise EnvelopeError("image_env_names")
    for name in image_env_names:
        if not isinstance(name, str) or not name:
            raise EnvelopeError("image_env_names")

    security_opt = _observed_list(inspect, "HostConfig", "SecurityOpt")
    env_names = []
    for item in _observed_list(inspect, "Config", "Env"):
        if not isinstance(item, str):
            raise EnvelopeError("Config.Env")
        env_names.append(item.split("=", 1)[0])

    devices = []
    for item in _observed_list(inspect, "HostConfig", "Devices"):
        if type(item) is not dict or "PathInContainer" not in item:
            raise EnvelopeError("HostConfig.Devices")
        devices.append(item["PathInContainer"])

    mounts = []
    for item in _observed_list(inspect, "Mounts"):
        if type(item) is not dict:
            raise EnvelopeError("Mounts")
        mounts.append({
            "destination": _observed_str(item, "Destination"),
            "rw": _observed_bool(item, "RW"),
            "type": _observed_str(item, "Type"),
        })

    tmpfs = {}
    observed_tmpfs = _observed(inspect, "HostConfig", "Tmpfs")
    if type(observed_tmpfs) is not dict:
        raise EnvelopeError("HostConfig.Tmpfs")
    for destination in sorted(observed_tmpfs):
        tmpfs[destination] = _observed_tmpfs(
            observed_tmpfs[destination], "HostConfig.Tmpfs")

    return {
        "cap_add": sorted(_observed_list(inspect, "HostConfig", "CapAdd")),
        "cap_drop": sorted(_observed_list(inspect, "HostConfig", "CapDrop")),
        "devices": sorted(devices),
        "env_names": sorted(env_names),
        "image": _observed_str(inspect, "Image"),
        "image_env_names": sorted(image_env_names),
        "memory": _observed_int(inspect, "HostConfig", "Memory"),
        "memory_swap": _observed_int(inspect, "HostConfig", "MemorySwap"),
        "mounts": sorted(mounts, key=lambda row: row["destination"]),
        "network_mode": _observed_str(inspect, "HostConfig", "NetworkMode"),
        "no_new_privileges": any(
            str(item).replace("=", ":") == "no-new-privileges:true"
            for item in security_opt),
        "pid_mode": _observed_str(inspect, "HostConfig", "PidMode"),
        "pids_limit": _observed_int(inspect, "HostConfig", "PidsLimit"),
        "privileged": _observed_bool(inspect, "HostConfig", "Privileged"),
        "read_only_root": _observed_bool(inspect, "HostConfig", "ReadonlyRootfs"),
        "runtime_version": runtime_version,
        "tmpfs": tmpfs,
        "user": _observed_str(inspect, "Config", "User"),
        "userns_mode": _observed_str(inspect, "HostConfig", "UsernsMode"),
    }


def requested_envelope(*, execution_profile, image_id, mount_spec,
                       resource_profile, sealed) -> dict:
    """The declaration side. These values are compared, never projected.

    The pinned image's own environment is NOT here: it is an observation of
    an immutable artifact, so it sits in `effective` and the environment
    check is observation against observation, with no declaration involved.
    """
    if execution_profile not in ca.CLOSED_EXECUTION_PROFILES:
        raise EnvelopeError("execution_profile")
    if execution_profile != CONTAINED_PROFILE:
        raise EnvelopeError("execution_profile")
    if type(sealed) is not bool:
        raise EnvelopeError("sealed")
    return {
        "execution_profile": execution_profile,
        "image_id": contained.require_image_id(image_id),
        "mount_spec": sorted(
            destination for _key, destination
            in contained._require_mount_spec(mount_spec)),
        "resource_profile": contained.require_resource_profile(resource_profile),
        "sealed": sealed,
    }


def _require_exact(doc, keys, where: str) -> None:
    if type(doc) is not dict or set(doc) != set(keys):
        raise EnvelopeError(where)


def require_requested_record(requested) -> dict:
    """Validate that a stored requested declaration conforms to the closed schema.

    Enforces that execution_profile is contained-oci-v0, image_id is a valid
    sha256 digest, sealed is strictly a bool, resource_profile conforms to
    RESOURCE_PROFILE_SCHEMA with positive integer limits and bool work_exec,
    and mount_spec is a strictly sorted list of unique destination strings
    starting with '/'.
    """
    _require_exact(requested, REQUESTED_KEYS, "requested")
    if requested["execution_profile"] != CONTAINED_PROFILE:
        raise EnvelopeError("execution_profile")
    try:
        contained.require_image_id(requested["image_id"])
    except contained.PrepareError as exc:
        raise EnvelopeError("image_id") from exc
    if type(requested["sealed"]) is not bool:
        raise EnvelopeError("sealed")
    try:
        contained.require_resource_profile(requested["resource_profile"])
    except contained.PrepareError as exc:
        raise EnvelopeError("resource_profile") from exc
    mount_spec = requested["mount_spec"]
    if type(mount_spec) not in (list, tuple):
        raise EnvelopeError("mount_spec")
    seen_destinations = set()
    prev = None
    for dest in mount_spec:
        if not isinstance(dest, str) or not dest.startswith("/") or not dest:
            raise EnvelopeError("mount_spec")
        if dest in seen_destinations:
            raise EnvelopeError("mount_spec")
        if prev is not None and dest <= prev:
            raise EnvelopeError("mount_spec")
        seen_destinations.add(dest)
        prev = dest
    return requested


def require_envelope_matches_request(effective, requested) -> None:
    """Hold one observation against one declaration. Observation cannot yield.

    Every projected key is compared here, so a field cannot be recorded
    without being checked and cannot be checked without being recorded.
    """
    require_requested_record(requested)
    _require_exact(effective, EFFECTIVE_KEYS, "effective")
    profile = requested["resource_profile"]

    if effective["image"] != requested["image_id"]:
        raise EnvelopeError("image")
    if not isinstance(effective["runtime_version"], str) or not effective[
            "runtime_version"].strip():
        raise EnvelopeError("runtime_version")
    if type(effective["privileged"]) is not bool or effective["privileged"] is not False:
        raise EnvelopeError("privileged")
    if effective["cap_add"] != [] or type(effective["cap_add"]) is not list:
        raise EnvelopeError("cap_add")
    if effective["cap_drop"] != ["ALL"] or type(effective["cap_drop"]) is not list:
        raise EnvelopeError("cap_drop")
    if effective["devices"] != [] or type(effective["devices"]) is not list:
        raise EnvelopeError("devices")
    if effective["pid_mode"] != "":
        raise EnvelopeError("pid_mode")
    if effective["userns_mode"] != "":
        raise EnvelopeError("userns_mode")
    if type(effective["no_new_privileges"]) is not bool or effective["no_new_privileges"] is not True:
        raise EnvelopeError("no_new_privileges")
    if type(effective["read_only_root"]) is not bool or effective["read_only_root"] is not True:
        raise EnvelopeError("read_only_root")
    if effective["user"] != CONTAINED_USER:
        raise EnvelopeError("user")

    sealed = requested["sealed"]
    if sealed and effective["network_mode"] != "none":
        raise EnvelopeError("network_mode")
    if not sealed and effective["network_mode"] == "none":
        raise EnvelopeError("network_mode")

    if type(effective["memory"]) is not int or effective["memory"] != profile["memory_bytes"]:
        raise EnvelopeError("memory")
    if type(effective["memory_swap"]) is not int or effective["memory_swap"] != profile["memory_swap_bytes"]:
        raise EnvelopeError("memory_swap")
    if type(effective["pids_limit"]) is not int or effective["pids_limit"] != profile["pids"]:
        raise EnvelopeError("pids_limit")

    if type(effective["tmpfs"]) is not dict:
        raise EnvelopeError("tmpfs")
    expected_tmpfs = {
        "/tmp": {"exec": False, "nr_inodes": profile["tmp_inodes"],
                 "size": profile["tmp_bytes"]},
        "/work": {"exec": profile["work_exec"],
                  "nr_inodes": profile["work_inodes"],
                  "size": profile["work_bytes"]},
    }
    if effective["tmpfs"] != expected_tmpfs:
        raise EnvelopeError("tmpfs")
    for _dest, spec in effective["tmpfs"].items():
        if type(spec) is not dict:
            raise EnvelopeError("tmpfs")
        if type(spec.get("exec")) is not bool:
            raise EnvelopeError("tmpfs")
        if type(spec.get("nr_inodes")) is not int or type(spec.get("size")) is not int:
            raise EnvelopeError("tmpfs")

    # The allowed environment is the pinned image's own observed environment
    # plus exactly what the create argv adds. A name injected at create time
    # is outside that set by construction, so no denylist is needed and no
    # value is ever read.
    if type(effective["image_env_names"]) not in (list, tuple) or any(
            not isinstance(name, str) or not name for name in effective["image_env_names"]):
        raise EnvelopeError("image_env_names")
    if type(effective["env_names"]) not in (list, tuple) or any(
            not isinstance(name, str) or not name for name in effective["env_names"]):
        raise EnvelopeError("env_names")

    allowed = set(effective["image_env_names"])
    if sealed:
        allowed.add(OFFLINE_ENV_NAME)
    if set(effective["env_names"]) - allowed:
        raise EnvelopeError("env_names")
    if sealed != (OFFLINE_ENV_NAME in effective["env_names"]):
        raise EnvelopeError("env_names")

    if type(effective["mounts"]) not in (list, tuple):
        raise EnvelopeError("mounts")
    for mount in effective["mounts"]:
        if type(mount) is not dict:
            raise EnvelopeError("mounts")
        if type(mount.get("rw")) is not bool or mount.get("rw") is not False:
            raise EnvelopeError("mounts")
        if not isinstance(mount.get("destination"), str) or not isinstance(mount.get("type"), str):
            raise EnvelopeError("mounts")

    expected_mounts = [
        {"destination": destination, "rw": False, "type": "bind"}
        for destination in requested["mount_spec"]
    ]
    if effective["mounts"] != expected_mounts:
        raise EnvelopeError("mounts")


def _require_member(value, members, where: str) -> str:
    for member in members:
        if value == member:
            return member
    raise EnvelopeError(where)


def _require_hex(value, length: int, where: str) -> str:
    if (not isinstance(value, str) or len(value) != length or
            any(ch not in contained.HEX64 for ch in value)):
        raise EnvelopeError(where)
    return value


def publication_permission(*, setup_status, envelope_status, candidate_outcome,
                           cleanup) -> tuple[str, str | None]:
    """One rule. Permission is derived, never supplied."""
    if setup_status != "ready":
        return "withheld", "setup_status"
    if envelope_status != "verified":
        return "withheld", "envelope_status"
    if candidate_outcome != "completed":
        return "withheld", "candidate_outcome"
    if cleanup != "removed-and-absent":
        return "withheld", "cleanup"
    return "permitted", None


def build_envelope_record(*, requested, setup_status, envelope_status,
                          unverified_field, effective, candidate_outcome,
                          cleanup, prepare_sha256, execution_commit,
                          report_sha256) -> dict:
    """Close the state model over one contained run.

    Setup, candidate and cleanup failures are preserved rather than folded
    together, and no combination manufactures a score. There is deliberately
    no `publication_permission` parameter: it cannot be caller-supplied.
    """
    require_requested_record(requested)
    setup_status = _require_member(setup_status, SETUP_STATUSES, "setup_status")
    envelope_status = _require_member(
        envelope_status, ENVELOPE_STATUSES, "envelope_status")
    candidate_outcome = _require_member(
        candidate_outcome, CANDIDATE_OUTCOMES, "candidate_outcome")
    cleanup = _require_member(cleanup, CLEANUP_RESULTS, "cleanup")

    if setup_status != "ready":
        if candidate_outcome != "not-run":
            raise EnvelopeError("candidate_outcome")
        if envelope_status != "unverified":
            raise EnvelopeError("envelope_status")
        if effective is not None:
            raise EnvelopeError("effective")

    if envelope_status == "verified":
        if unverified_field is not None:
            raise EnvelopeError("unverified_field")
        _require_exact(effective, EFFECTIVE_KEYS, "effective")
        require_envelope_matches_request(effective, requested)
    else:
        if not isinstance(unverified_field, str) or not unverified_field:
            raise EnvelopeError("unverified_field")
        if effective is not None:
            raise EnvelopeError("effective")

    permission, reason = publication_permission(
        setup_status=setup_status,
        envelope_status=envelope_status,
        candidate_outcome=candidate_outcome,
        cleanup=cleanup,
    )
    record = {
        "candidate_outcome": candidate_outcome,
        "cleanup": cleanup,
        "effective": None if effective is None else dict(effective),
        "envelope_status": envelope_status,
        "execution_commit": _require_hex(execution_commit, 40, "execution_commit"),
        "non_claims": list(NON_CLAIMS),
        "prepare_sha256": _require_hex(prepare_sha256, 64, "prepare_sha256"),
        "publication_permission": permission,
        "report_sha256": (
            None if report_sha256 is None
            else _require_hex(report_sha256, 64, "report_sha256")),
        "requested": dict(requested),
        "schema": ENVELOPE_SCHEMA,
        "setup_status": setup_status,
        "unverified_field": unverified_field,
        "withheld_reason": reason,
    }
    _require_exact(record, ENVELOPE_KEYS, "envelope")
    return record


def bind_report(record: dict, report_sha256) -> dict:
    """Attach the produced report digest. Envelope to report, never back."""
    _require_exact(record, ENVELOPE_KEYS, "envelope")
    return build_envelope_record(
        requested=record["requested"],
        setup_status=record["setup_status"],
        envelope_status=record["envelope_status"],
        unverified_field=record["unverified_field"],
        effective=record["effective"],
        candidate_outcome=record["candidate_outcome"],
        cleanup=record["cleanup"],
        prepare_sha256=record["prepare_sha256"],
        execution_commit=record["execution_commit"],
        report_sha256=report_sha256,
    )


def validate_envelope_record(record: dict) -> dict:
    """Validate that an execution-envelope record is internally consistent.

    Reconstructs the envelope record through bind_report and requires exact
    equality with the original document. Round-trip equality verifies the
    closure of the state model (derived publication permission, withheld reason,
    schema, non-claims, and state invariants) against explicit nested validators
    for requested declarations and effective observations. It does not prove
    that the record was authentic or produced by a specific unverified run.
    An inconsistent or mutated record raises EnvelopeError and is never
    normalized into a pass.
    """
    if type(record) is not dict:
        raise EnvelopeError("envelope")
    _require_exact(record, ENVELOPE_KEYS, "envelope")
    rebuilt = bind_report(record, record["report_sha256"])
    if rebuilt != record:
        raise EnvelopeError("envelope_semantic_mismatch")
    return record


def encode_envelope(record: dict) -> bytes:
    _require_exact(record, ENVELOPE_KEYS, "envelope")
    return (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")
