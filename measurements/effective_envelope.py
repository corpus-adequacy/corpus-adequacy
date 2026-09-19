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

import suggestion_evidence as _evidence
import contained_oci as contained
import kernel_readback

ENVELOPE_SCHEMA = _evidence._envelope_ENVELOPE_SCHEMA
ENVELOPE_SCHEMA_V1 = _evidence._envelope_ENVELOPE_SCHEMA_V1
ENVELOPE_SCHEMA_V2 = _evidence._envelope_ENVELOPE_SCHEMA_V2
# v3 is v2 plus the kernel's own read-back of the limits, taken while the container was held
# (#197). v0 to v2 records are read as before and never gain the field.
ENVELOPE_SCHEMA_V3 = _evidence._envelope_ENVELOPE_SCHEMA_V3
ENVELOPE_SCHEMAS = _evidence._envelope_ENVELOPE_SCHEMAS
# Schemas that bind the owner's tmpfs declaration and require CPU and nofile observations.
_OWNER_BOUND_SCHEMAS = _evidence._envelope_OWNER_BOUND_SCHEMAS
_RESOURCE_OBSERVING_SCHEMAS = _evidence._envelope_RESOURCE_OBSERVING_SCHEMAS
CONTAINED_PROFILE = _evidence._envelope_CONTAINED_PROFILE
CONTAINED_PROFILE_V1 = _evidence._envelope_CONTAINED_PROFILE_V1
# The one pairing rule for a request: the resource-profile loader each contained execution
# profile admits. contained-oci-v0 pairs only with a v1 profile, contained-oci-v1 only with v2.
_REQUESTED_RESOURCE_PROFILE = _evidence._envelope_REQUESTED_RESOURCE_PROFILE
# The envelope schema a new candidate run under each profile emits. Historical v1 and v2 bytes
# remain readable; new contained-oci-v1 records use v3, which adds the kernel read-back.
ENVELOPE_SCHEMA_BY_PROFILE = _evidence._envelope_ENVELOPE_SCHEMA_BY_PROFILE
CONTAINED_USER = _evidence._envelope_CONTAINED_USER
OFFLINE_ENV_NAME = _evidence._envelope_OFFLINE_ENV_NAME

SETUP_STATUSES = _evidence._envelope_SETUP_STATUSES
# No `degraded`: contained-oci-v0 has no optional containment axis, so a
# missing or contradicted required field is `unverified` and the run is
# withheld. A third member here would be a state the engine cannot produce.
ENVELOPE_STATUSES = _evidence._envelope_ENVELOPE_STATUSES
CANDIDATE_OUTCOMES = _evidence._envelope_CANDIDATE_OUTCOMES
CLEANUP_RESULTS = _evidence._envelope_CLEANUP_RESULTS
PUBLICATION_PERMISSIONS = _evidence._envelope_PUBLICATION_PERMISSIONS

EFFECTIVE_KEYS = _evidence._envelope_EFFECTIVE_KEYS
EFFECTIVE_KEYS_V1 = _evidence._envelope_EFFECTIVE_KEYS_V1
EFFECTIVE_KEYS_V3 = _evidence._envelope_EFFECTIVE_KEYS_V3
REQUESTED_KEYS = _evidence._envelope_REQUESTED_KEYS
REQUESTED_KEYS_V2 = _evidence._envelope_REQUESTED_KEYS_V2
ENVELOPE_KEYS = _evidence._envelope_ENVELOPE_KEYS
NON_CLAIMS = _evidence._envelope_NON_CLAIMS


class EnvelopeError(contained.PrepareError):
    """An observation was missing, contradicted, or outside the closed model."""


def _shared_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _evidence.EnvelopeContractError as exc:
        raise EnvelopeError(str(exc)) from exc
    except _evidence._contained_contract.ContractError as exc:
        raise contained.PrepareError(str(exc)) from exc


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


def _observed_tmpfs(spec: str, where: str, *, owner_bound=False) -> dict:
    """Use the executor's one tmpfs parser, then select the schema's stored shape."""
    try:
        parsed = contained.parse_tmpfs_options(spec, owner_bound=owner_bound)
    except contained.PrepareError as exc:
        raise EnvelopeError(where) from exc
    if owner_bound:
        return parsed
    return {key: parsed[key] for key in ("exec", "nr_inodes", "size")}


def _project_effective_envelope(inspect, *, image_env_names, runtime_version,
                                owner_bound=False) -> dict:
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
            observed_tmpfs[destination], "HostConfig.Tmpfs", owner_bound=owner_bound)

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


def project_effective_envelope(inspect, *, image_env_names, runtime_version) -> dict:
    return _project_effective_envelope(
        inspect, image_env_names=image_env_names, runtime_version=runtime_version)


def _effective_keys(schema):
    return _shared_call(_evidence._envelope_effective_keys, schema)


def _v1_integer(value, where):
    return _shared_call(_evidence._envelope_v1_integer, value, where)


def _v1_identity(value, where):
    return _shared_call(_evidence._envelope_v1_identity, value, where)


def _v1_options(value, where):
    return _shared_call(_evidence._envelope_v1_options, value, where)


def _require_v1_values(effective):
    """Shared stored-value rules; projection cannot stand in for reader validation."""
    return _shared_call(_evidence._envelope_require_v1_values, effective)


def _add_v1_observations(effective, inspect, daemon_info):
    for stored, wire in (("cpu_period", "CpuPeriod"), ("cpu_quota", "CpuQuota"),
                         ("nano_cpus", "NanoCpus")):
        effective[stored] = _v1_integer(
            _observed(inspect, "HostConfig", wire), "HostConfig." + wire)
    limits = _observed(inspect, "HostConfig", "Ulimits")
    nofile = None
    if limits is not None:
        if type(limits) is not list:
            raise EnvelopeError("HostConfig.Ulimits")
        for item in limits:
            if type(item) is not dict or "Name" not in item or not isinstance(item["Name"], str):
                raise EnvelopeError("HostConfig.Ulimits")
            if item["Name"] != "nofile":
                continue
            if nofile is not None or "Soft" not in item or "Hard" not in item:
                raise EnvelopeError("HostConfig.Ulimits")
            nofile = {"soft": item["Soft"], "hard": item["Hard"]}
    effective["ulimit_nofile"] = nofile
    if type(daemon_info) is not dict:
        raise EnvelopeError("daemon")
    daemon = {}
    for stored, wire in (("kernel_version", "KernelVersion"),
                         ("cgroup_version", "CgroupVersion"),
                         ("cgroup_driver", "CgroupDriver")):
        if wire not in daemon_info:
            raise EnvelopeError("daemon." + wire)
        daemon[stored] = _v1_identity(daemon_info[wire], "daemon." + wire)
    if "SecurityOptions" not in daemon_info:
        raise EnvelopeError("daemon.SecurityOptions")
    options = daemon_info["SecurityOptions"]
    if options is None:
        options = []
    daemon["security_options"] = _v1_options(options, "daemon.SecurityOptions")
    effective["daemon"] = daemon
    _require_v1_values(effective)
    return effective


def project_effective_envelope_v1(inspect, *, image_env_names, runtime_version,
                                  daemon_info):
    """Historical v1 shape; its tmpfs projection remains byte-compatible."""
    effective = project_effective_envelope(
        inspect, image_env_names=image_env_names, runtime_version=runtime_version)
    return _add_v1_observations(effective, inspect, daemon_info)


def project_effective_envelope_v2(inspect, *, image_env_names, runtime_version,
                                  daemon_info):
    """Owner-bound tmpfs observations plus the existing v1 resource observations."""
    effective = _project_effective_envelope(
        inspect, image_env_names=image_env_names, runtime_version=runtime_version,
        owner_bound=True)
    return _add_v1_observations(effective, inspect, daemon_info)


def project_effective_envelope_v3(inspect, *, image_env_names, runtime_version,
                                  daemon_info, kernel_files):
    """v2 plus the kernel's own read-back, taken while the container was held (#197)."""
    effective = project_effective_envelope_v2(
        inspect, image_env_names=image_env_names, runtime_version=runtime_version,
        daemon_info=daemon_info)
    try:
        effective["kernel"] = kernel_readback.observe(
            {} if kernel_files is None else kernel_files)
    except kernel_readback.ReadbackError as exc:
        raise EnvelopeError("kernel") from exc
    return effective


def _require_kernel_readback(kernel, profile) -> None:
    """The kernel must hold exactly what was requested. The first problem names the field.

    A differing value is `readback_mismatch:<field>`, a value that did not read in the kernel's
    own form is `readback_unreadable:<field>`; either leaves the envelope unverified. This is the
    kernel's view for one container at one moment, not proof the limit was ever reached.
    """
    return _shared_call(_evidence._envelope_require_kernel_readback, kernel, profile)


def _resource_profile_loader(execution_profile):
    """The resource-profile loader a requested execution profile admits; any other refuses."""
    return _shared_call(_evidence._envelope_resource_profile_loader, execution_profile)


def envelope_schema_for_profile(execution_profile) -> str:
    """The envelope schema a candidate run under `execution_profile` emits."""
    return _shared_call(_evidence._envelope_envelope_schema_for_profile, execution_profile)


def _require_schema_profile(schema, execution_profile) -> None:
    return _shared_call(_evidence._envelope_require_schema_profile, schema, execution_profile)


def requested_envelope(*, execution_profile, image_id, mount_spec, resource_profile, sealed, schema=None) -> dict:
    """The declaration side. These values are compared, never projected.

    The pinned image's own environment is NOT here: it is an observation of
    an immutable artifact, so it sits in `effective` and the environment
    check is observation against observation, with no declaration involved.
    """
    return _shared_call(_evidence._envelope_requested_envelope, execution_profile=execution_profile, image_id=image_id, mount_spec=mount_spec, resource_profile=resource_profile, sealed=sealed, schema=schema)


def _require_exact(doc, keys, where: str) -> None:
    return _shared_call(_evidence._envelope_require_exact, doc, keys, where)


def require_requested_record(requested, *, schema=None) -> dict:
    """Validate that a stored requested declaration conforms to the closed schema.

    Enforces that execution_profile is a contained profile paired with its own
    resource-profile version (contained-oci-v0 with RESOURCE_PROFILE_SCHEMA,
    contained-oci-v1 with RESOURCE_PROFILE_V2_SCHEMA), image_id is a valid
    sha256 digest, sealed is strictly a bool, resource_profile has positive
    integer limits and bool work_exec, and mount_spec is a strictly sorted
    list of unique destination strings starting with '/'.
    """
    return _shared_call(_evidence._envelope_require_requested_record, requested, schema=schema)


def _requests_cpu_and_nofile(requested) -> bool:
    """A v2 resource profile is a request for CPU and nofile limits; a v1 one is not.

    After `require_requested_record` this is exactly a contained-oci-v1 request, since that
    profile pairs only with a v2 resource profile.
    """
    return _shared_call(_evidence._envelope_requests_cpu_and_nofile, requested)


def _require_cpu_and_nofile_match(effective, profile) -> None:
    """Exact comparison of daemon-stored CPU and nofile against a v2 request.

    The daemon may discard a limit and store it unset (0, or no nofile entry); that reads as a
    mismatch here, never as satisfied. `NanoCpus` must be stored unset: moby refuses it beside a
    CFS period, so a nonzero value next to the requested period/quota is not what the v2 codec
    asked for. This compares configuration the daemon reports, not a limit the kernel applied.
    """
    return _shared_call(_evidence._envelope_require_cpu_and_nofile_match, effective, profile)


def require_envelope_matches_request(effective, requested, *, schema=ENVELOPE_SCHEMA) -> None:
    """Hold one observation against one declaration. Observation cannot yield.

    The v0 fields retain their declaration comparisons. For a v2 request the
    observed CPU period, quota and nofile soft/hard are compared exactly and
    NanoCpus must be stored unset (0), so a v2 request needs a v1 or v2 envelope.
    For a v1 resource request those fields, and the daemon fields always, are
    observations with shape checks, not requested limits.
    """
    return _shared_call(_evidence._envelope_require_envelope_matches_request, effective, requested, schema=schema)


def _require_member(value, members, where: str) -> str:
    return _shared_call(_evidence._envelope_require_member, value, members, where)


def _require_hex(value, length: int, where: str) -> str:
    return _shared_call(_evidence._envelope_require_hex, value, length, where)


def publication_permission(*, setup_status, envelope_status, candidate_outcome, cleanup) -> tuple[str, str | None]:
    """One rule. Permission is derived, never supplied."""
    return _shared_call(_evidence.envelope_permission_data, setup_status=setup_status, envelope_status=envelope_status, candidate_outcome=candidate_outcome, cleanup=cleanup)


def build_envelope_record(*, requested, setup_status, envelope_status, unverified_field, effective, candidate_outcome, cleanup, prepare_sha256, execution_commit, report_sha256, schema=ENVELOPE_SCHEMA) -> dict:
    """Close the state model over one contained run.

    Setup, candidate and cleanup failures are preserved rather than folded
    together, and no combination manufactures a score. There is deliberately
    no `publication_permission` parameter: it cannot be caller-supplied.
    """
    return _shared_call(_evidence._envelope_build_envelope_record, requested=requested, setup_status=setup_status, envelope_status=envelope_status, unverified_field=unverified_field, effective=effective, candidate_outcome=candidate_outcome, cleanup=cleanup, prepare_sha256=prepare_sha256, execution_commit=execution_commit, report_sha256=report_sha256, schema=schema)


def bind_report(record: dict, report_sha256) -> dict:
    """Attach the produced report digest. Envelope to report, never back."""
    return _shared_call(_evidence._envelope_bind_report, record, report_sha256)


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
    return _shared_call(_evidence.require_envelope_record_data, record)


def encode_envelope(record: dict) -> bytes:
    _require_exact(record, ENVELOPE_KEYS, "envelope")
    return (json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")
