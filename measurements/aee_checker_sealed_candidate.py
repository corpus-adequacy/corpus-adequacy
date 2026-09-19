"""Bounded sealed-OCI candidate backend. Synthetic host adapter only.

Reuses the existing process/batch runner and the canonical adapter
expected_ids/project rule. Incomplete inner events become returncode 75.
Does not run a real corpus/checker experiment.
"""

from __future__ import annotations

import suggestion_evidence as assessment_evidence

import importlib
import json
import corpus_adequacy as ca
import shlex
import subprocess
import sys
from pathlib import Path

from aee_checker_sealed_common import (
    INERT_RESOURCE_PROFILE,
    DockerUnavailable,
    PrepareError,
    load_strict,
    preserve_cleanup_failure,
    require_resource_profile,
)
from aee_checker_sealed_oci import (
    DEFAULT_MOUNT_SPEC,
    docker_bounded,
    docker_create_argv,
    parse_inspect_payload,
    require_container_absent,
    require_image_id,
    require_local_image,
    validate_inspect_contract,
)
from aee_checker_sealed_run import load_prepare_for_profile
import bounded_run as br
import contained_oci as contained
import effective_envelope as envelope
import kernel_readback
from sealed_measurement_contract import (
    AEE_CHECKER_SEALED_CONTRACT,
    CANDIDATE_WRAPPER_STAGE_RETURNCODES,
)

_ROOT = Path(__file__).resolve().parents[1]
_ADAPTERS = str(_ROOT / "adapters")
if _ADAPTERS not in sys.path:
    sys.path.insert(0, _ADAPTERS)
from sealed_measurement_contract import (  # noqa: E402
    OWNED_CONTAINED_V1_CONTRACT,
    OWNED_INDEPENDENT_V0_CONTRACT,
)

CANDIDATE_MOUNT_SPEC = DEFAULT_MOUNT_SPEC + (("subject", "/subject"),)
CANDIDATE_ENTRYPOINT = "/bin/sh"
CONTAINER_BUILD = AEE_CHECKER_SEALED_CONTRACT.candidate_build
CONTAINER_ENTRYPOINT = AEE_CHECKER_SEALED_CONTRACT.candidate_entrypoint
UNPROVED_EXIT = 75
WRAPPER_STAGE_RETURNCODES = dict(CANDIDATE_WRAPPER_STAGE_RETURNCODES)
WRAPPER_STAGES = tuple(WRAPPER_STAGE_RETURNCODES)


def wrapper_stage_returncode(stage: str) -> int:
    if stage not in WRAPPER_STAGE_RETURNCODES:
        raise PrepareError("candidate wrapper stage")
    return WRAPPER_STAGE_RETURNCODES[stage]


def _wrapper_stage(returncode) -> str | None:
    if type(returncode) is not int:
        return None
    for stage, stage_returncode in WRAPPER_STAGE_RETURNCODES.items():
        if returncode == stage_returncode:
            return stage
    return None


def _readback_hold() -> str:
    """Wait for the host's release before anything else runs (#197).

    The host reads the kernel's limits through `docker exec` while the container is held here,
    then creates the release file. No candidate code has run yet. A release that never comes is
    the wrapper stage `readback-hold`, unproved, rather than a hang.
    """
    stage = WRAPPER_STAGE_RETURNCODES["readback-hold"]
    release = shlex.quote(kernel_readback.RELEASE_PATH)
    return "".join((
        "i=0; while test ! -e %s; do i=$((i+1)); " % release,
        "test \"$i\" -gt %d && candidate_stage %d; " % (kernel_readback.HOLD_POLLS, stage),
        "sleep %s; done; " % kernel_readback.HOLD_POLL_SECONDS,
        "rm -f %s || candidate_stage %d; " % (release, stage),
    ))


def candidate_script(execution_contract: dict,
                     *, contract=AEE_CHECKER_SEALED_CONTRACT,
                     readback_hold: bool = False) -> str:
    if type(execution_contract) is not dict:
        raise PrepareError("candidate execution contract")
    build = execution_contract.get("build")
    entrypoint = execution_contract.get("entrypoint_command")
    if (build != list(contract.candidate_build) or
            entrypoint != list(contract.candidate_entrypoint)):
        raise PrepareError("candidate execution contract")
    complete = "|".join(str(value) for value in contract.candidate_complete_returncodes)
    stage = WRAPPER_STAGE_RETURNCODES
    return "".join((
        "set -u; ",
        "candidate_stage() { exit \"$1\"; }; ",
        _readback_hold() if readback_hold else "",
        "test -d /input/vectors && test -d /vendor && test -f /tool/config.toml ",
        "&& test -d /subject || candidate_stage %d; " % stage["preflight"],
        "cp -R /subject/. /work/ || candidate_stage %d; " % stage["copy"],
        "cd /work || candidate_stage %d; " % stage["copy"],
        "PATH=/usr/local/cargo/bin:$PATH CARGO_HOME=/tool ",
        shlex.join(build), " 1>&2 || candidate_stage %d; " % stage["build"],
        shlex.join(entrypoint), " 1>&2; status=$?; ",
        "case \"$status\" in ", complete,
        ") ;; *) exit %d ;; esac; " % UNPROVED_EXIT,
        "test -e /work/report.json || candidate_stage %d; " % stage["report-missing"],
        "test -s /work/report.json || candidate_stage %d; " % stage["report-empty"],
        "cat /work/report.json || candidate_stage %d; " % stage["report-read"],
        "exit $status",
    ))


DEFAULT_EXECUTION_CONTRACT = {
    "build": list(CONTAINER_BUILD),
    "entrypoint_command": list(CONTAINER_ENTRYPOINT),
}
CANDIDATE_SCRIPT = candidate_script(DEFAULT_EXECUTION_CONTRACT)


def _unproved(reason: str = "malformed") -> subprocess.CompletedProcess:
    token = ca.sanitize_unproved_reason(reason)
    if token is None:
        token = "malformed"
    completed = subprocess.CompletedProcess(
        args=[], returncode=UNPROVED_EXIT, stdout="", stderr="")
    completed.unproved_reason = token
    return completed


INNER_STDOUT_OUTPUT_CAP = object()


def inner_protocol_stdout(stdout):
    """Accept one JSON object that ends with exactly one LF.

    CR, leading whitespace, extra trailing whitespace, a prefix before
    the object, zero LFs, and more than one final LF are rejected.
    Internal pretty-print newlines are allowed only when the value
    starts with '{' and the whole value has exactly one final LF.
    An over-cap payload is a distinguished output-cap outcome.
    """
    if type(stdout) is not str:
        return None
    if len(stdout.encode("utf-8")) > br.OUTPUT_CAP_BYTES:
        return INNER_STDOUT_OUTPUT_CAP
    if stdout == "":
        return None
    if "\r" in stdout:
        return None
    if not stdout.endswith("\n") or stdout.endswith("\n\n"):
        return None
    body = stdout[:-1]
    if body.endswith((" ", "\t", "\n")):
        return None
    if body == "" or body[0] != "{":
        return None
    return body


_cleanup_candidate = contained.cleanup_container


def require_candidate_image(*, image_id: str, toolchain_image_id: str,
                            probe_image_id: str) -> str:
    image_id = require_image_id(image_id)
    toolchain_image_id = require_image_id(toolchain_image_id)
    probe_image_id = require_image_id(probe_image_id)
    if image_id == probe_image_id:
        raise PrepareError("candidate cannot use inert probe image")
    if image_id != toolchain_image_id:
        raise PrepareError("candidate image must be toolchain.image_id")
    return image_id


def host_vectors_path(mounts: dict) -> str:
    return str(Path(mounts["input"]) / "vectors")


def sealed_adapter_for(contract):
    """Resolve only the code-owned adapters; paths are never operator input."""
    from sealed_measurement_contract import OwnedAssessmentVariantContract
    if type(contract) is OwnedAssessmentVariantContract:
        return importlib.import_module("owned_contained_v1")
    if contract is AEE_CHECKER_SEALED_CONTRACT:
        return importlib.import_module("aee_checker_sealed")
    if contract is OWNED_CONTAINED_V1_CONTRACT or contract is OWNED_INDEPENDENT_V0_CONTRACT:
        # The independent selection measures the same owned candidate and corpus (#199).
        return importlib.import_module("owned_contained_v1")
    raise PrepareError("sealed measurement adapter")


def normalize_inner_event(*, returncode, stdout, vectors,
                          contract=AEE_CHECKER_SEALED_CONTRACT) -> subprocess.CompletedProcess:
    """Parse the inner report once, then reuse adapter expected_ids/project."""
    stage = _wrapper_stage(returncode)
    if stage is not None:
        return _unproved("candidate-" + stage)
    if returncode not in contract.candidate_complete_returncodes:
        return _unproved("inner-exit")
    body = inner_protocol_stdout(stdout)
    if body is INNER_STDOUT_OUTPUT_CAP:
        return _unproved("output-cap")
    if body is None:
        if stdout == "" or stdout is None:
            return _unproved("empty-or-missing")
        return _unproved("malformed")
    try:
        inner = load_strict(body.encode("utf-8"))
    except (PrepareError, json.JSONDecodeError, TypeError, ValueError):
        return _unproved("malformed")
    if type(inner) is not dict:
        return _unproved("malformed")
    try:
        adapter = sealed_adapter_for(contract)
        expected = adapter.expected_ids(vectors)
        projected = adapter.project(inner, expected)
    except (PrepareError, ca.ManifestError, KeyError, TypeError, ValueError, OSError):
        return _unproved("projection")
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            projected, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        stderr="",
    )


OOM_KILLED_REPORTED = "oom-killed-reported"


def candidate_result(raw: dict, *, mounts: dict,
                     contract=AEE_CHECKER_SEALED_CONTRACT) -> subprocess.CompletedProcess:
    """The candidate's result from one contained run's raw outcome, on both paths.

    A run that did not complete keeps its own state: a deadline remains `timeout` and an
    output cap remains `output-cap`, even when the daemon also reported an OOM kill.

    For a completed run, `oom_killed` True is `oom-killed-reported`, whatever the exit code
    (0, 1, 137 or any other), and the inner report is not read. The daemon reported an OOM
    kill in this container's cgroup during the run (the container's memory limit or a
    host-wide OOM), so the result was not produced under clean conditions: it is named, not
    scored, and never a mutant kill. It does not claim the measured process was the one
    killed. False or None (not observed) changes nothing, so exit 137 stays `inner-exit`:
    exit 137 is also `docker stop`'s SIGKILL, and no exit code, stderr text or other
    candidate-controlled signal alone establishes a resource cause.
    """
    if raw["state"] != "completed":
        return _unproved(raw["state"])
    if raw["oom_killed"] is True:
        return _unproved(OOM_KILLED_REPORTED)
    proc = raw["process"]
    return normalize_inner_event(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        vectors=host_vectors_path(mounts),
        contract=contract,
    )


def candidate_create_argv(*, image_id: str, name: str, mounts: dict,
                          sealed: bool = True, resource_profile=None,
                          execution_contract=None,
                          contract=AEE_CHECKER_SEALED_CONTRACT) -> list[str]:
    return docker_create_argv(
        image_id=image_id,
        name=name,
        mounts=mounts,
        command=["-lc", candidate_script(
            {"build": list(contract.candidate_build),
             "entrypoint_command": list(contract.candidate_entrypoint)}
            if execution_contract is None else execution_contract,
            contract=contract)],
        sealed=sealed,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        entrypoint=CANDIDATE_ENTRYPOINT,
        resource_profile=resource_profile,
    )


_DockerTransport = contained.DockerTransport


def envelope_binding(*, prepare_sha256: str, execution_commit: str) -> dict:
    """The digests an envelope record binds itself to. No record without one."""
    return {
        "execution_commit": execution_commit,
        "prepare_sha256": prepare_sha256,
    }


def _candidate_outcome(state: str, completed) -> str:
    """The candidate's own result, kept separate from the envelope's."""
    if state != "completed":
        return state
    if completed.returncode == UNPROVED_EXIT:
        return "unproved"
    return "completed"


def _refused_envelope(binding: dict, requested, status: str,
                      field: str, schema: str) -> subprocess.CompletedProcess:
    """Setup never became ready, so no candidate outcome may be claimed."""
    completed = _unproved("setup")
    if requested is None:
        return completed
    completed.envelope_record = envelope.build_envelope_record(
        schema=schema,
        requested=requested,
        setup_status=status,
        envelope_status="unverified",
        unverified_field=field,
        effective=None,
        candidate_outcome="not-run",
        cleanup="removed-and-absent",
        prepare_sha256=binding["prepare_sha256"],
        execution_commit=binding["execution_commit"],
        report_sha256=None,
    )
    return completed


def _requested_envelope(*, execution_profile, image_id: str, resource_profile,
                        sealed: bool, schema: str) -> dict:
    """Pure declaration, so a record always exists to hold what happened.

    The profile is the one admission resolved, never a constant: a request that named a
    different profile than the run was admitted under would be a silent downgrade.
    """
    return envelope.requested_envelope(
        execution_profile=execution_profile,
        image_id=image_id,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        resource_profile=resource_profile,
        sealed=sealed,
        schema=schema,
    )


def _observed(transport, name: str, *args):
    """Read one observation from the transport. Absence is not a value."""
    reader = getattr(transport, name, None)
    if not callable(reader):
        raise envelope.EnvelopeError(name)
    return reader(*args)


def _project_effective(transport, inspect, *, image_id: str, schema: str,
                       kernel_files=None) -> dict:
    """Project this run's envelope with the projector its schema names.

    A v1 envelope adds this run's daemon observation, read from the transport's own daemon
    reader; a missing reader or field raises and the envelope is unverified.
    """
    image_env_names = _observed(transport, "image_env_names", image_id)
    runtime_version = _observed(transport, "version")
    if schema == envelope.ENVELOPE_SCHEMA_V3:
        return envelope.project_effective_envelope_v3(
            inspect, image_env_names=image_env_names, runtime_version=runtime_version,
            daemon_info=_observed(transport, "daemon_info"), kernel_files=kernel_files)
    if schema == envelope.ENVELOPE_SCHEMA_V2:
        return envelope.project_effective_envelope_v2(
            inspect, image_env_names=image_env_names, runtime_version=runtime_version,
            daemon_info=_observed(transport, "daemon_info"))
    if schema == envelope.ENVELOPE_SCHEMA_V1:
        return envelope.project_effective_envelope_v1(
            inspect, image_env_names=image_env_names, runtime_version=runtime_version,
            daemon_info=_observed(transport, "daemon_info"))
    return envelope.project_effective_envelope(
        inspect, image_env_names=image_env_names, runtime_version=runtime_version)


def _require_no_create_warnings(create_warnings) -> None:
    """A second signal beside the stored config: the daemon said it changed the request.

    moby can discard a requested limit, store the changed config and report it only as a
    create-time warning (#102 §3). The comparator already catches a discard it can see in the
    stored config; this runs after it, so a more specific field keeps precedence. Only an
    empty tuple verifies: None is a transport that did not observe create warnings, and
    absence is not a value. The warning text is not recorded.
    """
    if type(create_warnings) is not tuple or create_warnings:
        raise envelope.EnvelopeError("create_warnings")


def _contained_candidate_run(*, image_id: str, mounts: dict, resource_profile,
                             name_prefix: str, sealed: bool, transport,
                             execution_contract, record_cleanup: bool,
                             contract=AEE_CHECKER_SEALED_CONTRACT,
                             readback: bool = False) -> dict:
    # The wrapper holds only when this run will release it: a hold nobody releases would wait
    # out its bound and turn every run unproved.
    return contained.run_contained(
        image_id=image_id,
        mounts=mounts,
        command=["-lc", candidate_script(
            {"build": list(contract.candidate_build),
             "entrypoint_command": list(contract.candidate_entrypoint)}
            if execution_contract is None else execution_contract,
            contract=contract, readback_hold=readback)],
        readback=readback,
        entrypoint=CANDIDATE_ENTRYPOINT,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        resource_profile=resource_profile,
        sealed=sealed,
        name_prefix=name_prefix,
        transport=transport,
        record_cleanup=record_cleanup,
    )


def _recorded_sealed_candidate(*, image_id, mounts, resource_profile,
                               execution_profile, name_prefix, sealed, transport,
                               execution_contract, binding, contract,
                               ) -> subprocess.CompletedProcess:
    """Run the candidate and keep one envelope record whatever happens.

    The envelope is projected from this run's own inspect output and this
    run's own runtime version. PREPARE's inert-probe evidence describes a
    different image and profile and cannot stand in for either. The record's
    schema follows the execution profile: new contained-oci-v1 records v3, which also
    carries the kernel's read-back taken while this container was held (#197).
    """
    schema = envelope.envelope_schema_for_profile(execution_profile)
    requested = _requested_envelope(
        execution_profile=execution_profile, image_id=image_id,
        resource_profile=resource_profile, sealed=sealed, schema=schema)
    try:
        transport = contained.resolve_transport(image_id, transport)
        raw = _contained_candidate_run(
            image_id=image_id, mounts=mounts,
            resource_profile=resource_profile, name_prefix=name_prefix,
            sealed=sealed, transport=transport,
            execution_contract=execution_contract, record_cleanup=True,
            contract=contract,
            readback=schema == envelope.ENVELOPE_SCHEMA_V3)
    except DockerUnavailable as exc:
        return _refused_envelope(binding, requested, "unavailable", str(exc), schema)
    except PrepareError as exc:
        return _refused_envelope(binding, requested, "refused", str(exc), schema)

    completed = candidate_result(raw, mounts=mounts, contract=contract)

    effective = None
    unverified_field = None
    try:
        effective = _project_effective(
            transport, raw["inspect"], image_id=image_id, schema=schema,
            kernel_files=raw.get("kernel_files"))
        envelope.require_envelope_matches_request(effective, requested, schema=schema)
        _require_no_create_warnings(raw["create_warnings"])
    except (envelope.EnvelopeError, PrepareError) as exc:
        effective, unverified_field = None, str(exc) or "effective"

    completed.envelope_record = envelope.build_envelope_record(
        schema=schema,
        requested=requested,
        setup_status="ready",
        envelope_status="unverified" if effective is None else "verified",
        unverified_field=unverified_field,
        effective=effective,
        candidate_outcome=_candidate_outcome(raw["state"], completed),
        cleanup=raw["cleanup"],
        prepare_sha256=binding["prepare_sha256"],
        execution_commit=binding["execution_commit"],
        report_sha256=None,
    )
    return completed


def _run_sealed_candidate(*, image_id: str, mounts: dict,
                          resource_profile,
                          name_prefix: str = "aee-cand-",
                          sealed: bool = True, transport=None,
                          execution_contract=None, binding=None,
                          execution_profile=None,
                          contract=AEE_CHECKER_SEALED_CONTRACT,
                          ) -> subprocess.CompletedProcess:
    """Without a binding this is the legacy unrecorded run, unchanged.

    A record binds itself to PREPARE and execution digests, so it exists
    only where those digests do. A recorded run also names its execution
    profile; one without a contained profile refuses before any effect.
    Below admission: the profile/PREPARE pairing is `run_sealed_candidate`'s.
    """
    # Resolve the code-owned adapter before container creation. A selected adapter whose
    # module cannot load is an admission failure, not a post-execution projection failure.
    sealed_adapter_for(contract)
    if binding is not None:
        return _recorded_sealed_candidate(
            image_id=image_id, mounts=mounts,
            resource_profile=resource_profile,
            execution_profile=execution_profile, name_prefix=name_prefix,
            sealed=sealed, transport=transport,
            execution_contract=execution_contract, binding=binding, contract=contract)
    raw = _contained_candidate_run(
        image_id=image_id, mounts=mounts, resource_profile=resource_profile,
        name_prefix=name_prefix, sealed=sealed, transport=transport,
        execution_contract=execution_contract, record_cleanup=False, contract=contract)
    return candidate_result(raw, mounts=mounts, contract=contract)


# The one profile with a legacy unrecorded run: contained-oci-v0 predates the envelope record.
# An allowlist, so a profile added later is recorded unless it is listed here.
UNRECORDED_PROFILES = frozenset({"contained-oci-v0"})


def require_recording(*, execution_profile, binding) -> None:
    """Refuse an unrecorded run under any profile but the legacy one, before any effect.

    Without a binding there is no envelope record, and a run under a profile whose evidence
    is that record would carry the profile's name and none of what it stands for.
    """
    if binding is None and (type(execution_profile) is not str
                            or execution_profile not in UNRECORDED_PROFILES):
        raise PrepareError(
            "%s requires a recorded run; an unrecorded run has no envelope and is refused"
            % (execution_profile,))


def run_sealed_candidate(*, prepare_raw: bytes, mounts: dict, execution_profile,
                         name_prefix: str = "aee-cand-",
                         transport=None, execution_contract=None,
                         binding=None, assessment_context=None,
                         contract=AEE_CHECKER_SEALED_CONTRACT) -> subprocess.CompletedProcess:
    """Admit PREPARE bytes under the resolved execution profile, then run them.

    `execution_profile` has no default: omission is TypeError, never an implied
    contained-oci-v0. The shared dispatcher admits prepare.v1 only under
    contained-oci-v0 and prepare.v2 only under contained-oci-v1, before any effect.
    """
    admitted = assessment_evidence.admit_assessment_call(
        assessment_context, execution_profile, contract, prepare_raw)
    if admitted is None:
        prepare = load_prepare_for_profile(
            prepare_raw, execution_profile=execution_profile, contract=contract)
    else:
        expected_binding = envelope_binding(
            prepare_sha256=assessment_evidence.digest(prepare_raw),
            execution_commit=admitted['source']['commit'])
        if binding != expected_binding:
            assessment_evidence.refuse('binding', 'prepare-authorization')
        prepare = admitted['runtime']
    require_recording(execution_profile=execution_profile, binding=binding)
    image_id = require_candidate_image(
        image_id=prepare["toolchain"]["image_id"],
        toolchain_image_id=prepare["toolchain"]["image_id"],
        probe_image_id=prepare["image"]["id"],
    )
    return _run_sealed_candidate(
        image_id=image_id,
        mounts=mounts,
        resource_profile=prepare["candidate_profile"],
        execution_profile=execution_profile,
        name_prefix=name_prefix,
        sealed=True,
        transport=transport,
        execution_contract=execution_contract,
        binding=binding,
        contract=contract,
    )
