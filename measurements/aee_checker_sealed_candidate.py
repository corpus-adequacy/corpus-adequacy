"""Bounded sealed-OCI candidate backend. Synthetic host adapter only.

Reuses the existing process/batch runner and the canonical adapter
expected_ids/project rule. Incomplete inner events become returncode 75.
Does not run a real corpus/checker experiment.
"""

from __future__ import annotations

import json
import corpus_adequacy as ca
import shlex
import subprocess
import sys
from pathlib import Path

from aee_checker_sealed_common import (
    INERT_RESOURCE_PROFILE,
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
from aee_checker_sealed_run import load_prepare_v1
import bounded_run as br
import contained_oci as contained

_ROOT = Path(__file__).resolve().parents[1]
_ADAPTERS = str(_ROOT / "adapters")
if _ADAPTERS not in sys.path:
    sys.path.insert(0, _ADAPTERS)
import aee_checker_sealed as sealed_adapter  # noqa: E402

CANDIDATE_MOUNT_SPEC = DEFAULT_MOUNT_SPEC + (("subject", "/subject"),)
CANDIDATE_ENTRYPOINT = "/bin/sh"
CONTAINER_BUILD = ("cargo", "build", "--release", "--locked", "--offline")
CONTAINER_ENTRYPOINT = (
    "/work/target/release/aee-checker", "/input/vectors", "--json", "/work/report.json",
)


def candidate_script(execution_contract: dict) -> str:
    if type(execution_contract) is not dict:
        raise PrepareError("candidate execution contract")
    build = execution_contract.get("build")
    entrypoint = execution_contract.get("entrypoint_command")
    if build != list(CONTAINER_BUILD) or entrypoint != list(CONTAINER_ENTRYPOINT):
        raise PrepareError("candidate execution contract")
    return (
    "set -eu; "
    "test -d /input/vectors; test -d /vendor; test -f /tool/config.toml; test -d /subject; "
    "cp -R /subject/. /work/; "
    "cd /work; "
    "PATH=/usr/local/cargo/bin:$PATH CARGO_HOME=/tool "
    + shlex.join(build) + " 1>&2; "
    "set +e; "
    + shlex.join(entrypoint) + " 1>&2; "
    "status=$?; "
    "set -e; "
    "cat /work/report.json; "
    "exit $status"
    )


DEFAULT_EXECUTION_CONTRACT = {
    "build": list(CONTAINER_BUILD),
    "entrypoint_command": list(CONTAINER_ENTRYPOINT),
}
CANDIDATE_SCRIPT = candidate_script(DEFAULT_EXECUTION_CONTRACT)
UNPROVED_EXIT = 75
COMPLETE_RETURNCODES = (0, 1)


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


def normalize_inner_event(*, returncode, stdout, vectors) -> subprocess.CompletedProcess:
    """Parse the inner report once, then reuse adapter expected_ids/project."""
    if returncode not in COMPLETE_RETURNCODES:
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
        expected = sealed_adapter.expected_ids(vectors)
        projected = sealed_adapter.project(inner, expected)
    except (PrepareError, ca.ManifestError, KeyError, TypeError, ValueError, OSError):
        return _unproved("projection")
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(
            projected, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        stderr="",
    )


def candidate_create_argv(*, image_id: str, name: str, mounts: dict,
                          sealed: bool = True, resource_profile=None,
                          execution_contract=None) -> list[str]:
    return docker_create_argv(
        image_id=image_id,
        name=name,
        mounts=mounts,
        command=["-lc", candidate_script(
            DEFAULT_EXECUTION_CONTRACT
            if execution_contract is None else execution_contract)],
        sealed=sealed,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        entrypoint=CANDIDATE_ENTRYPOINT,
        resource_profile=resource_profile,
    )


_DockerTransport = contained.DockerTransport


def _run_sealed_candidate(*, image_id: str, mounts: dict,
                          resource_profile,
                          name_prefix: str = "aee-cand-",
                          sealed: bool = True, transport=None,
                          execution_contract=None,
                          ) -> subprocess.CompletedProcess:
    raw = contained.run_contained(
        image_id=image_id,
        mounts=mounts,
        command=["-lc", candidate_script(
            DEFAULT_EXECUTION_CONTRACT
            if execution_contract is None else execution_contract)],
        entrypoint=CANDIDATE_ENTRYPOINT,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        resource_profile=resource_profile,
        sealed=sealed,
        name_prefix=name_prefix,
        transport=transport,
    )
    if raw["state"] != "completed":
        return _unproved(raw["state"])
    proc = raw["process"]
    return normalize_inner_event(
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        vectors=host_vectors_path(mounts),
    )


def run_sealed_candidate(*, prepare_raw: bytes, mounts: dict,
                         name_prefix: str = "aee-cand-",
                         transport=None, execution_contract=None,
                         ) -> subprocess.CompletedProcess:
    prepare = load_prepare_v1(prepare_raw)
    image_id = require_candidate_image(
        image_id=prepare["toolchain"]["image_id"],
        toolchain_image_id=prepare["toolchain"]["image_id"],
        probe_image_id=prepare["image"]["id"],
    )
    return _run_sealed_candidate(
        image_id=image_id,
        mounts=mounts,
        resource_profile=prepare["candidate_profile"],
        name_prefix=name_prefix,
        sealed=True,
        transport=transport,
        execution_contract=execution_contract,
    )
