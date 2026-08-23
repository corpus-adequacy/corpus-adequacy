"""Bounded sealed-OCI candidate backend. Synthetic host adapter only.

Reuses the existing process/batch runner and the canonical adapter
expected_ids/project rule. Incomplete inner events become returncode 75.
Does not run a real corpus/checker experiment.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path
from secrets import token_hex

from aee_checker_sealed_common import (
    INERT_RESOURCE_PROFILE,
    PrepareError,
    load_strict,
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


def _unproved() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=UNPROVED_EXIT, stdout="", stderr="")


def _note_cleanup_failure(primary: BaseException, action: str,
                          failure: BaseException) -> None:
    primary.add_note("candidate %s failed: %s: %s" % (
        action, type(failure).__name__, failure))


def _cleanup_candidate(transport, name: str,
                       primary: BaseException | None) -> None:
    remove_failure = None
    try:
        transport.remove(name)
    except BaseException as exc:
        remove_failure = exc
        if primary is not None:
            _note_cleanup_failure(primary, "remove", exc)
    try:
        transport.require_absent(name)
    except BaseException as exc:
        if primary is not None:
            _note_cleanup_failure(primary, "absence proof", exc)
        elif remove_failure is not None:
            refusal = PrepareError("candidate remove failed")
            _note_cleanup_failure(refusal, "absence proof", exc)
            raise refusal from remove_failure
        else:
            raise PrepareError("candidate absence proof failed") from exc
    if primary is None and remove_failure is not None:
        raise PrepareError("candidate remove failed") from remove_failure


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
    if returncode not in COMPLETE_RETURNCODES or type(stdout) is not str:
        return _unproved()
    if stdout == "" or stdout[0] != "{" or stdout != stdout.strip():
        return _unproved()
    try:
        inner = load_strict(stdout.encode("utf-8"))
        expected = sealed_adapter.expected_ids(vectors)
        projected = sealed_adapter.project(inner, expected)
    except (PrepareError, KeyError, TypeError, ValueError, OSError):
        return _unproved()
    if type(inner) is not dict:
        return _unproved()
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
    expected = {key for key, _destination in CANDIDATE_MOUNT_SPEC}
    extra = set(mounts) - expected
    if extra:
        raise PrepareError("unexpected mount")
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


class _DockerTransport:
    skip_absent = False

    def create(self, argv):
        docker_bounded(argv[1:])

    def start(self, name, deadline_seconds):
        if type(deadline_seconds) is not int or deadline_seconds <= 0:
            raise PrepareError("candidate deadline")
        return br._run_capped(
            ["docker", "start", "-a", name],
            Path.cwd(),
            deadline_seconds,
        )

    def inspect(self, name):
        return parse_inspect_payload(docker_bounded(["inspect", name]))

    def remove(self, name):
        docker_bounded(["rm", "-f", name])

    def require_absent(self, name):
        require_container_absent(name)


def _run_sealed_candidate(*, image_id: str, mounts: dict,
                          resource_profile,
                          name_prefix: str = "aee-cand-",
                          sealed: bool = True, transport=None,
                          execution_contract=None,
                          ) -> subprocess.CompletedProcess:
    image_id = require_image_id(image_id)
    profile = require_resource_profile(resource_profile)
    if transport is None:
        require_local_image(image_id)
        transport = _DockerTransport()
    if getattr(transport, "skip_absent", False):
        raise PrepareError("absence proof skipped")
    name = "%s%s" % (name_prefix, token_hex(4))
    completed = _unproved()
    error = None
    try:
        argv = candidate_create_argv(
            image_id=image_id, name=name, mounts=mounts, sealed=sealed,
            resource_profile=profile, execution_contract=execution_contract)
        transport.create(argv)
        try:
            proc = transport.start(name, profile["deadline_seconds"])
        except subprocess.TimeoutExpired:
            completed = _unproved()
        except br._OutputTooLarge:
            completed = _unproved()
        except Exception as exc:
            if str(exc) == "output_cap":
                completed = _unproved()
            else:
                raise
        else:
            completed = normalize_inner_event(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                vectors=host_vectors_path(mounts),
            )
        inspect = transport.inspect(name)
        validate_inspect_contract(
            inspect, sealed=sealed, mount_spec=CANDIDATE_MOUNT_SPEC,
            resource_profile=profile)
    except BaseException as exc:
        error = exc
    finally:
        _cleanup_candidate(transport, name, error)
    if error is not None:
        raise error
    return completed


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
