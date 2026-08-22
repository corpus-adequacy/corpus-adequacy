"""Bounded sealed-OCI candidate backend. Synthetic host adapter only.

Reuses the existing process/batch runner for mutation, classification, and
scoring. Incomplete inner events become returncode 75; stdout is discarded.
Does not run a real corpus/checker experiment.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from secrets import token_hex

from aee_checker_sealed_common import PrepareError
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
import bounded_run as br

CANDIDATE_MOUNT_SPEC = DEFAULT_MOUNT_SPEC + (("subject", "/subject"),)
CANDIDATE_ENTRYPOINT = "/bin/sh"
CANDIDATE_SCRIPT = (
    "set -eu; "
    "cp -a /subject/. /work/; "
    "cd /work; "
    "cargo build --locked --offline 1>&2; "
    "exec cargo test --locked --offline -- --quiet"
)
UNPROVED_EXIT = 75


def _unproved() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=UNPROVED_EXIT, stdout="", stderr="")


def normalize_inner_event(*, returncode, stdout) -> subprocess.CompletedProcess:
    """Parse a complete inner JSON object once; otherwise emit rc 75."""
    if returncode != 0 or type(stdout) is not str:
        return _unproved()
    if stdout == "" or stdout[0] != "{" or stdout != stdout.strip():
        return _unproved()
    try:
        inner = json.loads(stdout)
    except Exception:
        return _unproved()
    if type(inner) is not dict:
        return _unproved()
    outer = {
        "schema": "aee-checker-sealed-candidate-result.v0",
        "status": "ok",
    }
    return subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout=json.dumps(outer, separators=(",", ":")),
        stderr="",
    )


def candidate_create_argv(*, image_id: str, name: str, mounts: dict,
                          sealed: bool = True) -> list[str]:
    expected = {key for key, _destination in CANDIDATE_MOUNT_SPEC}
    extra = set(mounts) - expected
    if extra:
        raise PrepareError("unexpected mount")
    return docker_create_argv(
        image_id=image_id,
        name=name,
        mounts=mounts,
        command=["-lc", CANDIDATE_SCRIPT],
        sealed=sealed,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        entrypoint=CANDIDATE_ENTRYPOINT,
    )


class _DockerTransport:
    skip_absent = False

    def create(self, argv):
        docker_bounded(argv[1:])

    def start(self, name):
        return br._run_capped(
            ["docker", "start", "-a", name],
            Path.cwd(),
            60,
        )

    def inspect(self, name):
        return parse_inspect_payload(docker_bounded(["inspect", name]))

    def remove(self, name):
        docker_bounded(["rm", "-f", name])

    def require_absent(self, name):
        require_container_absent(name)


def run_sealed_candidate(*, image_id: str, mounts: dict,
                         name_prefix: str = "aee-cand-",
                         sealed: bool = True, transport=None,
                         ) -> subprocess.CompletedProcess:
    require_image_id(image_id)
    if transport is None:
        require_local_image(image_id)
        transport = _DockerTransport()
    if getattr(transport, "skip_absent", False):
        raise PrepareError("absence proof skipped")
    name = "%s%s" % (name_prefix, token_hex(4))
    created = False
    completed = _unproved()
    error = None
    try:
        argv = candidate_create_argv(
            image_id=image_id, name=name, mounts=mounts, sealed=sealed)
        transport.create(argv)
        created = True
        try:
            proc = transport.start(name)
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
                returncode=proc.returncode, stdout=proc.stdout or "")
        inspect = transport.inspect(name)
        validate_inspect_contract(
            inspect, sealed=sealed, mount_spec=CANDIDATE_MOUNT_SPEC)
    except PrepareError as exc:
        error = exc
    finally:
        if created:
            try:
                transport.remove(name)
            except PrepareError:
                transport.require_absent(name)
                raise PrepareError("container remove failed")
        transport.require_absent(name)
    if error is not None:
        raise error
    return completed
