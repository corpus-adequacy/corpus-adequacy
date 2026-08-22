"""Bounded sealed-OCI candidate backend. Synthetic host adapter only.

Reuses the existing process/batch runner and the canonical adapter
expected_ids/project rule. Incomplete inner events become returncode 75.
Does not run a real corpus/checker experiment.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from secrets import token_hex

from aee_checker_sealed_common import PrepareError, load_strict
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

_ROOT = Path(__file__).resolve().parents[1]
_ADAPTERS = str(_ROOT / "adapters")
if _ADAPTERS not in sys.path:
    sys.path.insert(0, _ADAPTERS)
import aee_checker_sealed as sealed_adapter  # noqa: E402

CANDIDATE_MOUNT_SPEC = DEFAULT_MOUNT_SPEC + (("subject", "/subject"),)
CANDIDATE_ENTRYPOINT = "/bin/sh"
CANDIDATE_SCRIPT = (
    "set -eu; "
    "test -d /input/vectors; test -d /vendor; test -f /tool/config.toml; test -d /subject; "
    "cp -a /subject/. /work/; "
    "cd /work; "
    "CARGO_HOME=/tool cargo build --release --locked --offline 1>&2; "
    "set +e; "
    "/work/target/release/aee-checker /input/vectors --json /work/report.json 1>&2; "
    "status=$?; "
    "set -e; "
    "cat /work/report.json; "
    "exit $status"
)
UNPROVED_EXIT = 75
COMPLETE_RETURNCODES = (0, 1)


def _unproved() -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=UNPROVED_EXIT, stdout="", stderr="")


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
    completed = _unproved()
    error = None
    try:
        argv = candidate_create_argv(
            image_id=image_id, name=name, mounts=mounts, sealed=sealed)
        transport.create(argv)
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
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                vectors=host_vectors_path(mounts),
            )
        inspect = transport.inspect(name)
        validate_inspect_contract(
            inspect, sealed=sealed, mount_spec=CANDIDATE_MOUNT_SPEC)
    except Exception as exc:
        error = exc
    finally:
        try:
            transport.remove(name)
        except Exception:
            pass
        try:
            transport.require_absent(name)
        except PrepareError:
            raise
    if error is not None:
        raise error
    return completed
