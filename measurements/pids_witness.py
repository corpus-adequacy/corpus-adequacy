#!/usr/bin/env python3
"""A first-party witness that the kernel enforces `pids` for `contained-oci-v1` (#197, part 3).

The read-back of part 2 shows that the kernel *held* the requested limits. It does not show that
a limit was ever reached. For `pids` the cgroup counts every fork it refuses at `pids.max` in
`pids.events`, so a hit is observable from outside the payload. This module runs a container
under the owned resource profile whose payload forks until the kernel refuses, and reads that
counter.

The container's PID 1 is a fixed shell script from this module, never a candidate:

1. Hold, exactly as the candidate wrapper does, while the host reads the kernel's limits.
2. Fork in a subshell until a fork is refused. dash exits at the first refused fork, so the
   subshell dies and PID 1 survives. Every child is short-lived, and PID 1 waits until they have
   been reaped, so the cgroup has room again for the host's `docker exec`.
3. Write a ready file and hold a second time. The host reads `pids.events` and releases it.

The payload's own output is never read as evidence. A run counts as `witnessed` only when the
kernel's `pids.events` shows `max` above zero, the limits read back as requested, the run
completed with exit 0, the create raised no warning, and the container was removed. Anything
else is `unproved`, with the reasons named.

What a witness record can and cannot say:

- It can say that on one host, at one time, the kernel held the owned profile's limits for this
  container and refused forks at `pids.max`.
- It cannot say that any candidate was bounded, nor anything about CPU, memory or escape
  resistance. It says nothing about open files: `RLIMIT_NOFILE` has no kernel-side counter.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _entry in (_HERE, _ROOT):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import contained_oci as contained  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import kernel_readback as kr  # noqa: E402

WITNESS_SCHEMA = "corpus-adequacy.pids-witness.v0"
VERDICTS = ("witnessed", "unproved")
READY_PATH = "/tmp/.corpus-adequacy-witness-ready"
WITNESS_RELEASE_PATH = "/tmp/.corpus-adequacy-witness-release"
PIDS_EVENTS_PATHS = (("pids.events", "/sys/fs/cgroup/pids.events"),)
# The witness's own exit codes. They share the candidate wrapper's `readback-hold` code for the
# first hold, so a hold that times out reads the same wherever it happens.
EXIT_READBACK_HOLD = 82
EXIT_WITNESS_HOLD = 83
EXIT_READY_WRITE = 84
# Each child sleeps this long, and PID 1 waits a little longer before it is ready, so every child
# has exited and been reaped by then.
CHILD_SECONDS = 5
SETTLE_SECONDS = 6
ENTRYPOINT = "/bin/sh"
# The witness reads no input. One empty read-only bind satisfies the mount contract.
WITNESS_MOUNT_SPEC = (("witness", "/witness"),)
NAME_PREFIX = "ca-pids-witness-"
NON_CLAIMS = (
    "no candidate was bounded by this run",
    "cpu, memory and open-file enforcement are not witnessed",
    "escape resistance is not tested",
    "one host, one time",
)


def hold_shell(release_path: str, exit_code: int) -> str:
    """Wait, bounded, for the host to create `release_path`; exit `exit_code` if it never does."""
    release = shlex.quote(release_path)
    return "".join((
        "i=0; while test ! -e %s; do i=$((i+1)); " % release,
        "test \"$i\" -gt %d && exit %d; " % (kr.HOLD_POLLS, exit_code),
        "sleep %s; done; " % kr.HOLD_POLL_SECONDS,
        "rm -f %s || exit %d; " % (release, exit_code),
    ))


def witness_script(profile) -> str:
    """PID 1 of the witness container. Twice `pids.max` attempts is more than the limit allows."""
    checked = contained.require_resource_profile_v2(profile)
    attempts = 2 * checked["pids"]
    return "".join((
        "set -u; ",
        hold_shell(kr.RELEASE_PATH, EXIT_READBACK_HOLD),
        "( i=0; while test \"$i\" -lt %d; do i=$((i+1)); sleep %d & done ) 2>/dev/null; " % (
            attempts, CHILD_SECONDS),
        "sleep %d; wait; " % SETTLE_SECONDS,
        ": > %s || exit %d; " % (shlex.quote(READY_PATH), EXIT_READY_WRITE),
        hold_shell(WITNESS_RELEASE_PATH, EXIT_WITNESS_HOLD),
        "exit 0",
    ))


def run_raw(*, image_id: str, profile=contained.CANDIDATE_RESOURCE_PROFILE_V2,
            transport=None) -> dict:
    """Run the witness container once and return `run_contained`'s raw outcome."""
    with tempfile.TemporaryDirectory(prefix="ca-pids-witness-") as scratch:
        return contained.run_contained(
            image_id=image_id,
            mounts={"witness": Path(scratch)},
            command=["-c", witness_script(profile)],
            entrypoint=ENTRYPOINT,
            mount_spec=WITNESS_MOUNT_SPEC,
            resource_profile=profile,
            sealed=True,
            name_prefix=NAME_PREFIX,
            transport=transport,
            cleanup_label="witness",
            record_cleanup=True,
            readback=True,
            second_hold=(READY_PATH, PIDS_EVENTS_PATHS, WITNESS_RELEASE_PATH),
        )


def derive_reasons(*, state, exit_code, create_warnings, kernel_problems, events,
                   cleanup) -> list:
    """Every reason a witness is `unproved`, in a fixed order. Empty means `witnessed`.

    The run and the independent `verify` both judge through this one function.
    """
    reasons = []
    if state != "completed":
        reasons.append("state:%s" % state)
    elif exit_code != 0:
        reasons.append("exit:%s" % exit_code)
    if create_warnings:
        reasons.append("create-warnings")
    if kernel_problems:
        reasons.append("readback:%s" % kernel_problems[0])
    if events is None:
        reasons.append("pids-events-unreadable")
    elif events.get(kr.MAX, 0) <= 0:
        reasons.append("pids-limit-not-reached")
    if cleanup != "removed-and-absent":
        reasons.append("cleanup:%s" % cleanup)
    return reasons


def witness_record(raw: dict, *, image_id: str,
                   profile=contained.CANDIDATE_RESOURCE_PROFILE_V2) -> dict:
    """Judge one raw outcome. Only the kernel's files and the daemon's own state count."""
    files = raw.get("kernel_files") or {}
    kernel = kr.readback_record({key: files.get(key) for key, _ in kr.READBACK_PATHS}, profile)
    try:
        events = kr.parse_pids_events(files.get("pids.events"))
    except kr.ReadbackError:
        events = None
    exit_code = getattr(raw.get("process"), "returncode", None)
    warnings = raw.get("create_warnings")
    create_warnings = [str(line) for line in warnings] if warnings else []
    reasons = derive_reasons(
        state=raw.get("state"), exit_code=exit_code, create_warnings=create_warnings,
        kernel_problems=kernel["problems"], events=events, cleanup=raw.get("cleanup"))
    return {
        "schema": WITNESS_SCHEMA,
        "image_id": image_id,
        "resource_profile": profile,
        "state": raw.get("state"),
        "exit_code": exit_code,
        "create_warnings": create_warnings,
        "cleanup": raw.get("cleanup"),
        "kernel": kernel,
        "pids_events": events,
        "verdict": "unproved" if reasons else "witnessed",
        "unproved_reasons": reasons,
        "non_claims": list(NON_CLAIMS),
    }


def run_witness(*, image_id: str, profile=contained.CANDIDATE_RESOURCE_PROFILE_V2,
                transport=None) -> dict:
    raw = run_raw(image_id=image_id, profile=profile, transport=transport)
    return witness_record(raw, image_id=image_id, profile=profile)


# --- The hosted witness route (#197 part 4) ------------------------------------------------
#
# The witness has no subject, corpus or sites, so it does not ride the mutation rails' packet.
# Its pre-registration is the dispatch itself: the owner names the runner revision R and the
# SHA-256 of the witness's execution identity at R, computed locally with `identity`. The hosted
# run refuses unless GitHub says it runs R's workflow at R and the identity it computes over its
# own checkout equals the dispatched one. `verify` is the independent readback: it re-derives
# the verdict from the recorded kernel values and recomputes the identity from a checkout of R.

ROOT = _ROOT
ATTEMPT_SCHEMA = "corpus-adequacy.pids-witness-attempt.v0"
ATTEMPT_FILENAME = "pids-witness-attempt.v0.json"
PREDICATE_FILENAME = "pids-witness-predicate.v0.json"
SUMS_FILENAME = "SHA256SUMS"
PREDICATE_TYPE = ("https://github.com/corpus-adequacy/corpus-adequacy/attestations/"
                  "pids-witness/v0")
# The toolchain image every owned run uses. It carries dash and `sleep`, all the witness needs.
IMAGE_INDEX = ("docker.io/library/rust@sha256:"
               "e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2")
# Every file whose bytes decide what a witness run does. A test traces the imports and holds
# this list to them, so a new dependency cannot run outside the identity.
EXECUTION_PATHS = (
    ".github/workflows/pids-witness.yml",
    "bounded_run.py",
    "corpus_adequacy.py",
    "isolated_tree.py",
    "measurements/contained_oci.py",
    "measurements/kernel_readback.py",
    "measurements/pids_witness.py",
)
WORKFLOW_ENV = (
    ("github_sha", "GITHUB_SHA"),
    ("github_workflow_sha", "GITHUB_WORKFLOW_SHA"),
    ("github_run_id", "GITHUB_RUN_ID"),
    ("github_run_attempt", "GITHUB_RUN_ATTEMPT"),
    ("image_os", "ImageOS"),
    ("image_version", "ImageVersion"),
)
HOST_INFO_KEYS = ("Architecture", "CgroupDriver", "CgroupVersion", "KernelVersion",
                  "OperatingSystem", "ServerVersion")
ATTEMPT_KEYS = ("dispatch", "host", "identity", "image", "schema", "witness", "workflow")
WITNESS_KEYS = ("cleanup", "create_warnings", "exit_code", "image_id", "kernel",
                "non_claims", "pids_events", "resource_profile", "schema", "state",
                "unproved_reasons", "verdict")
_HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
MAX_ATTEMPT_BYTES = 1 << 20


class WitnessRouteError(ValueError):
    """The hosted witness refused, or a record did not verify. The message is the reason."""


def _hex(value, pattern, label):
    if not isinstance(value, str) or not pattern.match(value):
        raise WitnessRouteError(label)
    return value


def identity(root: Path = ROOT) -> dict:
    """SHA-256 over every execution path: its name, its length and its bytes, in order."""
    digest = hashlib.sha256()
    for relpath in EXECUTION_PATHS:
        raw = (Path(root) / relpath).read_bytes()
        for part in (relpath.encode("utf-8"), str(len(raw)).encode("ascii"), raw):
            digest.update(part)
            digest.update(b"\0")
    return {"content_sha256": digest.hexdigest(), "paths": list(EXECUTION_PATHS)}


def observe_workflow(environ=None) -> dict:
    env = os.environ if environ is None else environ
    return {key: env.get(name) for key, name in WORKFLOW_ENV}


def check_workflow(workflow: dict, runner_revision: str) -> None:
    """GITHUB_SHA and GITHUB_WORKFLOW_SHA both equal R, or refuse. Absent is not equal."""
    for key in ("github_sha", "github_workflow_sha"):
        if workflow.get(key) != runner_revision:
            raise WitnessRouteError("%s_binding" % key)


def _docker_stdout(args, timeout=120) -> str:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise WitnessRouteError("docker %s failed" % args[0])
    return proc.stdout


def pull_image() -> str:
    """Pull the pinned index and return the local image id this daemon gives it."""
    _docker_stdout(["pull", "-q", IMAGE_INDEX], timeout=600)
    return contained.require_image_id(
        _docker_stdout(["image", "inspect", "-f", "{{.Id}}", IMAGE_INDEX]).strip())


def observe_host() -> dict:
    """What the daemon says about its host. Observed and recorded, never judged."""
    info = json.loads(_docker_stdout(["info", "--format", "{{json .}}"]))
    return {key: info.get(key) for key in HOST_INFO_KEYS}


def _write_new(path: Path, raw: bytes) -> None:
    with open(path, "xb") as handle:
        handle.write(raw)


def _encode(doc) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def run_hosted(*, runner_revision: str, identity_sha256: str, out_dir: Path,
               environ=None, root: Path = ROOT, docker_ready=None, pull=pull_image,
               host=observe_host, witness=run_witness) -> dict:
    """The hosted attempt. Refuses before any container unless dispatch, workflow and identity
    agree; after that, every outcome, `unproved` included, is written and sealed."""
    runner_revision = _hex(runner_revision, _HEX40, "runner_revision")
    identity_sha256 = _hex(identity_sha256, _HEX64, "identity_sha256")
    workflow = observe_workflow(environ)
    check_workflow(workflow, runner_revision)
    observed_identity = identity(root)
    if observed_identity["content_sha256"] != identity_sha256:
        raise WitnessRouteError("identity_binding")
    (contained.require_docker_ready if docker_ready is None else docker_ready)()
    image_id = pull()
    attempt = {
        "schema": ATTEMPT_SCHEMA,
        "dispatch": {"identity_sha256": identity_sha256, "runner_revision": runner_revision},
        "workflow": workflow,
        "identity": observed_identity,
        "image": {"id": image_id, "index": IMAGE_INDEX},
        "host": host(),
        "witness": witness(image_id=image_id),
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=False)
    attempt_raw = _encode(attempt)
    predicate_raw = _encode({
        "attempt_sha256": hashlib.sha256(attempt_raw).hexdigest(),
        "identity_sha256": identity_sha256,
        "runner_revision": runner_revision,
        "verdict": attempt["witness"]["verdict"],
    })
    _write_new(out / ATTEMPT_FILENAME, attempt_raw)
    _write_new(out / PREDICATE_FILENAME, predicate_raw)
    sums = "".join("%s  %s\n" % (hashlib.sha256(raw).hexdigest(), name)
                   for name, raw in sorted(((ATTEMPT_FILENAME, attempt_raw),
                                            (PREDICATE_FILENAME, predicate_raw))))
    _write_new(out / SUMS_FILENAME, sums.encode("ascii"))
    return attempt


def _exact(doc, keys, label):
    if type(doc) is not dict or set(doc) != set(keys):
        raise WitnessRouteError("%s_keys" % label)


def verify(attempt_raw: bytes, *, runner_revision: str, identity_sha256: str,
           root: Path = ROOT) -> dict:
    """The independent readback of one hosted attempt, from a checkout of R at `root`.

    It trusts none of the attempt's own judgements: it recomputes the identity from `root`,
    compares the kernel's recorded values with the owned profile, re-derives every reason and
    the verdict, and requires them to equal what was recorded.

    It catches an attempt that contradicts itself, R, or the owned profile. It cannot catch one
    forged consistently, values and verdict alike: that the bytes came from the dispatched run
    rests on the GitHub attestation, which the reader checks first (`gh attestation verify`).
    """
    runner_revision = _hex(runner_revision, _HEX40, "runner_revision")
    identity_sha256 = _hex(identity_sha256, _HEX64, "identity_sha256")
    if not isinstance(attempt_raw, bytes) or len(attempt_raw) > MAX_ATTEMPT_BYTES:
        raise WitnessRouteError("attempt_size")
    doc = contained.load_strict(attempt_raw)
    _exact(doc, ATTEMPT_KEYS, "attempt")
    if doc["schema"] != ATTEMPT_SCHEMA:
        raise WitnessRouteError("attempt_schema")
    if doc["dispatch"] != {"identity_sha256": identity_sha256,
                           "runner_revision": runner_revision}:
        raise WitnessRouteError("dispatch_binding")
    _exact(doc["workflow"], [key for key, _ in WORKFLOW_ENV], "workflow")
    check_workflow(doc["workflow"], runner_revision)
    recomputed = identity(root)
    if recomputed["content_sha256"] != identity_sha256:
        raise WitnessRouteError("identity_root")
    if doc["identity"] != recomputed:
        raise WitnessRouteError("identity_binding")
    _exact(doc["image"], ("id", "index"), "image")
    if doc["image"]["index"] != IMAGE_INDEX:
        raise WitnessRouteError("image_index")
    _exact(doc["host"], HOST_INFO_KEYS, "host")
    record = doc["witness"]
    _exact(record, WITNESS_KEYS, "witness")
    if record["schema"] != WITNESS_SCHEMA or record["image_id"] != doc["image"]["id"]:
        raise WitnessRouteError("witness_binding")
    profile = contained.CANDIDATE_RESOURCE_PROFILE_V2
    if record["resource_profile"] != profile:
        raise WitnessRouteError("resource_profile")
    kernel = record["kernel"]
    _exact(kernel, ("observed", "problems", "schema", "status"), "kernel")
    problems = kr.compare(kernel["observed"], kr.expected_readback(profile))
    if problems != kernel["problems"]:
        raise WitnessRouteError("kernel_problems")
    events = record["pids_events"]
    if events is not None:
        encoded = "".join("%s %s\n" % item for item in events.items()).encode("ascii")
        if kr.parse_pids_events(encoded) != events:
            raise WitnessRouteError("pids_events")
    reasons = derive_reasons(
        state=record["state"], exit_code=record["exit_code"],
        create_warnings=record["create_warnings"], kernel_problems=problems,
        events=events, cleanup=record["cleanup"])
    if reasons != record["unproved_reasons"]:
        raise WitnessRouteError("reasons")
    verdict = "unproved" if reasons else "witnessed"
    if verdict != record["verdict"]:
        raise WitnessRouteError("verdict")
    if record["non_claims"] != list(NON_CLAIMS):
        raise WitnessRouteError("non_claims")
    return {"verdict": verdict, "unproved_reasons": reasons,
            "pids_events": events, "host": doc["host"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pids_witness", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    local = sub.add_parser("local", help="run once against a local image; not rail evidence")
    local.add_argument("--image", required=True, help="local image id, sha256:<64 hex>")
    local.add_argument("--out", type=Path, help="write the record here as well as to stdout")
    sub.add_parser("identity", help="print the execution identity of this checkout")
    hosted = sub.add_parser("hosted", help="the hosted attempt; run only by the workflow")
    hosted.add_argument("--runner-revision", required=True)
    hosted.add_argument("--identity-sha256", required=True)
    hosted.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("verify", help="independent readback, from a checkout of R")
    check.add_argument("--attempt", type=Path, required=True)
    check.add_argument("--runner-revision", required=True)
    check.add_argument("--identity-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "identity":
            sys.stdout.write(json.dumps(identity(), indent=2) + "\n")
            return 0
        if args.command == "local":
            contained.require_docker_ready()
            record = run_witness(image_id=args.image)
            text = _encode(record).decode("utf-8")
            if args.out is not None:
                args.out.write_text(text, encoding="utf-8")
            sys.stdout.write(text)
            return 0 if record["verdict"] == "witnessed" else 1
        if args.command == "hosted":
            attempt = run_hosted(runner_revision=args.runner_revision,
                                 identity_sha256=args.identity_sha256, out_dir=args.out)
            print("pids-witness verdict=%s" % attempt["witness"]["verdict"])
            return 0
        result = verify(ca.read_bounded_regular_file(args.attempt, cap=MAX_ATTEMPT_BYTES),
                        runner_revision=args.runner_revision,
                        identity_sha256=args.identity_sha256)
        print("pids-witness-verify=pass verdict=%s reasons=%s" % (
            result["verdict"], ",".join(result["unproved_reasons"]) or "-"))
        return 0
    except (WitnessRouteError, contained.PrepareError, kr.ReadbackError) as exc:
        print("pids-witness refused: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
