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
import json
import shlex
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for _entry in (_HERE, _ROOT):
    if str(_entry) not in sys.path:
        sys.path.insert(0, str(_entry))

import contained_oci as contained  # noqa: E402
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


def witness_record(raw: dict, *, image_id: str,
                   profile=contained.CANDIDATE_RESOURCE_PROFILE_V2) -> dict:
    """Judge one raw outcome. Only the kernel's files and the daemon's own state count."""
    files = raw.get("kernel_files") or {}
    kernel = kr.readback_record({key: files.get(key) for key, _ in kr.READBACK_PATHS}, profile)
    raw_events = files.get("pids.events")
    try:
        events = kr.parse_pids_events(raw_events)
    except kr.ReadbackError:
        events = None
    process = raw.get("process")
    exit_code = getattr(process, "returncode", None)
    reasons = []
    if raw.get("state") != "completed":
        reasons.append("state:%s" % raw.get("state"))
    elif exit_code != 0:
        reasons.append("exit:%s" % exit_code)
    if raw.get("create_warnings"):
        reasons.append("create-warnings")
    if kernel["status"] != "verified":
        reasons.append("readback:%s" % kernel["problems"][0])
    if events is None:
        reasons.append("pids-events-unreadable")
    elif kr.classify_pids_witness(raw_events) != "witnessed":
        reasons.append("pids-limit-not-reached")
    if raw.get("cleanup") != "removed-and-absent":
        reasons.append("cleanup:%s" % raw.get("cleanup"))
    return {
        "schema": WITNESS_SCHEMA,
        "image_id": image_id,
        "resource_profile": profile,
        "state": raw.get("state"),
        "exit_code": exit_code,
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True, help="local image id, sha256:<64 hex>")
    parser.add_argument("--out", type=Path, help="write the record here as well as to stdout")
    args = parser.parse_args(argv)
    contained.require_docker_ready()
    record = run_witness(image_id=args.image)
    text = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0 if record["verdict"] == "witnessed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
