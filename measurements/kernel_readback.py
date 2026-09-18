#!/usr/bin/env python3
"""Kernel-interface limit read-back for `contained-oci-v1` (#197, part 1 of 4).

`contained-oci-v1` compares the configuration the Docker daemon *stored*. That is evidence about
configuration, not about the kernel: moby/moby#49599 shows `docker inspect` reporting a value the
cgroup never received. The kernel's own files are the better witness, and this module is the pure
half of reading them: parse the kernel's formats, derive what a validated resource profile should
read back as, compare, and classify a limit-hit witness.

Nothing here touches a container, a file or a process. The runtime reads the files while the
container lives, because the cgroup is removed when the container's init exits: the trusted
wrapper holds at its start, the host reads through `docker exec`, then releases it (#197 part 2).
The record goes into `execution-envelope.v3`. This module is inside every contract's execution
identity, so changing it needs a fresh PREPARE.

What a read-back can and cannot say:

- It can say the kernel held the requested memory, swap, pids, CPU and open-file values for one
  container at one moment.
- It cannot say a limit was ever reached. For `pids` the cgroup counts refusals in `pids.events`,
  so a hit is kernel-observable. For open files it is not: `RLIMIT_NOFILE` is a per-process limit
  with no kernel-side counter, and the only sign of a hit is an error returned to the candidate,
  whose own output never counts as evidence. A `nofile` hit therefore cannot be witnessed this way.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import contained_oci as contained  # noqa: E402

READBACK_SCHEMA = "corpus-adequacy.kernel-readback.v0"
READBACK_FIELDS = ("memory_max", "memory_swap_max", "pids_max", "cpu_max",
                   "nofile_soft", "nofile_hard")
MAX = "max"
UNLIMITED = "unlimited"
_UINT = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")
_EVENTS_KEY = re.compile(r"\A[a-z][a-z._]*\Z")
# `/proc/<pid>/limits` is fixed-width: a 26-column name, two 21-column values, then units.
_LIMITS_ROW = re.compile(r"\A(?P<name>.{25}) (?P<soft>\S+) +(?P<hard>\S+)(?: +\S+)? *\Z")
_OPEN_FILES = "Max open files"
_MAX_TEXT_BYTES = 4096


# Where the files are read, from inside the held container: with a private cgroup namespace the
# container's own cgroup is at the root, and PID 1 is the trusted wrapper, whose limits are the
# container's. `limits` is the only per-process file.
READBACK_PATHS = (
    ("memory.max", "/sys/fs/cgroup/memory.max"),
    ("memory.swap.max", "/sys/fs/cgroup/memory.swap.max"),
    ("pids.max", "/sys/fs/cgroup/pids.max"),
    ("cpu.max", "/sys/fs/cgroup/cpu.max"),
    ("limits", "/proc/1/limits"),
)
# The file the host creates to release the held wrapper. It lives on the container's own /tmp.
RELEASE_PATH = "/tmp/.corpus-adequacy-readback-release"
# How long the wrapper waits for the release before it gives up: HOLD_POLLS polls of
# HOLD_POLL_SECONDS. A hold that times out is the wrapper stage `readback-hold`, unproved.
HOLD_POLLS = 600
HOLD_POLL_SECONDS = "0.05"


class ReadbackError(ValueError):
    """The kernel text is not in the form the kernel writes. Never read as a value."""


def _single_line(raw: bytes, label: str) -> str:
    if not isinstance(raw, bytes) or len(raw) > _MAX_TEXT_BYTES:
        raise ReadbackError("%s is not bounded kernel text" % label)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ReadbackError("%s is not ASCII" % label) from exc
    if not text.endswith("\n") or "\n" in text[:-1]:
        raise ReadbackError("%s is not one newline-terminated line" % label)
    return text[:-1]


def _uint(token: str, label: str) -> int:
    # ASCII digits only: Python's int() also accepts other scripts' digits, spaces and a sign.
    if not _UINT.match(token):
        raise ReadbackError("%s is not a non-negative decimal integer" % label)
    return int(token)


def parse_limit(raw: bytes, label: str) -> int | str:
    """`memory.max`, `memory.swap.max`, `pids.max`: a decimal integer or `max`."""
    text = _single_line(raw, label)
    return MAX if text == MAX else _uint(text, label)


def parse_cpu_max(raw: bytes) -> tuple[int | str, int]:
    """`cpu.max`: `<quota> <period>`, where the quota may be `max`."""
    parts = _single_line(raw, "cpu.max").split(" ")
    if len(parts) != 2:
        raise ReadbackError("cpu.max is not '<quota> <period>'")
    quota = MAX if parts[0] == MAX else _uint(parts[0], "cpu.max quota")
    return quota, _uint(parts[1], "cpu.max period")


def parse_pids_events(raw: bytes) -> dict:
    """`pids.events`: `key value` lines. `max` counts forks refused at `pids.max`."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_TEXT_BYTES or not raw.endswith(b"\n"):
        raise ReadbackError("pids.events is not bounded newline-terminated kernel text")
    try:
        lines = raw.decode("ascii")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise ReadbackError("pids.events is not ASCII") from exc
    events = {}
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 2 or not _EVENTS_KEY.match(parts[0]) or parts[0] in events:
            raise ReadbackError("pids.events line is not 'key value'")
        events[parts[0]] = _uint(parts[1], "pids.events %s" % parts[0])
    if MAX not in events:
        raise ReadbackError("pids.events carries no max counter")
    return events


def parse_open_files(raw: bytes) -> tuple[int | str, int | str]:
    """The soft and hard open-file limits from `/proc/<pid>/limits`."""
    if not isinstance(raw, bytes) or len(raw) > _MAX_TEXT_BYTES or not raw.endswith(b"\n"):
        raise ReadbackError("proc limits is not bounded newline-terminated kernel text")
    try:
        lines = raw.decode("ascii")[:-1].split("\n")
    except UnicodeDecodeError as exc:
        raise ReadbackError("proc limits is not ASCII") from exc
    # The kernel always writes this header first (fs/proc/base.c, proc_pid_limits).
    if not lines or lines[0].split() != ["Limit", "Soft", "Limit", "Hard", "Limit", "Units"]:
        raise ReadbackError("proc limits does not start with the kernel's header")
    found = []
    for line in lines[1:]:
        match = _LIMITS_ROW.match(line)
        if match and match.group("name").rstrip() == _OPEN_FILES:
            found.append(match)
    if len(found) != 1:
        raise ReadbackError("proc limits has no single '%s' row" % _OPEN_FILES)

    def value(token: str, label: str) -> int | str:
        return UNLIMITED if token == UNLIMITED else _uint(token, label)

    return (value(found[0].group("soft"), "open files soft"),
            value(found[0].group("hard"), "open files hard"))


def cgroup_v2_swap(memory_swap_bytes: int, memory_bytes: int) -> int:
    """What cgroup v2 `memory.swap.max` holds for Docker's `--memory-swap` and `--memory`.

    Docker's `--memory-swap` is memory plus swap. cgroup v2 `memory.swap.max` is swap alone, so
    runc subtracts: `ConvertMemorySwapToCgroupV2Value` in opencontainers/cgroups `utils.go`.
    Only positive memory with swap at least that large is accepted. A profile with less swap
    than memory can validate, but runc and Docker refuse it too, so it has no read-back.
    """
    if (type(memory_bytes) is not int or type(memory_swap_bytes) is not int
            or memory_bytes <= 0 or memory_swap_bytes < memory_bytes):
        raise ReadbackError("memory-swap must be at least a positive memory limit")
    return memory_swap_bytes - memory_bytes


def expected_readback(profile) -> dict:
    """What the kernel should hold for a validated `resource-profile.v2`."""
    checked = contained.require_resource_profile_v2(profile)
    return {
        "memory_max": checked["memory_bytes"],
        "memory_swap_max": cgroup_v2_swap(checked["memory_swap_bytes"], checked["memory_bytes"]),
        "pids_max": checked["pids"],
        # The one shared mapping from the v2 rate, so argv, comparator and read-back cannot drift.
        "cpu_max": [contained.cpu_quota_usec(checked), contained.CPU_PERIOD_USEC],
        "nofile_soft": checked["nofile_soft"],
        "nofile_hard": checked["nofile_hard"],
    }


def observe(files: dict) -> dict:
    """Parse the raw kernel bytes into one observation. A file that did not read, or that is not
    in the kernel's own form, is recorded as unreadable: never a value."""
    if type(files) is not dict:
        raise ReadbackError("read-back files must be a mapping")
    known = {"memory.max", "memory.swap.max", "pids.max", "cpu.max", "limits"}
    unknown = sorted(set(files) - known)
    if unknown:
        raise ReadbackError("unknown read-back files: %s" % unknown)
    observed = {field: None for field in READBACK_FIELDS}

    def attempt(name, parse):
        raw = files.get(name)
        if raw is None:
            return None
        try:
            return parse(raw)
        except ReadbackError:
            return None

    observed["memory_max"] = attempt("memory.max", lambda raw: parse_limit(raw, "memory.max"))
    observed["memory_swap_max"] = attempt(
        "memory.swap.max", lambda raw: parse_limit(raw, "memory.swap.max"))
    observed["pids_max"] = attempt("pids.max", lambda raw: parse_limit(raw, "pids.max"))
    cpu = attempt("cpu.max", parse_cpu_max)
    observed["cpu_max"] = list(cpu) if cpu is not None else None
    limits = attempt("limits", parse_open_files)
    if limits is not None:
        observed["nofile_soft"], observed["nofile_hard"] = limits
    return observed


def compare(observed: dict, expected: dict) -> list[str]:
    """Every problem with an observation, named by field. An empty list means verified."""
    if type(observed) is not dict or set(observed) != set(READBACK_FIELDS):
        raise ReadbackError("observation must carry exactly %s" % (READBACK_FIELDS,))
    if type(expected) is not dict or set(expected) != set(READBACK_FIELDS):
        raise ReadbackError("expectation must carry exactly %s" % (READBACK_FIELDS,))
    problems = []
    for field in READBACK_FIELDS:
        if observed[field] is None:
            problems.append("readback_unreadable:%s" % field)
        elif observed[field] != expected[field]:
            problems.append("readback_mismatch:%s" % field)
    return problems


def readback_record(files: dict, profile) -> dict:
    """The closed record part 2 will place in `execution-envelope.v3`."""
    observed = observe(files)
    problems = compare(observed, expected_readback(profile))
    return {
        "schema": READBACK_SCHEMA,
        "observed": observed,
        "status": "unverified" if problems else "verified",
        "problems": problems,
    }


def classify_pids_witness(raw_events: bytes) -> str:
    """A pids witness counts only if the kernel refused at least one fork at `pids.max`.

    A witness run that completes with `max 0` shows nothing about enforcement: the limit was
    never reached, so it is `unproved`. Unreadable events are `unproved` too, never assumed.
    """
    try:
        events = parse_pids_events(raw_events)
    except ReadbackError:
        return "unproved"
    return "witnessed" if events[MAX] > 0 else "unproved"
