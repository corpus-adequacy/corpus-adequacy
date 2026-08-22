"""Shared PREPARE helpers for the sealed #211 runner. Stdlib only."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import bounded_run as br
import corpus_adequacy as ca

HEX64 = frozenset("0123456789abcdef")
TMPFS_BYTES = 1048576
TMPFS_INODES = 128
MEMORY_4G = 4 * 1024 * 1024 * 1024
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
FROZEN_CORPUS_MANIFEST_SHA256 = (
    "aaee0241d5f92a65ecfa603113f5c313b3f0593aa97ce8a54732287f0dc26c67"
)
FROZEN_SUBJECT_TREE_SHA256 = (
    "393d742154918f640593fe9962cf87a273a28c93b24c0569ee4bef3a039fdc3d"
)
FROZEN_CORPUS_TREE_SHA256 = (
    "4bd2f2bf1208beb613fef0e6cc4728483cecae1097b74b54baaf54ce22569c42"
)
DECLARED_CEILINGS = {
    "deadline_seconds": 8,
    "disk_bytes": TMPFS_BYTES,
    "file_count": TMPFS_INODES,
    "output_bytes": br.OUTPUT_CAP_BYTES,
}
MATERIALIZE_CEILINGS = {
    "deadline_seconds": 300,
    "disk_bytes": 64 * 1024 * 1024,
    "entry_count": 10_000,
    "output_bytes": br.OUTPUT_CAP_BYTES,
}


class PrepareError(Exception):
    """PREPARE refused before a sealed measurement could start."""


class DockerUnavailable(PrepareError):
    """docker executable is not available. Distinct from daemon-not-ready."""


class MaterializeBudget:
    """One bytes/entries/deadline budget for downloads+subject+corpus+vendor."""

    def __init__(self, ceilings=None):
        spec = dict(ceilings or MATERIALIZE_CEILINGS)
        exact_object(spec, MATERIALIZE_CEILINGS, "materialize_ceilings")
        self.ceilings = spec
        self.used_bytes = 0
        self.used_entries = 0
        self._deadline = time.monotonic() + spec["deadline_seconds"]

    def check_deadline(self) -> None:
        if time.monotonic() > self._deadline:
            raise PrepareError("materialize deadline")

    def remaining_bytes(self) -> int:
        self.check_deadline()
        return max(0, self.ceilings["disk_bytes"] - self.used_bytes)

    def remaining_entries(self) -> int:
        self.check_deadline()
        return max(0, self.ceilings["entry_count"] - self.used_entries)

    def charge(self, *, bytes=0, entries=0) -> None:
        self.check_deadline()
        if type(bytes) is not int or type(entries) is not int or bytes < 0 or entries < 0:
            raise PrepareError("materialize charge")
        nxt_bytes = self.used_bytes + bytes
        nxt_entries = self.used_entries + entries
        if nxt_bytes > self.ceilings["disk_bytes"]:
            raise PrepareError("materialize exceeds byte ceiling")
        if nxt_entries > self.ceilings["entry_count"]:
            raise PrepareError("materialize exceeds entry ceiling")
        self.used_bytes = nxt_bytes
        self.used_entries = nxt_entries


def encode_json(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def exact_object(doc, keys, where: str) -> None:
    if type(doc) is not dict:
        raise PrepareError("%s must be an object" % where)
    want, got = set(keys), set(doc)
    if got != want:
        raise PrepareError(
            "%s exact keys missing=%s unknown=%s" % (
                where, sorted(want - got), sorted(got - want)))


def load_strict(raw: bytes):
    try:
        return ca._parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise PrepareError(str(exc)) from exc


def verify_file_digest(path: Path, expected: str) -> bytes:
    try:
        raw = ca.read_bounded_regular_file(Path(path))
    except ca.ManifestError as exc:
        raise PrepareError(str(exc)) from exc
    got = hashlib.sha256(raw).hexdigest()
    if got != expected:
        raise PrepareError("digest mismatch for %s" % path)
    return raw
