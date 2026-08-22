"""Shared PREPARE helpers for the sealed #211 runner. Stdlib only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import bounded_run as br
import corpus_adequacy as ca

HEX64 = frozenset("0123456789abcdef")
TMPFS_BYTES = 1048576
TMPFS_INODES = 128
MEMORY_4G = 4 * 1024 * 1024 * 1024
DECLARED_CEILINGS = {
    "deadline_seconds": 8,
    "disk_bytes": TMPFS_BYTES,
    "file_count": TMPFS_INODES,
    "output_bytes": br.OUTPUT_CAP_BYTES,
}


class PrepareError(Exception):
    """PREPARE refused before a sealed measurement could start."""


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
    except ca.ManifestError as exc:
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
