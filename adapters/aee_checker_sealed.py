#!/usr/bin/env python3
"""Batch wrapper for the pinned Rust AEE checker.

Runs `checker <vectors-dir> --json <file>` from the wrapper cwd (the
materialized repo-root). Inner exits 0/1 are a completed batch. Every
other inner exit, timeout, signal, output-cap or unusable protocol is 75
(#45 unproved_exit_codes). Never parses the checker's human stdout.

Stdout is one object `{rows, diagnostics}` keyed by MANIFEST.json ids so
batch dict-equality can see diagnostic-only movement without scoring
`code`. Per-id attribution of `<batch>` movement is a non-claim.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if (_ROOT / "corpus_adequacy.py").is_file() and str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402
from bounded_run import _OutputTooLarge, _run_capped  # noqa: E402

UNPROVED_EXIT = 75
ACCEPTED_EXIT = 0
INNER_ACCEPTED = (0, 1)
DEFAULT_TIMEOUT = 600
OUTCOME_KEYS = ("verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey")
DIAGNOSTIC_KEY = "reason"


def checker_argv(checker: str) -> list[str]:
    """Run a .py fixture with this interpreter so Windows CI needs no shebang."""
    if checker.endswith(".py"):
        return [sys.executable, checker]
    return [checker]


def normalize_reason(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("reason is not prose")
    return value.strip()


def _manifest_path(vectors: str) -> Path:
    path = Path(vectors)
    if path.is_file():
        return path
    return path / "MANIFEST.json"


def expected_ids(vectors: str) -> list[str]:
    raw = ca.read_bounded_regular_file(_manifest_path(vectors))
    doc = ca._parse_projection_json(raw)
    rows = doc["vectors"]
    if not isinstance(rows, list):
        raise ValueError("manifest vectors")
    ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("manifest row")
        vid = row.get("id")
        if not isinstance(vid, str) or not vid.strip():
            raise ValueError("manifest id")
        if vid in seen:
            raise ValueError("duplicate expected id")
        seen.add(vid)
        ids.append(vid)
    if not ids:
        raise ValueError("empty expected ids")
    return ids


def project(doc: dict, expected: list[str]) -> dict:
    want = set(expected)
    if len(want) != len(expected):
        raise ValueError("duplicate expected id")
    rows = doc["vectors"]
    if not isinstance(rows, list):
        raise ValueError("vectors is not a list")
    actual: dict[str, dict] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("row is not an object")
        vid = row.get("id")
        if not isinstance(vid, str) or not vid.strip():
            raise ValueError("row id")
        if vid in actual:
            raise ValueError("duplicate actual id")
        missing = [key for key in OUTCOME_KEYS if key not in row]
        if missing or DIAGNOSTIC_KEY not in row:
            raise ValueError("missing projection field")
        actual[vid] = row
    if set(actual) != want:
        raise ValueError("id set")
    out_rows = {}
    out_diag = {}
    for vid in sorted(actual):
        row = actual[vid]
        out_rows[vid] = {key: row[key] for key in OUTCOME_KEYS}
        out_diag[vid] = {DIAGNOSTIC_KEY: normalize_reason(row[DIAGNOSTIC_KEY])}
    return {"rows": out_rows, "diagnostics": out_diag}


def run_wrapper(checker: str, vectors: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    handle = tempfile.NamedTemporaryFile(prefix="aee-batch-", suffix=".json", delete=False)
    json_out = handle.name
    handle.close()
    cwd = Path.cwd()
    try:
        try:
            expected = expected_ids(vectors)
        except (KeyError, TypeError, ValueError, ca.ManifestError, OSError):
            return UNPROVED_EXIT
        try:
            proc = _run_capped(
                checker_argv(checker) + [vectors, "--json", json_out],
                cwd, timeout)
        except subprocess.TimeoutExpired:
            return UNPROVED_EXIT
        except _OutputTooLarge:
            return UNPROVED_EXIT
        except OSError:
            return UNPROVED_EXIT
        if proc.returncode not in INNER_ACCEPTED:
            return UNPROVED_EXIT
        try:
            raw = ca.read_bounded_regular_file(Path(json_out))
            projected = project(ca._parse_projection_json(raw), expected)
        except (ca.ManifestError, KeyError, TypeError, ValueError):
            return UNPROVED_EXIT
        sys.stdout.write(json.dumps(
            projected, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        return ACCEPTED_EXIT
    finally:
        try:
            os.unlink(json_out)
        except OSError:
            pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="AEE checker batch wrapper")
    parser.add_argument("--checker", required=True)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("vectors")
    args = parser.parse_args(argv)
    return run_wrapper(args.checker, args.vectors, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
