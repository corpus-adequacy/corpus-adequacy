#!/usr/bin/env python3
"""Batch wrapper for the pinned Rust AEE checker.

Runs `checker <vectors-dir> --json <file>` through the repository's
bounded child helper. Inner exits 0/1 are a completed batch. Every other
inner exit, timeout, signal, output-cap or unusable protocol is 75
(#45 unproved_exit_codes). Never parses the checker's human stdout.
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
EXPECTED_VECTOR_COUNT = 250
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


def project(doc: dict, expected_count: int) -> dict:
    rows = doc["vectors"]
    if not isinstance(rows, list):
        raise ValueError("vectors is not a list")
    if len(rows) != expected_count:
        raise ValueError("row count")
    seen: set[str] = set()
    out = {key: [] for key in OUTCOME_KEYS}
    out[DIAGNOSTIC_KEY] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("row is not an object")
        vid = row.get("id")
        if not isinstance(vid, str) or not vid.strip():
            raise ValueError("row id")
        if vid in seen:
            raise ValueError("duplicate row id")
        seen.add(vid)
        missing = [key for key in OUTCOME_KEYS if key not in row]
        if missing or DIAGNOSTIC_KEY not in row:
            raise ValueError("missing projection field")
        for key in OUTCOME_KEYS:
            out[key].append(row[key])
        out[DIAGNOSTIC_KEY].append(normalize_reason(row[DIAGNOSTIC_KEY]))
    if len(seen) != expected_count:
        raise ValueError("dropped row id")
    return out


def run_wrapper(checker: str, vectors: str, timeout: int = DEFAULT_TIMEOUT,
                expected_count: int = EXPECTED_VECTOR_COUNT) -> int:
    handle = tempfile.NamedTemporaryFile(prefix="aee-batch-", suffix=".json", delete=False)
    json_out = handle.name
    handle.close()
    cwd = Path(vectors)
    if not cwd.is_dir():
        cwd = cwd.parent
    try:
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
        except ca.ManifestError:
            return UNPROVED_EXIT
        try:
            projected = project(json.loads(raw.decode("utf-8")), expected_count)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return UNPROVED_EXIT
        sys.stdout.write(json.dumps(projected, ensure_ascii=False, separators=(",", ":")) + "\n")
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
    parser.add_argument("--expected-count", type=int, default=EXPECTED_VECTOR_COUNT)
    parser.add_argument("vectors")
    args = parser.parse_args(argv)
    return run_wrapper(
        args.checker, args.vectors, timeout=args.timeout,
        expected_count=args.expected_count)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
