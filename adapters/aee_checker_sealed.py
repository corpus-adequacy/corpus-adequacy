#!/usr/bin/env python3
"""Batch wrapper for the pinned Rust AEE checker. Stdlib only.

Runs `checker <vectors-dir> --json <file>`. Reads that file. Never parses
the checker's human stdout. Checker exit 0/1 is a completed batch and this
wrapper exits 0. Build, timeout, signal, output-cap or unusable protocol
exit 75 — the #45 unproved_exit_codes policy.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

UNPROVED_EXIT = 75
ACCEPTED_EXIT = 0
OUTPUT_CAP_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 600
OUTCOME_KEYS = ("verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey")


def _unproved(_why: str) -> int:
    return UNPROVED_EXIT


def project(doc: dict) -> dict:
    rows = doc["vectors"]
    if not isinstance(rows, list):
        raise ValueError("vectors is not a list")
    out = {key: [] for key in OUTCOME_KEYS}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("vector row is not an object")
        for key in OUTCOME_KEYS:
            out[key].append(row.get(key))
    return out


def run_wrapper(checker: str, vectors: str, timeout: int = DEFAULT_TIMEOUT) -> int:
    handle = tempfile.NamedTemporaryFile(prefix="aee-batch-", suffix=".json", delete=False)
    json_out = handle.name
    handle.close()
    try:
        try:
            proc = subprocess.run(
                [checker, vectors, "--json", json_out],
                capture_output=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return _unproved("timeout")
        except OSError:
            return _unproved("build-or-exec")
        if proc.returncode is None or proc.returncode < 0:
            return _unproved("signal")
        if len(proc.stdout) + len(proc.stderr) > OUTPUT_CAP_BYTES:
            return _unproved("output-cap")
        try:
            raw = Path(json_out).read_bytes()
        except OSError:
            return _unproved("protocol")
        if len(raw) > OUTPUT_CAP_BYTES:
            return _unproved("output-cap")
        try:
            doc = json.loads(raw.decode("utf-8"))
            projected = project(doc)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return _unproved("protocol")
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
    parser.add_argument("vectors")
    args = parser.parse_args(argv)
    return run_wrapper(args.checker, args.vectors, timeout=args.timeout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
