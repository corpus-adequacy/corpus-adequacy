#!/usr/bin/env python3
"""Dispatch-only process wrapper for pinned Tersign CHECKS. Stdlib only.

Reads one adapted case file, calls CHECKS[kind](input), and prints
{"verdict": ..., "reason": ...}. Does not reimplement a check, does not
call the suite entrypoint, and does not project detail.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from verify import CHECKS  # noqa: E402

ACCEPTED_EXIT = 0
OUTPUT_CAP_BYTES = 4 * 1024 * 1024


def _read_bounded(path: Path) -> bytes:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ValueError("could not stat %s: %s" % (path, exc)) from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise ValueError("%s is not a regular file" % path)
    if st.st_size > OUTPUT_CAP_BYTES:
        raise ValueError("%s exceeds the input cap" % path)
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        flags |= nofollow
    fd = os.open(path, flags)
    try:
        chunks = []
        n = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            n += len(block)
            if n > OUTPUT_CAP_BYTES:
                raise ValueError("%s exceeds the input cap" % path)
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def evaluate(path) -> dict:
    raw = _read_bounded(Path(path))
    doc = json.loads(raw.decode("utf-8"))
    kind = doc["kind"]
    verdict, reason, _detail = CHECKS[kind](doc["input"])
    return {"verdict": verdict, "reason": reason}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: tersign_checks.py <case.json>", file=sys.stderr)
        sys.exit(1)
    try:
        print(json.dumps(evaluate(sys.argv[1]), ensure_ascii=False))
    except Exception as exc:
        print("could not evaluate: %s" % exc, file=sys.stderr)
        sys.exit(1)
    return ACCEPTED_EXIT


if __name__ == "__main__":
    sys.exit(main())
