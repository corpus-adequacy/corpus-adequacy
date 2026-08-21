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
    """No-follow bounded read. Matches the public lstat/open/fstat fallback.

    Isolated: does not import corpus_adequacy. When O_NOFOLLOW is missing,
    (st_dev, st_ino) must be identical between lstat and fstat.
    """
    cap = OUTPUT_CAP_BYTES
    path = Path(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    identity = None
    if nofollow is not None:
        flags |= nofollow
    else:
        try:
            before = os.lstat(path)
        except OSError as exc:
            raise ValueError("%s is not a regular file" % path) from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("%s is not a regular file" % path)
        identity = (before.st_dev, before.st_ino)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("%s is not a regular file" % path) from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("%s is not a regular file" % path)
        if identity is not None and (st.st_dev, st.st_ino) != identity:
            raise ValueError("%s changed between lstat and open; refusing" % path)
        if st.st_size > cap:
            raise ValueError("%s exceeds the input cap" % path)
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(fd, min(65536, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > cap:
            raise ValueError("%s exceeds the input cap" % path)
        return bytes(data)
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
