#!/usr/bin/env python3
"""Phase C GO-RUN authorization for issue #211. Stdlib only.

Binds exact prepare.v0 bytes. Does not run the checker. Public non-claims:
not MC/DC, not atomic-subcondition adequacy, not complete mutation
adequacy, not sandbox-efficacy, not certification, not ranking.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402
from aee_checker_sealed_common import (  # noqa: E402
    PrepareError,
    encode_json,
    exact_object,
    load_strict,
    verify_file_digest,
)
from aee_checker_sealed_run import (  # noqa: E402
    PHASE_A_INSTRUMENT_COMMIT,
    PHASE_A_PIN_DIGESTS,
    PREPARE_KEYS,
    PREPARE_PART_KEYS,
    PREPARE_SCHEMA,
    emit_prepare_v0,
    execution_identity,
)

AUTHORIZE_SCHEMA = "corpus-adequacy.aee-checker-sealed.authorize.v0"
AUTHORIZE_PHASE = "authorize"
AUTHORIZE_KEYS = ("phase", "prepare_schema", "prepare_sha256", "schema")
GO_RUN_OPERATOR = "whole-condition-to-false"
SEALED_IDS = tuple("sealed-%d" % i for i in range(1, 8))
UNPROVED_STATES = frozenset({
    "wrapper-75", "timeout", "signal", "output-cap", "protocol",
})
NON_CLAIMS = (
    "MC/DC",
    "atomic-subcondition adequacy",
    "complete mutation adequacy",
    "sandbox-efficacy",
    "certification",
    "ranking",
)
_TIMING_KEYS = frozenset({
    "built_at", "created", "created_at", "ctime", "duration", "elapsed",
    "elapsed_seconds", "host_path", "mtime", "timestamp", "timing", "wall_ms",
})
_HOST_MARKERS = (
    "/Users/", "/home/", "/private/tmp/", "/private/var/", "/var/folders/",
    "C:/", "C:\\",
)


class AuthorizeError(Exception):
    """Authorization record or its bound prepare is not acceptable."""


def _wrap(exc: Exception) -> AuthorizeError:
    return AuthorizeError(str(exc))


def _exact(doc, keys, where: str) -> None:
    try:
        exact_object(doc, keys, where)
    except PrepareError as exc:
        raise _wrap(exc) from exc


def _refuse_host_timing(doc) -> None:
    stack = [doc]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if _TIMING_KEYS.intersection(item):
                raise AuthorizeError("authorize must not store timings")
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            if any(marker in item for marker in _HOST_MARKERS):
                raise AuthorizeError("authorize must not store host paths")


def load_prepare(raw: bytes) -> dict:
    try:
        doc = load_strict(raw)
    except PrepareError as exc:
        raise _wrap(exc) from exc
    if doc.get("schema") != PREPARE_SCHEMA:
        raise AuthorizeError("prepare_schema drift")
    _exact(doc, PREPARE_KEYS, "prepare.v0")
    parts = {key: doc[key] for key in PREPARE_PART_KEYS}
    with tempfile.TemporaryDirectory() as tmp:
        try:
            emitted = emit_prepare_v0(parts, Path(tmp) / "prepare.v0.json")
        except PrepareError as exc:
            raise _wrap(exc) from exc
    if emitted != raw:
        raise AuthorizeError("prepare is not canonical emit_prepare_v0 bytes")
    return doc


def require_bound_prepare(doc: dict) -> dict:
    execution = doc.get("execution")
    if type(execution) is not dict:
        raise AuthorizeError("execution missing")
    if not execution.get("commit") or not execution.get("content_sha256"):
        raise AuthorizeError("execution.commit/content_sha256 required")
    if execution.get("commit") == PHASE_A_INSTRUMENT_COMMIT:
        raise AuthorizeError("execution commit conflated with instrument")
    try:
        identity = execution_identity(_ROOT)
    except PrepareError as exc:
        raise _wrap(exc) from exc
    if execution.get("content_sha256") != identity["content_sha256"]:
        raise AuthorizeError("execution.content_sha256 is not producer identity")
    image = doc.get("image")
    if type(image) is not dict:
        raise AuthorizeError("image missing")
    if not image.get("id") or not image.get("platform"):
        raise AuthorizeError("image.id/platform required")
    return doc


def load_frozen_sites(pins_dir: Path) -> dict:
    raw = verify_file_digest(Path(pins_dir) / "sites.json", PHASE_A_PIN_DIGESTS["sites.json"])
    try:
        return load_strict(raw)
    except PrepareError as exc:
        raise _wrap(exc) from exc


def required_sequence(sites_doc: dict) -> tuple:
    sites = sites_doc.get("sites")
    if type(sites) is not list:
        raise AuthorizeError("sequence")
    ids = [site.get("id") for site in sites]
    if ids != list(SEALED_IDS):
        raise AuthorizeError("sequence")
    if any(site.get("replacement") != "false" for site in sites):
        raise AuthorizeError("operator must be whole-condition-to-false")
    steps = (
        {"id": "baseline", "kind": "baseline", "scored": False},
        {"id": "control", "kind": "must-die", "scored": False},
    )
    for site_id in SEALED_IDS:
        steps += ({
            "id": site_id,
            "kind": "mutant",
            "operator": GO_RUN_OPERATOR,
        },)
    return steps


def classify_observation(step: dict, observation: dict) -> str:
    state = observation.get("state")
    if state in UNPROVED_STATES:
        return "unproved"
    kind = step.get("kind")
    if kind == "baseline":
        return "passed" if observation.get("status") == "passed" else "void"
    if kind == "must-die":
        if observation.get("scored") is not False:
            return "void"
        if observation.get("status") != "killed":
            return "void"
        return "passed"
    if kind == "mutant":
        if step.get("operator") != GO_RUN_OPERATOR:
            return "void"
        return observation.get("status") or "unproved"
    raise AuthorizeError("unknown step")


def emit_authorize_v0(prepare_raw: bytes, dest: Path) -> bytes:
    doc = {
        "phase": AUTHORIZE_PHASE,
        "prepare_schema": PREPARE_SCHEMA,
        "prepare_sha256": hashlib.sha256(prepare_raw).hexdigest(),
        "schema": AUTHORIZE_SCHEMA,
    }
    _exact(doc, AUTHORIZE_KEYS, "authorize.v0")
    _refuse_host_timing(doc)
    raw = encode_json(doc)
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return raw


def validate_authorize(authorize_raw: bytes, prepare_raw: bytes) -> dict:
    try:
        auth = load_strict(authorize_raw)
    except PrepareError as exc:
        raise _wrap(exc) from exc
    _exact(auth, AUTHORIZE_KEYS, "authorize.v0")
    _refuse_host_timing(auth)
    if auth.get("schema") != AUTHORIZE_SCHEMA:
        raise AuthorizeError("schema")
    if auth.get("phase") != AUTHORIZE_PHASE:
        raise AuthorizeError("phase")
    if auth.get("prepare_schema") != PREPARE_SCHEMA:
        raise AuthorizeError("prepare_schema drift")
    got = hashlib.sha256(prepare_raw).hexdigest()
    if auth.get("prepare_sha256") != got:
        raise AuthorizeError("prepare_sha256")
    prepare = require_bound_prepare(load_prepare(prepare_raw))
    return {"authorize": auth, "prepare": prepare}


def main(argv: list[str]) -> int:
    if len(argv) >= 4 and argv[1] == "validate":
        auth_raw = ca.read_bounded_regular_file(Path(argv[2]))
        prep_raw = ca.read_bounded_regular_file(Path(argv[3]))
        validate_authorize(auth_raw, prep_raw)
        return 0
    sys.stderr.write("usage: aee_checker_sealed_authorize.py validate <authorize.v0> <prepare.v0>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
