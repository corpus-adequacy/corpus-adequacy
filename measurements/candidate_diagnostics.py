"""Bounded, closed candidate failure observations for hosted readback (#172).

The sidecar records only harness-owned tokens.  It is a diagnostic byproduct,
not an execution outcome, score, or root-cause claim.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import contained_oci
import corpus_adequacy as ca

SCHEMA = "corpus-adequacy.candidate-diagnostics.v0"
FILENAME = "candidate-diagnostics.v0.json"
MAX_MEMBERS = 256
MAX_BYTES = 65536
UNKNOWN_REASON = "unknown"
OUTCOMES = ("completed", "timeout", "output-cap", "unproved", "not-run")
DOCUMENT_KEYS = ("schema", "bindings", "members", "non_claims")
BINDING_KEYS = (
    "candidate_revision", "runner_revision", "image_digest", "prepare_sha256",
    "report_sha256", "collection_index_sha256", "workflow_run_id", "run_attempt",
)
MEMBER_KEYS = ("ordinal", "candidate_outcome", "unproved_reason")
NON_CLAIMS = (
    "Records a harness-observed closed token, not a root-cause proof.",
    "Not a mutation kill, score, adequacy result, audit, certification, "
    "or publication authorization.",
)


class DiagnosticError(Exception):
    """The candidate diagnostic is unsafe or structurally invalid."""


def _require_exact(value, keys, where):
    if type(value) is not dict or set(value) != set(keys):
        raise DiagnosticError("%s keys" % where)


def _require_hex(value, length, where):
    if (not isinstance(value, str) or len(value) != length
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise DiagnosticError(where)


def _validate_bindings(bindings):
    _require_exact(bindings, BINDING_KEYS, "bindings")
    _require_hex(bindings["candidate_revision"], 40, "candidate_revision")
    _require_hex(bindings["runner_revision"], 40, "runner_revision")
    image = bindings["image_digest"]
    if not isinstance(image, str) or not image.startswith("sha256:"):
        raise DiagnosticError("image_digest")
    _require_hex(image[7:], 64, "image_digest")
    for key in ("prepare_sha256", "report_sha256", "collection_index_sha256"):
        _require_hex(bindings[key], 64, key)
    for key in ("workflow_run_id", "run_attempt"):
        if not isinstance(bindings[key], str) or not bindings[key].isdigit():
            raise DiagnosticError(key)
    return dict(bindings)


def observation(ordinal, candidate_outcome, unproved_reason):
    if type(ordinal) is not int or ordinal < 0 or ordinal >= MAX_MEMBERS:
        raise DiagnosticError("ordinal")
    if candidate_outcome not in OUTCOMES:
        raise DiagnosticError("candidate_outcome")
    if candidate_outcome == "completed":
        if unproved_reason is not None:
            raise DiagnosticError("completed reason")
        reason = None
    else:
        if unproved_reason is None:
            raise DiagnosticError("unproved reason")
        reason = ca.sanitize_unproved_reason(unproved_reason) or UNKNOWN_REASON
    return {
        "ordinal": ordinal,
        "candidate_outcome": candidate_outcome,
        "unproved_reason": reason,
    }


def build_document(*, bindings, members):
    if type(members) is not list:
        raise DiagnosticError("members")
    if len(members) > MAX_MEMBERS:
        raise DiagnosticError("member count ceiling")
    closed = []
    for position, row in enumerate(members):
        _require_exact(row, MEMBER_KEYS, "member")
        rebuilt = observation(
            row["ordinal"], row["candidate_outcome"], row["unproved_reason"])
        if rebuilt != row or row["ordinal"] != position:
            raise DiagnosticError("member")
        closed.append(rebuilt)
    return {
        "schema": SCHEMA,
        "bindings": _validate_bindings(bindings),
        "members": closed,
        "non_claims": list(NON_CLAIMS),
    }


def encode_document(doc, *, max_bytes=MAX_BYTES):
    validated = validate_document(doc)
    raw = (json.dumps(validated, ensure_ascii=False, indent=2, sort_keys=True)
           + "\n").encode("utf-8")
    if len(raw) > max_bytes:
        raise DiagnosticError("byte ceiling")
    return raw


def validate_document(doc, *, expected_bindings=None):
    _require_exact(doc, DOCUMENT_KEYS, "document")
    if doc.get("schema") != SCHEMA or doc.get("non_claims") != list(NON_CLAIMS):
        raise DiagnosticError("document")
    rebuilt = build_document(bindings=doc.get("bindings"), members=doc.get("members"))
    if rebuilt != doc:
        raise DiagnosticError("document")
    if (expected_bindings is not None
            and rebuilt["bindings"] != _validate_bindings(expected_bindings)):
        raise DiagnosticError("bindings")
    return rebuilt


def write_document(path, doc, *, max_bytes=MAX_BYTES):
    path = Path(path)
    raw = encode_document(doc, max_bytes=max_bytes)
    if path.exists():
        raise DiagnosticError("destination occupied")
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_name(".%s.staging" % path.name)
    if staging.exists():
        raise DiagnosticError("staging occupied")
    try:
        with staging.open("xb") as stream:
            stream.write(raw)
        os.replace(staging, path)
    except BaseException:
        try:
            staging.unlink()
        except OSError:
            pass
        raise
    return raw


def load_document(path, *, expected_bindings=None, max_bytes=MAX_BYTES):
    try:
        raw = ca.read_bounded_regular_file(Path(path), cap=max_bytes)
        doc = contained_oci.load_strict(raw)
    except (ca.ManifestError, contained_oci.PrepareError, UnicodeError, ValueError) as exc:
        raise DiagnosticError("input") from exc
    if len(raw) > max_bytes:
        raise DiagnosticError("byte ceiling")
    validated = validate_document(doc, expected_bindings=expected_bindings)
    if encode_document(validated, max_bytes=max_bytes) != raw:
        raise DiagnosticError("canonical encoding")
    return validated
