#!/usr/bin/env python3
"""Unsigned in-toto statement over one hosted attempt's upload surface (#187).

The gate writes the attempt's artifacts; this module seals what is there, after the gate
returned, whatever it returned. It observes files, it does not produce them: the seal reads the
closed upload surface (setup status, candidate result, rerun ledger, and exactly the verified
collection or the withheld diagnostic package that the workflow uploads), hashes each file, and
writes three files beside them under `attempt-statement.v0/`:

- `SHA256SUMS`: one shasum-format line per subject, the file `actions/attest` reads as
  `subject-checksums`;
- `hosted-attempt-predicate.v0.json`: the closed predicate the same step signs as
  `predicate-path` (dispatch inputs, run identity, workflow identity, gate outcome);
- `hosted-attempt-statement.v0.json`: the in-toto Statement v1 those two make together, kept so a
  reader can check the unsigned shape offline without the signing step.

Signing and signature verification stay outside this module and outside the tool: the workflow
step signs, `gh attestation verify` verifies. Nothing here authenticates the candidate author,
the corpus owner or the operator, and nothing here changes a decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://github.com/corpus-adequacy/corpus-adequacy/attestations/hosted-attempt/v0")
PREDICATE_SCHEMA = "corpus-adequacy.hosted-attempt-predicate.v0"
PREDICATE_KIND = "hosted-attempt-predicate"
STATEMENT_DIRNAME = "attempt-statement.v0"
SUMS_FILENAME = "SHA256SUMS"
PREDICATE_FILENAME = "hosted-attempt-predicate.v0.json"
STATEMENT_FILENAME = "hosted-attempt-statement.v0.json"
STATEMENT_FILENAMES = (SUMS_FILENAME, PREDICATE_FILENAME, STATEMENT_FILENAME)

# The upload surface, restated from the workflow's upload steps and pinned by the workflow
# contract test: a file outside this list (the materialize tree, a quarantined collection, the
# refusal stub that is never uploaded) is not a subject even when it sits under the out root.
SUBJECT_FILES = ("setup-status.json", "candidate-result.json", "rerun-evidence.jsonl")
# The owned rail also uploads its published report (#186); the external rail never does.
REPORT_SUBJECT = "report.v0.json"
OWNED_SUBJECT_FILES = SUBJECT_FILES + (REPORT_SUBJECT,)
SUBJECT_FILE_SETS = (SUBJECT_FILES, OWNED_SUBJECT_FILES)
SUBJECT_DIRS = ("effective-envelope-collection.v0", "withheld-diagnostic-package.v0")
# `actions/attest` refuses more than 1024 subjects; a larger surface is a defect, not a bigger
# statement.
MAX_SUBJECTS = 1024
MAX_SUMS_BYTES = 262144
MAX_STATEMENT_BYTES = 262144
GATE_OUTCOMES = ("success", "failure", "cancelled", "skipped")
BINDING_KEYS = ("candidate_revision", "runner_revision", "image_digest")
DISPATCH_INPUT_KEYS = BINDING_KEYS + ("packet_release_tag", "packet_manifest_sha256")
RUN_IDENTITY_KEYS = ("run_id", "run_attempt")
WORKFLOW_IDENTITY_KEYS = ("github_sha", "github_workflow_sha", "image_os", "image_version")
PREDICATE_KEYS = (
    "schema", "kind", "rail", "bindings", "dispatch_inputs", "run_identity",
    "workflow_identity", "gate_outcome", "subjects", "subjects_sha256", "non_claims",
)
STATEMENT_KEYS = ("_type", "subject", "predicateType", "predicate")
NON_CLAIMS = (
    "Binds the listed bytes to one dispatch, run and workflow identity as the runner "
    "reported them; the signature, when present, is the workflow's, not the operator's.",
    "Does not authenticate the candidate author, the corpus owner or the operator.",
    "Does not change, score or verify the attempt it seals.",
    "Not adequacy, endorsement, audit or certification.",
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SUMS_LINE = re.compile(r"^([0-9a-f]{64}) ([ *])(.+)$")
_DIGITS = re.compile(r"^[0-9]{1,20}$")


class StatementError(Exception):
    """Structural refusal. The seal writes nothing on refusal."""


def _require_str(value, where: str, *, max_len: int = 256) -> str:
    if type(value) is not str or not value or len(value) > max_len:
        raise StatementError(where)
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise StatementError(where)
    return value


def require_bindings(bindings) -> dict:
    if type(bindings) is not dict or tuple(sorted(bindings)) != tuple(sorted(BINDING_KEYS)):
        raise StatementError("bindings")
    for key in ("candidate_revision", "runner_revision"):
        if not _HEX40.match(_require_str(bindings[key], key)):
            raise StatementError(key)
    image = _require_str(bindings["image_digest"], "image_digest")
    if not image.startswith("sha256:") or not _HEX64.match(image[len("sha256:"):]):
        raise StatementError("image_digest")
    return {key: bindings[key] for key in BINDING_KEYS}


def require_dispatch_inputs(inputs, *, bindings) -> dict:
    if (type(inputs) is not dict
            or tuple(sorted(inputs)) != tuple(sorted(DISPATCH_INPUT_KEYS))):
        raise StatementError("dispatch_inputs")
    for key in BINDING_KEYS:
        if inputs[key] != bindings[key]:
            raise StatementError("dispatch_inputs:%s" % key)
    _require_str(inputs["packet_release_tag"], "packet_release_tag")
    if not _HEX64.match(_require_str(inputs["packet_manifest_sha256"],
                                     "packet_manifest_sha256")):
        raise StatementError("packet_manifest_sha256")
    return {key: inputs[key] for key in DISPATCH_INPUT_KEYS}


def require_run_identity(identity) -> dict:
    if (type(identity) is not dict
            or tuple(sorted(identity)) != tuple(sorted(RUN_IDENTITY_KEYS))):
        raise StatementError("run_identity")
    for key in RUN_IDENTITY_KEYS:
        if not _DIGITS.match(_require_str(identity[key], key, max_len=20)):
            raise StatementError(key)
    return {key: identity[key] for key in RUN_IDENTITY_KEYS}


def require_workflow_identity(identity) -> dict:
    if (type(identity) is not dict
            or tuple(sorted(identity)) != tuple(sorted(WORKFLOW_IDENTITY_KEYS))):
        raise StatementError("workflow_identity")
    for key in WORKFLOW_IDENTITY_KEYS:
        _require_str(identity[key], key)
    if not _HEX40.match(identity["github_sha"]) or not _HEX40.match(
            identity["github_workflow_sha"]):
        raise StatementError("workflow_identity_sha")
    return {key: identity[key] for key in WORKFLOW_IDENTITY_KEYS}


def _regular_file(path: Path, where: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise StatementError(where)
    return path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def enumerate_subjects(out_dir, *, subject_files=SUBJECT_FILES) -> list[tuple[str, str]]:
    """`(name, sha256)` per upload-surface file under `out_dir`, in sorted name order.

    Names are POSIX paths relative to `out_dir`. Exactly one of the two subject directories
    may be present: a publish attempt leaves the collection, a non-publish attempt the
    diagnostic package, and both at once is not a shape the gate writes.
    """
    if subject_files not in SUBJECT_FILE_SETS:
        raise StatementError("subject_files")
    out = Path(out_dir)
    if out.is_symlink() or not out.is_dir():
        raise StatementError("out_dir")
    subjects = []
    for name in subject_files:
        path = out / name
        if path.exists() or path.is_symlink():
            _regular_file(path, "subject:%s" % name)
            subjects.append((name, _sha256_file(path)))
    present_dirs = [name for name in SUBJECT_DIRS if (out / name).exists()]
    if len(present_dirs) > 1:
        raise StatementError("subject_dirs")
    for dirname in present_dirs:
        root = out / dirname
        if root.is_symlink() or not root.is_dir():
            raise StatementError("subject:%s" % dirname)
        for path in sorted(root.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            _regular_file(path, "subject:%s" % path.relative_to(out).as_posix())
            subjects.append((path.relative_to(out).as_posix(), _sha256_file(path)))
    subjects.sort()
    if not subjects:
        raise StatementError("no_subjects")
    if len(subjects) > MAX_SUBJECTS:
        raise StatementError("max_subjects")
    names = [name for name, _ in subjects]
    if len(set(names)) != len(names):
        raise StatementError("duplicate_subject")
    return subjects


def encode_sums(subjects) -> bytes:
    """shasum text-mode lines: `<hex64>  <name>`, the format `subject-checksums` reads."""
    lines = []
    for name, digest in subjects:
        if not _HEX64.match(digest) or type(name) is not str or not name:
            raise StatementError("subject")
        if "\n" in name or "\r" in name or name.startswith("/") or ".." in name.split("/"):
            raise StatementError("subject_name")
        lines.append("%s  %s\n" % (digest, name))
    raw = "".join(lines).encode("utf-8")
    if len(raw) > MAX_SUMS_BYTES:
        raise StatementError("max_sums_bytes")
    return raw


def parse_sums(raw: bytes) -> list[tuple[str, str]]:
    if type(raw) is not bytes or len(raw) > MAX_SUMS_BYTES:
        raise StatementError("max_sums_bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise StatementError("sums_encoding") from exc
    if not text or not text.endswith("\n"):
        raise StatementError("sums_shape")
    subjects = []
    for line in text[:-1].split("\n"):
        match = _SUMS_LINE.match(line)
        if match is None:
            raise StatementError("sums_line")
        digest, mode, name = match.groups()
        if mode != " ":
            raise StatementError("sums_mode")
        subjects.append((name, digest))
    if subjects != sorted(subjects) or encode_sums(subjects) != raw:
        raise StatementError("sums_canonical")
    if len(subjects) > MAX_SUBJECTS or not subjects:
        raise StatementError("max_subjects")
    return subjects


def build_predicate(*, rail: str, bindings, dispatch_inputs, run_identity,
                    workflow_identity, gate_outcome, sums_raw: bytes, subjects) -> dict:
    bound = require_bindings(bindings)
    if gate_outcome not in GATE_OUTCOMES:
        raise StatementError("gate_outcome")
    if type(sums_raw) is not bytes or parse_sums(sums_raw) != list(subjects):
        raise StatementError("subjects_binding")
    return {
        "schema": PREDICATE_SCHEMA,
        "kind": PREDICATE_KIND,
        "rail": _require_str(rail, "rail"),
        "bindings": bound,
        "dispatch_inputs": require_dispatch_inputs(dispatch_inputs, bindings=bound),
        "run_identity": require_run_identity(run_identity),
        "workflow_identity": require_workflow_identity(workflow_identity),
        "gate_outcome": gate_outcome,
        "subjects": len(subjects),
        "subjects_sha256": hashlib.sha256(sums_raw).hexdigest(),
        "non_claims": list(NON_CLAIMS),
    }


def build_statement(subjects, predicate: dict) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": digest}} for name, digest in subjects],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def encode_json(doc) -> bytes:
    raw = (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(raw) > MAX_STATEMENT_BYTES:
        raise StatementError("max_statement_bytes")
    return raw


def seal_attempt(*, out_dir, rail, bindings, dispatch_inputs, run_identity,
                 workflow_identity, gate_outcome, subject_files=SUBJECT_FILES) -> dict:
    """Write `attempt-statement.v0/` under `out_dir`; refuse rather than overwrite."""
    out = Path(out_dir)
    subjects = enumerate_subjects(out, subject_files=subject_files)
    sums_raw = encode_sums(subjects)
    predicate = build_predicate(
        rail=rail, bindings=bindings, dispatch_inputs=dispatch_inputs,
        run_identity=run_identity, workflow_identity=workflow_identity,
        gate_outcome=gate_outcome, sums_raw=sums_raw, subjects=subjects)
    statement = build_statement(subjects, predicate)
    predicate_raw = encode_json(predicate)
    statement_raw = encode_json(statement)
    dest = out / STATEMENT_DIRNAME
    if dest.exists() or dest.is_symlink():
        raise StatementError("statement_occupied")
    dest.mkdir()
    (dest / SUMS_FILENAME).write_bytes(sums_raw)
    (dest / PREDICATE_FILENAME).write_bytes(predicate_raw)
    (dest / STATEMENT_FILENAME).write_bytes(statement_raw)
    return {
        "subjects": len(subjects),
        "subjects_sha256": predicate["subjects_sha256"],
        "statement_sha256": hashlib.sha256(statement_raw).hexdigest(),
        "gate_outcome": gate_outcome,
    }


def _read_bounded(path: Path, cap: int) -> bytes:
    _regular_file(path, "statement_file")
    if path.stat().st_size > cap:
        raise StatementError("statement_file_bytes")
    return path.read_bytes()


def _require_exact(doc, keys, where: str) -> dict:
    if type(doc) is not dict or tuple(sorted(doc)) != tuple(sorted(keys)):
        raise StatementError(where)
    return doc


def load_statement_dir(statement_dir) -> dict:
    """Read the three sealed files and require them to be one consistent, canonical set."""
    root = Path(statement_dir)
    if root.is_symlink() or not root.is_dir():
        raise StatementError("statement_dir")
    sums_raw = _read_bounded(root / SUMS_FILENAME, MAX_SUMS_BYTES)
    predicate_raw = _read_bounded(root / PREDICATE_FILENAME, MAX_STATEMENT_BYTES)
    statement_raw = _read_bounded(root / STATEMENT_FILENAME, MAX_STATEMENT_BYTES)
    subjects = parse_sums(sums_raw)
    try:
        predicate = json.loads(predicate_raw.decode("utf-8"))
        statement = json.loads(statement_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise StatementError("statement_json") from exc
    _require_exact(predicate, PREDICATE_KEYS, "predicate_keys")
    if predicate.get("schema") != PREDICATE_SCHEMA or predicate.get("kind") != PREDICATE_KIND:
        raise StatementError("predicate_schema")
    if predicate.get("non_claims") != list(NON_CLAIMS):
        raise StatementError("predicate_non_claims")
    rebuilt = build_predicate(
        rail=predicate.get("rail"), bindings=predicate.get("bindings"),
        dispatch_inputs=predicate.get("dispatch_inputs"),
        run_identity=predicate.get("run_identity"),
        workflow_identity=predicate.get("workflow_identity"),
        gate_outcome=predicate.get("gate_outcome"), sums_raw=sums_raw, subjects=subjects)
    if rebuilt != predicate or encode_json(rebuilt) != predicate_raw:
        raise StatementError("predicate_canonical")
    if predicate.get("subjects") != len(subjects):
        raise StatementError("subjects_count")
    _require_exact(statement, STATEMENT_KEYS, "statement_keys")
    if (statement != build_statement(subjects, predicate)
            or encode_json(build_statement(subjects, predicate)) != statement_raw):
        raise StatementError("statement_canonical")
    return {"subjects": subjects, "predicate": predicate, "statement": statement,
            "sums_sha256": hashlib.sha256(sums_raw).hexdigest()}


def check_statement_against_files(loaded: dict, files: dict, *, bindings, run_identity,
                                  rail=None) -> dict:
    """Every subject is one of `files` (name -> path) with the same bytes, and vice versa.

    `files` is the reader's own download: what it holds must be exactly what was sealed. A
    subject the reader does not hold cannot be checked and refuses; a held file the seal does
    not name is not covered by the signature and refuses as well.
    """
    predicate = loaded["predicate"]
    if rail is not None and predicate["rail"] != rail:
        raise StatementError("statement_rail")
    if predicate["bindings"] != require_bindings(bindings):
        raise StatementError("statement_bindings")
    if predicate["run_identity"] != require_run_identity(run_identity):
        raise StatementError("statement_run_identity")
    sealed = dict(loaded["subjects"])
    if type(files) is not dict or sorted(files) != sorted(sealed):
        raise StatementError("statement_subjects")
    for name, path in files.items():
        if _sha256_file(_regular_file(Path(path), "subject:%s" % name)) != sealed[name]:
            raise StatementError("statement_subject_bytes:%s" % name)
    return {
        "statement": "verified-unsigned",
        "statement_subjects": len(sealed),
        "predicate_type": PREDICATE_TYPE,
        "gate_outcome": predicate["gate_outcome"],
        "subjects_sha256": predicate["subjects_sha256"],
    }
