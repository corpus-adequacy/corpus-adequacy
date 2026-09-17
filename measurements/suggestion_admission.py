#!/usr/bin/env python3
"""Deterministic admission for proposed test vectors (#200). Stdlib only; no model calls.

A proposal names one new vector for a frozen selection and the outcome it expects. Admission is a
fixed sequence of gates, each with a named refusal. This module implements the gates that need no
execution (0 shape, 1 freeze, 2 corpus separation, 7 review, 8 accounting). The execution gates
(3 reference pass, 4 controls, 5 intended distinction, 6 transformation robustness) are recorded as
`not-run`, so no record written here can say `admitted`: the best it can say is
`pending-execution`.

Nothing here changes a frozen corpus, a frozen selection, `report.v0` or any score. An admitted
proposal, once execution gates exist, is only a candidate for a human-authored corpus change.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _entry in (str(ROOT), str(ROOT / "measurements")):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import corpus_adequacy as ca  # noqa: E402
from aee_checker_sealed_materialize import tree_sha256  # noqa: E402

PROPOSAL_SCHEMA = "corpus-adequacy.suggestion-proposal.v0"
REVIEW_SCHEMA = "corpus-adequacy.suggestion-review.v0"
ADMISSION_SCHEMA = "corpus-adequacy.suggestion-admission.v0"
ADMISSION_SCHEMA_V1 = "corpus-adequacy.suggestion-admission.v1"
PROPOSAL_KEYS = ("schema", "proposal_id", "selection", "target", "vector", "expected",
                 "authorship")
TARGET_KEYS = ("group", "mutation_id")
VECTOR_KEYS = ("id", "file", "value_class", "document")
AUTHORSHIP_KEYS = ("author_kind", "author", "model_id", "prompt_sha256", "input_sha256",
                   "source_pin")
REVIEW_KEYS = ("schema", "proposal_id", "reviewer", "decision", "minutes")
AUTHOR_KINDS = ("human", "model")
REVIEW_DECISIONS = ("accept", "reject")
GATES = (
    (0, "proposal-shape"),
    (1, "freeze"),
    (2, "corpus-separation"),
    (3, "reference-pass"),
    (4, "controls-bite"),
    (5, "intended-distinction"),
    (6, "transformation-robustness"),
    (7, "semantic-review"),
    (8, "accounting"),
)
EXECUTION_GATES = (3, 4, 5, 6)
GATE_STATUSES = ("passed", "refused", "not-run")
DECISIONS = ("refused", "pending-execution")
DECISIONS_V1 = ("refused", "admitted")
EXECUTION_KEYS = ("route", "profile", "recording_sha256", "transformations")
# Only a route that actually ran the candidate can carry an admitted decision.
ADMITTING_ROUTES = ("contained-oci-v1-derived",)
TERMINAL_STATES = ("admitted", "refused", "no-improvement")
NON_CLAIMS = (
    "Admission decides whether one proposed vector may be considered for a human-authored corpus "
    "change; it changes no corpus, selection, report or score.",
    "Execution gates not run here are recorded as not-run; nothing in this record is admitted.",
    "Authorship names are descriptive and unauthenticated; no suggestion-value, real-fault, "
    "adequacy or provider claim follows.",
)
NON_CLAIMS_V1 = NON_CLAIMS[:1] + (
    "Execution gates judge one recording of one run on one host; they are not a containment, "
    "adequacy or real-fault claim.",
    "An admitted proposal is a candidate for a human-authored corpus change; no corpus, "
    "selection, report or score changes here.",
) + NON_CLAIMS[2:]
MAX_PROPOSAL_BYTES = 65536
MAX_TEXT = 256
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OUTCOME_EXPECTATION_KEYS = ("accepted", "reason")
_DIAGNOSTIC_KEYS = ("detail",)
_EQUIVALENCE_WORDS = ("equivalent", "equivalence")
_I64 = (-(2 ** 63), 2 ** 63 - 1)

# The one closed selection this harness can judge; paths are code-owned, never proposal input.
SELECTIONS = {
    "owned-independent-v0": {
        "group": "independent",
        "mutation_id": "upper-guard-first-overflow-only",
        "bundle": ("measurements", "owned-independent-v0", "mutation-bundle.json"),
        "corpus": ("fixtures", "contained-v1-owned", "corpus", "vectors"),
    },
}


class AdmissionError(Exception):
    """A named refusal; the name is the gate's refusal token."""


def _text(value, token) -> str:
    if (type(value) is not str or not value or len(value.encode("utf-8")) > MAX_TEXT
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise AdmissionError(token)
    return value


def _exact(doc, keys, token) -> dict:
    if type(doc) is not dict or tuple(sorted(doc)) != tuple(sorted(keys)):
        raise AdmissionError(token)
    return doc


def _walk_keys(value):
    if type(value) is dict:
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif type(value) is list:
        for item in value:
            yield from _walk_keys(item)


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_proposal(path) -> tuple[dict, bytes]:
    """Gate 0. Bytes first, then closed shape; refusal tokens name what failed."""
    try:
        raw = ca.read_bounded_regular_file(Path(path), cap=MAX_PROPOSAL_BYTES)
    except ca.ManifestError as exc:
        raise AdmissionError("proposal-shape") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise AdmissionError("proposal-shape") from exc
    return require_proposal(doc), raw


def require_proposal(doc) -> dict:
    if type(doc) is dict and any(
            word in str(key).lower() for key in _walk_keys(doc) for word in _EQUIVALENCE_WORDS):
        # An equivalence judgement is a human disposition, never a proposal field.
        raise AdmissionError("model-equivalence-claim")
    _exact(doc, PROPOSAL_KEYS, "proposal-shape")
    if doc["schema"] != PROPOSAL_SCHEMA:
        raise AdmissionError("proposal-shape")
    if type(doc["proposal_id"]) is not str or not _TOKEN.match(doc["proposal_id"]):
        raise AdmissionError("proposal-shape")
    selection = SELECTIONS.get(doc["selection"])
    if selection is None:
        raise AdmissionError("proposal-selection")
    target = _exact(doc["target"], TARGET_KEYS, "proposal-shape")
    if (target["group"], target["mutation_id"]) != (selection["group"],
                                                    selection["mutation_id"]):
        raise AdmissionError("proposal-target")
    vector = _exact(doc["vector"], VECTOR_KEYS, "proposal-shape")
    if type(vector["id"]) is not str or not _TOKEN.match(vector["id"]):
        raise AdmissionError("proposal-shape")
    if vector["file"] != vector["id"] + ".json":
        raise AdmissionError("proposal-shape")
    _text(vector["value_class"], "proposal-shape")
    document = _exact(vector["document"], ("value",), "proposal-shape")
    value = document["value"]
    if type(value) is not int or not _I64[0] <= value <= _I64[1]:
        raise AdmissionError("proposal-shape")
    expected = doc["expected"]
    if type(expected) is not dict:
        raise AdmissionError("proposal-shape")
    if any(key in _DIAGNOSTIC_KEYS for key in expected):
        # Only the declared outcome channel can witness a distinction.
        raise AdmissionError("proposal-expects-diagnostic")
    _exact(expected, _OUTCOME_EXPECTATION_KEYS, "proposal-shape")
    if type(expected["accepted"]) is not bool:
        raise AdmissionError("proposal-shape")
    _text(expected["reason"], "proposal-shape")
    authorship = _exact(doc["authorship"], AUTHORSHIP_KEYS, "proposal-shape")
    if authorship["author_kind"] not in AUTHOR_KINDS:
        raise AdmissionError("proposal-authorship")
    _text(authorship["author"], "proposal-authorship")
    if type(authorship["source_pin"]) is not str or not _HEX40.match(authorship["source_pin"]):
        raise AdmissionError("proposal-authorship")
    model_fields = (authorship["model_id"], authorship["prompt_sha256"],
                    authorship["input_sha256"])
    if authorship["author_kind"] == "model":
        _text(authorship["model_id"], "proposal-authorship")
        for digest in model_fields[1:]:
            if type(digest) is not str or not _DIGEST.match(digest):
                raise AdmissionError("proposal-authorship")
    elif any(field is not None for field in model_fields):
        raise AdmissionError("proposal-authorship")
    return doc


def check_freeze(proposal: dict, *, root: Path = ROOT) -> dict:
    """Gate 1. Every file the selection froze still has its frozen bytes."""
    selection = SELECTIONS[proposal["selection"]]
    try:
        bundle = json.loads(ca.read_bounded_regular_file(
            Path(root).joinpath(*selection["bundle"])).decode("utf-8"))
        frozen = bundle["candidate_freeze"]["sha256"]
    except (ca.ManifestError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise AdmissionError("freeze-drift") from exc
    for relpath, digest in sorted(frozen.items()):
        path = Path(root) / relpath
        try:
            raw = ca.read_bounded_regular_file(path)
        except ca.ManifestError as exc:
            raise AdmissionError("freeze-drift:%s" % relpath) from exc
        if hashlib.sha256(raw).hexdigest() != digest:
            raise AdmissionError("freeze-drift:%s" % relpath)
    return {"frozen_files": len(frozen)}


def corpus_digest(manifest_rows, vectors_dir: Path) -> str:
    """The fixture's own corpusDigest formula: sha256 over `file\\0bytes` in manifest order."""
    digest = hashlib.sha256()
    for row in manifest_rows:
        digest.update(row["file"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(ca.read_bounded_regular_file(Path(vectors_dir) / row["file"]))
    return digest.hexdigest()


def build_proposal_corpus(proposal: dict, dest, *, root: Path = ROOT) -> dict:
    """Gate 2. A separate corpus: the frozen vectors plus the proposal, never the frozen dir."""
    selection = SELECTIONS[proposal["selection"]]
    frozen_dir = Path(root).joinpath(*selection["corpus"])
    before = tree_sha256(frozen_dir)
    dest = Path(dest)
    if dest.exists() or dest.is_symlink():
        raise AdmissionError("proposal-corpus-exists")
    try:
        manifest = json.loads(ca.read_bounded_regular_file(
            frozen_dir / "MANIFEST.json").decode("utf-8"))
        rows = list(manifest["vectors"])
    except (ca.ManifestError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise AdmissionError("freeze-drift") from exc
    vector = proposal["vector"]
    # File names compare case-insensitively: on macOS and Windows `manifest.json` is the
    # manifest, and a proposal must never be able to replace it.
    taken_files = {row["file"].casefold() for row in rows} | {"manifest.json"}
    if (vector["id"] in {row["id"] for row in rows}
            or vector["file"].casefold() in taken_files):
        raise AdmissionError("duplicate-vector-id")
    if corpus_digest(rows, frozen_dir) != manifest["corpusDigest"]:
        raise AdmissionError("freeze-drift")
    dest.mkdir(parents=True)
    for row in rows:
        shutil.copyfile(frozen_dir / row["file"], dest / row["file"])
    (dest / vector["file"]).write_bytes(
        json.dumps(vector["document"], separators=(",", ":"), sort_keys=True).encode("utf-8"))
    new_rows = rows + [{"file": vector["file"], "id": vector["id"],
                        "value_class": vector["value_class"]}]
    new_manifest = {"corpusDigest": corpus_digest(new_rows, dest), "vectors": new_rows}
    (dest / "MANIFEST.json").write_bytes(
        (json.dumps(new_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    if tree_sha256(frozen_dir) != before:
        raise AdmissionError("frozen-corpus-touched")
    return {"frozen_tree_sha256": before, "proposal_corpus_digest": new_manifest["corpusDigest"],
            "vectors": len(new_rows)}


def require_review(review, proposal: dict, *, packet_author=None) -> dict:
    """Gate 7. A named human review by someone who did not write the proposal."""
    if review is None:
        raise AdmissionError("review-missing")
    if type(review) is dict and any(
            word in str(key).lower() for key in _walk_keys(review) for word in _EQUIVALENCE_WORDS):
        raise AdmissionError("model-equivalence-claim")
    _exact(review, REVIEW_KEYS, "review-shape")
    if review["schema"] != REVIEW_SCHEMA or review["proposal_id"] != proposal["proposal_id"]:
        raise AdmissionError("review-shape")
    reviewer = _text(review["reviewer"], "review-shape")
    if review["decision"] not in REVIEW_DECISIONS:
        raise AdmissionError("review-shape")
    if type(review["minutes"]) is not int or not 0 <= review["minutes"] <= 24 * 60:
        raise AdmissionError("review-shape")
    # Exact string comparison over names the record itself calls unauthenticated: it catches an
    # honest self-review, not someone who chooses a different spelling.
    authorship = proposal["authorship"]
    excluded = {authorship["author"], authorship["model_id"], packet_author} - {None}
    if reviewer in excluded:
        raise AdmissionError("review-by-author")
    return review


def admission_record(proposal_raw: bytes, proposal: dict, gate_results: dict) -> dict:
    """The closed record. Gates missing from `gate_results` are refused as a harness fault."""
    gates = []
    refusal = None
    for number, name in GATES:
        if number in EXECUTION_GATES:
            status, reason = "not-run", None
        else:
            if number not in gate_results:
                raise AdmissionError("accounting-gap")
            status, reason = gate_results[number]
            if status not in ("passed", "refused") or (status == "refused") != (reason is not None):
                raise AdmissionError("accounting-gap")
        if status == "refused" and refusal is None:
            refusal = reason
        gates.append({"gate": number, "name": name, "status": status, "refusal": reason})
    return {
        "schema": ADMISSION_SCHEMA,
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": _digest(proposal_raw),
        "selection": proposal["selection"],
        "gates": gates,
        "decision": "refused" if refusal is not None else "pending-execution",
        "refusal": refusal,
        "non_claims": list(NON_CLAIMS),
    }


def admission_record_v1(proposal_raw: bytes, proposal: dict, gate_results: dict,
                        execution: dict) -> dict:
    """The record for a run that judged the execution gates. Every gate must be accounted for."""
    _exact(execution, EXECUTION_KEYS, "admission-shape")
    gates = []
    refusal = None
    for number, name in GATES:
        if number not in gate_results:
            raise AdmissionError("accounting-gap")
        status, reason = gate_results[number]
        if status not in ("passed", "refused") or (status == "refused") != (reason is not None):
            raise AdmissionError("accounting-gap")
        if status == "refused" and refusal is None:
            refusal = reason
        gates.append({"gate": number, "name": name, "status": status, "refusal": reason})
    return {
        "schema": ADMISSION_SCHEMA_V1,
        "proposal_id": proposal["proposal_id"],
        "proposal_sha256": _digest(proposal_raw),
        "selection": proposal["selection"],
        "gates": gates,
        "execution": dict(execution),
        "decision": "refused" if refusal is not None else "admitted",
        "refusal": refusal,
        "non_claims": list(NON_CLAIMS_V1),
    }


def encode_admission(record: dict) -> bytes:
    """Encode a v0 or v1 record. The schema decides what the gates are allowed to say."""
    schema = record.get("schema")
    if schema == ADMISSION_SCHEMA:
        if record.get("decision") not in DECISIONS:
            raise AdmissionError("admission-shape")
        # Every execution gate must read not-run here, whatever a hand-built record claims.
        if any(gate["status"] != "not-run" for gate in record["gates"]
               if gate["gate"] in EXECUTION_GATES):
            raise AdmissionError("admission-shape")
        return ca._encode_class_artifact_v0(record)
    if schema != ADMISSION_SCHEMA_V1 or record.get("decision") not in DECISIONS_V1:
        raise AdmissionError("admission-shape")
    execution = record.get("execution")
    _exact(execution, EXECUTION_KEYS, "admission-shape")
    # A v1 record must have judged every execution gate: not-run belongs to v0.
    if any(gate["status"] not in ("passed", "refused") for gate in record["gates"]):
        raise AdmissionError("admission-shape")
    if record["decision"] == "admitted" and execution["route"] not in ADMITTING_ROUTES:
        raise AdmissionError("admission-shape")
    return ca._encode_class_artifact_v0(record)


def judge(proposal_path, *, corpus_dest, review=None, packet_author=None,
          root: Path = ROOT) -> dict:
    """Run the non-execution gates in order; the first refusal stops the later ones."""
    # A shape refusal raises: without a valid proposal there is nothing to record against.
    proposal, raw = load_proposal(proposal_path)
    results = {0: ("passed", None)}
    for number, step in (
        (1, lambda: check_freeze(proposal, root=root)),
        (2, lambda: build_proposal_corpus(proposal, corpus_dest, root=root)),
        (7, lambda: require_review(review, proposal, packet_author=packet_author)),
    ):
        if any(status == "refused" for status, _ in results.values()):
            results[number] = ("refused", "stopped-after-refusal")
            continue
        try:
            step()
            results[number] = ("passed", None)
        except AdmissionError as exc:
            results[number] = ("refused", str(exc))
    results[8] = ("passed", None)
    return admission_record(raw, proposal, results)


def account(proposal_ids, terminal_states: dict, *, baseline_covers_survivor: bool) -> dict:
    """Gate 8. Every proposal reaches exactly one terminal state; counts add up."""
    ids = list(proposal_ids)
    if len(ids) != len(set(ids)) or set(ids) != set(terminal_states):
        raise AdmissionError("accounting-gap")
    counts = {state: 0 for state in TERMINAL_STATES}
    for proposal_id in ids:
        state = terminal_states[proposal_id]
        base = state.split(":", 1)[0]
        if base not in TERMINAL_STATES or (base == "refused") != (":" in state):
            raise AdmissionError("accounting-gap")
        counts[base] += 1
    if sum(counts.values()) != len(ids):
        raise AdmissionError("accounting-gap")
    return {"proposals": len(ids), "counts": counts,
            "baseline_covers_survivor": bool(baseline_covers_survivor)}
