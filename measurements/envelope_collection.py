#!/usr/bin/env python3
"""One envelope record per attempted invocation, carried in a sibling collection.

`emit_envelope` refuses unless exactly one record exists, while a contained run can invoke the
backend more than once. Retaining only one record would hide another execution, so the attempts
are collected instead.

Contract:

- members are ordinary v0 records, built and validated by the shared `build_envelope_record` /
  `validate_envelope_record`. Member semantics are not reimplemented here;
- `publication_permission` stays the one derivation; this module only quantifies it universally;
- no summary record exists: a folded artifact would validate on its own and become an alternative
  to the members, so a deletion would stop being visible;
- an index digest binds bytes. It does not authenticate origin and cannot detect a byte-identical
  record from another run.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import effective_envelope as envelope

COLLECTION_SCHEMA = "corpus-adequacy.execution-envelope-collection.v0"
INDEX_FILENAME = "collection-index.v0.json"
MEMBER_TEMPLATE = "member-%04d.json"

# Ceilings. Anchored on the existing 5 MiB artifact budget rather than a new number, with an
# index reserve taken out first and an independent count cap, so whichever binds first wins.
MAX_INDEX_BYTES = 262144
MAX_MEMBER_BYTES = 65536
MAX_MEMBER_TOTAL_BYTES = 5242880 - MAX_INDEX_BYTES
MAX_COLLECTION_MEMBERS = 256

RECORDED = "recorded"
RAISED = "raised"
NO_ENVELOPE = "no-envelope"
LEDGER_STATES = (RECORDED, RAISED, NO_ENVELOPE)

INDEX_KEYS = ("attempts", "execution_commit", "ledger", "members", "non_claims",
              "prepare_sha256", "report_sha256", "schema")

NON_CLAIMS = (
    "States that these attempted invocations left these records in one collection run.",
    "Does not authenticate origin: a digest binds bytes, not who produced them.",
    "Cannot detect substitution of a byte-identical record from a different run.",
    "Not a score, not an audit, not a certification, and not publication authorization.",
)


class CollectionError(Exception):
    """Structural refusal. Member semantics remain the envelope validator's to judge."""


def member_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bounded_encoded_size(record: dict, limit: int) -> int:
    """Exact final size including the trailing newline, refused as soon as it passes `limit`.

    SCOPE, and it is narrower than "bounded allocation". `iterencode` avoids holding the whole
    document, so accumulated output is checked as it is produced and an over-large record is
    refused mid-encode. It does NOT bound a single value: the encoder yields an entire escaped
    string scalar as one chunk, so one huge string is materialized before this sees it. Bounding
    that needs per-scalar and per-collection limits, which are not implemented here and are not
    claimed.

    The `+ 1` is inside the check, not after it: `encode_envelope` appends a newline, so a record
    that fits only without it would otherwise pass here and write one byte over.
    """
    total = 1  # the trailing newline encode_envelope appends, counted from the start
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, sort_keys=True)
    for chunk in encoder.iterencode(record):
        total += len(chunk.encode("utf-8"))
        if total > limit:
            raise CollectionError("collection member byte ceiling")
    return total


def _encode_index(doc: dict) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


class Ledger:
    """Attempts registered BEFORE the candidate call, so a raised one still counts.

    A sink-side counter cannot do this: the sink runs after return, so it can never observe an
    invocation that raised. That is why `attempts` is never derived from emissions.
    """

    def __init__(self, *, max_members: int = MAX_COLLECTION_MEMBERS,
                 max_member_bytes: int = MAX_MEMBER_BYTES,
                 max_member_total_bytes: int = MAX_MEMBER_TOTAL_BYTES) -> None:
        self.max_members = int(max_members)
        self.max_member_bytes = int(max_member_bytes)
        self.max_member_total_bytes = int(max_member_total_bytes)
        self._states: list[str | None] = []
        self._records: dict[int, dict] = {}


    def register(self) -> int:
        """Admission gate, before the invocation: the count cap, the only bound knowable here.

        Bytes cannot be judged yet -- the record does not exist, and its written size is not
        fixed until the report digest is bound. That gate lives in `write_collection`.
        """
        if len(self._states) >= self.max_members:
            raise CollectionError("collection member count ceiling")
        self._states.append(None)
        return len(self._states) - 1

    def _settle(self, ordinal: int, state: str) -> None:
        if not isinstance(ordinal, int) or not 0 <= ordinal < len(self._states):
            raise CollectionError("unregistered ordinal")
        if self._states[ordinal] is not None:
            raise CollectionError("ordinal already settled")
        self._states[ordinal] = state

    def recorded(self, ordinal: int, record: dict) -> None:
        """Settle the attempt. Size is NOT judged here: the bytes that get written are the
        report-bound encoding, which does not exist until the report digest is known."""
        self._settle(ordinal, RECORDED)
        self._records[ordinal] = record

    def raised(self, ordinal: int, exception_type: str) -> None:
        """Type name only. An exception message can carry host content."""
        self._settle(ordinal, RAISED)
        self._records[ordinal] = {"exception_type": str(exception_type)}

    def no_envelope(self, ordinal: int) -> None:
        self._settle(ordinal, NO_ENVELOPE)

    @property
    def attempts(self) -> int:
        return len(self._states)

    def record(self, ordinal: int) -> dict:
        return self._records[ordinal]

    def entries(self):
        for ordinal, state in enumerate(self._states):
            yield ordinal, (state or NO_ENVELOPE), self._records.get(ordinal)


def write_collection(ledger: Ledger, dest, *, report_sha256) -> Path:
    """Encode, bound, then write. A refusal happens before its write, so earlier members survive."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    members = []
    ledger_rows = []
    pending = []
    total = 0
    prepare_sha256 = None
    execution_commit = None
    for ordinal, state, payload in ledger.entries():
        row = {"ordinal": ordinal, "state": state}
        if state == RAISED:
            row["exception_type"] = payload["exception_type"]
        ledger_rows.append(row)
        if state != RECORDED:
            continue
        # Every member carries the same report digest: uniform, not a first/last selection.
        # Binding ATTACHES the digest to the observation; it does not rebuild the record.
        # `bind_report` reconstructs from a record's inputs, which is exactly how
        # `validate_envelope_record` detects a contradiction -- it rebuilds and demands equality.
        # Writing that reconstruction would make it agree with the stored bytes by construction,
        # so the contradiction would be erased by the very mechanism meant to catch it, and a
        # malformed member would land on disk as an honestly-withheld one. The writer therefore
        # preserves what was observed and leaves the judging to the reader, which validates every
        # member. The added digest field is the one authorized change; no observed value moves.
        bound = dict(ledger.record(ordinal))
        bound["report_sha256"] = report_sha256
        # Preflight the FINAL encoding -- the bytes actually written. The unbound record is a
        # different, smaller string.
        size = bounded_encoded_size(bound, ledger.max_member_bytes)
        if total + size > ledger.max_member_total_bytes:
            raise CollectionError("collection aggregate byte ceiling")
        raw = envelope.encode_envelope(bound)
        relpath = MEMBER_TEMPLATE % ordinal
        pending.append((relpath, raw))
        total += len(raw)
        members.append({"ordinal": ordinal, "relpath": relpath,
                        "sha256": member_digest(raw)})
        prepare_sha256 = prepare_sha256 or payload["prepare_sha256"]
        execution_commit = execution_commit or payload["execution_commit"]
    index = {
        "attempts": ledger.attempts,
        "execution_commit": execution_commit,
        "ledger": ledger_rows,
        "members": members,
        "non_claims": list(NON_CLAIMS),
        "prepare_sha256": prepare_sha256,
        "report_sha256": report_sha256,
        "schema": COLLECTION_SCHEMA,
    }
    raw_index = _encode_index(index)
    # Staged: the index is bounded before any member is written, so an index-size refusal
    # leaves no partial collection.
    if len(raw_index) > MAX_INDEX_BYTES:
        raise CollectionError("collection index byte ceiling")
    for relpath, raw in pending:
        (dest / relpath).write_bytes(raw)
    (dest / INDEX_FILENAME).write_bytes(raw_index)
    return dest / INDEX_FILENAME


def _require_exact(doc, keys, where):
    if type(doc) is not dict:
        raise CollectionError("%s must be an object" % where)
    if set(doc) != set(keys):
        raise CollectionError("%s exact keys missing=%s unknown=%s" % (
            where, sorted(set(keys) - set(doc)), sorted(set(doc) - set(keys))))


def load_collection(dest, *, max_index_bytes: int = MAX_INDEX_BYTES,
                    max_member_bytes: int = MAX_MEMBER_BYTES,
                    max_members: int = MAX_COLLECTION_MEMBERS) -> dict:
    """Structural integrity first, then member semantics. No singleton fallback exists here."""
    dest = Path(dest)
    index_path = dest / INDEX_FILENAME
    if not index_path.is_file():
        raise CollectionError("collection index absent")
    if index_path.stat().st_size > max_index_bytes:
        raise CollectionError("collection index byte ceiling")
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
    # ValueError, not JSONDecodeError: an integer literal past CPython's digit limit raises a
    # bare ValueError, and a narrower clause lets it escape unmapped -- the #116 F1 defect.
    except (UnicodeError, ValueError) as exc:
        raise CollectionError("collection index json") from exc
    _require_exact(index, INDEX_KEYS, "collection index")
    if index["schema"] != COLLECTION_SCHEMA:
        raise CollectionError("collection index schema")

    rows = index["ledger"]
    if type(rows) is not list or len(rows) != index["attempts"]:
        raise CollectionError("collection attempts do not match the ledger")
    # The attempt ceiling is independent of how many attempts emitted a record.
    if not isinstance(index["attempts"], int) or index["attempts"] > max_members:
        raise CollectionError("collection attempt count ceiling")
    for position, row in enumerate(rows):
        if type(row) is not dict or row.get("ordinal") != position:
            raise CollectionError("collection ledger ordinals are not contiguous")
        if row.get("state") not in LEDGER_STATES:
            raise CollectionError("collection ledger state")

    recorded = [row["ordinal"] for row in rows if row["state"] == RECORDED]
    entries = index["members"]
    if type(entries) is not list or len(entries) > max_members:
        raise CollectionError("collection member count ceiling")
    # Keyed to RECORDED, not to attempts: a raised attempt must still load so it can be reported.
    if [e.get("ordinal") for e in entries] != recorded:
        raise CollectionError("collection members do not match the recorded attempts")

    claimed_report = index["report_sha256"]
    if claimed_report is not None and (
            not isinstance(claimed_report, str) or len(claimed_report) != 64 or
            any(ch not in "0123456789abcdef" for ch in claimed_report)):
        raise CollectionError("collection index report digest")

    referenced = set()
    members = []
    for entry in entries:
        relpath = entry.get("relpath")
        if relpath != MEMBER_TEMPLATE % entry["ordinal"]:
            raise CollectionError("collection member relpath")
        path = dest / relpath
        if not path.is_file():
            raise CollectionError("collection member absent")
        if path.stat().st_size > max_member_bytes:
            raise CollectionError("collection member byte ceiling")
        raw = path.read_bytes()
        if member_digest(raw) != entry.get("sha256"):
            raise CollectionError("collection member digest")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise CollectionError("collection member json") from exc
        # The shared validator judges the record. A matching digest is not semantic validation.
        try:
            envelope.validate_envelope_record(doc)
        except envelope.EnvelopeError as exc:
            raise CollectionError("collection member semantics") from exc
        # The index's report claim is checked against every member, not trusted.
        if doc.get("report_sha256") != claimed_report:
            raise CollectionError("collection member report digest")
        referenced.add(relpath)
        members.append(doc)

    on_disk = {p.name for p in dest.iterdir() if p.name != INDEX_FILENAME}
    if on_disk - referenced:
        raise CollectionError("collection carries an unreferenced member")
    return {"index": index, "ledger": rows, "members": members}


def withheld_reason(loaded: dict):
    """The first reason publication is withheld, or None. Diagnostic states stay distinct."""
    for row in loaded.get("ledger", []):
        if row.get("state") == RAISED:
            return "attempt_raised"
        if row.get("state") == NO_ENVELOPE:
            return "attempt_left_no_envelope"
    members = loaded.get("members", [])
    if not members:
        return "no_attempt_recorded"
    for member in members:
        if member.get("publication_permission") != "permitted":
            return "member_withheld"
        if member.get("envelope_status") != "verified":
            return "member_unverified"
    return None


def collection_permission(loaded: dict) -> str:
    """Permitted only if EVERY observation permits. A later pass cannot rescue an earlier one."""
    return "withheld" if withheld_reason(loaded) is not None else "permitted"
