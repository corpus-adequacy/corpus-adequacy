#!/usr/bin/env python3
"""One envelope record per attempted invocation, carried in a sibling collection.

`emit_envelope` refuses unless exactly one record exists, while a contained run can invoke the
backend more than once. Retaining only one record would hide another execution, so the attempts
are collected instead.

What this module does NOT do, deliberately:

- it does not touch the frozen single-envelope v0 record. Every member IS one, built by
  `build_envelope_record` and validated by `validate_envelope_record`, which stay shared and
  unchanged. Member validation is not reimplemented here;
- it does not restate the permission rule. `publication_permission` remains the one derivation;
  this module only quantifies it over the members;
- it does not summarise. There is no folded record, because a derived artifact that validates on
  its own becomes an alternative to the evidence it derives from, and deleting a member would
  stop being visible;
- it does not promise provenance. An index digest binds bytes; it does not authenticate origin,
  and it cannot detect a byte-identical record produced by a different run.
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
        self._encoded: dict[int, bytes] = {}
        self._bytes = 0

    def register(self) -> int:
        """Admission gate, run BEFORE the invocation. Count, and capacity actually left.

        It cannot check this record's size: the record does not exist yet. It checks the two
        things that are knowable — the count cap, and whether the budget already consumed by
        settled members leaves any room at all. Reserving a full per-member ceiling here would
        make the later aggregate gate unreachable, which is how a bound stops being a bound.
        """
        if len(self._states) >= self.max_members:
            raise CollectionError("collection member count ceiling")
        if self._bytes >= self.max_member_total_bytes:
            raise CollectionError("collection aggregate byte ceiling")
        self._states.append(None)
        return len(self._states) - 1

    def _settle(self, ordinal: int, state: str) -> None:
        if not isinstance(ordinal, int) or not 0 <= ordinal < len(self._states):
            raise CollectionError("unregistered ordinal")
        if self._states[ordinal] is not None:
            raise CollectionError("ordinal already settled")
        self._states[ordinal] = state

    def recorded(self, ordinal: int, record: dict) -> None:
        """Size gate, run at settle time -- the earliest point the size is knowable.

        HONEST SCOPE, corrected after a coordinator probe: this is a **pre-write** size check on
        an already-materialized encoding, NOT bounded serialization. `encode_envelope` runs
        `json.dumps` over the whole record and returns the finished bytes; `len` is taken after
        that. Nothing here streams or truncates, and an earlier version of this docstring claimed
        otherwise.
        
        What actually bounds the allocation is upstream and structural: the record comes from
        `build_envelope_record`, whose shape is fixed by `ENVELOPE_KEYS` and whose variable parts
        (`env_names`, `image_env_names`, `mounts`, `tmpfs`) are themselves bounded by the
        container the run declared. That is a real bound, but it is not enforced here and is not
        claimed as one. Probing the true upstream ceiling would mean allocating a huge record on
        purpose, which is not worth doing to measure it.
        """
        self._settle(ordinal, RECORDED)
        raw = envelope.encode_envelope(envelope.bind_report(record, None))
        if len(raw) > self.max_member_bytes:
            self._states[ordinal] = None
            raise CollectionError("collection member byte ceiling")
        if self._bytes + len(raw) > self.max_member_total_bytes:
            self._states[ordinal] = None
            raise CollectionError("collection aggregate byte ceiling")
        self._bytes += len(raw)
        self._records[ordinal] = record
        self._encoded[ordinal] = raw

    def raised(self, ordinal: int, exception_type: str) -> None:
        """Type name only. An exception message can carry host content."""
        self._settle(ordinal, RAISED)
        self._records[ordinal] = {"exception_type": str(exception_type)}

    def no_envelope(self, ordinal: int) -> None:
        self._settle(ordinal, NO_ENVELOPE)

    @property
    def attempts(self) -> int:
        return len(self._states)

    def encoded(self, ordinal: int) -> bytes:
        return self._encoded[ordinal]

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
        # Bind through the SHARED function. The report is the product of the whole collection,
        # so every member carries the same digest: uniform, and therefore not the first/last
        # selection that binding it to one member would be.
        raw = envelope.encode_envelope(
            envelope.bind_report(ledger.record(ordinal), report_sha256))
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
    # Staged deliberately: the index is bounded BEFORE any member is written, so an index-size
    # refusal leaves no partial collection behind. An earlier version wrote members first and
    # then claimed that property it did not have.
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
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CollectionError("collection index json") from exc
    _require_exact(index, INDEX_KEYS, "collection index")
    if index["schema"] != COLLECTION_SCHEMA:
        raise CollectionError("collection index schema")

    rows = index["ledger"]
    if type(rows) is not list or len(rows) != index["attempts"]:
        raise CollectionError("collection attempts do not match the ledger")
    # The ATTEMPT ceiling is independent of how many attempts emitted a record. Checking only
    # `members` let 257 no-envelope attempts through a cap of 256: withheld, so never a false
    # publish, but a resource contract that did not hold on input.
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
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise CollectionError("collection member json") from exc
        # The shared validator judges the record. A matching digest is not semantic validation.
        try:
            envelope.validate_envelope_record(doc)
        except envelope.EnvelopeError as exc:
            raise CollectionError("collection member semantics") from exc
        # The index's report claim is checked against every member, not trusted. Leaving it
        # unchecked made the index an assertion nothing verified.
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
