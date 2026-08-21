#!/usr/bin/env python3
"""Adapt one pinned AlgoVoi jcs_edge_v1 anchor set for the process runner.

    python3 adapters/algovoi_jcs_edge.py <jcs_edge_v1.json> <empty-dest>

This is a format-specific adapter for exactly one pinned file, not a generic
JCS parser and not a scorer. It copies each source row's `preimage` value as
raw bytes so a numeric lexeme survives: `1.0` and `1` stay distinct, which a
parse-and-re-serialize implementation cannot guarantee.

The copy is a byte slice located by one scanner rule. The document is parsed
once for metadata through the same strict parser the projection uses, but the
parsed value never becomes case bytes.

This is not authenticity, endorsement, complete RFC 8785 coverage, correctness
of the authored section labels, correctness of the upstream reference
implementation, or adequacy of any implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402
import isolated_tree as iso  # noqa: E402

SOURCE_SCHEMA = "corpus-adequacy.algovoi-jcs-edge.source.v0"
PIN_REPOSITORY = "chopmob-cloud/algovoi-jcs-conformance-vectors"
PIN_COMMIT = "aa53149c670f1659dad511755168ad5231dc04de"
PIN_ANCHOR_PATH = "vectors/jcs_edge_v1/jcs_edge_v1.json"
PIN_SHA256 = "a8a1a1a8839553ea5309c381b39ba156e6b6a23a5a3e6aab59b53940cc386033"
PIN_SIZE_BYTES = 7622
PIN_LICENSE = "Apache-2.0"
PIN_MANIFEST_VERSION = "0.38.0"
PIN_CANON_VERSION = "jcs-rfc8785-v1"
PIN_SET_NAME = "jcs_edge_v1"
PIN_VECTOR_COUNT = 10
PIN_INVARIANT_COUNT = 2

# The anchor is 7,622 bytes. The ceiling is applied by fstat before any parse
# or scan, so an oversized substitute is refused without being materialized.
SOURCE_CAP_BYTES = 1 << 20

DOCUMENT_KEYS = frozenset({
    "name", "license", "copyright", "spec", "spec_authorship",
    "canon_version", "reference_impl", "vectors", "pair_invariants",
})
VECTOR_KEYS = frozenset({
    "vector_id", "description", "rfc8785_section", "expectation", "preimage",
    "expected_jcs_bytes_b64", "expected_sha256", "receipt",
    "expected_content_hash",
})
# `equal_sha256` names two vectors as `a`/`b`. Any other well-formed relation
# is refused with its own arity, so a single-vector relation is well formed
# and still not evaluated here.
INVARIANT_PAIR_KEYS = frozenset({"name", "a", "b", "relation", "why"})
INVARIANT_SINGLE_KEYS = frozenset({"name", "vector", "relation", "why"})
EVALUABLE_RELATION = "equal_sha256"
REFUSAL_REASON = "not mechanically evaluable by this adapter"

SHA256_HEX_LENGTH = 64


class AdapterError(Exception):
    """The pinned source cannot be adapted."""


def _wrap(exc: BaseException) -> AdapterError:
    return AdapterError(str(exc))


def _load_source_bytes(path: Path) -> bytes:
    """One bounded, no-follow regular-file read before any parse or scan."""
    try:
        return ca.read_bounded_regular_file(path, cap=SOURCE_CAP_BYTES)
    except ca.ManifestError as exc:
        raise _wrap(exc) from exc


def _parse_strict(raw: bytes):
    """One strict parse: UTF-8, no duplicate keys, no non-finite constants."""
    try:
        return ca._parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError) as exc:
        raise _wrap(exc) from exc


def _encode(doc: dict) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def _require_exact_keys(obj, allowed: frozenset, where: str) -> dict:
    if not isinstance(obj, dict):
        raise AdapterError("%s is not an object" % where)
    keys = frozenset(obj)
    unknown = sorted(keys - allowed)
    if unknown:
        raise AdapterError("%s has unknown fields: %s" % (where, ", ".join(unknown)))
    missing = sorted(allowed - keys)
    if missing:
        raise AdapterError("%s is missing fields: %s" % (where, ", ".join(missing)))
    return obj


def _require_sha256_hex(value, where: str) -> str:
    if not isinstance(value, str) or len(value) != SHA256_HEX_LENGTH:
        raise AdapterError("%s is not a 64-character hex digest" % where)
    if any(c not in "0123456789abcdef" for c in value):
        raise AdapterError("%s is not lowercase hex" % where)
    return value


def _require_safe_vector_id(vector_id, where: str) -> str:
    if not isinstance(vector_id, str) or not vector_id:
        raise AdapterError("%s is not a non-empty string" % where)
    if vector_id != Path(vector_id).name:
        raise AdapterError("%s is not a single basename: %r" % (where, vector_id))
    for bad in ("/", "\\", "\x00", ":"):
        if bad in vector_id:
            raise AdapterError("%s contains an unsafe path character: %r"
                               % (where, vector_id))
    if vector_id in (".", ".."):
        raise AdapterError("%s is a relative path element: %r" % (where, vector_id))
    return vector_id


def _scandir_names(directory: Path) -> list[str]:
    try:
        entries = os.scandir(directory)
    except OSError as exc:
        raise AdapterError("could not read %s: %s" % (directory, exc)) from exc
    with entries:
        return [entry.name for entry in entries]


def _require_empty_dest(dest: Path) -> None:
    try:
        st = dest.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        raise AdapterError("destination is a symlink: %s" % dest)
    if not stat.S_ISDIR(st.st_mode):
        raise AdapterError("destination is not a directory: %s" % dest)
    if _scandir_names(dest):
        raise AdapterError("destination is not empty: %s" % dest)


def raw_preimage_slices(raw: bytes) -> list[bytes]:
    """Locate every `preimage` value as an exact byte slice of the source.

    One rule, applied in document order: find the next `"preimage"` token that
    is a mapping key, then let the JSON decoder report where that value ends.
    The decoder is used only to find the span; the decoded object is discarded
    and never re-serialized, so the source spelling of a number survives.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AdapterError("source is not UTF-8") from None
    decoder = json.JSONDecoder()
    token = '"preimage"'
    slices: list[bytes] = []
    cursor = 0
    while True:
        start = text.find(token, cursor)
        if start == -1:
            return slices
        cursor = start + len(token)
        after = cursor
        while after < len(text) and text[after] in " \t\r\n":
            after += 1
        if after >= len(text) or text[after] != ":":
            # `"preimage"` appeared as a value or inside prose, not as a key.
            continue
        after += 1
        while after < len(text) and text[after] in " \t\r\n":
            after += 1
        try:
            _, end = decoder.raw_decode(text, after)
        except ValueError as exc:
            raise AdapterError("preimage value at offset %d is not JSON: %s"
                               % (after, exc)) from exc
        slices.append(text[after:end].encode("utf-8"))
        cursor = end


def _vector_rows(document: dict) -> list[dict]:
    vectors = document["vectors"]
    if not isinstance(vectors, list):
        raise AdapterError("vectors is not a list")
    if len(vectors) != PIN_VECTOR_COUNT:
        raise AdapterError("expected %d vectors, found %d"
                           % (PIN_VECTOR_COUNT, len(vectors)))
    rows = []
    seen: set[str] = set()
    for index, vector in enumerate(vectors):
        where = "vectors[%d]" % index
        _require_exact_keys(vector, VECTOR_KEYS, where)
        vector_id = _require_safe_vector_id(vector["vector_id"], where + ".vector_id")
        if vector_id in seen:
            raise AdapterError("duplicate vector_id: %s" % vector_id)
        seen.add(vector_id)
        _require_sha256_hex(vector["expected_sha256"], where + ".expected_sha256")
        section = vector["rfc8785_section"]
        if not isinstance(section, str) or not section:
            raise AdapterError("%s.rfc8785_section is not a non-empty string" % where)
        rows.append({
            "vector_id": vector_id,
            "vector_path": "cases/%s.json" % vector_id,
            "authored_section": section,
        })
    return rows


def _invariant_disposition(document: dict, by_id: dict) -> list[dict]:
    """Account for every declared invariant exactly once.

    `equal_sha256` is evaluated against the two declared digests. Any other
    well-formed relation is typed `refused`, never skipped and never passed.
    """
    invariants = document["pair_invariants"]
    if not isinstance(invariants, list):
        raise AdapterError("pair_invariants is not a list")
    if len(invariants) != PIN_INVARIANT_COUNT:
        raise AdapterError("expected %d pair invariants, found %d"
                           % (PIN_INVARIANT_COUNT, len(invariants)))
    disposition = []
    names: set[str] = set()
    for index, entry in enumerate(invariants):
        where = "pair_invariants[%d]" % index
        if not isinstance(entry, dict):
            raise AdapterError("%s is not an object" % where)
        if "a" in entry or "b" in entry:
            _require_exact_keys(entry, INVARIANT_PAIR_KEYS, where)
            referenced = [entry["a"], entry["b"]]
        else:
            _require_exact_keys(entry, INVARIANT_SINGLE_KEYS, where)
            referenced = [entry["vector"]]
        name = entry["name"]
        if not isinstance(name, str) or not name:
            raise AdapterError("%s.name is not a non-empty string" % where)
        if name in names:
            raise AdapterError("duplicate invariant name: %s" % name)
        names.add(name)
        relation = entry["relation"]
        if not isinstance(relation, str) or not relation:
            raise AdapterError("%s.relation is not a non-empty string" % where)
        for reference in referenced:
            if not isinstance(reference, str) or reference not in by_id:
                raise AdapterError("%s references unknown vector %r"
                                   % (where, reference))
        if relation == EVALUABLE_RELATION:
            left, right = (by_id[r]["expected_sha256"] for r in referenced)
            if left != right:
                raise AdapterError(
                    "%s declares %s but the two declared digests differ"
                    % (where, EVALUABLE_RELATION))
            disposition.append({
                "name": name,
                "relation": relation,
                "vectors": list(referenced),
                "disposition": "projected",
                "declared_sha256": left,
            })
        else:
            disposition.append({
                "name": name,
                "relation": relation,
                "vectors": list(referenced),
                "disposition": "refused",
                "reason": REFUSAL_REASON,
            })
    return disposition


def adapt(source: Path, dest: Path) -> None:
    source = Path(source)
    dest = Path(dest)
    _require_empty_dest(dest)

    raw = _load_source_bytes(source)
    if len(raw) != PIN_SIZE_BYTES:
        raise AdapterError("source is %d bytes; the pinned anchor is %d"
                           % (len(raw), PIN_SIZE_BYTES))
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PIN_SHA256:
        raise AdapterError("source digest %s does not match the pin %s"
                           % (digest, PIN_SHA256))

    document = _parse_strict(raw)
    _require_exact_keys(document, DOCUMENT_KEYS, "document")
    if document["name"] != PIN_SET_NAME:
        raise AdapterError("anchor set name %r does not match the pin %r"
                           % (document["name"], PIN_SET_NAME))
    if document["canon_version"] != PIN_CANON_VERSION:
        raise AdapterError("canon_version %r does not match the pin %r"
                           % (document["canon_version"], PIN_CANON_VERSION))
    if document["license"] != PIN_LICENSE:
        raise AdapterError("license %r does not match the pin %r"
                           % (document["license"], PIN_LICENSE))

    rows = _vector_rows(document)
    by_id = {v["vector_id"]: v for v in document["vectors"]}

    slices = raw_preimage_slices(raw)
    if len(slices) != len(rows):
        raise AdapterError(
            "found %d raw preimage values for %d vectors; refusing to guess"
            % (len(slices), len(rows)))

    disposition = _invariant_disposition(document, by_id)
    sections = sorted({row["authored_section"] for row in rows})

    source_doc = {
        "schema": SOURCE_SCHEMA,
        "repository": PIN_REPOSITORY,
        "commit": PIN_COMMIT,
        "anchor_path": PIN_ANCHOR_PATH,
        "anchor_sha256": digest,
        "anchor_size_bytes": len(raw),
        "manifest_version": PIN_MANIFEST_VERSION,
        "canon_version": document["canon_version"],
        "set_name": document["name"],
        "license": document["license"],
        "copyright": document["copyright"],
        "reference_impl": document["reference_impl"],
        "authored_sections": sections,
        "vector_count": len(rows),
        "pair_invariants": disposition,
        "non_claims": [
            "This adapter preserves and addresses one upstream anchor set.",
            "It does not establish authenticity, endorsement, or complete "
            "RFC 8785 coverage.",
            "It does not establish correctness of the authored section labels "
            "or of the upstream reference implementation.",
            "It does not establish adequacy of any implementation.",
            "An authored section label is source metadata, not a rule "
            "inventory.",
        ],
    }

    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix="algovoi-adapt-", dir=str(dest.parent)))
    try:
        cases = temp / "cases"
        cases.mkdir()
        for row, preimage in zip(rows, slices):
            out = cases / ("%s.json" % row["vector_id"])
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_BINARY"):
                flags |= os.O_BINARY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            fd = os.open(out, flags, 0o600)
            try:
                iso.write_all(fd, preimage + b"\n")
            except iso.IsolationError as exc:
                raise AdapterError(str(exc)) from exc
            finally:
                os.close(fd)
        (temp / "vectors.json").write_bytes(_encode({"vectors": rows}))
        (temp / "source.json").write_bytes(_encode(source_doc))
        if dest.exists():
            dest.rmdir()
        os.replace(temp, dest)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("source", type=Path)
    ap.add_argument("dest", type=Path)
    args = ap.parse_args()
    try:
        adapt(args.source, args.dest)
    except (AdapterError, ca.ManifestError, OSError, json.JSONDecodeError) as exc:
        print("could not adapt: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
