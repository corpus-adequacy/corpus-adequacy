#!/usr/bin/env python3
"""Render a no-JS static overview and detail pages from one publication load."""

from __future__ import annotations

import argparse
import json
import hashlib
import html
import os
import stat
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import corpus_adequacy as ca  # noqa: E402
from corpus_adequacy import (  # noqa: E402
    _parse_projection_json,
    _require_report_rows,
    read_bounded_regular_file,
    survivor_findings,
)

INDEX_REL = "publications/index.v0.json"
INDEX_SCHEMA = "corpus-adequacy.publication-index.v0"
INDEX_KEYS = frozenset({"schema", "records"})
ATTEMPT_INDEX_REL = "publications/run-attempts/index.v0.json"
ATTEMPT_INDEX_SCHEMA = "corpus-adequacy.run-attempt-index.v0"
ATTEMPT_INDEX_KEYS = frozenset({"schema", "attempts"})
CLASS_INDEX_REL = "publications/class-comparisons/index.v0.json"
CLASS_INDEX_SCHEMA = "corpus-adequacy.class-comparison-index.v0"
CLASS_INDEX_KEYS = frozenset({"schema", "comparisons"})
# Every byte a comparison page relies on is listed by digest. The declared side has no class
# artifacts: its mutants are the corpus author's own declaration.
CLASS_ENTRY_FILES = {
    "declared_report_sha256": "declared/report.v0.json",
    "declared_prepare_sha256": "declared/prepare.v2.json",
    "independent_report_sha256": "independent/report.v0.json",
    "independent_prepare_sha256": "independent/prepare.v2.json",
    "independent_provenance_sha256": "independent/class-provenance.v0.json",
    "independent_attempt_sha256": "independent/class-attempt.v0.json",
}
CLASS_ENTRY_KEYS = frozenset({"id", "evidence"}) | frozenset(CLASS_ENTRY_FILES)
CLASS_PAGE_PREFIX = "classes"
CLASS_NON_CLAIMS = (
    "Two evidence classes, two denominators. They are never added together, and neither is a "
    "population estimate.",
    "A declared set that kills every mutant shows its own mutants are distinguished. It does not "
    "show the rule set is complete. The independent column is one probe of that, not a proof.",
    "Authorship names are recorded as written and are not authenticated.",
    "Local contained evidence, not hosted containment proof. A survivor is bounded to this "
    "selection, corpus, projection, environment and host.",
)
RAW_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/raw"
BLOB_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/blob"
ISSUES_INTAKE = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=add-corpus.yml"
ISSUES_PUBLISH = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml"
# VERSION names the checkout being prepared. This names the last release whose
# tag and GitHub Release are already addressable; advance it only after publish.
PUBLISHED_RELEASE_VERSION = "0.2.0"
HEX64 = set("0123456789abcdef")
DISPLAY_VERDICTS = ("killed", "survived", "silent", "unproved")
NO_LOCAL_REPRODUCTION_COMMAND = (
    "No local reproduction command is published for this measurement."
)
KIND_VOID_RUN_ATTEMPT = "void-run-attempt"
KIND_COMPLETED_MEASUREMENT = "completed-measurement"
VOID_RENDER_REFUSAL = "void run attempt cannot enter the measurement renderer"
ATTEMPT_SCHEMA = "corpus-adequacy.run-attempt.v0"
ATTEMPT_REL_PREFIX = "publications/run-attempts"
ATTEMPT_REQUIRED = (
    "schema",
    "kind",
    "raw_report_sha256",
    "execution_commit",
    "prepare_sha256",
    "authorize_sha256",
    "baseline_status",
    "control_status",
    "mutant_status",
    "score_status",
    "failures",
)
HOST_MARKERS = (
    "/Users/", "/home/", "/private/tmp/", "/private/var/", "/var/folders/",
    "/tmp/", "C:/", "C:\\",
)
VOID_NON_CLAIMS = (
    "A void-attempt page does not validate the corpus, checker, execution "
    "environment, control, mutants, or adequacy.",
    "It is an auditable record that a bounded authorized attempt occurred "
    "and failed closed.",
    "This is an attempt/void result, not a measurement or score.",
    "PREPARE, AUTHORIZE, and raw-report source artifact bytes are not "
    "publicly retained or recomputed here.",
)


def published_local_command(report_path: Path):
    """Return the copyable argv only for a regular sibling manifest.json.

    Uses lstat + S_ISREG. Does not follow the path or read its bytes. A hit
    proves only that the displayed argv names that sibling, not that it
    succeeds or reproduces sealed execution.
    """
    sibling = Path(report_path).parent / "manifest.json"
    try:
        mode = os.lstat(sibling).st_mode
    except OSError:
        return None
    if not stat.S_ISREG(mode):
        return None
    directory = Path(report_path).parent.name
    return (
        "python3 corpus_adequacy.py measurements/%s/manifest.json --json"
        % directory
    )


def _card_command_html(record: dict) -> str:
    command = record.get("command")
    if command is None:
        return "<p>%s</p>\n" % _esc(NO_LOCAL_REPRODUCTION_COMMAND)
    return (
        "<p>Copyable command</p>\n"
        "<pre><code>%s</code></pre>\n" % _esc(command)
    )


CEILING_LINES = (
    "not a leaderboard/badge/certification/trust score/automatic admission/completeness of declared inventory",
    "not authenticity/endorsement/implementation safety",
    'silent:0 without diagnostic_channel_declared is not "no silent rules"',
    "score_percent is percent of author-declared in-scope rules, not of the implementation",
)
DOSSIER_NON_CLAIMS = (
    "Rule linkage is author-declared traceability at one pin; it does not prove normative completeness, formal compliance, or engine correctness.",
    "An anchor is an author-declared source excerpt at one pin; it does not prove reachability or execution flow.",
    "An unavailable manifest is unavailable evidence, not an empty or compliant rule set.",
    "A manifest digest mismatch leaves rule and anchor evidence unavailable; report observations remain unaltered.",
)
SHARED_STYLE = """
:root { color-scheme: light; }
html, body { max-width: 100%; overflow-x: hidden; margin: 0; }
body { font-family: system-ui, sans-serif; line-height: 1.45; color: #1a1a1a; background: #f7f5f0; padding: 1rem; }
a:focus, button:focus, .skip:focus { outline: 3px solid #0033aa; outline-offset: 2px; }
.skip { position: absolute; left: -999px; top: 0; background: #fff; padding: 0.5rem; }
.skip:focus { left: 1rem; z-index: 2; }
h1, h2, h3 { line-height: 1.2; }
.non-claims { max-width: 46rem; }
.ctas { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0 1.5rem; }
.ctas a { display: inline-block; padding: 0.5rem 0.75rem; background: #0033aa; color: #fff; text-decoration: underline; }
.cards { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 1rem; }
.card { box-sizing: border-box; width: min(100%, 390px); max-width: 100%; background: #fff; border: 2px solid #1a1a1a; padding: 1rem; }
.counts { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem; }
.count { border: 1px solid #333; padding: 0.35rem 0.5rem; min-width: 5rem; }
.count-label { display: block; font-size: 0.8rem; }
.mono, pre { overflow-wrap: anywhere; word-break: break-word; }
pre { background: #eee; padding: 0.5rem; user-select: text; white-space: pre-wrap; }
.links a { margin-right: 0.75rem; overflow-wrap: anywhere; }
.finding { box-sizing: border-box; width: min(100%, 390px); max-width: 100%; background: #fff; border: 2px solid #1a1a1a; padding: 1rem; }
"""


class PublicationError(ValueError):
    """Fail-closed publication load or check error."""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _has_ascii_drive_root(value: str) -> bool:
    """True when value contains an ASCII Windows drive root such as D:/ or D:\\."""
    for index in range(len(value) - 2):
        letter = value[index]
        if not letter.isascii() or not letter.isalpha():
            continue
        if value[index + 1] == ":" and value[index + 2] in "/\\":
            return True
    return False


def _require_portable_public_text(value: str, *, field: str) -> str:
    """Refuse host markers or absolute local paths before a record is public."""
    if not isinstance(value, str) or not value:
        raise PublicationError("%s must be a non-empty string" % field)
    if any(marker in value for marker in HOST_MARKERS):
        raise PublicationError("%s contains a host-local path" % field)
    if _has_ascii_drive_root(value):
        raise PublicationError("%s contains a host-local path" % field)
    if value.startswith("/") or value.startswith("\\") or ":\\" in value:
        raise PublicationError("%s contains an absolute local path" % field)
    return value


def is_void_run_attempt(doc) -> bool:
    """Typed void discriminator from issue #80 report.v0 signals only."""
    if not isinstance(doc, dict) or doc.get("schema") != "corpus-adequacy.report.v0":
        return False
    if doc.get("score_percent") is not None:
        return False
    mutants = doc.get("mutants")
    if not isinstance(mutants, list) or mutants:
        return False
    if doc.get("control_status") != "absent-or-invalid":
        return False
    failures = doc.get("failures")
    if not isinstance(failures, list) or not failures:
        return False
    return any(
        isinstance(item, str)
        and "UNMUTATED" in item
        and "unproved" in item.lower()
        for item in failures
    )


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _looks_like_repo(value: str) -> bool:
    if not isinstance(value, str) or value.count("/") != 1:
        return False
    owner, name = value.split("/", 1)
    if not owner or len(owner) > 39 or owner[0] == "-" or owner[-1] == "-":
        return False
    owner_ok = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    if set(owner) - owner_ok:
        return False
    if not name or len(name) > 100 or name in (".", ".."):
        return False
    name_ok = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if set(name) - name_ok:
        return False
    return True


def _looks_like_commit(value: str) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def _require_source_shape(source) -> tuple[str, str]:
    repository = source.get("repository") if isinstance(source, dict) else None
    commit = source.get("commit") if isinstance(source, dict) else None
    if not _looks_like_repo(repository):
        raise PublicationError("source repository is not owner/name")
    if not _looks_like_commit(commit):
        raise PublicationError("source commit is not a 40-hex digest")
    return repository, commit


def _require_hex64(value, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - HEX64:
        raise PublicationError("%s is not a 64-hex digest" % field)
    return value


def _require_record_id(value) -> str:
    if not isinstance(value, str) or not value:
        raise PublicationError("index record id is missing")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    if set(value) - allowed or value in (".", ".."):
        raise PublicationError("index record id is not a measurement directory name")
    return value


def _adapter_name(source: dict, record_id: str) -> str:
    schema = source.get("schema") if isinstance(source, dict) else None
    if isinstance(schema, str) and "tersign-evidence-record" in schema:
        return "tersign_evidence_record"
    if isinstance(schema, str) and schema.startswith("corpus-adequacy.") and schema.endswith(".source.v0"):
        mid = schema[len("corpus-adequacy.") : -len(".source.v0")]
        if mid:
            return mid.replace("-", "_")
    return record_id


def _counts_from_mutants(mutants: list) -> dict:
    counts = {name: 0 for name in DISPLAY_VERDICTS}
    for row in mutants:
        verdict = row.get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _control_status_from_rows(mutants: list) -> str:
    statuses = []
    for row in mutants:
        verdict = row.get("verdict")
        if not isinstance(verdict, str) or not verdict.startswith("control-"):
            continue
        rest = verdict[len("control-") :].lower()
        statuses.append(rest)
    if "error" in statuses:
        return "error"
    if not statuses:
        return "absent-or-invalid"
    if "survived" in statuses:
        return "survived"
    return "killed"


def _require_displayed_parity(doc: dict, mutants: list) -> None:
    derived = _counts_from_mutants(mutants)
    for name in DISPLAY_VERDICTS:
        value = doc.get(name)
        if type(value) is not int:
            raise PublicationError(
                "displayed %s must be an int, got %s"
                % (name, type(value).__name__)
            )
        if value != derived[name]:
            raise PublicationError(
                "displayed %s %r does not match mutants[] count %r"
                % (name, value, derived[name])
            )
    derived_control = _control_status_from_rows(mutants)
    if doc.get("control_status") != derived_control:
        raise PublicationError(
            "control_status %r does not match control rows %r"
            % (doc.get("control_status"), derived_control)
        )


def _diagnostic_channel_declared(doc: dict) -> bool:
    value = doc["diagnostic_channel_declared"]
    if type(value) is not bool:
        raise PublicationError(
            "diagnostic_channel_declared must be a bool, got %s"
            % type(value).__name__
        )
    return value


def _load_json_object(path: Path, *, label: str) -> tuple[bytes, dict]:
    try:
        raw = read_bounded_regular_file(path)
        doc = _parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError) as exc:
        raise PublicationError("%s: %s" % (label, exc)) from exc
    if not isinstance(doc, dict):
        raise PublicationError("%s is not a JSON object" % label)
    return raw, doc


def _load_manifest_snapshot(report_path: Path, expected_digest: str) -> dict:
    """Read at most one bounded manifest snapshot and classify its evidence state."""
    path = report_path.parent / "manifest.json"
    try:
        raw = read_bounded_regular_file(path)
    except ca.ManifestError as exc:
        try:
            os.lstat(path)
        except FileNotFoundError:
            return {
                "state": "absent",
                "reason": "manifest absent",
                "projection_bytes": b"manifest-unavailable:absent",
                "object": None,
            }
        except OSError:
            pass
        return {
            "state": "unavailable",
            "reason": "manifest unavailable",
            "projection_bytes": b"manifest-unavailable:unavailable",
            "object": None,
        }
    if ca._file_sha256(raw) != expected_digest:
        return {
            "state": "digest-mismatch",
            "reason": "manifest digest mismatch",
            "projection_bytes": b"manifest-unavailable:digest-mismatch",
            "object": None,
        }
    try:
        parsed = ca._require_anchor_manifest(_parse_projection_json(raw))
        inventory = ca.rule_inventory_index(parsed)
    except (ca.ManifestError, json.JSONDecodeError) as exc:
        raise PublicationError("manifest: %s" % exc) from exc
    return {
        "state": "accepted",
        "reason": "",
        "projection_bytes": raw,
        "object": parsed,
        "inventory": inventory,
    }


def load_record(
    report_path: Path,
    *,
    expected_report_sha256: str | None = None,
    expected_source_sha256: str | None = None,
    record_id: str | None = None,
) -> dict:
    report_path = Path(report_path)
    raw, doc = _load_json_object(report_path, label=str(report_path))
    if is_void_run_attempt(doc):
        raise PublicationError(VOID_RENDER_REFUSAL)
    try:
        mutants = _require_report_rows(doc)
    except ca.ManifestError as exc:
        raise PublicationError(str(exc)) from exc
    _require_displayed_parity(doc, mutants)
    # A report records the manifest path it was handed, and the page publishes the report's bytes
    # verbatim. Refuse a host marker or an absolute path there, as the void path already does for
    # its free text, so an operator's machine never reaches a published page (#204).
    _require_portable_public_text(doc.get("manifest"), field="manifest")
    digest = _sha256_bytes(raw)
    if expected_report_sha256 is not None and digest != expected_report_sha256:
        raise PublicationError("report digest mismatch for %s" % report_path)
    source_path = report_path.parent / "source.json"
    source_raw, source = _load_json_object(source_path, label=str(source_path))
    source_digest = _sha256_bytes(source_raw)
    if expected_source_sha256 is not None and source_digest != expected_source_sha256:
        raise PublicationError("source digest mismatch for %s" % source_path)
    directory = record_id if record_id is not None else report_path.parent.name
    repository, source_commit = _require_source_shape(source)
    non_claims = []
    extra = source.get("non_claims")
    if isinstance(extra, list):
        non_claims.extend(str(item) for item in extra)
    runner = doc.get("runner") if doc.get("runner") is not None else ""
    diagnostic = _diagnostic_channel_declared(doc)
    silent = doc.get("silent")
    silent_label = "not measured" if (silent == 0 and not diagnostic) else str(silent)
    control = doc.get("control_status")
    manifest_snapshot = _load_manifest_snapshot(
        report_path, doc.get("manifest_sha256") or ""
    )
    rel_report = "measurements/%s/report.v0.json" % directory
    command = published_local_command(report_path)
    review_rel = "measurements/%s/PROVENANCE.md" % directory
    return {
        "directory": directory,
        "digest": digest,
        "source_digest": source_digest,
        "report_bytes": raw,
        "source_bytes": source_raw,
        "doc": doc,
        "source": source,
        "repository": repository,
        "source_commit": source_commit,
        "non_claims": non_claims,
        "adapter": _adapter_name(source, directory),
        "runner": runner,
        "killed": doc.get("killed"),
        "survived": doc.get("survived"),
        "silent": silent,
        "silent_label": silent_label,
        "unproved": doc.get("unproved"),
        "control_status": control,
        "diagnostic_channel_declared": diagnostic,
        "report_rel": rel_report,
        "command": command,
        "review_rel": review_rel,
        "tool_commit": doc.get("tool_commit") or "",
        "tool_content_sha256": doc.get("tool_content_sha256") or "",
        "tool_version": doc.get("tool_version") or "",
        "manifest_sha256": doc.get("manifest_sha256") or "",
        "manifest_snapshot": manifest_snapshot,
        "manifest_projection_bytes": manifest_snapshot["projection_bytes"],
        "kind": KIND_COMPLETED_MEASUREMENT,
    }


def load_run_attempt(
    attempt_path: Path,
    *,
    expected_attempt_sha256: str | None = None,
    record_id: str | None = None,
) -> dict:
    """Load one public run-attempt.v0.json. Never reads a raw report."""
    attempt_path = Path(attempt_path)
    raw, doc = _load_json_object(attempt_path, label=str(attempt_path))
    if "execution_commit" not in doc or "commit" in doc or "source" in doc:
        raise PublicationError(
            "execution_commit is required; source.commit cannot substitute"
        )
    allowed = set(ATTEMPT_REQUIRED) | {"non_claims"}
    unknown = sorted(set(doc) - allowed)
    if unknown:
        raise PublicationError("run-attempt has unknown fields: %s" % unknown)
    missing = [key for key in ATTEMPT_REQUIRED if key not in doc]
    if missing:
        raise PublicationError("run-attempt missing fields: %s" % missing)
    if doc.get("schema") != ATTEMPT_SCHEMA:
        raise PublicationError("run-attempt schema is not %s" % ATTEMPT_SCHEMA)
    if doc.get("kind") != KIND_VOID_RUN_ATTEMPT:
        raise PublicationError("run-attempt kind is not %s" % KIND_VOID_RUN_ATTEMPT)
    raw_report = _require_hex64(doc.get("raw_report_sha256"), field="raw_report_sha256")
    execution_commit = doc.get("execution_commit")
    if not _looks_like_commit(execution_commit):
        raise PublicationError("execution_commit is not a 40-hex digest")
    prepare = _require_hex64(doc.get("prepare_sha256"), field="prepare_sha256")
    authorize = _require_hex64(doc.get("authorize_sha256"), field="authorize_sha256")
    if doc.get("baseline_status") != "unproved":
        raise PublicationError("baseline_status must be unproved")
    if doc.get("control_status") != "absent-or-invalid":
        raise PublicationError("control_status must be absent-or-invalid")
    if doc.get("mutant_status") != "not-scored":
        raise PublicationError("mutant_status must be not-scored")
    if doc.get("score_status") != "none":
        raise PublicationError("score_status must be none")
    raw_failures = doc.get("failures")
    if not isinstance(raw_failures, list) or not raw_failures:
        raise PublicationError("void run attempt must retain a failure")
    failures = [
        _require_portable_public_text(item, field="failures")
        for item in raw_failures
    ]
    digest = _sha256_bytes(raw)
    if expected_attempt_sha256 is not None and digest != expected_attempt_sha256:
        raise PublicationError("attempt digest mismatch for %s" % attempt_path)
    directory = record_id if record_id is not None else attempt_path.parent.name
    non_claims = []
    extra = doc.get("non_claims")
    if extra is not None:
        if not isinstance(extra, list) or not extra:
            raise PublicationError("non_claims must be a non-empty list")
        non_claims.extend(
            _require_portable_public_text(item, field="non_claims")
            for item in extra
        )
    for item in VOID_NON_CLAIMS:
        if item not in non_claims:
            non_claims.append(item)
    return {
        "directory": directory,
        "kind": KIND_VOID_RUN_ATTEMPT,
        "attempt_bytes": raw,
        "digest": digest,
        "doc": doc,
        "raw_report_sha256": raw_report,
        "execution_commit": execution_commit,
        "prepare_sha256": prepare,
        "authorize_sha256": authorize,
        "failures": failures,
        "non_claims": non_claims,
        "attempt_rel": "%s/%s/run-attempt.v0.json" % (ATTEMPT_REL_PREFIX, directory),
    }


def load_publication_index(root: Path) -> tuple[bytes, list[dict]]:
    index_path = Path(root) / INDEX_REL
    raw, doc = _load_json_object(index_path, label=INDEX_REL)
    unknown = sorted(set(doc) - INDEX_KEYS)
    if unknown:
        raise PublicationError("publication index has unknown fields: %s" % unknown)
    missing = sorted(INDEX_KEYS - set(doc))
    if missing:
        raise PublicationError("publication index missing fields: %s" % missing)
    if doc.get("schema") != INDEX_SCHEMA:
        raise PublicationError("publication index schema is not %s" % INDEX_SCHEMA)
    listed = doc.get("records")
    if not isinstance(listed, list):
        raise PublicationError("publication index records must be a list")
    entries = []
    seen = set()
    for i, item in enumerate(listed):
        if not isinstance(item, dict):
            raise PublicationError("publication index records[%d] is not an object" % i)
        rec_id = _require_record_id(item.get("id"))
        if rec_id in seen:
            raise PublicationError("publication index lists %s more than once" % rec_id)
        seen.add(rec_id)
        entries.append(
            {
                "id": rec_id,
                "report_sha256": _require_hex64(item.get("report_sha256"), field="report_sha256"),
                "source_sha256": _require_hex64(item.get("source_sha256"), field="source_sha256"),
            }
        )
    return raw, entries


def load_attempt_index(root: Path) -> tuple[bytes, list[dict]]:
    index_path = Path(root) / ATTEMPT_INDEX_REL
    if not index_path.exists():
        return b"", []
    raw, doc = _load_json_object(index_path, label=ATTEMPT_INDEX_REL)
    unknown = sorted(set(doc) - ATTEMPT_INDEX_KEYS)
    if unknown:
        raise PublicationError("run-attempt index has unknown fields: %s" % unknown)
    missing = sorted(ATTEMPT_INDEX_KEYS - set(doc))
    if missing:
        raise PublicationError("run-attempt index missing fields: %s" % missing)
    if doc.get("schema") != ATTEMPT_INDEX_SCHEMA:
        raise PublicationError("run-attempt index schema is not %s" % ATTEMPT_INDEX_SCHEMA)
    listed = doc.get("attempts")
    if not isinstance(listed, list):
        raise PublicationError("run-attempt index attempts must be a list")
    attempts = []
    seen = set()
    for i, item in enumerate(listed):
        if not isinstance(item, dict):
            raise PublicationError("run-attempt index attempts[%d] is not an object" % i)
        rec_id = _require_record_id(item.get("id"))
        if rec_id in seen:
            raise PublicationError("run-attempt index lists %s more than once" % rec_id)
        seen.add(rec_id)
        attempts.append(
            {
                "id": rec_id,
                "attempt_sha256": _require_hex64(
                    item.get("attempt_sha256"), field="attempt_sha256"
                ),
            }
        )
    return raw, attempts


def load_listed_records(root: Path) -> tuple[bytes, list[dict]]:
    """Load only index-listed measurements and typed run attempts."""
    root = Path(root)
    index_bytes, entries = load_publication_index(root)
    _attempt_index_bytes, attempts = load_attempt_index(root)
    records = []
    for entry in entries:
        rec_id = entry["id"]
        report_path = root / "measurements" / rec_id / "report.v0.json"
        source_path = root / "measurements" / rec_id / "source.json"
        if not report_path.exists() and not source_path.exists():
            raise PublicationError("listed measurement %s is missing" % rec_id)
        records.append(
            load_record(
                report_path,
                expected_report_sha256=entry["report_sha256"],
                expected_source_sha256=entry["source_sha256"],
                record_id=rec_id,
            )
        )
    seen = {entry["id"] for entry in entries}
    for entry in attempts:
        rec_id = entry["id"]
        if rec_id in seen:
            raise PublicationError("run-attempt index lists %s more than once" % rec_id)
        seen.add(rec_id)
        attempt_path = (
            root / ATTEMPT_REL_PREFIX / rec_id / "run-attempt.v0.json"
        )
        if not attempt_path.exists():
            raise PublicationError("listed run attempt %s is missing" % rec_id)
        records.append(
            load_run_attempt(
                attempt_path,
                expected_attempt_sha256=entry["attempt_sha256"],
                record_id=rec_id,
            )
        )
    return index_bytes, records


KIND_CLASS_COMPARISON = "class-comparison"
VISIBILITY_WORDS = {
    "declared": "committed openly before the run; not held out",
    "hidden-until-freeze": "hidden until the candidate froze; held out",
    "disclosed-before-freeze": "disclosed before the candidate froze; not held out",
    "unknown": "not established",
}


def load_class_index(root: Path) -> tuple[bytes, list[dict]]:
    """The optional class-comparison index. Absent means no comparison is published."""
    index_path = Path(root) / CLASS_INDEX_REL
    if not index_path.exists():
        return b"", []
    raw, doc = _load_json_object(index_path, label=CLASS_INDEX_REL)
    unknown = sorted(set(doc) - CLASS_INDEX_KEYS)
    if unknown:
        raise PublicationError("class-comparison index has unknown fields: %s" % unknown)
    missing = sorted(CLASS_INDEX_KEYS - set(doc))
    if missing:
        raise PublicationError("class-comparison index missing fields: %s" % missing)
    if doc.get("schema") != CLASS_INDEX_SCHEMA:
        raise PublicationError("class-comparison index schema is not %s" % CLASS_INDEX_SCHEMA)
    listed = doc.get("comparisons")
    if not isinstance(listed, list):
        raise PublicationError("class-comparison index comparisons must be a list")
    entries = []
    seen = set()
    for i, item in enumerate(listed):
        if not isinstance(item, dict):
            raise PublicationError("class-comparison index comparisons[%d] is not an object" % i)
        unknown = sorted(set(item) - CLASS_ENTRY_KEYS)
        missing = sorted(CLASS_ENTRY_KEYS - set(item))
        if unknown or missing:
            raise PublicationError(
                "class-comparison index comparisons[%d]: unknown %s, missing %s"
                % (i, unknown, missing))
        comparison_id = _require_record_id(item.get("id"))
        if comparison_id in seen:
            raise PublicationError(
                "class-comparison index lists %s more than once" % comparison_id)
        seen.add(comparison_id)
        entry = {"id": comparison_id, "evidence": _require_record_id(item.get("evidence"))}
        for key in CLASS_ENTRY_FILES:
            entry[key] = _require_hex64(item.get(key), field=key)
        entries.append(entry)
    return raw, entries


def _parse_bound(raw: bytes, label: str) -> dict:
    try:
        doc = _parse_projection_json(raw)
    except (ca.ManifestError, json.JSONDecodeError) as exc:
        raise PublicationError("%s: %s" % (label, exc)) from exc
    if not isinstance(doc, dict):
        raise PublicationError("%s is not a JSON object" % label)
    return doc


def _repository_file(root: Path, rel: str, *, label: str) -> bytes:
    """A file this repository ships, named by a repository-relative path, read confined."""
    parts = Path(rel).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise PublicationError("%s is not a repository path" % label)
    try:
        return read_bounded_regular_file(Path(root).joinpath(*parts))
    except (ca.ManifestError, OSError) as exc:
        raise PublicationError("%s is missing from this repository" % label) from exc


def _is_termination_how(how) -> bool:
    """A kill whose `how` names only termination kinds rests on the child ending abnormally."""
    if not isinstance(how, str) or not how:
        return False
    return all(token in ca.TERMINATED_KINDS for token in how.split(", "))


def _class_side(root: Path, files: dict, side: str, comparison_id: str) -> dict:
    label = "class comparison %s %s report" % (comparison_id, side)
    doc = _parse_bound(files["%s/report.v0.json" % side], label)
    if is_void_run_attempt(doc):
        raise PublicationError(VOID_RENDER_REFUSAL)
    try:
        mutants = _require_report_rows(doc)
    except ca.ManifestError as exc:
        raise PublicationError("%s: %s" % (label, exc)) from exc
    _require_displayed_parity(doc, mutants)
    manifest_rel = _require_portable_public_text(doc.get("manifest"), field="manifest")
    manifest_raw = _repository_file(root, manifest_rel, label="%s manifest" % label)
    if doc.get("manifest_sha256") != "sha256:" + _sha256_bytes(manifest_raw):
        raise PublicationError("%s names a manifest whose bytes it did not measure" % label)
    counts = _counts_from_mutants(mutants)
    scored = counts["killed"] + counts["survived"] + counts["silent"]
    # A side whose positive control did not die, or that left anything unproved, has no result
    # to set beside another: its numbers would say nothing about the corpus.
    if doc.get("control_status") != "killed":
        raise PublicationError("%s: positive control is %s, so the run has no result"
                               % (label, doc.get("control_status")))
    if counts["unproved"]:
        raise PublicationError("%s: %d mutant(s) unproved" % (label, counts["unproved"]))
    if scored == 0:
        raise PublicationError("%s: nothing was scored" % label)
    for row in mutants:
        if row.get("verdict") in ("control-MOVED", "control-error"):
            raise PublicationError("%s: a control is %s, so the run has no result"
                                   % (label, row.get("verdict")))
    inert = [row for row in mutants if row.get("verdict") == "control-unchanged"]
    # Survivors first: an undistinguished mutant is the finding a reader can act on.
    order = {"survived": 0, "silent": 1, "killed": 2}
    ordinary = sorted(
        ((row["verdict"], row["label"], _is_termination_how(row.get("how")))
         for row in mutants if row.get("verdict") in order),
        key=lambda item: (order[item[0]], item[1]))
    return {
        "doc": doc,
        "manifest": manifest_rel,
        "counts": counts,
        "scored": scored,
        "control_status": doc.get("control_status"),
        "adequate": doc.get("adequate") is True,
        "by_termination": sum(1 for row in mutants if row.get("verdict") == "killed"
                              and _is_termination_how(row.get("how"))),
        "not_distinguished": [(row["verdict"], row["label"]) for row in mutants
                              if row.get("verdict") in ("survived", "silent")],
        "ordinary": ordinary,
        "inert_controls": len(inert),
        "prepare": _parse_bound(files["%s/prepare.v2.json" % side],
                                "class comparison %s %s prepare" % (comparison_id, side)),
    }


def load_class_comparison(root: Path, entry: dict) -> dict:
    """Load and bind every byte one comparison page relies on, or refuse."""
    comparison_id = entry["id"]
    base = Path(root) / "measurements" / entry["evidence"]
    files = {}
    for key, rel in CLASS_ENTRY_FILES.items():
        try:
            raw = read_bounded_regular_file(base / rel)
        except (ca.ManifestError, OSError) as exc:
            raise PublicationError(
                "class comparison %s is missing %s" % (comparison_id, rel)) from exc
        if _sha256_bytes(raw) != entry[key]:
            raise PublicationError(
                "class comparison %s digest mismatch for %s" % (comparison_id, rel))
        files[rel] = raw
    declared = _class_side(root, files, "declared", comparison_id)
    independent = _class_side(root, files, "independent", comparison_id)
    # Compare what was measured, not only where it lives: two paths can hold the same bytes.
    if (declared["manifest"] == independent["manifest"]
            or declared["doc"].get("manifest_sha256")
            == independent["doc"].get("manifest_sha256")):
        raise PublicationError(
            "class comparison %s names the same selection on both sides" % comparison_id)

    provenance_raw = files["independent/class-provenance.v0.json"]
    attempt_raw = files["independent/class-attempt.v0.json"]
    provenance = _parse_bound(provenance_raw, "class provenance")
    attempt = _parse_bound(attempt_raw, "class attempt")
    try:
        canonical_provenance = ca.encode_class_provenance_v0(provenance)
        canonical_attempt = ca.encode_class_attempt_v0(attempt)
    except ca.ManifestError as exc:
        raise PublicationError("class comparison %s: %s" % (comparison_id, exc)) from exc
    if canonical_provenance != provenance_raw or canonical_attempt != attempt_raw:
        raise PublicationError(
            "class comparison %s: class artifacts are not canonical bytes" % comparison_id)
    bindings = (
        ("report_sha256", entry["independent_report_sha256"]),
        ("environment_sha256", entry["independent_prepare_sha256"]),
        ("provenance_sha256", entry["independent_provenance_sha256"]),
    )
    for key, digest in bindings:
        if attempt[key] != "sha256:" + digest:
            raise PublicationError(
                "class comparison %s: the class attempt does not bind the listed %s"
                % (comparison_id, key))
    if attempt["manifest_sha256"] != independent["doc"].get("manifest_sha256"):
        raise PublicationError(
            "class comparison %s: the class attempt names another selection" % comparison_id)
    if attempt["status"] != "completed":
        raise PublicationError(
            "class comparison %s: the class attempt is %s, and an unproved class has no "
            "result to set beside another" % (comparison_id, attempt["status"]))
    # This page sets a declared set beside an independent one. A held-out class is stronger
    # evidence and would need its own wording, so it is not published under this header.
    if attempt["effective_class"] != "independent":
        raise PublicationError(
            "class comparison %s: the second column must be an independent class, not %s"
            % (comparison_id, attempt["effective_class"]))
    for name in ("killed", "survived", "silent", "unproved"):
        if attempt["result"][name] != independent["counts"][name]:
            raise PublicationError(
                "class comparison %s: the class attempt and its report disagree on %s"
                % (comparison_id, name))

    # One candidate, one corpus, one environment: only the mutant set may differ.
    for key in ("toolchain", "runtime", "materialized"):
        if declared["prepare"].get(key) != independent["prepare"].get(key):
            raise PublicationError(
                "class comparison %s: the two sides did not share %s" % (comparison_id, key))
    measured_at = declared["prepare"].get("execution", {}).get("commit")
    if independent["prepare"].get("execution", {}).get("commit") != measured_at:
        raise PublicationError(
            "class comparison %s: the two sides were prepared at different commits"
            % comparison_id)
    for side in (declared, independent):
        if side["doc"].get("tool_commit") != measured_at:
            raise PublicationError(
                "class comparison %s: a report was not produced at the prepared commit"
                % comparison_id)
    return {
        "kind": KIND_CLASS_COMPARISON,
        "id": comparison_id,
        "evidence": entry["evidence"],
        "files": files,
        "declared": declared,
        "independent": independent,
        "provenance": provenance,
        "attempt": attempt,
        "measured_at": measured_at,
        "toolchain_image": declared["prepare"]["toolchain"]["image_id"],
    }


def load_class_comparisons(root: Path) -> tuple[bytes, list[dict]]:
    index_bytes, entries = load_class_index(Path(root))
    return index_bytes, [load_class_comparison(Path(root), entry) for entry in entries]


def discover_records(root: Path) -> list[dict]:
    """Index-bound records only. Kept as the listed-record loader name."""
    _index_bytes, records = load_listed_records(root)
    return records


def actionable_findings(record: dict) -> list[dict]:
    """Actionable rows from survivor_findings, addressed by report mutants[] index."""
    projected = survivor_findings(record["doc"])
    snapshot = record["manifest_snapshot"]
    manifest_obj = snapshot.get("object")
    inventory = snapshot.get("inventory")
    linked_rules = {}
    if inventory is not None:
        for rule in inventory["rules"]:
            if rule["disposition"] != "mutated":
                continue
            for label in rule["mutants"]:
                linked_rules[(rule["group"], label)] = rule
    if manifest_obj is not None:
        for finding in projected["findings"]:
            ca._apply_anchor(finding, manifest_obj)
    buckets: dict[tuple[str, str, str], list[dict]] = {}
    for finding in projected["findings"]:
        key = (finding["group"], finding["rule"], finding["verdict"])
        buckets.setdefault(key, []).append(finding)
    rows = []
    for i, row in enumerate(record["doc"]["mutants"]):
        key = (row["group"], row["label"], row["verdict"])
        bucket = buckets.get(key)
        if not bucket:
            continue
        finding = bucket.pop(0)
        how = row.get("how")
        if not isinstance(how, str) or not how:
            raise PublicationError("report.mutants[%d].how must be a non-empty string" % i)
        item = {
            "index": i,
            "path_id": "%04d" % i,
            "rule": finding["rule"],
            "group": finding["group"],
            "verdict": finding["verdict"],
            "how": row["how"],
            "obligation": finding["obligation"],
            "moved": finding["moved"],
            "moved_diagnostic": finding["moved_diagnostic"],
            "observation": {
                "runner": record["runner"],
                "diagnostic_channel_declared": record[
                    "diagnostic_channel_declared"
                ],
                "mechanism": (
                    "declared outcome unchanged; declared diagnostic changed"
                    if finding["verdict"] == "silent"
                    else "declared outcome unchanged"
                ),
            },
            "control": {
                "status": record["control_status"],
                "valid": (
                    record["control_status"] == "killed"
                    and record["doc"].get("score_percent") is not None
                ),
                "unproved": record["unproved"],
            },
        }
        rule = linked_rules.get((finding["group"], finding["rule"]))
        if rule is not None:
            item["rule_evidence"] = {
                "status": "linked",
                "id": rule["id"],
                "text": rule["text"],
                "url": rule["url"],
            }
        elif snapshot["state"] != "accepted":
            item["rule_evidence"] = {
                "status": "unavailable", "reason": snapshot["reason"]
            }
        elif inventory is None:
            item["rule_evidence"] = {
                "status": "unavailable", "reason": "manifest.v0"
            }
        else:
            item["rule_evidence"] = {
                "status": "unavailable", "reason": "unlinked"
            }
        if "anchor_excerpt" in finding:
            item["anchor_evidence"] = {
                "status": "present", "excerpt": finding["anchor_excerpt"]
            }
        elif "anchor_omitted" in finding:
            item["anchor_evidence"] = {
                "status": "omitted", "reason": finding["anchor_omitted"]
            }
        elif snapshot["state"] != "accepted":
            item["anchor_evidence"] = {
                "status": "unavailable", "reason": snapshot["reason"]
            }
        else:
            item["anchor_evidence"] = {
                "status": "omitted", "reason": "not declared"
            }
        rows.append(item)
    leftover = [key for key, bucket in buckets.items() if bucket]
    if leftover:
        raise PublicationError("leftover survivor_findings: %s" % leftover)
    return rows


def _evidence_hrefs(record: dict, build_commit: str) -> tuple[str, str, str]:
    raw_href = (
        "%s/%s/%s" % (RAW_PREFIX, build_commit, record["report_rel"])
        if _looks_like_commit(build_commit)
        else record["report_rel"]
    )
    review_href = (
        "%s/%s/%s" % (BLOB_PREFIX, build_commit, record["review_rel"])
        if _looks_like_commit(build_commit)
        else record["review_rel"]
    )
    source_href = _source_commit_url(record)
    if not source_href:
        raise PublicationError("source commit URL is missing")
    return raw_href, review_href, source_href


def _source_url(record: dict) -> str:
    repo = record["repository"]
    if _looks_like_repo(repo):
        return "https://github.com/%s" % repo
    return ""


def _source_commit_url(record: dict) -> str:
    repo_url = _source_url(record)
    commit = record["source_commit"]
    if repo_url and _looks_like_commit(commit):
        return "%s/commit/%s" % (repo_url, commit)
    return ""


def _plain_sentence(record: dict) -> str:
    silent_bit = (
        "silent was not measured"
        if record["silent_label"] == "not measured"
        else "%s were silent" % record["silent"]
    )
    return (
        "Of the author-declared in-scope mutants in this record, "
        "%s were killed, %s survived, %s, and %s were unproved. "
        "The control path status is %s."
        % (
            record["killed"],
            record["survived"],
            silent_bit,
            record["unproved"],
            record["control_status"],
        )
    )


def _inspect_command(record: dict) -> str:
    return "python3 corpus_adequacy.py --survivors %s --json" % record["report_rel"]


def _release_href() -> str:
    return (
        "https://github.com/corpus-adequacy/corpus-adequacy/releases/tag/v%s"
        % PUBLISHED_RELEASE_VERSION
    )


def _clone_command() -> str:
    return (
        "git clone --depth 1 --branch v%s "
        "https://github.com/corpus-adequacy/corpus-adequacy.git"
        % PUBLISHED_RELEASE_VERSION
    )


def _first_run_route(records: list[dict]) -> str:
    lines = [
        _clone_command(),
        "cd corpus-adequacy",
        _inspect_command(records[-1]),
    ]
    return "\n".join(lines)


def _first_run_html(records: list[dict], source_commit: str) -> str:
    tool_rows = []
    for record in records:
        tool_rows.append(
            "<p>report tool_commit <span class=\"mono\">%s</span></p>\n"
            "<p>report tool_content_sha256 <span class=\"mono\">%s</span></p>\n"
            "<p>report tool_version <span class=\"mono\">%s</span></p>"
            % (
                _esc(record["tool_commit"]),
                _esc(record["tool_content_sha256"]),
                _esc(record["tool_version"]),
            )
        )
    tag = "v%s" % PUBLISHED_RELEASE_VERSION
    return (
        '<section id="first-run" class="non-claims" aria-labelledby="first-run-heading">\n'
        '<h2 id="first-run-heading">What this measures</h2>\n'
        "<p>This page identifies which author-declared rule-removal mutants "
        "the corpus distinguished.</p>\n"
        "<p>Obtain the tagged tool, then inspect. The inspect line reads "
        "existing report bytes and does not measure.</p>\n"
        "<pre><code>%s</code></pre>\n"
        "<p>The card below keeps the measurement command. exit 1 with --json "
        "is a completed inadequate measurement with declared survivors, not a "
        "crash; exit 2 is refusal.</p>\n"
        "%s\n"
        "<p>evidence-link commit <span class=\"mono\">%s</span></p>\n"
        "<p>tagged tool <span class=\"mono\">%s</span></p>\n"
        '<p><a href="%s">Release %s</a></p>\n'
        "<p>Equal counts do not imply identical report bytes.</p>\n"
        "</section>"
        % (
            _esc(_first_run_route(records)),
            "\n".join(tool_rows),
            _esc(source_commit),
            _esc(tag),
            _esc(_release_href()),
            _esc(tag),
        )
    )


def _non_claims_html(
    records: list[dict] | None = None,
    ceilings: tuple[str, ...] = CEILING_LINES,
) -> str:
    seen = []
    for rec in records or []:
        for item in rec.get("non_claims") or []:
            if item not in seen:
                seen.append(item)
    for item in ceilings:
        if item not in seen:
            seen.append(item)
    return (
        '<section class="non-claims" aria-labelledby="non-claims-heading">\n'
        '<h2 id="non-claims-heading">Non-claims</h2>\n'
        "<ul>\n%s\n</ul>\n"
        "</section>"
        % "\n".join("<li>%s</li>" % _esc(item) for item in seen)
    )


def _counts_html(record: dict) -> str:
    silent_value = record["silent_label"]
    channel = "declared" if record["diagnostic_channel_declared"] else "not declared"
    rows = (
        ("killed", record["killed"], "killed %s" % record["killed"]),
        ("survived", record["survived"], "survived %s" % record["survived"]),
        ("silent", silent_value, "silent %s" % silent_value),
        ("unproved", record["unproved"], "unproved %s" % record["unproved"]),
        ("control_status", record["control_status"], "control_status %s" % record["control_status"]),
        ("diagnostic_channel_declared", channel, "diagnostic_channel_declared %s" % channel),
    )
    items = []
    for label, value, accessible in rows:
        items.append(
            '<li class="count" aria-label="%s"><span class="count-label">%s</span> '
            '<span class="count-value">%s</span></li>'
            % (_esc(accessible), _esc(label), _esc(value))
        )
    return '<ul class="counts">%s</ul>' % "".join(items)


def _card_html(record: dict, build_commit: str) -> str:
    if record.get("kind") == KIND_VOID_RUN_ATTEMPT or is_void_run_attempt(
        record.get("doc")
    ):
        raise PublicationError(VOID_RENDER_REFUSAL)
    raw_href, review_href, source_href = _evidence_hrefs(record, build_commit)
    source_link = (
        '<a href="%s">source commit %s</a>' % (_esc(source_href), _esc(record["source_commit"]))
    )
    detail_href = "runs/%s/" % record["directory"]
    return (
        '<li class="card">\n'
        '<h3>%s</h3>\n'
        '<p>corpus id <span class="mono">%s</span></p>\n'
        '<p>source commit <span class="mono">%s</span></p>\n'
        '<p>adapter <span class="mono">%s</span> · runner <span class="mono">%s</span></p>\n'
        '<p>report digest <span class="mono">%s</span></p>\n'
        '<p>source.json metadata SHA-256 <span class="mono">%s</span></p>\n'
        '%s'
        '%s\n'
        '<p class="plain">%s</p>\n'
        '<p class="links">\n'
        '<a href="%s">run detail</a>\n'
        '<a href="%s">raw report.v0.json</a>\n'
        '%s\n'
        '<a href="%s">review</a>\n'
        '</p>\n'
        '</li>'
        % (
            _esc(record["directory"]),
            _esc(record["directory"]),
            _esc(record["source_commit"]),
            _esc(record["adapter"]),
            _esc(record["runner"]),
            _esc(record["digest"]),
            _esc(record["source_digest"]),
            _card_command_html(record),
            _counts_html(record),
            _esc(_plain_sentence(record)),
            _esc(detail_href),
            _esc(raw_href),
            source_link,
            _esc(review_href),
        )
    )


def _handoff_command(record: dict) -> str:
    return "python3 scripts/publication_handoff.py %s" % record["report_rel"]


def _handoff_section(records: list[dict]) -> str:
    commands = "\n".join(_handoff_command(record) for record in records)
    return (
        '<section id="publication-handoff" class="non-claims" '
        'aria-labelledby="handoff-heading">\n'
        '<h2 id="handoff-heading">Local publication handoff</h2>\n'
        "<p>Recompute machine prefills from local report and source.json "
        "metadata bytes. Review must recompute those fields. Query values "
        "stay untrusted.</p>\n"
        "<pre><code>%s</code></pre>\n"
        '<p><a href="%s">Manual empty publication form</a> '
        "(fallback if the local command is unavailable).</p>\n"
        "</section>"
        % (_esc(commands), _esc(ISSUES_PUBLISH))
    )


def _void_plain_sentence() -> str:
    return (
        "This is a void run attempt, not a measurement or score. "
        "Baseline unproved. No valid control result. No scored mutants. No score."
    )


def _void_digest_html(record: dict) -> str:
    rows = (
        ("recorded raw report SHA-256", record["raw_report_sha256"]),
        ("execution commit", record["execution_commit"]),
        ("recorded PREPARE digest", record["prepare_sha256"]),
        ("recorded AUTHORIZE digest", record["authorize_sha256"]),
        ("attempt digest", record["digest"]),
    )
    return "\n".join(
        '<p>%s <span class="mono">%s</span></p>' % (_esc(label), _esc(value))
        for label, value in rows
    )


def _void_failures_html(record: dict, *, heading: str = "h2") -> str:
    if heading not in ("h2", "h4"):
        raise PublicationError("void failure heading must be h2 or h4")
    items = [
        '<li><span class="mono">%s</span></li>' % _esc(item)
        for item in record["failures"]
    ]
    return (
        "<%s>Retained failure</%s>\n"
        "<ul>\n%s\n</ul>" % (heading, heading, "\n".join(items))
    )


def _void_site_attempt_href(record: dict, *, from_overview: bool) -> str:
    name = "run-attempt.v0.json"
    if from_overview:
        return "runs/%s/%s" % (record["directory"], name)
    return name


def _void_links_html(record: dict) -> str:
    execution_href = (
        "https://github.com/corpus-adequacy/corpus-adequacy/commit/%s"
        % record["execution_commit"]
    )
    return (
        '<p class="links">\n'
        '<a href="%s">attempt detail</a>\n'
        '<a href="%s">execution commit %s</a>\n'
        '<a href="%s">run-attempt.v0.json</a>\n'
        "</p>"
        % (
            _esc("runs/%s/" % record["directory"]),
            _esc(execution_href),
            _esc(record["execution_commit"]),
            _esc(_void_site_attempt_href(record, from_overview=True)),
        )
    )


def _void_card_html(record: dict) -> str:
    return (
        '<li class="card">\n'
        "<h3>Void run attempt</h3>\n"
        '<p>attempt id <span class="mono">%s</span></p>\n'
        "%s\n"
        '<p class="plain">%s</p>\n'
        "%s\n"
        "%s\n"
        "</li>"
        % (
            _esc(record["directory"]),
            _void_digest_html(record),
            _esc(_void_plain_sentence()),
            _void_failures_html(record, heading="h4"),
            _void_links_html(record),
        )
    )


def _split_publication_records(records: list[dict]) -> tuple[list[dict], list[dict]]:
    measurements = []
    attempts = []
    for record in records:
        kind = record.get("kind", KIND_COMPLETED_MEASUREMENT)
        if kind == KIND_VOID_RUN_ATTEMPT:
            attempts.append(record)
        elif kind == KIND_COMPLETED_MEASUREMENT:
            measurements.append(record)
        else:
            raise PublicationError("unknown publication kind %r" % kind)
    return measurements, attempts


def _intake_nav_links(*, include_handoff: bool) -> str:
    links = ['<a href="%s">Request source intake</a>' % _esc(ISSUES_INTAKE)]
    if include_handoff:
        links.append(
            '<a href="#publication-handoff">Hand off a completed measurement</a>'
        )
    return "\n".join(links)


def _overview_heading(*, has_attempts: bool) -> tuple[str, str]:
    if has_attempts:
        label = "Published corpus-adequacy records"
        return label, label
    return "Published corpus-adequacy measurements", "Published measurements"


def _listing_copy(*, has_measurements: bool, has_attempts: bool) -> str:
    parts = []
    if has_measurements:
        parts.append(
            "completed measurements listed in "
            "<code>publications/index.v0.json</code>"
        )
    if has_attempts:
        parts.append(
            "void run attempts listed in "
            "<code>publications/run-attempts/index.v0.json</code>"
        )
    if not parts:
        parts.append(
            "completed measurements listed in "
            "<code>publications/index.v0.json</code>"
        )
    if len(parts) == 2:
        return "Committed %s and %s." % (parts[0], parts[1])
    return "Committed %s." % parts[0]


def _page_body(records: list[dict], source_commit: str, projection_digest: str,
               comparisons=()) -> str:
    measurements, attempts = _split_publication_records(records)
    cards = "\n".join(_card_html(rec, source_commit) for rec in measurements)
    first_run = _first_run_html(measurements, source_commit) if measurements else ""
    handoff = _handoff_section(measurements) if measurements else ""
    non_claims = _non_claims_html(
        measurements or attempts,
        ceilings=CEILING_LINES if measurements else (),
    )
    void_section = ""
    if attempts:
        void_section = (
            '<section id="void-attempts" class="non-claims" '
            'aria-labelledby="void-attempts-heading">\n'
            '<h2 id="void-attempts-heading">Void run attempts</h2>\n'
            '<ul class="cards">\n%s\n</ul>\n'
            "</section>\n"
            % "\n".join(_void_card_html(rec) for rec in attempts)
        )
    measurement_block = ""
    if measurements:
        measurement_block = (
            "<h2>Committed records</h2>\n"
            '<ul class="cards">\n%s\n</ul>\n' % cards
        )
    title, heading = _overview_heading(has_attempts=bool(attempts))
    listing = _listing_copy(
        has_measurements=bool(measurements),
        has_attempts=bool(attempts),
    )
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="projection-digest" content="%s">
<meta name="source-commit" content="%s">
<title>%s</title>
<style>
%s
#results:focus { outline: 3px solid #0033aa; outline-offset: 2px; }
</style>
</head>
<body>
<a class="skip" href="#results">Skip to results</a>
<header>
<h1>%s</h1>
<p>%s</p>
</header>
%s
%s
<nav class="ctas" aria-label="intake and publication forms">
%s
</nav>
%s
<main id="results" tabindex="-1">
%s%s%s</main>
</body>
</html>
""" % (
        _esc(projection_digest),
        _esc(source_commit),
        _esc(title),
        SHARED_STYLE,
        _esc(heading),
        listing,
        first_run,
        non_claims,
        _intake_nav_links(include_handoff=bool(measurements)),
        handoff,
        void_section,
        measurement_block,
        _class_section_html(comparisons),
    )


def compute_projection_digest(
    index_bytes: bytes,
    records: list[dict],
    renderer_bytes: bytes,
    source_commit: str,
    attempts_index_bytes: bytes = b"",
    class_index_bytes: bytes = b"",
    comparisons=(),
) -> str:
    """SHA-256 of projection inputs, not of the emitted HTML.

    The finished page embeds this digest, so hashing the page would be a
    self-reference. This is not a digest of a deployed artifact. It binds
    the inputs that determine visible projection content, including the
    evidence-link commit and the tagged tool version, each with a label
    and an 8-byte big-endian length prefix so concatenation is unambiguous.
    """
    hasher = hashlib.sha256()

    def _add(label: bytes, payload: bytes) -> None:
        hasher.update(label)
        hasher.update(b"\0")
        hasher.update(len(payload).to_bytes(8, "big"))
        hasher.update(payload)

    _add(b"index", index_bytes)
    if attempts_index_bytes:
        _add(b"attempts_index", attempts_index_bytes)
    if class_index_bytes:
        _add(b"class_index", class_index_bytes)
        for comparison in comparisons:
            for rel, raw in comparison["files"].items():
                _add(("class:%s:%s" % (comparison["id"], rel)).encode("utf-8"), raw)
    for record in records:
        kind = record.get("kind", KIND_COMPLETED_MEASUREMENT)
        if kind == KIND_VOID_RUN_ATTEMPT:
            _add(b"attempt", record["attempt_bytes"])
        elif kind == KIND_COMPLETED_MEASUREMENT:
            _add(b"report", record["report_bytes"])
            _add(b"source", record["source_bytes"])
            _add(b"manifest_projection", record["manifest_projection_bytes"])
        else:
            raise PublicationError("unknown publication kind %r" % kind)
    _add(b"renderer", renderer_bytes)
    _add(b"source_commit", source_commit.encode("ascii"))
    _add(b"published_release_version", PUBLISHED_RELEASE_VERSION.encode("ascii"))
    return hasher.hexdigest()


def _shell_page(title: str, skip_href: str, skip_label: str, body: str) -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
%s
</style>
</head>
<body>
<a class="skip" href="%s">%s</a>
%s
</body>
</html>
""" % (_esc(title), SHARED_STYLE, _esc(skip_href), _esc(skip_label), body)


def _evidence_links_html(record: dict, build_commit: str) -> str:
    raw_href, review_href, source_href = _evidence_hrefs(record, build_commit)
    return (
        '<p class="links">\n'
        '<a href="%s">raw report.v0.json</a>\n'
        '<a href="%s">source commit %s</a>\n'
        '<a href="%s">review</a>\n'
        "</p>"
        % (
            _esc(raw_href),
            _esc(source_href),
            _esc(record["source_commit"]),
            _esc(review_href),
        )
    )


def _run_page(record: dict, findings: list[dict], build_commit: str) -> str:
    if record.get("kind") == KIND_VOID_RUN_ATTEMPT or is_void_run_attempt(
        record.get("doc")
    ):
        raise PublicationError(VOID_RENDER_REFUSAL)
    items = []
    for finding in findings:
        items.append(
            '<li><a href="rules/%s.html">%s</a> <span>%s</span></li>'
            % (_esc(finding["path_id"]), _esc(finding["rule"]), _esc(finding["verdict"]))
        )
    body = (
        "<header>\n"
        "<h1>%s</h1>\n"
        '<p><a href="../../index.html">overview</a></p>\n'
        "</header>\n"
        "%s\n"
        "%s\n"
        '<main id="findings">\n'
        "<h2>Actionable findings</h2>\n"
        "<ul class=\"finding\">\n%s\n</ul>\n"
        "%s\n"
        "</main>"
        % (
            _esc(record["directory"]),
            _non_claims_html([record]),
            _counts_html(record),
            "\n".join(items),
            _evidence_links_html(record, build_commit),
        )
    )
    return _shell_page(
        record["directory"],
        "#findings",
        "Skip to findings",
        body,
    )


def _void_run_page(record: dict) -> str:
    execution_href = (
        "https://github.com/corpus-adequacy/corpus-adequacy/commit/%s"
        % record["execution_commit"]
    )
    body = (
        "<header>\n"
        "<h1>Void run attempt</h1>\n"
        '<p><a href="../../index.html">overview</a></p>\n'
        "</header>\n"
        "%s\n"
        '<main id="attempt" tabindex="-1">\n'
        '<p class="plain">%s</p>\n'
        "%s\n"
        "%s\n"
        '<p class="links">\n'
        '<a href="%s">execution commit %s</a>\n'
        '<a href="%s">run-attempt.v0.json</a>\n'
        "</p>\n"
        "</main>"
        % (
            _non_claims_html([record], ceilings=()),
            _esc(_void_plain_sentence()),
            _void_digest_html(record),
            _void_failures_html(record, heading="h2"),
            _esc(execution_href),
            _esc(record["execution_commit"]),
            _esc(_void_site_attempt_href(record, from_overview=False)),
        )
    )
    return _shell_page(
        "Void run attempt — %s" % record["directory"],
        "#attempt",
        "Skip to attempt",
        body,
    )


def _rule_page(record: dict, finding: dict, build_commit: str) -> str:
    diagnostic = ""
    if record["diagnostic_channel_declared"]:
        diagnostic = (
            '<p>moved_diagnostic <span class="mono">%s</span></p>\n'
            % _esc(finding["moved_diagnostic"])
        )
    rule = finding["rule_evidence"]
    if rule["status"] == "linked":
        if rule["url"] is None:
            rule_url_html = (
                '<p>rule_url <span class="unavailable">unavailable (not declared)</span></p>\n'
            )
        else:
            rule_url_html = (
                '<p>rule_url <a href="%s">%s</a></p>\n'
                % (_esc(rule["url"]), _esc(rule["url"]))
            )
        rule_html = (
            '<div class="rule-link">\n'
            '<p>rule_id <span class="mono">%s</span></p>\n'
            '<p>rule_text <span>%s</span></p>\n'
            '%s'
            '</div>\n'
            % (_esc(rule["id"]), _esc(rule["text"]), rule_url_html)
        )
    else:
        rule_html = (
            '<p>rule <span class="unavailable">unavailable (%s)</span></p>\n'
            % _esc(rule["reason"])
        )
    anchor = finding["anchor_evidence"]
    if anchor["status"] == "present":
        anchor_html = (
            '<p>anchor <span class="mono">%s</span></p>\n'
            % _esc(anchor["excerpt"])
        )
    else:
        anchor_html = (
            '<p>anchor <span class="unavailable">omitted (%s)</span></p>\n'
            % _esc(anchor["reason"])
        )
    observation = finding["observation"]
    observation_html = (
        '<p>runner <span class="mono">%s</span></p>\n'
        '<p>diagnostic_channel_declared <span class="mono">%s</span></p>\n'
        '<p>verdict mechanism %s</p>\n'
        % (
            _esc(observation["runner"]),
            _esc(str(observation["diagnostic_channel_declared"]).lower()),
            _esc(observation["mechanism"]),
        )
    )
    control = finding["control"]
    control_html = (
        '<p>control_status <span>%s</span></p>\n'
        '<p>unproved <span class="mono">%s</span></p>\n'
        % (_esc(control["status"]), _esc(control["unproved"]))
    )
    if not control["valid"]:
        control_html += '<p class="warning">control invalid: run is unscored</p>\n'
    body = (
        "<header>\n"
        "<h1>%s</h1>\n"
        '<p><a href="../../../index.html">overview</a> · '
        '<a href="../">run detail</a></p>\n'
        "</header>\n"
        "%s\n"
        '<main id="finding" class="finding">\n'
        "%s"
        "<p>verdict <span>%s</span></p>\n"
        "<p>group <span class=\"mono\">%s</span></p>\n"
        "<p>obligation %s</p>\n"
        "<p>moved <span class=\"mono\">%s</span></p>\n"
        "%s%s%s%s"
        "%s\n"
        "</main>"
        % (
            _esc(finding["rule"]),
            _non_claims_html([record], ceilings=CEILING_LINES + DOSSIER_NON_CLAIMS),
            rule_html,
            _esc(finding["verdict"]),
            _esc(finding["group"]),
            _esc(finding["obligation"]),
            _esc(finding["moved"]),
            diagnostic,
            anchor_html,
            observation_html,
            control_html,
            _evidence_links_html(record, build_commit),
        )
    )
    return _shell_page(
        "%s — %s" % (finding["rule"], record["directory"]),
        "#finding",
        "Skip to finding",
        body,
    )


def _of(count: int, total: int) -> str:
    """A count with its own denominator. Never a percentage: these denominators are tiny."""
    return "%d of %d" % (count, total)


def _class_sentence(rec: dict) -> str:
    declared, independent = rec["declared"], rec["independent"]
    return (
        "The corpus author's own mutant set: %s killed. A separately authored set: %s killed, "
        "%d not distinguished. Two sets, two denominators, never added together."
        % (_of(declared["counts"]["killed"], declared["scored"]),
           _of(independent["counts"]["killed"], independent["scored"]),
           len(independent["not_distinguished"])))


def _class_card_html(rec: dict) -> str:
    return (
        '<li class="card">\n'
        '<h3><a href="%s/%s/index.html">%s</a></h3>\n'
        "<p>%s</p>\n"
        "</li>"
        % (CLASS_PAGE_PREFIX, _esc(rec["id"]), _esc(rec["id"]), _esc(_class_sentence(rec))))


def _class_section_html(comparisons) -> str:
    if not comparisons:
        return ""
    return (
        '<section id="evidence-classes" aria-labelledby="evidence-classes-heading">\n'
        '<h2 id="evidence-classes-heading">Separate evidence classes</h2>\n'
        "<p>Where one candidate and one corpus were measured with more than one mutant set, "
        "each set keeps its own denominator. They are shown side by side and never added "
        "together.</p>\n"
        '<ul class="cards">\n%s\n</ul>\n'
        "</section>\n"
        % "\n".join(_class_card_html(rec) for rec in comparisons))


def _class_table_html(rec: dict) -> str:
    declared, independent = rec["declared"], rec["independent"]
    authoring = rec["provenance"]["authoring"]
    attempt = rec["attempt"]
    seen = "yes" if authoring.get("candidate_outcomes_seen") else "no"
    rows = (
        ("Mutants written by",
         "the corpus author, as declared in the manifest",
         "%s, as recorded and not authenticated" % authoring.get("mutation_author")),
        ("Author had seen the candidate's outcomes",
         "not recorded for an author declaration",
         seen),
        ("Evidence class",
         "declared",
         "%s; %s" % (attempt["effective_class"],
                     VISIBILITY_WORDS.get(attempt["visibility_status"], "not established"))),
        ("Killed",
         _of(declared["counts"]["killed"], declared["scored"]),
         _of(independent["counts"]["killed"], independent["scored"])),
        ("Kills that rest only on the candidate ending abnormally",
         str(declared["by_termination"]),
         str(independent["by_termination"])),
        ("Survived",
         _of(declared["counts"]["survived"], declared["scored"]),
         _of(independent["counts"]["survived"], independent["scored"])),
        ("Silent",
         _of(declared["counts"]["silent"], declared["scored"]),
         _of(independent["counts"]["silent"], independent["scored"])),
        ("Unproved, outside the denominator",
         str(declared["counts"]["unproved"]),
         str(independent["counts"]["unproved"])),
        ("Positive control",
         "killed: the harness can see a change",
         "killed: the harness can see a change"),
        ("Inert control",
         _inert_words(declared["inert_controls"]),
         _inert_words(independent["inert_controls"])),
        ("Every mutant in this set distinguished",
         "yes" if declared["adequate"] else "no",
         "yes" if independent["adequate"] else "no"),
    )
    body = "\n".join(
        '<tr><th scope="row">%s</th><td>%s</td><td>%s</td></tr>'
        % (_esc(name), _esc(left), _esc(right)) for name, left, right in rows)
    return (
        "<table>\n"
        "<caption>Two mutant sets for one candidate and one corpus, measured at "
        '<span class="mono">%s</span>. Each column has its own denominator. There is no '
        "total.</caption>\n"
        '<thead><tr><td></td><th scope="col">Declared</th>'
        '<th scope="col">Independent</th></tr></thead>\n'
        "<tbody>\n%s\n</tbody>\n"
        "</table>"
        % (_esc(rec["measured_at"]), body))


def _inert_words(count: int) -> str:
    if count == 0:
        return "none declared"
    return "unchanged: a change that must not matter did not move the outcomes"


def _findings_html(rec: dict) -> str:
    """Every ordinary mutant per set, survivors first: the per-mutant view, not a score."""
    parts = []
    for side, title in (("declared", "Declared set"), ("independent", "Independent set")):
        items = []
        for verdict, label, by_termination in rec[side]["ordinary"]:
            word = verdict
            if verdict == "killed" and by_termination:
                word = "killed, but only by the candidate ending abnormally"
            items.append("<li><strong>%s</strong>: %s</li>" % (_esc(word), _esc(label)))
        parts.append("<h3>%s</h3>\n<ul>\n%s\n</ul>" % (title, "\n".join(items)))
    return (
        '<section aria-labelledby="findings-heading">\n'
        '<h2 id="findings-heading">What each set found</h2>\n'
        "<p>Each mutant removes or weakens one rule in the candidate. A survivor is a rule the "
        "corpus does not notice losing.</p>\n"
        "%s\n</section>" % "\n".join(parts))


def _class_links_html(rec: dict, build_commit: str) -> str:
    base = "measurements/%s" % rec["evidence"]
    links = ['<a href="%s/%s/%s/README.md">evidence README</a>'
             % (_esc(BLOB_PREFIX), _esc(build_commit), _esc(base))]
    for rel in rec["files"]:
        links.append('<a href="%s/%s/%s/%s">%s</a>'
                     % (_esc(RAW_PREFIX), _esc(build_commit), _esc(base), _esc(rel), _esc(rel)))
    return '<p class="links">\n%s\n</p>' % "\n".join(links)


def _class_page(rec: dict, build_commit: str) -> str:
    environment = (
        "<p>Both columns ran against the same candidate and corpus trees, with the same "
        'toolchain image <span class="mono">%s</span>, prepared at the same commit. Only '
        "the mutant set differs.</p>" % _esc(rec["toolchain_image"]))
    non_claims = list(CLASS_NON_CLAIMS)
    for item in rec["attempt"]["non_claims"]:
        if item not in non_claims:
            non_claims.append(item)
    body = (
        "<header>\n"
        "<h1>%s: two evidence classes</h1>\n"
        '<p><a href="../../index.html">overview</a></p>\n'
        "</header>\n"
        '<main id="comparison">\n'
        "<p>%s</p>\n"
        "%s\n"
        '<section aria-labelledby="side-by-side-heading">\n'
        '<h2 id="side-by-side-heading">Side by side</h2>\n'
        "%s\n"
        "<p>The engine scores a mutant whose candidate ends abnormally as killed. The row "
        "for kills that rest only on that shows how many such kills each set has, because "
        "an abnormal ending shows the harness can fail, not that the corpus can tell right "
        "from wrong.</p>\n"
        "%s\n"
        "</section>\n"
        "<h2>Evidence</h2>\n"
        "%s\n"
        "%s\n"
        "</main>"
        % (_esc(rec["id"]), _esc(_class_sentence(rec)), _findings_html(rec),
           _class_table_html(rec), environment,
           _class_links_html(rec, build_commit),
           _non_claims_html(None, ceilings=tuple(non_claims))))
    return _shell_page("%s: two evidence classes" % rec["id"], "#comparison",
                       "Skip to comparison", body)


def render_site(root: Path, source_commit: str) -> dict[str, bytes]:
    index_bytes, records = load_listed_records(Path(root))
    attempts_index_bytes, _attempts = load_attempt_index(Path(root))
    class_index_bytes, comparisons = load_class_comparisons(Path(root))
    renderer_bytes = read_bounded_regular_file(Path(__file__))
    digest = compute_projection_digest(
        index_bytes,
        records,
        renderer_bytes,
        source_commit,
        attempts_index_bytes=attempts_index_bytes,
        class_index_bytes=class_index_bytes,
        comparisons=comparisons,
    )
    files = {
        "index.html": _page_body(records, source_commit, digest,
                                 comparisons).encode("utf-8"),
    }
    for comparison in comparisons:
        files["%s/%s/index.html" % (CLASS_PAGE_PREFIX, comparison["id"])] = _class_page(
            comparison, source_commit).encode("utf-8")
    for record in records:
        rec_id = record["directory"]
        kind = record.get("kind", KIND_COMPLETED_MEASUREMENT)
        if kind == KIND_VOID_RUN_ATTEMPT:
            files["runs/%s/index.html" % rec_id] = _void_run_page(record).encode(
                "utf-8"
            )
            files["runs/%s/run-attempt.v0.json" % rec_id] = record["attempt_bytes"]
            continue
        if kind != KIND_COMPLETED_MEASUREMENT:
            raise PublicationError("unknown publication kind %r" % kind)
        findings = actionable_findings(record)
        files["runs/%s/index.html" % rec_id] = _run_page(
            record, findings, source_commit
        ).encode("utf-8")
        for finding in findings:
            rel = "runs/%s/rules/%s.html" % (rec_id, finding["path_id"])
            files[rel] = _rule_page(record, finding, source_commit).encode("utf-8")
    return files


def render_html(root: Path, source_commit: str) -> str:
    return render_site(root, source_commit)["index.html"].decode("utf-8")


def _meta_content(page: str, name: str) -> str:
    marker = 'name="%s" content="' % name
    start = page.find(marker)
    if start < 0:
        raise ValueError("missing %s" % name)
    start += len(marker)
    end = page.find('"', start)
    return page[start:end]


def projection_digest_from_html(page: str) -> str:
    return _meta_content(page, "projection-digest")


def source_commit_from_html(page: str) -> str:
    return _meta_content(page, "source-commit")


generation_digest_from_html = projection_digest_from_html


def _git_head(root: Path) -> str:
    out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True)
    return out.strip()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _is_preserved_rel(rel: str) -> bool:
    return rel == "CNAME"


def _list_site_files(site_root: Path) -> dict[str, Path]:
    found = {}
    if not site_root.exists():
        return found
    root_st = os.lstat(site_root)
    if stat.S_ISLNK(root_st.st_mode) or not stat.S_ISDIR(root_st.st_mode):
        raise PublicationError("site path is not a regular file: %s" % site_root)
    for dirpath, dirnames, filenames in os.walk(site_root, followlinks=False):
        base = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            path = base / name
            mode = os.lstat(path).st_mode
            if stat.S_ISLNK(mode):
                raise PublicationError("site path is not a regular file: %s" % path)
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise PublicationError("site path is not a regular file: %s" % path)
            rel = path.relative_to(site_root).as_posix()
            if _is_preserved_rel(rel):
                continue
            found[rel] = path
    return dict(sorted(found.items()))


def _write_site(site_root: Path, files: dict[str, bytes]) -> None:
    found = _list_site_files(site_root)
    surplus = [rel for rel in found if rel not in files]
    if surplus:
        raise PublicationError("surplus generated site files: %s" % ", ".join(surplus))
    for rel, data in files.items():
        _atomic_write(site_root / rel, data)


def _check_site(site_root: Path, expected: dict[str, bytes]) -> None:
    found = _list_site_files(site_root)
    missing = [rel for rel in expected if rel not in found]
    surplus = [rel for rel in found if rel not in expected]
    if missing:
        raise PublicationError("missing generated site files: %s" % ", ".join(missing))
    if surplus:
        raise PublicationError("surplus generated site files: %s" % ", ".join(surplus))
    for rel, data in expected.items():
        current = read_bounded_regular_file(found[rel])
        if current != data:
            raise PublicationError("stale generated site file: %s" % rel)



def _git_run(root: Path, args: list[str]) -> int:
    return subprocess.run(
        args,
        cwd=str(root),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode


def _git_oid(root: Path, spec: str) -> str | None:
    proc = subprocess.run(
        ["git", "rev-parse", "--verify", spec],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        return None
    oid = proc.stdout.strip()
    return oid or None


def _hash_object_oid(root: Path, data: bytes) -> str:
    proc = subprocess.run(
        ["git", "hash-object", "--stdin"],
        cwd=str(root),
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        raise PublicationError("git hash-object failed")
    oid = proc.stdout.decode("ascii", "replace").strip()
    if not oid:
        raise PublicationError("git hash-object returned no object id")
    return oid


def _require_recorded_link_commit(root: Path, recorded: str, records: list[dict],
                                  comparisons=()) -> None:
    """Refuse an implicit --check commit that is not a real ancestor with matching bytes."""
    if not _looks_like_commit(recorded):
        raise PublicationError("recorded source-commit is not a 40-hex digest")
    if _git_run(root, ["git", "cat-file", "-e", recorded + "^{commit}"]) != 0:
        raise PublicationError("recorded source-commit is not a git commit")
    if _git_run(root, ["git", "merge-base", "--is-ancestor", recorded, "HEAD"]) != 0:
        raise PublicationError("recorded source-commit is not an ancestor of HEAD")
    for record in records:
        if record.get("kind") == KIND_VOID_RUN_ATTEMPT:
            continue
        source_rel = "measurements/%s/source.json" % record["directory"]
        for rel in (record["report_rel"], source_rel, record["review_rel"]):
            recorded_oid = _git_oid(root, "%s:%s" % (recorded, rel))
            if recorded_oid is None:
                raise PublicationError("recorded source-commit is missing %s" % rel)
            current = read_bounded_regular_file(root / rel)
            current_oid = _hash_object_oid(root, current)
            if recorded_oid != current_oid:
                raise PublicationError("recorded source-commit bytes differ for %s" % rel)
    # A comparison page links every byte it binds, plus the evidence README, at that commit.
    for comparison in comparisons:
        base = "measurements/%s" % comparison["evidence"]
        for rel in list(comparison["files"]) + ["README.md"]:
            path = "%s/%s" % (base, rel)
            recorded_oid = _git_oid(root, "%s:%s" % (recorded, path))
            if recorded_oid is None:
                raise PublicationError("recorded source-commit is missing %s" % path)
            current_oid = _hash_object_oid(root, read_bounded_regular_file(root / path))
            if recorded_oid != current_oid:
                raise PublicationError("recorded source-commit bytes differ for %s" % path)

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render the publication page")
    parser.add_argument("--root", default=".", type=Path)
    parser.add_argument("--out", default="site/index.html", type=Path)
    parser.add_argument("--source-commit", default="")
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare every generated site file and do not write",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    site_root = out.parent
    if args.check:
        existing = read_bounded_regular_file(out)
        if args.source_commit:
            recorded = args.source_commit
        else:
            recorded = source_commit_from_html(existing.decode("utf-8"))
            _index_bytes, records = load_listed_records(root)
            _class_index_bytes, comparisons = load_class_comparisons(root)
            _require_recorded_link_commit(root, recorded, records, comparisons)
        expected = render_site(root, recorded)
        _check_site(site_root, expected)
        return 0
    source_commit = args.source_commit or _git_head(root)
    _write_site(site_root, render_site(root, source_commit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
