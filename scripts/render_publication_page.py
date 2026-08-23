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
RAW_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/raw"
BLOB_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/blob"
ISSUES_INTAKE = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=add-corpus.yml"
ISSUES_PUBLISH = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml"
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


def _require_portable_public_text(value: str, *, field: str) -> str:
    """Refuse host markers or absolute local paths before a record is public."""
    if not isinstance(value, str) or not value:
        raise PublicationError("%s must be a non-empty string" % field)
    if any(marker in value for marker in HOST_MARKERS):
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
    if "diagnostic_channel_declared" not in doc:
        return False
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
    if doc.get("control_status") != "not-run":
        raise PublicationError("control_status must be not-run")
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


def discover_records(root: Path) -> list[dict]:
    """Index-bound records only. Kept as the listed-record loader name."""
    _index_bytes, records = load_listed_records(root)
    return records


def actionable_findings(record: dict) -> list[dict]:
    """Actionable rows from survivor_findings, addressed by report mutants[] index."""
    projected = survivor_findings(record["doc"])
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
        }
        if "anchor_excerpt" in finding:
            item["anchor_excerpt"] = finding["anchor_excerpt"]
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
        % ca.VERSION
    )


def _clone_command() -> str:
    return (
        "git clone --depth 1 --branch v%s "
        "https://github.com/corpus-adequacy/corpus-adequacy.git"
        % ca.VERSION
    )


def _first_run_route(records: list[dict]) -> str:
    lines = [_clone_command(), "cd corpus-adequacy"]
    lines.extend(_inspect_command(record) for record in records)
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
    tag = "v%s" % ca.VERSION
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
        "Baseline unproved. Control not run. No scored mutants. No score."
    )


def _void_digest_html(record: dict) -> str:
    rows = (
        ("raw report SHA-256", record["raw_report_sha256"]),
        ("execution commit", record["execution_commit"]),
        ("prepare digest", record["prepare_sha256"]),
        ("authorize digest", record["authorize_sha256"]),
        ("attempt digest", record["digest"]),
    )
    return "\n".join(
        '<p>%s <span class="mono">%s</span></p>' % (_esc(label), _esc(value))
        for label, value in rows
    )


def _void_failures_html(record: dict) -> str:
    items = [
        '<li><span class="mono">%s</span></li>' % _esc(item)
        for item in record["failures"]
    ]
    return (
        "<h2>Retained failure</h2>\n"
        "<ul>\n%s\n</ul>" % "\n".join(items)
    )


def _void_attempt_href(record: dict, build_commit: str) -> str:
    if _looks_like_commit(build_commit):
        return "%s/%s/%s" % (BLOB_PREFIX, build_commit, record["attempt_rel"])
    return record["attempt_rel"]


def _void_links_html(record: dict, build_commit: str) -> str:
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
            _esc(_void_attempt_href(record, build_commit)),
        )
    )


def _void_card_html(record: dict, build_commit: str) -> str:
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
            _void_failures_html(record),
            _void_links_html(record, build_commit),
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


def _page_body(records: list[dict], source_commit: str, projection_digest: str) -> str:
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
            % "\n".join(_void_card_html(rec, source_commit) for rec in attempts)
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
%s%s</main>
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
    )


def compute_projection_digest(
    index_bytes: bytes,
    records: list[dict],
    renderer_bytes: bytes,
    source_commit: str,
    attempts_index_bytes: bytes = b"",
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
    for record in records:
        kind = record.get("kind", KIND_COMPLETED_MEASUREMENT)
        if kind == KIND_VOID_RUN_ATTEMPT:
            _add(b"attempt", record["attempt_bytes"])
        elif kind == KIND_COMPLETED_MEASUREMENT:
            _add(b"report", record["report_bytes"])
            _add(b"source", record["source_bytes"])
        else:
            raise PublicationError("unknown publication kind %r" % kind)
    _add(b"renderer", renderer_bytes)
    _add(b"source_commit", source_commit.encode("ascii"))
    _add(b"version", ca.VERSION.encode("ascii"))
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


def _void_run_page(record: dict, build_commit: str) -> str:
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
        '<main id="attempt">\n'
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
            _void_failures_html(record),
            _esc(execution_href),
            _esc(record["execution_commit"]),
            _esc(_void_attempt_href(record, build_commit)),
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
    excerpt = ""
    if finding.get("anchor_excerpt"):
        excerpt = (
            '<p>anchor <span class="mono">%s</span></p>\n'
            % _esc(finding["anchor_excerpt"])
        )
    body = (
        "<header>\n"
        "<h1>%s</h1>\n"
        '<p><a href="../../../index.html">overview</a> · '
        '<a href="../">run detail</a></p>\n'
        "</header>\n"
        "%s\n"
        '<main id="finding" class="finding">\n'
        "<p>verdict <span>%s</span></p>\n"
        "<p>group <span class=\"mono\">%s</span></p>\n"
        "<p>how %s</p>\n"
        "<p>obligation %s</p>\n"
        "<p>moved <span class=\"mono\">%s</span></p>\n"
        "%s%s"
        "%s\n"
        "</main>"
        % (
            _esc(finding["rule"]),
            _non_claims_html([record]),
            _esc(finding["verdict"]),
            _esc(finding["group"]),
            _esc(finding["how"]),
            _esc(finding["obligation"]),
            _esc(finding["moved"]),
            diagnostic,
            excerpt,
            _evidence_links_html(record, build_commit),
        )
    )
    return _shell_page(
        "%s — %s" % (finding["rule"], record["directory"]),
        "#finding",
        "Skip to finding",
        body,
    )


def render_site(root: Path, source_commit: str) -> dict[str, bytes]:
    index_bytes, records = load_listed_records(Path(root))
    attempts_index_bytes, _attempts = load_attempt_index(Path(root))
    renderer_bytes = read_bounded_regular_file(Path(__file__))
    digest = compute_projection_digest(
        index_bytes,
        records,
        renderer_bytes,
        source_commit,
        attempts_index_bytes=attempts_index_bytes,
    )
    files = {
        "index.html": _page_body(records, source_commit, digest).encode("utf-8"),
    }
    for record in records:
        rec_id = record["directory"]
        kind = record.get("kind", KIND_COMPLETED_MEASUREMENT)
        if kind == KIND_VOID_RUN_ATTEMPT:
            files["runs/%s/index.html" % rec_id] = _void_run_page(
                record, source_commit
            ).encode("utf-8")
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

def _require_recorded_link_commit(root: Path, recorded: str, records: list[dict]) -> None:
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
            _require_recorded_link_commit(root, recorded, records)
        expected = render_site(root, recorded)
        _check_site(site_root, expected)
        return 0
    source_commit = args.source_commit or _git_head(root)
    _write_site(site_root, render_site(root, source_commit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
