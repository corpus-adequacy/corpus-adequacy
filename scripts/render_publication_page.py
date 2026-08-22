#!/usr/bin/env python3
"""Render a no-JS static overview of index-listed report.v0 records."""

from __future__ import annotations

import argparse
import json
import hashlib
import html
import os
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
)

INDEX_REL = "publications/index.v0.json"
INDEX_SCHEMA = "corpus-adequacy.publication-index.v0"
RAW_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/raw"
BLOB_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/blob"
ISSUES_INTAKE = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=add-corpus.yml"
ISSUES_PUBLISH = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml"
HEX64 = set("0123456789abcdef")
DISPLAY_VERDICTS = ("killed", "survived", "silent", "unproved")
CEILING_LINES = (
    "not a leaderboard/badge/certification/trust score/automatic admission/completeness of declared inventory",
    "not authenticity/endorsement/implementation safety",
    'silent:0 without diagnostic_channel_declared is not "no silent rules"',
    "score_percent is percent of author-declared in-scope rules, not of the implementation",
)


class PublicationError(ValueError):
    """Fail-closed publication load or check error."""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _looks_like_repo(value: str) -> bool:
    if not isinstance(value, str) or value.count("/") != 1:
        return False
    owner, name = value.split("/", 1)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    return bool(owner) and bool(name) and set(owner) <= allowed and set(name) <= allowed


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
        if doc.get(name) != derived[name]:
            raise PublicationError(
                "displayed %s %r does not match mutants[] count %r"
                % (name, doc.get(name), derived[name])
            )
    derived_control = _control_status_from_rows(mutants)
    if doc.get("control_status") != derived_control:
        raise PublicationError(
            "control_status %r does not match control rows %r"
            % (doc.get("control_status"), derived_control)
        )


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
    diagnostic = bool(doc.get("diagnostic_channel_declared"))
    silent = doc.get("silent")
    silent_label = "not measured" if (silent == 0 and not diagnostic) else str(silent)
    control = doc.get("control_status")
    rel_report = "measurements/%s/report.v0.json" % directory
    command = "python3 corpus_adequacy.py measurements/%s/manifest.json --json" % directory
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
    }


def load_publication_index(root: Path) -> tuple[bytes, list[dict]]:
    index_path = Path(root) / INDEX_REL
    raw, doc = _load_json_object(index_path, label=INDEX_REL)
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


def load_listed_records(root: Path) -> tuple[bytes, list[dict]]:
    """Load only index-listed measurements. Unlisted dirs are not published."""
    root = Path(root)
    index_bytes, entries = load_publication_index(root)
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
    return index_bytes, records


def discover_records(root: Path) -> list[dict]:
    """Index-bound records only. Kept as the listed-record loader name."""
    _index_bytes, records = load_listed_records(root)
    return records


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


def _card_html(record: dict, build_commit: str) -> str:
    raw_href = "%s/%s/%s" % (RAW_PREFIX, build_commit, record["report_rel"]) if _looks_like_commit(build_commit) else record["report_rel"]
    review_href = "%s/%s/%s" % (BLOB_PREFIX, build_commit, record["review_rel"]) if _looks_like_commit(build_commit) else record["review_rel"]
    source_href = _source_commit_url(record)
    if not source_href:
        raise PublicationError("source commit URL is missing")
    source_link = (
        '<a href="%s">source commit %s</a>' % (_esc(source_href), _esc(record["source_commit"]))
    )
    silent_value = record["silent_label"]
    counts = (
        ("killed", record["killed"], "killed %s" % record["killed"]),
        ("survived", record["survived"], "survived %s" % record["survived"]),
        ("silent", silent_value, "silent %s" % silent_value),
        ("unproved", record["unproved"], "unproved %s" % record["unproved"]),
        ("control_status", record["control_status"], "control_status %s" % record["control_status"]),
    )
    count_html = []
    for label, value, accessible in counts:
        count_html.append(
            '<li class="count" aria-label="%s"><span class="count-label">%s</span> '
            '<span class="count-value">%s</span></li>'
            % (_esc(accessible), _esc(label), _esc(value))
        )
    return (
        '<li class="card">\n'
        '<h3>%s</h3>\n'
        '<p>corpus id <span class="mono">%s</span></p>\n'
        '<p>source commit <span class="mono">%s</span></p>\n'
        '<p>adapter <span class="mono">%s</span> · runner <span class="mono">%s</span></p>\n'
        '<p>report digest <span class="mono">%s</span></p>\n'
        '<p>Copyable command</p>\n'
        '<pre><code>%s</code></pre>\n'
        '<ul class="counts">%s</ul>\n'
        '<p class="plain">%s</p>\n'
        '<p class="links">\n'
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
            _esc(record["command"]),
            "".join(count_html),
            _esc(_plain_sentence(record)),
            _esc(raw_href),
            source_link,
            _esc(review_href),
        )
    )


def _page_body(records: list[dict], source_commit: str, projection_digest: str) -> str:
    collected = []
    for rec in records:
        collected.extend(rec.get("non_claims") or [])
    collected.extend(CEILING_LINES)
    seen = []
    for item in collected:
        if item not in seen:
            seen.append(item)
    non_claims = "\n".join("<li>%s</li>" % _esc(item) for item in seen)
    cards = "\n".join(_card_html(rec, source_commit) for rec in records)
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="projection-digest" content="%s">
<meta name="source-commit" content="%s">
<title>Published corpus-adequacy measurements</title>
<style>
:root { color-scheme: light; }
html, body { max-width: 100%%; overflow-x: hidden; margin: 0; }
body { font-family: system-ui, sans-serif; line-height: 1.45; color: #1a1a1a; background: #f7f5f0; padding: 1rem; }
a:focus, button:focus, .skip:focus { outline: 3px solid #0033aa; outline-offset: 2px; }
.skip { position: absolute; left: -999px; top: 0; background: #fff; padding: 0.5rem; }
.skip:focus { left: 1rem; z-index: 2; }
h1, h2, h3 { line-height: 1.2; }
.non-claims { max-width: 46rem; }
.ctas { display: flex; flex-wrap: wrap; gap: 0.75rem; margin: 1rem 0 1.5rem; }
.ctas a { display: inline-block; padding: 0.5rem 0.75rem; background: #0033aa; color: #fff; text-decoration: underline; }
.cards { list-style: none; padding: 0; margin: 0; display: flex; flex-wrap: wrap; gap: 1rem; }
.card { box-sizing: border-box; width: min(100%%, 390px); max-width: 100%%; background: #fff; border: 2px solid #1a1a1a; padding: 1rem; }
.counts { list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem; }
.count { border: 1px solid #333; padding: 0.35rem 0.5rem; min-width: 5rem; }
.count-label { display: block; font-size: 0.8rem; }
.mono, pre { overflow-wrap: anywhere; word-break: break-word; }
pre { background: #eee; padding: 0.5rem; user-select: text; }
.links a { margin-right: 0.75rem; }
</style>
</head>
<body>
<a class="skip" href="#results">Skip to results</a>
<header>
<h1>Published measurements</h1>
<p>Committed <code>report.v0</code> records listed in <code>publications/index.v0.json</code>.</p>
</header>
<section class="non-claims" aria-labelledby="non-claims-heading">
<h2 id="non-claims-heading">Non-claims</h2>
<ul>
%s
</ul>
</section>
<nav class="ctas" aria-label="intake and publication forms">
<a href="%s">Request source intake</a>
<a href="%s">Hand off a completed measurement</a>
</nav>
<main id="results">
<h2>Committed records</h2>
<ul class="cards">
%s
</ul>
</main>
</body>
</html>
""" % (
        _esc(projection_digest),
        _esc(source_commit),
        non_claims,
        _esc(ISSUES_INTAKE),
        _esc(ISSUES_PUBLISH),
        cards,
    )


def compute_projection_digest(
    index_bytes: bytes,
    records: list[dict],
    renderer_bytes: bytes,
) -> str:
    # projection-digest is SHA-256 of this concatenation, in this order:
    #   publications/index.v0.json bytes
    #   then each listed record in index order:
    #     measurements/<id>/report.v0.json bytes
    #     measurements/<id>/source.json bytes
    #   then scripts/render_publication_page.py source bytes
    hasher = hashlib.sha256()
    hasher.update(index_bytes)
    for record in records:
        hasher.update(record["report_bytes"])
        hasher.update(record["source_bytes"])
    hasher.update(renderer_bytes)
    return hasher.hexdigest()


def render_html(root: Path, source_commit: str) -> str:
    index_bytes, records = load_listed_records(Path(root))
    renderer_bytes = read_bounded_regular_file(Path(__file__))
    digest = compute_projection_digest(index_bytes, records, renderer_bytes)
    return _page_body(records, source_commit, digest)


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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render the publication page")
    parser.add_argument("--root", default=".", type=Path)
    parser.add_argument("--out", default="site/index.html", type=Path)
    parser.add_argument("--source-commit", default="")
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare checked-in --out to a freshly rendered page and do not write",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    if args.check:
        existing = read_bounded_regular_file(out)
        recorded = args.source_commit or source_commit_from_html(existing.decode("utf-8"))
        rendered = render_html(root, recorded).encode("utf-8")
        if existing != rendered:
            raise PublicationError("checked-in %s does not match a fresh render" % out)
        return 0
    source_commit = args.source_commit or _git_head(root)
    rendered = render_html(root, source_commit).encode("utf-8")
    _atomic_write(out, rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
