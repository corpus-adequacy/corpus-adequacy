#!/usr/bin/env python3
"""Render a no-JS static overview of validated report.v0 records."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import subprocess
import sys
from pathlib import Path

REPO_SCHEMA = "corpus-adequacy.report.v0"
RAW_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/raw"
BLOB_PREFIX = "https://github.com/corpus-adequacy/corpus-adequacy/blob"
ISSUES_INTAKE = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=add-corpus.yml"
ISSUES_PUBLISH = "https://github.com/corpus-adequacy/corpus-adequacy/issues/new?template=publish-measurement.yml"
PLACEHOLDER = "0" * 64
CEILING_LINES = (
    "not a leaderboard/badge/certification/trust score/automatic admission/completeness of declared inventory",
    "not authenticity/endorsement/implementation safety",
    'silent:0 without diagnostic_channel_declared is not "no silent rules"',
    "score_percent is percent of author-declared in-scope rules, not of the implementation",
)


def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_report_rows(doc: dict) -> None:
    if not isinstance(doc, dict):
        raise ValueError("report is not an object")
    if doc.get("schema") != REPO_SCHEMA:
        raise ValueError("report schema is not corpus-adequacy.report.v0")
    mutants = doc.get("mutants")
    if not isinstance(mutants, list) or not mutants:
        raise ValueError("report mutants[] is missing")
    for row in mutants:
        if not isinstance(row, dict):
            raise ValueError("mutant row is not an object")
        group = row.get("group")
        label = row.get("label")
        verdict = row.get("verdict")
        if not group or not label or not verdict:
            raise ValueError("mutant row missing group/label/verdict")


def _looks_like_repo(value: str) -> bool:
    if not isinstance(value, str) or value.count("/") != 1:
        return False
    owner, name = value.split("/", 1)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    return bool(owner) and bool(name) and set(owner) <= allowed and set(name) <= allowed


def _looks_like_commit(value: str) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value)


def _adapter_name(source: dict, report_dir: Path) -> str:
    schema = source.get("schema") if isinstance(source, dict) else None
    if isinstance(schema, str) and "tersign-evidence-record" in schema:
        return "tersign_evidence_record"
    if isinstance(schema, str) and schema.startswith("corpus-adequacy.") and schema.endswith(".source.v0"):
        mid = schema[len("corpus-adequacy.") : -len(".source.v0")]
        if mid:
            return mid.replace("-", "_")
    return report_dir.name


def load_record(report_path: Path) -> dict:
    raw = report_path.read_bytes()
    doc = json.loads(raw.decode("utf-8"))
    _require_report_rows(doc)
    source_path = report_path.parent / "source.json"
    source = {}
    if source_path.is_file():
        source = json.loads(source_path.read_text(encoding="utf-8"))
        if not isinstance(source, dict):
            source = {}
    digest = _sha256_bytes(raw)
    directory = report_path.parent.name
    repository = source.get("repository") if isinstance(source.get("repository"), str) else ""
    source_commit = source.get("commit") if isinstance(source.get("commit"), str) else ""
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
        "doc": doc,
        "source": source,
        "repository": repository,
        "source_commit": source_commit,
        "non_claims": non_claims,
        "adapter": _adapter_name(source, report_path.parent),
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


def discover_records(root: Path) -> list[dict]:
    measurements = root / "measurements"
    if not measurements.is_dir():
        return []
    records = []
    for entry in measurements.iterdir():
        if not entry.is_dir():
            continue
        report = entry / "report.v0.json"
        if not report.is_file():
            continue
        try:
            records.append(load_record(report))
        except (ValueError, json.JSONDecodeError, OSError):
            continue
    records.sort(key=lambda rec: (rec["directory"], rec["digest"]))
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
    source_link = (
        '<a href="%s">source commit %s</a>' % (_esc(source_href), _esc(record["source_commit"]))
        if source_href
        else "<span>source commit %s</span>" % _esc(record["source_commit"])
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
        '<ul class="counts">%s</ul>\n'
        '<p class="plain">%s</p>\n'
        '<p class="links">\n'
        '<a href="%s">raw report.v0.json</a>\n'
        '%s\n'
        '<a href="%s">review</a>\n'
        '</p>\n'
        '<p>Copyable command</p>\n'
        '<pre><code>%s</code></pre>\n'
        '</li>'
        % (
            _esc(record["directory"]),
            _esc(record["directory"]),
            _esc(record["source_commit"]),
            _esc(record["adapter"]),
            _esc(record["runner"]),
            _esc(record["digest"]),
            "".join(count_html),
            _esc(_plain_sentence(record)),
            _esc(raw_href),
            source_link,
            _esc(review_href),
            _esc(record["command"]),
        )
    )


def _page_body(records: list[dict], source_commit: str, generation_digest: str) -> str:
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
<meta name="generation-digest" content="%s">
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
<p>Committed <code>report.v0</code> records only. Failed, partial, and unavailable outcomes stay representable.</p>
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
        _esc(generation_digest),
        _esc(source_commit),
        non_claims,
        _esc(ISSUES_INTAKE),
        _esc(ISSUES_PUBLISH),
        cards,
    )


def render_html(root: Path, source_commit: str) -> str:
    records = discover_records(Path(root))
    draft = _page_body(records, source_commit, PLACEHOLDER)
    digest = _sha256_bytes(draft.encode("utf-8"))
    return draft.replace(PLACEHOLDER, digest, 1)


def generation_digest_from_html(page: str) -> str:
    marker = 'name="generation-digest" content="'
    start = page.find(marker)
    if start < 0:
        raise ValueError("missing generation-digest")
    start += len(marker)
    end = page.find('"', start)
    return page[start:end]


def _git_head(root: Path) -> str:
    out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root), text=True)
    return out.strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render the publication page")
    parser.add_argument("--root", default=".", type=Path)
    parser.add_argument("--out", default="site/index.html", type=Path)
    parser.add_argument("--source-commit", default="")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    source_commit = args.source_commit or _git_head(root)
    html_text = render_html(root, source_commit)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(html_text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
