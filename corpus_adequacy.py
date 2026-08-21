#!/usr/bin/env python3
"""Mutation adequacy for a published conformance corpus, driven by a manifest.

Standard library only. No Assay import, no pip install, no network.

    python3 corpus_adequacy.py <manifest.json>
    python3 corpus_adequacy.py <manifest.json> --json

WHY A CORPUS NEEDS THIS AND A TEST SUITE DOES NOT
-------------------------------------------------
Outcome coverage is not rule coverage. A corpus can reach every declared
outcome while some rule never decides anything, because another rule reaches
the same outcome first on every vector it would have caught. Mutation adequacy
is the criterion that finds that, and it outperforms structural criteria such
as line and branch coverage for exactly this question.

The bar here is higher than the usual one. In ordinary mutation testing the
artifact under test is a test suite, a surviving mutant is a gap in confidence,
and a score near 80% is a working target. Here the artifact under test is a
*published corpus whose digest is the contract*. A surviving mutant means an
implementer can delete that rule, reproduce the pinned digest, and be
indistinguishable from a conforming implementation. That is not a confidence
gap, it is a hole in the contract. So the required score is 100% of
non-equivalent mutants.

WHAT THIS TOOL CAN AND CANNOT GENERALIZE, STATED PLAINLY
---------------------------------------------------------
It cannot infer a corpus's rules from arbitrary source. That would be a static
analysis project, and a tool that guessed would report a score it had not
earned. What is portable is the *method*, so a corpus that wants to be measured
declares its own mutants in a manifest:

  - one mutant per DECLARED RULE, not per line. A surviving mutant then names
    the rule an implementation could omit, instead of naming a line number.
    Generic operators would produce mostly-equivalent noise over rules this
    small.
  - ordinal axes are PERMUTED, not deleted. Deletion is the wrong operator for
    a ladder: the ordering lives in a table a comparison reads, not in a branch
    a mutant can cut. Declare flatten-to-top, flatten-to-bottom and invert.
  - equivalent mutants are DECLARED WITH A REASON, never inferred. Deciding
    mutant equivalence is undecidable in general, so a tool that claimed to
    detect it would be lying.
    - child termination is classified before stdout is parsed. Default
    accepted_exit_codes is [0]. A parseable report on an undeclared code,
    a signal, or a missing code is not an outcome. An observed unexpected
    exit or signal on an ordinary mutant may be a kill with that class
    named; a control abnormality is control-error and is not a score.

WHAT THE PERCENTAGE IS A PERCENTAGE OF
---------------------------------------
100% here means 100% of the rules THE AUTHOR DECLARED. It does not mean 100% of
the rules the implementation has. A rule nobody declared is invisible to this
check, and there is no honest mechanical fix for that inside a manifest-driven
design: the manifest is written by the same hand as the corpus.

That is why the report never prints a bare percentage. It prints the numerator,
the denominator, the count declared equivalent, the count declared out of scope,
and the ratio between excluded and measured. A score reported without those is a
percentage target wearing a different coat, because an author can exclude almost
everything and still print 100%.

For the same reason an out_of_scope mutant must carry a stated reason. It leaves
the denominator exactly as a declared-equivalent one does, so it carries the same
obligation.

SELF-COVERAGE, APPLIED TO THIS CHECK
-------------------------------------
A group present in the corpus that declares no mutant is the same defect one
level up: the check would silently cover less than its name claims. That is a
hard failure here, not a warning.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import subprocess
import tempfile
try:
    import fcntl                       # POSIX advisory locks
except ImportError:                          # pragma: no cover - non-POSIX
    fcntl = None
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bounded_run import (  # noqa: E402
    OUTPUT_CAP_BYTES, _OutputTooLarge, _run_capped,
)
from isolated_tree import IsolationError, IsolatedMutationTree  # noqa: E402

SCHEMA = "corpus-adequacy.manifest.v0"
ERROR_SCHEMA = "corpus-adequacy.error.v0"
REPORT_SCHEMA = "corpus-adequacy.report.v0"
# One place. The report, --version, and CHANGELOG name this.
# A tag v+VERSION exists only after the documented cut.
# A SHA pin is exact and opaque; this is the name a measurement can quote.
VERSION = "0.1.0"

# Every shipped runtime source, in one ordered explicit set. HEAD byte equality
# and the content digest read this same tuple, so a runtime file added without
# declaring it here cannot be silently excluded from tool identity. Enumerating
# sys.modules instead would absorb whatever the measured candidate imports.
TOOL_SOURCE_PATHS = (
    "bounded_run.py",
    "corpus_adequacy.py",
    "isolated_tree.py",
    "module_child.py",
)
# The digest is domain-tagged so it cannot be confused with a bare concatenation
# of the same bytes under some other rule.
TOOL_SOURCE_DIGEST_TAG = b"corpus-adequacy.tool-source.v0\n"
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class ManifestError(Exception):
    """The manifest does not describe a measurable corpus."""


class ReportEncodingError(ValueError):
    """A successful report cannot be represented by the v0 byte contract."""


def require_shape(obj, expected, where: str) -> None:
    """One boundary: a container is the declared JSON kind, or the run does not start.

    Walking .items() or a non-object entry is a traceback, not a measurement refusal.
    """
    if expected is dict:
        if not isinstance(obj, dict):
            raise ManifestError("%s must be an object, got %s" % (where, type(obj).__name__))
        return
    if expected is list:
        if not isinstance(obj, list):
            raise ManifestError("%s must be an array, got %s" % (where, type(obj).__name__))
        return
    raise TypeError("require_shape expected dict or list")


def error_envelope(exc: BaseException) -> dict:
    """Parseable --json body for a run that never produced a report."""
    return {
        "schema": ERROR_SCHEMA,
        "ok": False,
        "error": "could not measure: %s" % exc,
        "exit": 2,
    }


def _git_bytes(root: Path, *args: str) -> subprocess.CompletedProcess:
    """Plumbing, bytes out. Porcelain is never the source of truth here.

    `git status` answers whether git considers a path modified, which is an
    index-aware question. Tool identity asks a different one: are the bytes on
    disk the bytes HEAD committed. Only plumbing can answer that directly.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, timeout=10, env=env,
    )


def _runtime_source_bytes(root: Path) -> list | None:
    """Raw bytes of every declared runtime path, in declared order.

    None when the executing surface is not the declared surface: a missing
    path, a symlink, a directory, or a path that resolves outside the tool
    root. Those bytes are not this checkout's bytes, so there is nothing
    honest to attribute to HEAD and nothing honest to digest.
    """
    try:
        root_real = root.resolve()
    except OSError:
        return None
    collected = []
    for rel in TOOL_SOURCE_PATHS:
        path = root / rel
        try:
            st = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(st.st_mode):
            return None
        try:
            if path.resolve().parent != root_real:
                return None
            collected.append((rel, path.read_bytes()))
        except OSError:
            return None
    return collected


def _tool_content_digest(sources: list | None) -> str | None:
    """sha256 over an ordered, length-delimited (path, bytes) stream.

    Length delimiting is what makes the stream unambiguous: without it a
    rename plus a matching edit could produce one concatenation two ways.
    """
    if sources is None:
        return None
    digest = hashlib.sha256()
    digest.update(TOOL_SOURCE_DIGEST_TAG)
    for rel, data in sources:
        raw = rel.encode("utf-8")
        digest.update(b"%d\n" % len(raw))
        digest.update(raw)
        digest.update(b"%d\n" % len(data))
        digest.update(data)
    return "sha256:" + digest.hexdigest()


def _tool_source_state(root: Path, sources: list | None) -> tuple:
    """(state, commit). exact only when every declared runtime file is
    byte-identical to `HEAD:./<path>`.

    Two failures are kept apart. `unresolved` means the comparison could not
    be established: no git, an unresolvable HEAD, a HEAD that is not a commit
    id, or a `git show` that failed. `dirty` means it was established and the
    worktree differs. Neither yields a commit, because a commit id next to
    bytes it does not name is the defect this function exists to remove.

    `HEAD:./<path>` is resolved relative to the tool root, so a copy of this
    tool sitting inside an unrelated repository compares against nothing and
    reports unresolved rather than borrowing that repository's HEAD.

    A checkout filter that rewrites line endings on the way to the worktree
    makes those bytes genuinely differ from the committed bytes; this reports
    dirty there. That direction is the safe one: never a false exact.
    """
    try:
        head = _git_bytes(root, "rev-parse", "HEAD")
    except (OSError, subprocess.TimeoutExpired):
        return "unresolved", None
    if head.returncode != 0:
        return "unresolved", None
    commit = head.stdout.decode("utf-8", "replace").strip()
    if _COMMIT_RE.match(commit) is None:
        return "unresolved", None
    committed = {}
    for rel in TOOL_SOURCE_PATHS:
        try:
            shown = _git_bytes(root, "show", "HEAD:./%s" % rel)
        except (OSError, subprocess.TimeoutExpired):
            return "unresolved", None
        if shown.returncode != 0:
            return "unresolved", None
        committed[rel] = shown.stdout
    if sources is None:
        return "dirty", None
    for rel, data in sources:
        if data != committed[rel]:
            return "dirty", None
    return "exact", commit


def tool_identity(root: Path | None = None) -> dict:
    """One producer. What a pinned measurement may claim about its own bytes.

    CI pins this tool by commit SHA. That is exact and opaque; the version
    constant is the name a report can quote. `tool_commit` stays semantically
    a commit: it is the 40-hex HEAD only when every declared runtime source is
    byte-identical to that commit, and null otherwise. `tool_source_state`
    says which case it was, and `tool_content_sha256` keeps the executing
    bytes addressable even when no commit may be named. A checkout without
    `.git` still carries the version and the digest.

    Reading the sources and comparing them are not one instant, so the
    snapshot is re-read once the comparison is done and any observed change
    fails closed. That is a narrowed window, not an atomic snapshot: a change
    made and reverted entirely between the two reads is not detectable, and in
    that case the bytes on disk did equal HEAD at both observations.

    Non-claims: this is not an attestation, signature, or SBOM; it does not
    prove the recorded bytes are the code objects already loaded in
    sys.modules; and it does not make the checkout or its environment
    reproducible.
    """
    root = Path(__file__).resolve().parent if root is None else Path(root)
    sources = _runtime_source_bytes(root)
    state, commit = _tool_source_state(root, sources)
    if state == "exact" and _runtime_source_bytes(root) != sources:
        # The snapshot was read before the comparison ran, so the bytes could
        # move underneath it. Re-reading proves the snapshot still describes
        # the disk. It differs here, and the snapshot equalled HEAD, so the
        # bytes now on disk provably do not: dirty is measured, not hedged.
        # No single byte-state can be addressed either, so the digest is
        # dropped rather than naming bytes that have already been replaced.
        state, commit, sources = "dirty", None, None
    return {
        "tool_version": VERSION,
        "tool_commit": commit,
        "tool_source_state": state,
        "tool_content_sha256": _tool_content_digest(sources),
    }


def _with_tool_identity(report: dict) -> dict:
    report.update(tool_identity())
    return report


# One sentence for every runner. The module report carried an older, shorter
# version that predated the silent class, so a module consumer read a different
# description of the same number.
SCORE_MEANS = ("percent of author-declared in-scope rules killed; NOT percent of "
               "the rules the implementation actually has. Silent mutants count "
               "in the denominator and never the numerator. Without "
               "diagnostic_from the silent class is unreachable, so a zero there "
               "means it was not measured, not that none exist")


def encode_report_v0(report: dict) -> bytes:
    """Return the sole byte representation of a successful report.

    UTF-8, sorted keys, two-space indentation and one trailing LF are part of
    the v0 byte contract. Error envelopes have their own schema and must never
    be addressable as successful report bytes through this function.
    """
    if report.get("schema") != REPORT_SCHEMA:
        raise ValueError("encode_report_v0 accepts only %s" % REPORT_SCHEMA)
    try:
        return (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
            "utf-8")
    except UnicodeEncodeError:
        raise ReportEncodingError(
            "report contains text that cannot be encoded as valid UTF-8") from None


def _control_result(group: str, label: str, scope: str, *,
                    detected: bool, moved: int, error=None):
    """Produce one control row and its direct summary from the same rule."""
    if error is not None:
        status, verdict, how = "error", "control-error", str(error)
    elif detected:
        status, verdict, how = (
            "killed", "control-killed", "harness detects a change on this path")
    else:
        status, verdict, how = (
            "survived", "control-SURVIVED", "THE HARNESS DETECTS NOTHING")
    return ({"group": group, "label": label, "verdict": verdict,
             "scope": scope, "moved": moved, "how": how}, status)


def _record_control(results: list, statuses: list[str], group: str, label: str,
                    scope: str, *, detected: bool, moved: int, error=None) -> None:
    """Record the row and direct status together so neither path can omit one."""
    row, status = _control_result(
        group, label, scope, detected=detected, moved=moved, error=error)
    results.append(row)
    statuses.append(status)


def _declared_control_count(m: dict) -> int:
    return sum(bool(mut.get("control"))
               for group in m["mutants"].values() for mut in group)


def _control_status(statuses: list[str], declared_count: int) -> str:
    """Summarise all declared controls without asking a consumer to scan rows.

    Error outranks an incomplete observation, which outranks survived, which
    outranks killed. A missing row means a declared control was stale,
    unloadable or otherwise unmeasured, so a partial set cannot report killed.
    """
    if "error" in statuses:
        return "error"
    if declared_count == 0 or len(statuses) != declared_count:
        return "absent-or-invalid"
    if "survived" in statuses:
        return "survived"
    return "killed"


def _report_v0(manifest_path: Path, m: dict, *,
               killed: int, survived: int, silent: int, equivalent: int,
               out_of_scope: int, unproved: int, known_holes: int,
               score, results: list, failures: list,
               control_status: str = "absent-or-invalid",
               originals_unverified_against_head=None) -> dict:
    """The one `report.v0` shape, for every runner.

    There were two of these, and they drifted: the module one omitted `runner`,
    so a report could not name its own producer and a downstream consumer
    re-read the manifest to recover the field. They had also diverged on three
    expressions that happened to agree numerically only because the module
    runner cannot produce a silent mutant.

    `runner` is read from the manifest rather than passed by the caller.
    `load_manifest` defaults it to `module`, so it is always populated, and a
    caller that cannot supply it cannot supply the wrong one either.

    `originals_unverified_against_head` is a named optional rather than a
    generic extras mapping: process and batch own that field, module has no
    such guard, and a mapping splatted into this dictionary could overwrite a
    common field instead of adding a runner-specific one. It is included only
    when supplied, so its absence stays absence rather than a fake `None`.
    """
    denom = killed + survived + silent
    report = {
        "schema": REPORT_SCHEMA,
        "manifest": str(manifest_path),
        "manifest_sha256": m.get("_manifest_sha256"),
        "runner": m["runner"],
        "control_status": control_status,
        "killed": killed,
        "survived": survived,
        "silent": silent,
        "diagnostic_channel_declared": m.get("diagnostic_from") is not None,
        "known_holes": known_holes,
        "corpus_digest": m.get("_corpus_digest"),
        "acknowledged_digests": len(m.get("known_holes", {})),
        "hole_ratio": None if denom == 0 else round(known_holes / denom, 2),
        "equivalent": equivalent,
        "unexercised_out_of_scope": out_of_scope,
        "unproved": unproved,
        "declared_total": (killed + survived + silent + equivalent + out_of_scope
                           + unproved + known_holes),
        "out_of_scope_ratio": None if denom == 0 else round(out_of_scope / denom, 2),
        "score_percent": score,
        "score_means": SCORE_MEANS,
        "mutants": results,
        "failures": failures,
        "adequate": not failures,
    }
    if originals_unverified_against_head is not None:
        report["originals_unverified_against_head"] = originals_unverified_against_head
    return _with_tool_identity(report)


def format_tool_identity(identity: dict | None = None) -> str:
    """Render one producer result. This never resolves identity itself.

    A second resolution here would be a second answer to the same question,
    and the two could disagree with each other inside one report.
    """
    identity = identity if identity is not None else tool_identity()
    commit = identity.get("tool_commit") or "none"
    state = identity.get("tool_source_state") or "unresolved"
    content = identity.get("tool_content_sha256") or "none"
    return "corpus-adequacy %s commit=%s source=%s content=%s" % (
        identity["tool_version"], commit, state, content,
    )


def _req(obj: dict, key: str, where: str):
    if key not in obj:
        raise ManifestError("%s: missing required key %r" % (where, key))
    return obj[key]


def _diagnostic_note(m: dict, moved_diag: list) -> dict:
    """`moved_diagnostic` on rows whose verdict is not itself about diagnostics.

    An excluded or acknowledged row that the diagnostics DID move is a different
    fact from one nothing moved, and the row is the only place a reader can see
    which it was. Present only where a channel was declared, so absent and zero
    do not blur.
    """
    if m.get("diagnostic_from") is None:
        return {}
    return {"moved_diagnostic": len(moved_diag)}


def _diagnostic_suffix(moved_diag: list) -> str:
    """Said in the row's own `how`, because the verdict alone would overstate."""
    if not moved_diag:
        return ""
    return (". The declared diagnostic channel moved on %d vector(s); the pinned "
            "outcomes did not, and this verdict is not scored" % len(moved_diag))


def selector_members(sel) -> list:
    """The declared members of a selector, whether it is a scalar or a list.

    One function so the reader, the presence rule and the manifest validation
    cannot disagree about what a selector declares.
    """
    return sel if isinstance(sel, list) else [sel]


def label_identity(entry: dict, where: str = "entry") -> str:
    """Return the exact string identity used for declarations and acknowledgements."""
    label = entry["label"]
    if not isinstance(label, str) or not label.strip():
        raise ManifestError("%s: label must be a non-empty string" % where)
    return label


def _resolved_contained_source(path: Path, repo_root: Path) -> Path:
    """Resolve one source, refusing roots and targets outside the declared boundary."""
    root = repo_root.resolve()
    if not root.is_dir():
        raise ManifestError("repo_root must be an existing directory: %s" % root)
    resolved = path.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ManifestError(
            "implementation source %s resolves outside repo_root %s" % (path, root))
    if not resolved.is_file():
        raise ManifestError("implementation source not found: %s" % resolved)
    return resolved


def _require_unique_labels(m: dict) -> None:
    """Reject ambiguous mutant and per-digest acknowledgement declarations."""
    seen_mutants = {}
    for declaration in ("mutants", "equivalent"):
        for group, entries in m[declaration].items():
            for i, entry in enumerate(entries):
                ident = label_identity(entry, "%s[%s][%d]" % (declaration, group, i))
                if ident in seen_mutants:
                    previous_declaration, previous_group = seen_mutants[ident]
                    raise ManifestError(
                        "mutant label %r is declared more than once (already in %s group %r). "
                        "Labels are unique across the manifest, so one known-hole "
                        "acknowledgement cannot name two mutants"
                        % (ident, previous_declaration, previous_group))
                seen_mutants[ident] = (declaration, group)

    for digest, entries in m["known_holes"].items():
        seen_acknowledgements = set()
        for i, entry in enumerate(entries):
            ident = label_identity(entry, "known_holes[%s][%d]" % (digest, i))
            if ident in seen_acknowledgements:
                raise ManifestError(
                    "known_holes[%s] repeats acknowledgement %r. Each mutant may be "
                    "acknowledged at most once for one corpus digest" % (digest, ident))
            seen_acknowledgements.add(ident)


def load_manifest(path: Path) -> dict:
    manifest_bytes = path.read_bytes()
    m = json.loads(manifest_bytes)
    if m.get("schema") != SCHEMA:
        raise ManifestError("schema must be %r, got %r" % (SCHEMA, m.get("schema")))
    base = path.parent
    # Exact on-disk bytes are the input parsed above. Whitespace and key order
    # therefore remain addressable rather than being silently canonicalised.
    m["_manifest_sha256"] = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    _req(m, "vectors", "manifest")
    if m.get("runner", "module") == "module":
        _req(m, "implementation", "manifest")
    m["_impl_path"] = (base / m["implementation"]).resolve() if m.get("implementation") else None
    m["_vectors_path"] = (base / m["vectors"]).resolve()
    m.setdefault("entrypoint", "evaluate")
    # group_key is OPTIONAL. A corpus with no axis column is one group; forcing it to invent
    # an axis would be the tool bending the corpus to fit itself.
    m.setdefault("group_key", None)
    m.setdefault("id_key", "vector_id")
    m.setdefault("inputs_key", "inputs")
    m.setdefault("vectors_key", "vectors")
    # Which vector fields are passed positionally to the entrypoint. Signatures differ between
    # corpora and a fixed arity would exclude every corpus that did not guess the same one.
    m.setdefault("entrypoint_args",
                 [k for k in (m["group_key"], m["inputs_key"]) if k is not None])
    m.setdefault("default_group", "all")
    m.setdefault("known_holes", {})
    require_shape(m["known_holes"], dict, "known_holes")
    m["_corpus_digest"] = None
    if m["known_holes"]:
        for key in ("corpus_digest_file", "corpus_digest_key"):
            _req(m, key, "manifest (known_holes declared)")
        dp = (base / m["corpus_digest_file"]).resolve()
        if not dp.is_file():
            raise ManifestError("corpus_digest_file not found: %s" % dp)
        m["_corpus_digest"] = json.loads(dp.read_text(encoding="utf-8"))[m["corpus_digest_key"]]
        for digest, entries in m["known_holes"].items():
            require_shape(entries, list, "known_holes[%s]" % digest)
            for i, e in enumerate(entries):
                require_shape(e, dict, "known_holes[%s][%d]" % (digest, i))
                for key in ("label", "reason", "recorded"):
                    _req(e, key, "known_holes[%s][%d]" % (digest, i))
                if not str(e["reason"]).strip():
                    raise ManifestError("known_holes[%s][%d] %r: a hole needs a stated reason"
                                        % (digest, i, e["label"]))
    m.setdefault("runner", "module")
    if m["runner"] not in ("module", "process", "batch"):
        raise ManifestError("runner must be module, process or batch, got %r" % m["runner"])
    if m.get("outcome_parse") == "test-names" and m["runner"] != "batch":
        raise ManifestError(
            "outcome_parse test-names is implemented only for runner=batch, "
            "not runner=%s" % m["runner"])
    if m["runner"] == "module" and m.get("diagnostic_from") is not None:
        # Silently ignoring it would be this tool's own failure mode: a manifest
        # declaring a channel that is never read, reporting `silent: 0` as though
        # the class had been measured.
        raise ManifestError(
            "diagnostic_from is not implemented for runner=module; the module runner "
            "reads one callable result, so there is no second channel to compare")
    if m["runner"] in ("process", "batch"):
        _req(m, "entrypoint_command", "manifest (runner=%s)" % m["runner"])
        if m.get("outcome_parse") != "test-names":
            _req(m, "outcome_from", "manifest (runner=%s)" % m["runner"])
        m.setdefault("outcome_from", [])
        # Optional second channel. Declaring it buys the `silent` verdict: a
        # mutant that moves nothing here is `survived`, one that moves only here
        # is `silent`. Refused beside `test-names`, where the names ARE the
        # outcome and there is no second channel to read.
        if m.get("diagnostic_from") is not None:
            if m.get("outcome_parse") == "test-names":
                raise ManifestError(
                    "diagnostic_from needs a JSON outcome; it cannot be read beside "
                    "outcome_parse test-names, where the test names are the outcome")
            if not isinstance(m["diagnostic_from"], (str, list)):
                raise ManifestError("diagnostic_from must be a string or a list of strings")
            sel = m["diagnostic_from"]
            sel = sel if isinstance(sel, list) else [sel]
            if not sel or not all(isinstance(k, str) and k for k in sel):
                raise ManifestError("diagnostic_from names no readable member")
            oc = m["outcome_from"] if isinstance(m["outcome_from"], list) else [m["outcome_from"]]
            overlap = sorted(set(sel) & set(oc))
            if overlap:
                # A member on both channels can never produce `silent`: any move
                # in it is already a move in the outcome, so the class would be
                # unreachable and the manifest would read as covering more.
                raise ManifestError(
                    "diagnostic_from and outcome_from both name %s; a member read as the "
                    "outcome can never be a silent-only move" % overlap)
        # A batch corpus is exercised as a unit, so there is nothing to build and no
        # per-vector path. Anything else must declare its build.
        if m["runner"] == "process":
            _req(m, "build", "manifest (runner=process)")
        m.setdefault("build", [])
        m.setdefault("repo_root", ".")
        m["_repo_root"] = (base / m["repo_root"]).resolve()
        srcs = m.get("implementation_sources") or [m["implementation"]]
        m["_source_paths"] = []
        for source in srcs:
            declared = base / source
            m["_source_paths"].append(
                _resolved_contained_source(declared, m["_repo_root"]))
        m.setdefault("vector_path_key", "path")
        m.setdefault("build_timeout", 1800)
        m.setdefault("vector_timeout", 120)
        m["accepted_exit_codes"] = accepted_exit_codes(m)
    # One deadline per child, on every runner. The module runner has a child too.
    m.setdefault("vector_timeout", 120)
    m.setdefault("mutants", {})
    m.setdefault("equivalent", {})
    require_shape(m["mutants"], dict, "mutants")
    require_shape(m["equivalent"], dict, "equivalent")
    if not m["mutants"]:
        raise ManifestError("manifest declares no mutants; there is nothing to measure")
    for group, entries in m["mutants"].items():
        require_shape(entries, list, "mutants[%s]" % group)
        for i, e in enumerate(entries):
            require_shape(e, dict, "mutants[%s][%d]" % (group, i))
            for key in ("label", "anchor", "replacement"):
                _req(e, key, "mutants[%s][%d]" % (group, i))
            e.setdefault("scope", "declared")
            e.setdefault("control", False)
            if e["control"] and e["scope"] != "declared":
                raise ManifestError("mutants[%s][%d] %r: a control cannot be out_of_scope"
                                    % (group, i, e["label"]))
            if e["scope"] not in ("declared", "out_of_scope"):
                raise ManifestError("mutants[%s][%d] %r: scope must be declared or out_of_scope"
                                    % (group, i, e["label"]))
            # An out-of-scope mutant leaves the denominator exactly as an equivalent one does,
            # so it carries the same obligation: a stated reason, never a bare exclusion.
            if e["scope"] == "out_of_scope" and not str(e.get("reason", "")).strip():
                raise ManifestError(
                    "mutants[%s][%d] %r: an out_of_scope mutant needs a stated reason. It leaves "
                    "the denominator like an equivalent one, so it carries the same obligation"
                    % (group, i, e["label"]))
            if not e["anchor"]:
                raise ManifestError(
                    "mutants[%s][%d] %r: the anchor is empty. An empty anchor matches everywhere, "
                    "corrupts the source and is then counted as a kill" % (group, i, e["label"]))
            if e["anchor"] == e["replacement"]:
                raise ManifestError(
                    "mutants[%s][%d] %r: anchor and replacement are identical, so it mutates nothing"
                    % (group, i, e["label"]))
    for group, entries in m["equivalent"].items():
        require_shape(entries, list, "equivalent[%s]" % group)
        for i, e in enumerate(entries):
            require_shape(e, dict, "equivalent[%s][%d]" % (group, i))
            for key in ("label", "reason"):
                _req(e, key, "equivalent[%s][%d]" % (group, i))
            if not str(e["reason"]).strip():
                raise ManifestError(
                    "equivalent[%s][%d] %r: an equivalence needs a stated reason, never a bare claim"
                    % (group, i, e["label"]))
    _require_unique_labels(m)
    return m


def _acknowledged_holes(m: dict) -> dict:
    """Holes acknowledged against the DECLARED corpus digest.

    STATED PRECISELY, because the earlier wording here was false. This pins to a
    digest STRING read from a file the manifest itself names. It is an
    author-supplied claim about the corpus, not a measurement of it: nothing here
    recomputes the digest from the vectors. Point the file at a stale value, or
    leave it untouched while the corpus moves, and every acknowledgement survives
    a corpus it no longer describes.

    So the expiry is only as strong as the honesty of that file. That is the same
    declared-versus-observed gap this tool exists to find, one level up, in its
    own implementation. Whether the tool should recompute the digest is a contract
    decision with a canonicalisation question attached, and it is not made here.
    """
    if not m.get("_corpus_digest"):
        return {}
    return {label_identity(e): e
            for e in m["known_holes"].get(m["_corpus_digest"], [])}


def _group_of(v: dict, m: dict) -> str:
    return v[m["group_key"]] if m["group_key"] else m["default_group"]


# ---------------------------------------------------------------------------
# module runner: the corpus runs in a disposable child, never in this process
# ---------------------------------------------------------------------------

MODULE_CHILD = Path(__file__).resolve().parent / "module_child.py"
MODULE_CHILD_SCHEMA = "corpus-adequacy.module-child.v0"

# Abnormal TERMINATION of the child, observed before a word of its output is
# read. The unmutated run completed on these same vectors and this one did not,
# so the harness distinguished the mutant, and that is a kill with the class
# named. Everything else -- a child that exited 0 leaving nothing parseable, a
# child that could not be started at all -- is a failure of the MEASUREMENT.
# Reporting one of those as a kill would credit the corpus with catching
# something it was never shown, which is the over-claim this tool exists to
# find, one level up in its own implementation. Those become unproved, and an
# unproved mutant already fails the run.
TERMINATED_KINDS = frozenset({"timeout", "output-cap", "unexpected-exit", "signal"})

_ModuleRun = namedtuple(
    "_ModuleRun", "outcomes raised unsupported load_error entrypoint_missing abnormal")


def _module_abnormal(kind: str) -> _ModuleRun:
    """A child that did not report. Never an outcome, on any of the three roles."""
    return _ModuleRun({}, [], [], None, False, kind)


def child_module_result(raw: str, count: int):
    """Validate the child's typed JSON before any of it becomes an outcome.

    Same contract as child_outcome on the process path: anything the child did
    not say EXACTLY is a kind, never a value. Empty output is the case that
    decides whether this tool is honest, because a child that was killed, or
    that called os._exit, leaves nothing behind -- and reading nothing as "no
    outcome moved" reports a rule as covered on the strength of silence.
    """
    if not raw.strip():
        return None, "no-result"
    try:
        doc = json.loads(raw)
    except Exception:  # noqa: BLE001 - unreadable output is a parse-error
        return None, "parse-error"
    if not isinstance(doc, dict) or doc.get("schema") != MODULE_CHILD_SCHEMA:
        return None, "parse-error"
    # Outcome VALUES are the corpus's own and are not constrained here. Their
    # keys, and the bookkeeping around them, are this protocol's business.
    outcomes = doc.get("outcomes")
    if not isinstance(outcomes, dict) or not all(type(k) is str for k in outcomes):
        return None, "parse-error"
    for key in ("raised", "unsupported"):
        seq = doc.get(key)
        if not isinstance(seq, list) or not all(type(x) is str for x in seq):
            return None, "parse-error"
    if doc.get("load_error") is not None and type(doc.get("load_error")) is not str:
        return None, "parse-error"
    if type(doc.get("entrypoint_missing")) is not bool:
        return None, "parse-error"
    seen = list(outcomes) + doc["raised"] + doc["unsupported"]
    if not all(k.isascii() and k.isdigit() and str(int(k)) == k and int(k) < count
               for k in seen):
        return None, "parse-error"
    index = [int(k) for k in seen]
    if len(set(index)) != len(index):
        return None, "parse-error"
    if doc["load_error"] is None and not doc["entrypoint_missing"]:
        # A child that ran accounts for every vector exactly once. Silence about
        # a vector reads as "unchanged", which is a false survivor wearing the
        # shape of a measurement.
        if sorted(index) != list(range(count)):
            return None, "parse-error"
    return doc, None


def _module_outcomes(m: dict, source: str, tag: str, vectors: list, tmp: Path) -> _ModuleRun:
    """Load one variant of the implementation and collect its outcomes, in a child.

    Corpus source -- mutated corpus source, at that -- is arbitrary code, and
    every way that ends badly was observed on this runner while it ran here: an
    endless mutant hung the tool with no report, SystemExit chose the tool's
    exit code, os._exit(0) ended it at exit 0 with no report at all, a printing
    mutant put 6.3 MB on the tool's own stdout, and a spawned descendant
    outlived the run.

    So the boundary is the one the process and batch runners already had, taken
    through the same _run_capped rather than written a second time: one
    deadline, one output ceiling, one POSIX process-group kill. Windows keeps
    bounded_run's stated non-claim -- the direct child is killed, the process
    tree is not.

    WHAT THIS DOES AND DOES NOT CLAIM
    ---------------------------------
    Process isolation for a trusted-local corpus, not a sandbox. The child
    inherits this process's filesystem, network, environment and credentials,
    and nothing here bounds its memory or its descriptors.

    The protocol channel is not authenticated either. Fd 1 is duplicated before
    any corpus code runs and the original is pointed at stderr, which stops
    accidental pollution; it does not stop a child that scans its descriptors,
    finds the duplicate, and writes a well-formed payload of its choosing.

    So the claim is narrower than "a misbehaving corpus cannot make this run
    say something untrue", which is what an earlier draft of this docstring
    said. What is claimed: the classes measured here -- direct-child timeout,
    output-cap breach, abnormal termination and protocol failure -- are
    fail-closed, so none can be read as a clean result. Same-user
    parent signalling (e.g. kill(getppid())), session escape and
    host resource exhaustion remain outside the process-isolation
    claim. A corpus written to forge a verdict is also outside that
    claim, and nothing in this file would detect one.
    """
    if not MODULE_CHILD.is_file():
        raise ManifestError("the module child shim is missing: %s" % MODULE_CHILD)
    request = tmp / ("request_%s.json" % tag)
    request.write_text(json.dumps({
        "source": source, "tag": tag, "work_dir": str(tmp),
        "entrypoint": m["entrypoint"], "arg_keys": list(m["entrypoint_args"]),
        "vectors": vectors,
        "sys_path": [p for p in sys.path if isinstance(p, str)],
    }), encoding="utf-8")
    cmd = [sys.executable, str(MODULE_CHILD), str(request)]
    try:
        p = _run_capped(cmd, Path.cwd(), timeout=m["vector_timeout"])
    except subprocess.TimeoutExpired:
        return _module_abnormal("timeout")
    except _OutputTooLarge:
        return _module_abnormal("output-cap")
    except OSError:
        return _module_abnormal("incomplete")
    # Classify the child before reading a word of its output, exactly as the
    # process path does: a parseable report on a code we did not accept is not
    # an outcome. The shim is ours, so the only accepted code is 0; the
    # manifest's accepted_exit_codes describe the corpus's own checker.
    kind = classify(p.returncode, [0])
    if kind != "ok":
        return _module_abnormal(kind)
    doc, kind = child_module_result(p.stdout, len(vectors))
    if kind:
        return _module_abnormal(kind)
    vids = [v[m["id_key"]] for v in vectors]
    return _ModuleRun(
        outcomes={vids[int(k)]: v for k, v in doc["outcomes"].items()},
        raised=[vids[int(k)] for k in doc["raised"]],
        unsupported=[vids[int(k)] for k in doc["unsupported"]],
        load_error=doc["load_error"],
        entrypoint_missing=doc["entrypoint_missing"],
        abnormal=None)


def classify(returncode, accepted) -> str:
    """ok | unexpected-exit | signal | incomplete. Never reads stdout.

    Signals and None never become ok, even if *accepted* is malformed.
    """
    if returncode is None or type(returncode) is not int:
        return "incomplete"
    if returncode < 0:
        return "signal"
    allowed = {code for code in (accepted or []) if type(code) is int and code >= 0}
    if returncode in allowed:
        return "ok"
    return "unexpected-exit"


def accepted_exit_codes(m: dict) -> list[int]:
    """One process/batch policy: unique nonnegative ints, plus parse rules.

    Default is [0]. Bools are excluded (JSON true is not exit 1). Signals are
    never accepted. outcome_parse test-names requires 101.
    JSON outcome_from has no protocol ID, so extra codes such as 2 are declared
    explicitly. This repository ships no manifests and does not infer codes
    from a command name.
    """
    raw = m.get("accepted_exit_codes", [0])
    if not isinstance(raw, list):
        raise ManifestError(
            "accepted_exit_codes must be an array of unique nonnegative integers")
    seen: set[int] = set()
    codes: list[int] = []
    for i, value in enumerate(raw):
        if type(value) is bool:
            raise ManifestError(
                "accepted_exit_codes[%d] must be a nonnegative integer, got bool" % i)
        if type(value) is not int:
            raise ManifestError(
                "accepted_exit_codes[%d] must be a nonnegative integer, got %s"
                % (i, type(value).__name__))
        if value < 0:
            raise ManifestError(
                "accepted_exit_codes[%d] is %s; signals are never accepted" % (i, value))
        if value in seen:
            raise ManifestError("accepted_exit_codes repeats %d" % value)
        seen.add(value)
        codes.append(value)
    if m.get("outcome_parse") == "test-names":
        if 101 not in seen:
            raise ManifestError(
                "outcome_parse test-names requires accepted_exit_codes to include 101")
    return codes


def child_outcome(m: dict, completed: subprocess.CompletedProcess):
    """Classify returncode against the accepted policy, then parse stdout.

    An accepted code with empty or malformed output is still a parse-error.
    """
    kind = classify(completed.returncode, m["accepted_exit_codes"])
    if kind != "ok":
        return None, None, kind
    if m.get("outcome_parse") == "test-names":
        out = completed.stdout + completed.stderr
        failed = sorted(set(re.findall(m.get("failed_test_pattern",
                                             r"^test (\S+) \.\.\. FAILED$"), out, re.M)))
        ran = sum(int(x) for x in re.findall(r"^test result: \w+\. (\d+) passed", out, re.M))
        if ran == 0 and not failed:
            return None, None, "parse-error"
        # `test-names` exposes no separate diagnostic channel: the names ARE the
        # outcome. A corpus wanting the silent class here must emit JSON.
        return tuple(failed), None, None
    try:
        doc = json.loads(completed.stdout)
    except Exception:  # noqa: BLE001 - unreadable output is a parse-error
        return None, None, "parse-error"
    if not isinstance(doc, dict):
        return None, None, "parse-error"
    def _read(name, sel):
        # Presence is recorded for EVERY selector, not only the outcome. A member
        # nothing emits compares None to None on every mutant, and that is the
        # same defect whichever selector declared it: on `outcome_from` it makes
        # the score over-generous, on `diagnostic_from` it makes the `silent`
        # class unreachable while the report still says the channel was declared.
        sl = selector_members(sel)
        m.setdefault("_selector_keys_seen", {}).setdefault(name, set()).update(
            k for k in sl if k in doc)
        if m.get("runner") == "batch":
            vals = [doc.get(k) for k in sl]
            return tuple(tuple(v) if isinstance(v, list) else v for v in vals)
        if isinstance(sel, list):
            return tuple(doc.get(k) for k in sel)
        return doc.get(sel)

    diag = (_read("diagnostic_from", m["diagnostic_from"])
            if m.get("diagnostic_from") is not None else None)
    return _read("outcome_from", m["outcome_from"]), diag, None


# ---------------------------------------------------------------------------
# process runner: a compiled implementation behind a command line
# ---------------------------------------------------------------------------


class _TreeLock:
    """One mutation run at a time per repository.

    _SourceGuard restores what THIS run mutated. It cannot see another run, and
    two runs over one working tree corrupt each other in two ways. The visible
    one is a wrong score: run A applies a mutant, run B reads the tree and finds
    its own anchor gone, and reports `anchor not found` or a plausible number
    over a smaller denominator. The silent one is worse: run A captures its
    "originals" while run B has a mutant applied, and A's restore then writes
    B's mutant back to the tree as though it were the original. That is a
    disabled rule left in a working tree, which is the exact outcome
    _SourceGuard exists to prevent.

    So the lock is taken BEFORE the isolated copy, not after: a tree
    observed outside the lock can change before the copy is made, which
    is the same bug one step earlier.

    Non-blocking on purpose. A run that queued and started twenty minutes later
    would measure a tree nobody chose for it.
    """

    def __init__(self, repo_root: Path) -> None:
        key = hashlib.sha256(str(repo_root.resolve()).encode("utf-8")).hexdigest()[:16]
        self.path = Path(tempfile.gettempdir()) / ("corpus-adequacy-%s.lock" % key)
        self.repo_root = repo_root
        self._fh = None
        self.held = False
        self.unavailable = fcntl is None

    def __enter__(self) -> "_TreeLock":
        if self.unavailable:
            raise ManifestError(
                "no advisory lock on this platform, so a process or batch run "
                "cannot exclude a concurrent writer. Refusing before source "
                "copy, build, or mutation of %s"
                % self.repo_root)
        self._fh = self._open_lockfile()
        try:
            fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._fh.close()
            self._fh = None
            raise ManifestError(
                "another corpus-adequacy run holds the lock on %s. It is mutating the "
                "tree you would measure, so this run would score a mixture of two "
                "mutants rather than either one. Wait for it, or measure a separate "
                "checkout." % self.repo_root)
        self.held = True
        return self

    def _open_lockfile(self):
        """POSIX lock open: no follow, no truncate. Fail-closed on a symlink."""
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ManifestError(
                "no O_NOFOLLOW on this platform, so the lock path cannot be "
                "opened without following a symlink. Refusing before isolation of %s"
                % self.repo_root)
        flags = os.O_RDWR | os.O_CREAT | nofollow
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError:
            raise ManifestError(
                "lock path %s is not a regular file; refusing before isolation of %s"
                % (self.path, self.repo_root))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                os.close(fd)
                raise ManifestError(
                    "lock path %s is not a regular file; refusing before isolation of %s"
                    % (self.path, self.repo_root))
            return os.fdopen(fd, "r+")
        except ManifestError:
            raise
        except Exception:
            os.close(fd)
            raise

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            fcntl.flock(self._fh, fcntl.LOCK_UN)
            self._fh.close()
            self._fh = None
        self.held = False


class _SourceGuard:
    """Restores every mutated source file while this Python process can unwind.

    The adapter edits files in the working tree. The originals are captured up
    front and rewritten in a finally block, covering normal return and ordinary
    Python exceptions. SIGKILL, power loss, and host termination cannot run that
    finally block, so this guard is not durable crash recovery.
    """

    def __init__(self, paths: list[Path], repo_root: Path | None = None) -> None:
        self.repo_root = repo_root
        self.original = {}
        for path in paths:
            current = (_resolved_contained_source(path, repo_root)
                       if repo_root is not None else path)
            self.original[path] = current.read_bytes()
        self.unverified: list[str] = []
        if repo_root is not None:
            self._verify_against_head(repo_root)

    def _verify_against_head(self, repo_root: Path) -> None:
        """The captured original must be the committed one, checked AT capture time.

        Checking `git status` before constructing this guard leaves a window: a
        concurrent actor can mutate a file between the check and the capture, and
        then the mutant IS the original, so restore writes it back and the run
        scores against a rule that was already deleted. That window was not
        theoretical. A run of this tool reported `anchor not found in any declared
        source` for two anchors that occur exactly once in the committed file,
        because a second run had a mutant applied at the moment of capture.

        The lock above stops another instance of THIS tool. It cannot stop a hand
        edit, an editor autosave, or an instance that started before the lock
        existed, so the content is compared rather than assumed.
        """
        for path in self.original:
            current = _resolved_contained_source(path, repo_root)
            rel = current.relative_to(repo_root.resolve())
            try:
                out = subprocess.run(["git", "-C", str(repo_root), "show", "HEAD:%s" % rel],
                                     capture_output=True, timeout=60)
            except (OSError, subprocess.TimeoutExpired):
                self.unverified.append(str(rel))
                continue
            if out.returncode != 0:
                self.unverified.append(str(rel))   # untracked or no git: cannot compare
                continue
            if out.stdout != self.original[path]:
                raise ManifestError(
                    "%s does not match HEAD at the moment its original was captured. "
                    "Something changed it between the dirty check and now, so this run "
                    "would treat that change as the original and restore it afterwards. "
                    "Refusing rather than measuring a tree it did not read." % rel)

    def restore(self) -> None:
        for path, data in self.original.items():
            current = (_resolved_contained_source(path, self.repo_root)
                       if self.repo_root is not None else path)
            if current.read_bytes() != data:
                current.write_bytes(data)

    def verify_clean(self) -> list[str]:
        leaked = []
        for path, data in self.original.items():
            current = (_resolved_contained_source(path, self.repo_root)
                       if self.repo_root is not None else path)
            if current.read_bytes() != data:
                leaked.append(str(path))
        return leaked


def _build(m: dict) -> tuple[bool, str]:
    if not m.get("build"):
        return True, "nothing to build"      # an interpreted corpus has no build step
    try:
        p = _run_capped(list(m["build"]), m["_repo_root"], timeout=m["build_timeout"])
    except _OutputTooLarge:
        return False, "build output exceeded the ceiling"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, "build could not complete: %r" % (exc,)
    if p.returncode != 0:
        tail = [ln for ln in (p.stdout + p.stderr).splitlines()
                if "error" in ln.lower()][-3:]
        return False, " | ".join(tail)[:300] or "build exited %d" % p.returncode
    return True, "built"


def _batch_outcome(m: dict) -> tuple[dict, dict[str, str]]:
    """Run the command ONCE over the whole corpus.

    Some corpora are consumed as a unit: the checker takes the vector file and
    reports a summary. Per-vector invocation is not available there, so the unit
    IS the outcome. Discrimination then depends entirely on the summary naming
    which cases moved -- a checker reporting only a boolean would make every
    mutant either kill everything or nothing, and this runner would be measuring
    almost nothing. That limitation belongs to the corpus, and it is stated in the
    report rather than hidden by a per-vector shape this corpus does not have.
    """
    cmd = [str(x) for x in m["entrypoint_command"]]
    try:
        p = _run_capped(cmd, m["_repo_root"], timeout=m["vector_timeout"])
    except subprocess.TimeoutExpired:
        return {}, {}, {"<batch>": "timeout"}
    except _OutputTooLarge:
        return {}, {}, {"<batch>": "output-cap"}
    except OSError:
        return {}, {}, {"<batch>": "incomplete"}
    value, diag, kind = child_outcome(m, p)
    if kind:
        return {}, {}, {"<batch>": kind}
    return {"<batch>": value}, {"<batch>": diag}, {}


def _process_outcomes(m: dict, vectors: list[dict]) -> tuple[dict, dict, dict]:
    """Run the built command once per vector. Classify the child before parse."""
    if m["runner"] == "batch":
        return _batch_outcome(m)
    outcomes, diags, raised = {}, {}, {}
    for v in vectors:
        vid = v[m["id_key"]]
        cmd = [str(x).replace("{vector}", str((m["_repo_root"] / v[m["vector_path_key"]]).resolve()))
               for x in m["entrypoint_command"]]
        try:
            p = _run_capped(cmd, m["_repo_root"], timeout=m["vector_timeout"])
        except subprocess.TimeoutExpired:
            raised[vid] = "timeout"
            continue
        except _OutputTooLarge:
            raised[vid] = "output-cap"
            continue
        except OSError:
            raised[vid] = "incomplete"
            continue
        value, diag, kind = child_outcome(m, p)
        if kind:
            raised[vid] = kind
        else:
            outcomes[vid] = value
            diags[vid] = diag
    return outcomes, diags, raised



def _run_process(m: dict, manifest_path: Path) -> dict:
    """Mutate declared sources, rebuild, and run the corpus against the binary."""
    doc = json.loads(m["_vectors_path"].read_text(encoding="utf-8"))
    if m["runner"] == "batch":
        # One synthetic unit. The corpus's real cases live inside the file the
        # command reads; the group exists so the self-coverage guard still applies.
        all_vectors = [{m["id_key"]: "<batch>",
                        (m["group_key"] or "_g"): m["default_group"]}]
        if m["group_key"] is None:
            m["group_key"] = "_g"
    else:
        all_vectors = doc[m["vectors_key"]] if isinstance(doc, dict) else doc
    failures: list[str] = []

    # Manifest loading and execution can be separated by arbitrary caller work.
    # Re-resolve before touching git, capturing originals, or mutating a source.
    m["_source_paths"] = [
        _resolved_contained_source(path, m["_repo_root"])
        for path in m["_source_paths"]]

    # Pure corpus/manifest validation happens before acquiring a mutation lock.
    # A malformed vector must not leave a lock or captured source behind.
    groups_in_corpus = {_group_of(v, m) for v in all_vectors}
    failures.extend(structural_failures(m, groups_in_corpus))
    acknowledged = _acknowledged_holes(m)
    results, killed, survived, equivalent, out_of_scope, unproved = [], 0, 0, 0, 0, 0
    control_statuses: list[str] = []
    declared_controls = _declared_control_count(m)
    silent = 0
    known_holes = 0

    # Taken BEFORE the isolated copy: a tree observed outside the lock can
    # change before materialize. Isolation copies working-tree bytes, so dirty
    # declared sources are measured rather than refused; the lock still comes
    # first.
    original_root = m["_repo_root"]
    lock = _TreeLock(original_root)
    lock.__enter__()

    iso = IsolatedMutationTree(original_root)
    guard = None
    try:
        try:
            isolated = iso.materialize()
        except IsolationError as exc:
            raise ManifestError(str(exc)) from exc
        remapped = []
        root_res = original_root.resolve()
        for path in m["_source_paths"]:
            remapped.append(isolated / path.resolve().relative_to(root_res))
        missing = [str(p) for p in remapped if not p.is_file()]
        if missing:
            raise ManifestError("implementation source not found: %s" % missing)
        m["_repo_root"] = isolated
        m["_source_paths"] = remapped
        # Isolated tree has no .git; dirty working-tree bytes are allowed.
        guard = _SourceGuard(m["_source_paths"], repo_root=None)
    except BaseException:
        iso.cleanup()
        lock.__exit__()
        raise

    try:
        ok, detail = _build(m)
        if not ok:
            raise ManifestError("the UNMUTATED tree does not build: %s" % detail)

        baselines = {}
        for group in sorted(m["mutants"]):
            vectors = [v for v in all_vectors if _group_of(v, m) == group]
            if not vectors:
                failures.append("%s: no vectors, so its mutants cannot be scored" % group)
                continue
            base, base_diag, raised = _process_outcomes(m, vectors)
            if raised:
                kinds = sorted(set(raised.values()))
                failures.append("%s: the UNMUTATED binary failed (%s) on %s"
                                % (group, ", ".join(kinds), sorted(raised)))
                continue
            baselines[group] = (vectors, base, base_diag)

        # An outcome member the implementation never emits contributes a constant
        # None to every comparison, so it discriminates nothing and every score
        # after it is over-generous by however much that member would have caught.
        # `doc.get(k)` made that silent. Absent on SOME vectors is legitimate --
        # `verdict` appears only when integrity passes, `claims` only when the
        # verdict is valid -- so the rule is "present at least once", not "always".
        for _selector in ("outcome_from", "diagnostic_from"):
            if m.get(_selector) is None:
                continue
            declared_keys = selector_members(m[_selector])
            seen = m.get("_selector_keys_seen", {}).get(_selector, set())
            never_seen = [k for k in declared_keys if k not in seen]
            if never_seen and baselines:
                failures.append(
                    "%s names %s, which the unmutated implementation never emits on any "
                    "vector. Those members compare None to None on every mutant, so they "
                    "discriminate nothing and this score is over-generous by whatever they "
                    "would have caught. Read the corpus's own declaration of its comparison "
                    "surface and match it." % (_selector, never_seen))

        for group in sorted(m["mutants"]):
            if group not in baselines:
                continue
            vectors, baseline, baseline_diag = baselines[group]
            for mut in m["mutants"][group]:
                scope = mut.get("scope", "declared")
                sources = [_resolved_contained_source(sp, m["_repo_root"])
                           for sp in m["_source_paths"]]
                hits = [(sp, sp.read_text(encoding="utf-8").count(mut["anchor"]))
                        for sp in sources]
                total = sum(n for _, n in hits)
                if total == 0:
                    failures.append("%s / %s: anchor not found in any declared source"
                                    % (group, mut["label"]))
                    continue
                if total > 1:
                    failures.append(
                        "%s / %s: the anchor occurs %d times across the declared sources, so "
                        "the substitution would pick one arbitrarily. Make it unique"
                        % (group, mut["label"], total))
                    continue

                target = next(sp for sp, n in hits if n == 1)
                target = _resolved_contained_source(target, m["_repo_root"])
                original = target.read_text(encoding="utf-8")
                target = _resolved_contained_source(target, m["_repo_root"])
                target.write_text(original.replace(mut["anchor"], mut["replacement"], 1),
                                  encoding="utf-8")
                try:
                    built, detail = _build(m)
                    if not built:
                        # Cursor's ruling on the design: rustc exit 1 yields no verdict, so
                        # the corpus never saw this mutant. Counting it killed would let a
                        # typo in the substitution print as "rule covered". Measure a
                        # load-bearing arm with a variant that COMPILES, or declare it
                        # equivalent.
                        results.append({"group": group, "label": mut["label"],
                                        "verdict": "unproved", "scope": scope, "moved": 0,
                                        "how": "the mutant does not build, so the corpus was "
                                               "never run against it: %s" % detail})
                        unproved += 1
                        continue
                    out, out_diag, raised = _process_outcomes(m, vectors)
                finally:
                    target = _resolved_contained_source(target, m["_repo_root"])
                    target.write_text(original, encoding="utf-8")

                moved = [vid for vid, val in out.items() if baseline.get(vid) != val]
                # The silent class, adopted from the forcing gate in
                # `astrogilda/aee-conformance` (see Related work): a mutant that
                # moves no declared outcome but does move a declared diagnostic
                # is a different finding from one nothing noticed at all. It is
                # NOT a kill -- the corpus's own verdict channel did not see the
                # rule go -- so it scores as a survivor, and it is named because
                # the repair differs: a survivor needs a new vector, a silent one
                # may only need the corpus to make its diagnostics normative.
                moved_diag = ([vid for vid, val in out_diag.items()
                               if baseline_diag.get(vid) != val]
                              if m.get("diagnostic_from") is not None else [])
                if mut.get("control"):
                    # Only a successfully parsed outcome change proves the control
                    # bites. An abnormal child is control-error, not a kill, and
                    # invalidates the run.
                    if raised:
                        how = ", ".join(sorted(set(raised.values())))
                        _record_control(
                            results, control_statuses,
                            group, mut["label"], scope, detected=False,
                            moved=0, error=how)
                        failures.append(
                            "control %r ended abnormally (%s); that is not a kill and "
                            "this run has no adequacy score" % (mut["label"], how))
                        continue
                    ok = bool(moved)
                    _record_control(
                        results, control_statuses,
                        group, mut["label"], scope, detected=ok, moved=len(moved))
                    if not ok:
                        failures.append(
                            "control %r survived: the harness cannot detect a change on this "
                            "path, so every other verdict in this run is meaningless"
                            % mut["label"])
                    continue
                if raised or moved:
                    how = (", ".join(sorted(set(raised.values()))) if raised
                           else "%d vector(s) moved" % len(moved))
                    results.append({"group": group, "label": mut["label"], "verdict": "killed",
                                    "scope": scope, "moved": len(moved), "how": how})
                    killed += 1
                # A diagnostic-only move never overrides a declared exclusion.
                # `silent` says "the corpus claims this rule and its pinned
                # outcomes cannot see it". An out-of-scope mutant is not making
                # that claim, and an acknowledged hole has already made it and
                # recorded the fact, so reclassifying either one scored a rule
                # the author excluded and called a still-valid acknowledgement
                # stale. Outcome movement is unaffected: it kills above, and the
                # linger guard still retires an acknowledgement it kills.
                elif scope == "out_of_scope":
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "unexercised", "scope": scope, "moved": 0,
                                    **_diagnostic_note(m, moved_diag),
                                    "how": "out of scope: %s%s"
                                           % (mut["reason"], _diagnostic_suffix(moved_diag))})
                    out_of_scope += 1
                elif label_identity(mut) in acknowledged:
                    ack = acknowledged[label_identity(mut)]
                    # A KNOWN HOLE is not a scope statement. The corpus does claim this
                    # rule, the rule is genuinely unexercised, and that fact is recorded
                    # against ONE digest rather than fixed today. It stays loud.
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "known-hole", "scope": scope, "moved": 0,
                                    **_diagnostic_note(m, moved_diag),
                                    "how": "KNOWN HOLE against %s, recorded %s: %s%s"
                                           % (m["_corpus_digest"][:19], ack["recorded"],
                                              ack["reason"], _diagnostic_suffix(moved_diag))})
                    known_holes += 1
                elif moved_diag:
                    results.append({"group": group, "label": mut["label"], "verdict": "silent",
                                    "scope": scope, "moved": 0,
                                    "moved_diagnostic": len(moved_diag),
                                    "how": "no vector's declared outcome distinguishes it, but "
                                           "%d vector(s) moved on the declared diagnostic "
                                           "channel. An implementation can delete this rule and "
                                           "still reproduce every pinned outcome; only a consumer "
                                           "comparing diagnostics would notice"
                                           % len(moved_diag)})
                    silent += 1
                else:
                    results.append({"group": group, "label": mut["label"], "verdict": "survived",
                                    "scope": scope, "moved": 0,
                                    "how": "no vector distinguishes it. An implementation can "
                                           "delete this rule and still reproduce the digest"})
                    survived += 1

            for eq in m["equivalent"].get(group, []):
                results.append({"group": group, "label": eq["label"], "verdict": "equivalent",
                                "how": eq["reason"], "moved": 0})
                equivalent += 1
    finally:
        try:
            if guard is not None:
                guard.restore()
                leaked = guard.verify_clean()
                if leaked:
                    failures.append("SOURCES NOT RESTORED: %s" % leaked)
        finally:
            iso.cleanup()
            lock.__exit__()

    # A stale acknowledgement is not only one whose rule became killed. Any verdict
    # other than known-hole means the acknowledgement no longer describes anything,
    # and a leftover that points at nothing is what hides the next regression.
    linger = {label_identity(r): r["verdict"] for r in results
              if label_identity(r) in acknowledged and r["verdict"] != "known-hole"}
    if linger:
        failures.append("known_holes acknowledge rules that are no longer holes: %s. Remove "
                        "them; an acknowledgement pointing at nothing hides the next regression"
                        % sorted("%s (now %s)" % kv for kv in linger.items()))
    # `silent` sits in the denominator beside `survived` and NEVER in the
    # numerator. A mutant the declared outcome channel could not see is a rule an
    # implementer can delete while reproducing every pinned outcome, whatever the
    # diagnostics did; counting it killed would inflate the score by exactly the
    # rules the corpus fails to force.
    denom = killed + survived + silent
    # No denominator means no measurement. Printing 100% over zero is the same
    # defect as excluding everything and printing 100%. An unmutated or control
    # abnormality fail-closes the run: there is no adequacy score.
    score = _score_or_none(None if denom == 0 else round(100.0 * killed / denom, 1),
                           results, failures)
    if unproved:
        failures.append("%d mutant(s) never ran, so this corpus was not measured against them"
                        % unproved)
    if survived:
        failures.append("%d mutant(s) survived; the required score is 100%% of non-equivalent "
                        "mutants" % survived)
    if silent:
        failures.append("%d mutant(s) were silent: no declared outcome moved, only a declared "
                        "diagnostic. The rule is not forced by the outcomes this corpus pins, so "
                        "it counts against the score; either write a vector that moves an outcome "
                        "or declare the diagnostic channel part of the pinned surface" % silent)
    if denom == 0:
        failures.append(null_result_reading(known_holes, equivalent, out_of_scope))

    return _report_v0(
        manifest_path, m,
        killed=killed, survived=survived, silent=silent, equivalent=equivalent,
        out_of_scope=out_of_scope, unproved=unproved, known_holes=known_holes,
        score=score, results=results, failures=failures,
        control_status=_control_status(control_statuses, declared_controls),
        originals_unverified_against_head=guard.unverified)


def run(manifest_path: Path) -> dict:
    m = load_manifest(manifest_path)
    if m["runner"] in ("process", "batch"):
        return _run_process(m, manifest_path)
    source = m["_impl_path"].read_text(encoding="utf-8")
    doc = json.loads(m["_vectors_path"].read_text(encoding="utf-8"))
    all_vectors = doc[m["vectors_key"]] if isinstance(doc, dict) else doc

    failures: list[str] = []
    groups_in_corpus = {_group_of(v, m) for v in all_vectors}

    failures.extend(structural_failures(m, groups_in_corpus))
    acknowledged = _acknowledged_holes(m)
    results, killed, survived, equivalent, out_of_scope = [], 0, 0, 0, 0
    control_statuses: list[str] = []
    declared_controls = _declared_control_count(m)
    # The module runner refuses `diagnostic_from` at load, so the silent class
    # cannot occur here. It is still reported: a consumer reading `.get("silent",
    # 0)` on a report that omits the key gets the false-measured answer the field
    # exists to prevent, and the same denominator rule has to hold on every path.
    silent = 0
    unproved = known_holes = 0
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        for group in sorted(m["mutants"]):
            vectors = [v for v in all_vectors if _group_of(v, m) == group]
            if not vectors:
                failures.append("%s: no vectors, so its mutants cannot be scored" % group)
                continue
            base = _module_outcomes(m, source, "base", vectors, tmp)
            if base.entrypoint_missing:
                raise ManifestError("implementation has no entrypoint %r" % m["entrypoint"])
            if base.load_error:
                raise ManifestError("the implementation does not load: %s" % base.load_error)
            # The unmutated run is what every other verdict in this group is
            # measured against, so its child dying is not a result about any
            # mutant. It invalidates the group and nulls the score.
            if base.abnormal:
                failures.append("%s: the UNMUTATED implementation could not be measured (%s)"
                                % (group, base.abnormal))
                continue
            if base.unsupported:
                failures.append(
                    "%s: the UNMUTATED implementation returned outcomes this runner cannot "
                    "transport on %s, so there is nothing for a mutant to be compared against"
                    % (group, base.unsupported))
                continue
            if base.raised:
                failures.append("%s: the UNMUTATED implementation raised on %s"
                                % (group, base.raised))
                continue
            baseline = base.outcomes

            for idx, mut in enumerate(m["mutants"][group]):
                occurrences = source.count(mut["anchor"])
                if occurrences == 0:
                    failures.append(
                        "%s / %s: anchor not found in %s. The rule was renamed or removed and the "
                        "mutant is measuring nothing" % (group, mut["label"], m["implementation"]))
                    continue
                if occurrences > 1:
                    # Substituting the first of several is a coin flip about which rule is being
                    # measured, and a mangled substitution is then scored as a kill.
                    failures.append(
                        "%s / %s: the anchor occurs %d times in %s, so the substitution would pick "
                        "one arbitrarily and any breakage would be scored as a kill. Make the "
                        "anchor unique" % (group, mut["label"], occurrences, m["implementation"]))
                    continue
                scope = mut.get("scope", "declared")
                mutated = source.replace(mut["anchor"], mut["replacement"], 1)
                res = _module_outcomes(m, mutated,
                                       "%s_%d" % (group.replace("-", "_"), idx), vectors, tmp)
                if res.load_error or res.entrypoint_missing:
                    # A mutant that never loaded was never shown to the corpus, so the
                    # corpus said nothing about it. Counting that as a kill lets a typo
                    # in the substitution print as "rule covered". The same argument
                    # rules out treating a Rust build failure as a kill; measure a
                    # load-bearing rule with a variant that RUNS, or declare it equivalent.
                    detail = res.load_error or ("no entrypoint %r" % m["entrypoint"])
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "unproved", "scope": scope, "moved": 0,
                                    "how": "the mutant does not load, so the corpus never "
                                           "saw it and said nothing about this rule: %s" % detail})
                    unproved += 1
                    continue
                if res.abnormal or res.unsupported:
                    kind = res.abnormal or "unsupported-outcome"
                    if mut.get("control"):
                        # The control is what proves the harness detects anything, so
                        # its child dying is not a kill. It leaves the run with no score.
                        _record_control(
                            results, control_statuses,
                            group, mut["label"], scope, detected=False,
                            moved=0, error=kind)
                        failures.append(
                            "control %r ended abnormally (%s); that is not a kill and "
                            "this run has no adequacy score" % (mut["label"], kind))
                        continue
                    if kind in TERMINATED_KINDS:
                        # Observed termination: the unmutated run completed on these
                        # same vectors and this one did not.
                        results.append({"group": group, "label": mut["label"],
                                        "verdict": "killed", "scope": scope, "moved": 0,
                                        "how": kind})
                        killed += 1
                        continue
                    results.append({
                        "group": group, "label": mut["label"], "verdict": "unproved",
                        "scope": scope, "moved": 0,
                        "how": "the measurement did not complete (%s), so the corpus was "
                               "never shown this mutant and said nothing about this rule" % kind})
                    unproved += 1
                    continue
                out = res.outcomes
                raised = list(res.raised)
                moved = [vid for vid, val in out.items() if baseline.get(vid) != val]
                if mut.get("control"):
                    ok = bool(raised or moved)
                    _record_control(
                        results, control_statuses,
                        group, mut["label"], scope, detected=ok, moved=len(moved))
                    if not ok:
                        failures.append(
                            "control %r survived: the harness cannot detect a change on this "
                            "path, so every other verdict in this run is meaningless"
                            % mut["label"])
                    continue
                if raised:
                    results.append({"group": group, "label": mut["label"], "verdict": "killed",
                                    "scope": scope, "how": "raises on %d vector(s)" % len(raised),
                                    "moved": len(moved), "raised": raised})
                    killed += 1
                elif moved:
                    results.append({"group": group, "label": mut["label"], "verdict": "killed",
                                    "scope": scope, "how": "%d vector(s) moved" % len(moved),
                                    "moved": len(moved)})
                    killed += 1
                elif scope == "out_of_scope":
                    # Declared by the manifest as a rule this corpus does not claim to cover.
                    # Reported every run, never scored: adequacy is relative to declared scope,
                    # and scoring a rule nobody claimed manufactures a hole that is not one.
                    results.append({
                        "group": group, "label": mut["label"], "verdict": "unexercised",
                        "scope": scope, "moved": 0,
                        # Print the stated reason, exactly as a declared equivalent does.
                        # "each with a stated reason" without showing one is an assertion.
                        "how": "out of scope: %s" % mut["reason"]})
                    out_of_scope += 1
                elif label_identity(mut) in acknowledged:
                    ack = acknowledged[label_identity(mut)]
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "known-hole", "scope": scope, "moved": 0,
                                    "how": "KNOWN HOLE against %s, recorded %s: %s"
                                           % (str(m["_corpus_digest"])[:19], ack["recorded"],
                                              ack["reason"])})
                    known_holes += 1
                else:
                    results.append({
                        "group": group, "label": mut["label"], "verdict": "survived",
                        "scope": scope, "moved": 0,
                        "how": "no vector distinguishes it. An implementation can delete this rule, "
                               "reproduce the pinned digest, and be indistinguishable from a "
                               "conforming one. The corpus needs a vector where this rule, and only "
                               "this rule, decides the outcome"})
                    survived += 1

            for eq in m["equivalent"].get(group, []):
                results.append({"group": group, "label": eq["label"], "verdict": "equivalent",
                                "how": eq["reason"], "moved": 0})
                equivalent += 1

    linger = {label_identity(r): r["verdict"] for r in results
              if label_identity(r) in acknowledged and r["verdict"] != "known-hole"}
    if linger:
        failures.append("known_holes acknowledge rules that are no longer holes: %s. Remove "
                        "them; an acknowledgement pointing at nothing hides the next regression"
                        % sorted("%s (now %s)" % kv for kv in linger.items()))
    denom = killed + survived + silent
    score = _score_or_none(None if denom == 0 else round(100.0 * killed / denom, 1),
                           results, failures)
    if unproved:
        # Not a soft warning: an unproved mutant means the measurement did not happen,
        # and a score computed over the rest reports more than the run established.
        failures.append("%d mutant(s) never ran, so this corpus was not measured against "
                        "them. Fix the substitution or declare them equivalent" % unproved)
    if survived:
        failures.append("%d mutant(s) survived; the required score is 100%% of non-equivalent "
                        "mutants" % survived)
    if denom == 0:
        failures.append(null_result_reading(known_holes, equivalent, out_of_scope))

    # `silent` is 0 here by construction: the module runner refuses
    # `diagnostic_from` at load, so the class cannot occur. It is projected
    # rather than omitted, so a consumer can tell zero from unmeasured.
    return _report_v0(
        manifest_path, m,
        killed=killed, survived=survived, silent=silent, equivalent=equivalent,
        out_of_scope=out_of_scope, unproved=unproved, known_holes=known_holes,
        score=score, results=results, failures=failures,
        control_status=_control_status(control_statuses, declared_controls))


def null_result_reading(known_holes, equivalent, out_of_scope):
    """What a denominator of zero actually licenses you to say.

    A null result feels like a fact about the corpus -- "this one cannot be
    measured" -- and reads like a finding. It is almost always a fact about the
    manifest instead, and reads like a mistake, which is why the wrong reading
    survives. The author of this tool published "not measurable" for a 14-vector
    corpus after declaring three rules for it, two of which mutated the wrong
    stage; the verifier had at least eight more that the vector names all but
    announce. The message says so rather than leaving the reader to make the
    same inference unaided.
    """
    if known_holes or equivalent or out_of_scope:
        return ("nothing was measured: every declared in-scope rule is either a known hole, "
                "declared equivalent or out of scope. There is no adequacy result here. "
                "A null result is a statement about the DECLARATION before it is one about "
                "the corpus: count the rules the implementation has, from the implementation "
                "rather than from this manifest, before concluding the corpus cannot be measured")
    return ("no non-equivalent mutants were scored, so no adequacy was measured. "
            "Declare the rules the implementation actually has; an empty declaration "
            "measures nothing and says nothing")


def _score_or_none(score, results: list, failures: list):
    """A run whose own harness or unmutated baseline failed has no score.

    One function because it was two. The process path nulled the score on a
    control-error or a failed UNMUTATED run; the module path did not, so the
    same abnormality was a refusal on one runner and a printed percentage on
    the other. That is the defect structural_failures already describes one
    level up, in the arithmetic instead of in the guards.
    """
    if (any(r.get("verdict") == "control-error" for r in results)
            or any("UNMUTATED" in f for f in failures)):
        return None
    return score


def structural_failures(m: dict, groups_in_corpus: set) -> list:
    """Guards that hold for EVERY runner, in one place because they drifted apart.

    These were written twice, once per runner, and the copies diverged: the
    control requirement reached the process and batch paths and never reached the
    module path. A module corpus could therefore score without ever declaring the
    one mutant that proves the harness can detect anything -- which is exactly the
    condition the control exists to exclude, missing from the runner where it was
    cheapest to check. One of this tool's own five subject corpora was in that
    state, while the page publishing its score said every manifest must declare a
    control.

    A rule stated in two places is a rule that will eventually be enforced in one.
    """
    failures = []
    unmutated = sorted(groups_in_corpus - set(m["mutants"]))
    if unmutated:
        failures.append(
            "groups present in the corpus with no declared mutants: %s. Declare a mutant per "
            "rule, or this check covers less than its name claims" % unmutated)
    stale = sorted(set(m["mutants"]) - groups_in_corpus)
    if stale:
        failures.append("mutants declared for groups not in the corpus: %s" % stale)
    if not any(mut.get("control") for muts in m["mutants"].values() for mut in muts):
        failures.append("no control mutant declared. Without one, a run of all-survivors "
                        "cannot be told apart from a harness that detects nothing")
    acknowledged = _acknowledged_holes(m)
    orphaned = set(acknowledged) - {
        label_identity(mu) for ms in m["mutants"].values() for mu in ms
    }
    if orphaned:
        failures.append("known_holes name mutants that do not exist: %s" % sorted(orphaned))
    return failures


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--version", action="store_true",
                    help="print tool version (and commit, if resolvable) and exit")
    ap.add_argument("manifest", type=Path, nargs="?")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.version:
        print(format_tool_identity())
        return 0
    if args.manifest is None:
        ap.error("manifest is required")
    try:
        rep = run(args.manifest)
        encoded = encode_report_v0(rep) if args.json else None
    except (ManifestError, OSError, json.JSONDecodeError, ReportEncodingError) as exc:
        print("could not measure: %s" % exc, file=sys.stderr)
        if args.json:
            print(json.dumps(error_envelope(exc), indent=2, sort_keys=True))
        return 2

    if args.json:
        assert encoded is not None
        if hasattr(sys.stdout, "buffer"):
            sys.stdout.buffer.write(encoded)
        else:
            # StringIO and embedded callers may expose only a text stream.
            sys.stdout.write(encoded.decode("utf-8"))
    else:
        print(format_tool_identity(rep))
        for r in rep["mutants"]:
            print("%-22s %-9s %s" % (r["group"], r["verdict"], r["label"]))
            if r["verdict"] != "killed" or rep.get("runner") in ("process", "batch"):
                print("    %s" % r["how"])
        print()
        # Never a bare percentage. A score reported without its denominator and its
        # exclusions is a percentage target wearing a different coat: an author can
        # exclude almost everything and still print 100%.
        pct = ("no result" if rep["score_percent"] is None
               else "%.1f%%" % rep["score_percent"])
        print("%d of %d DECLARED in-scope rules killed (%s). %d declared equivalent, "
              "%d declared out of scope, %d unproved. %d rules declared in total."
              % (rep["killed"], rep["killed"] + rep["survived"], pct,
                 rep["equivalent"], rep["unexercised_out_of_scope"], rep["unproved"],
                 rep["declared_total"]))
        if rep["score_percent"] is not None:
            print("This is %.1f%% of what the AUTHOR DECLARED, not of the rules the "
                  "implementation has. A rule nobody declared is invisible to this check."
                  % rep["score_percent"])
        if rep["unexercised_out_of_scope"]:
            print("out of scope (%d, each with a stated reason): real gaps in what the corpus "
                  "covers, not holes in what it claims" % rep["unexercised_out_of_scope"])
        if rep["out_of_scope_ratio"] is not None and rep["out_of_scope_ratio"] > 1.0:
            print("NOTE: more rules are excluded than measured (ratio %.2f). The score is real "
                  "but it is a statement about a minority of the declared rules."
                  % rep["out_of_scope_ratio"])
        for f in rep["failures"]:
            print("FAIL: %s" % f)
        if rep.get("known_holes"):
            # Louder than the pass line. Not pinned to the corpus: pinned to a value
            # another tool has to keep honest, which is what the text below says.
            print("%d KNOWN HOLE(S) against the DECLARED digest %s. These are rules the "
                  "corpus DOES claim and does NOT exercise."
                  % (rep["known_holes"], rep.get("corpus_digest")))
            print("  The digest is a value READ FROM A FILE THE MANIFEST NAMES. It is not "
                  "recomputed from the vectors, so these acknowledgements expire only if that "
                  "file is kept honest.")
            if rep.get("acknowledged_digests", 0) > 1:
                print("  %d digests carry acknowledgements in this manifest. Entries for a "
                      "digest that is not the declared one are not in force, but pre-declaring "
                      "future digests is how this expiry gets bypassed."
                      % rep["acknowledged_digests"])
            if rep.get("hole_ratio") is not None and rep["hole_ratio"] > 1.0:
                print("  more rules are acknowledged as holes than are measured (ratio %.2f). "
                      "The score printed above is a statement about a minority of the "
                      "declared rules." % rep["hole_ratio"])
        if rep["adequate"]:
            if rep["out_of_scope_ratio"] is not None and rep["out_of_scope_ratio"] > 1.0:
                # The closing line is what gets quoted. It may not read as unqualified
                # success when most declared rules were excluded from the measurement.
                print("mutation-adequacy check passed for the DECLARED IN-SCOPE rules only "
                      "(%d of %d rules declared here were excluded from it)"
                      % (rep["unexercised_out_of_scope"], rep["declared_total"]))
            else:
                suffix = ""
                if rep.get("known_holes"):
                    suffix = (" for the rules still measured -- %d are acknowledged holes"
                              % rep["known_holes"])
                print("mutation-adequacy check passed: every non-equivalent mutant is killed"
                      + suffix)

    return 0 if rep["adequate"] else 1


if __name__ == "__main__":
    sys.exit(main())
