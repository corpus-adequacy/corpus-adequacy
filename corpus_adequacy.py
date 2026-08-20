#!/usr/bin/env python3
"""Mutation adequacy for a published conformance corpus, driven by a manifest.

Standard library only. No Assay import, no pip install, no network.

    python3 conformance/corpus_adequacy.py <manifest.json>
    python3 conformance/corpus_adequacy.py <manifest.json> --json

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
  - a crash is a KILL, reported separately, because "raises without this rule"
    says more about the rule than "returns something else".

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
import importlib.util
import json
import re
import sys
import subprocess
import tempfile
try:
    import fcntl                       # POSIX advisory locks
except ImportError:                          # pragma: no cover - non-POSIX
    fcntl = None
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bounded_run import (  # noqa: E402
    OUTPUT_CAP_BYTES, _OutputTooLarge, _run_capped,
)

SCHEMA = "corpus-adequacy.manifest.v0"
# One place. The report, --version, CHANGELOG, and the git tag all name this.
# A SHA pin is exact and opaque; this is the name a measurement can quote.
VERSION = "0.1.0"


class ManifestError(Exception):
    """The manifest does not describe a measurable corpus."""


def tool_identity() -> dict:
    """What a pinned measurement should carry so a SHA is not the only name.

    CI pins this tool by commit SHA. That is exact and opaque. The version
    constant is the name a report can quote; the commit is resolved from this
    file's checkout when git is available, so a copied report still names the
    bytes that produced it. A checkout without `.git` still carries the version.
    """
    identity = {"tool_version": VERSION, "tool_commit": None}
    here = Path(__file__).resolve().parent
    try:
        p = subprocess.run(
            ["git", "-C", str(here), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if p.returncode == 0:
            commit = p.stdout.strip()
            identity["tool_commit"] = commit or None
    except (OSError, subprocess.TimeoutExpired):
        pass
    return identity


def _with_tool_identity(report: dict) -> dict:
    report.update(tool_identity())
    return report


def format_tool_identity(identity: dict | None = None) -> str:
    identity = identity if identity is not None else tool_identity()
    commit = identity.get("tool_commit") or "unresolved"
    return "corpus-adequacy %s commit=%s" % (identity["tool_version"], commit)


def _req(obj: dict, key: str, where: str):
    if key not in obj:
        raise ManifestError("%s: missing required key %r" % (where, key))
    return obj[key]


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
    m = json.loads(path.read_text(encoding="utf-8"))
    if m.get("schema") != SCHEMA:
        raise ManifestError("schema must be %r, got %r" % (SCHEMA, m.get("schema")))
    base = path.parent
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
    m["_corpus_digest"] = None
    if m["known_holes"]:
        for key in ("corpus_digest_file", "corpus_digest_key"):
            _req(m, key, "manifest (known_holes declared)")
        dp = (base / m["corpus_digest_file"]).resolve()
        if not dp.is_file():
            raise ManifestError("corpus_digest_file not found: %s" % dp)
        m["_corpus_digest"] = json.loads(dp.read_text(encoding="utf-8"))[m["corpus_digest_key"]]
        for digest, entries in m["known_holes"].items():
            for i, e in enumerate(entries):
                for key in ("label", "reason", "recorded"):
                    _req(e, key, "known_holes[%s][%d]" % (digest, i))
                if not str(e["reason"]).strip():
                    raise ManifestError("known_holes[%s][%d] %r: a hole needs a stated reason"
                                        % (digest, i, e["label"]))
    m.setdefault("runner", "module")
    if m["runner"] not in ("module", "process", "batch"):
        raise ManifestError("runner must be module, process or batch, got %r" % m["runner"])
    if m["runner"] in ("process", "batch"):
        _req(m, "entrypoint_command", "manifest (runner=%s)" % m["runner"])
        if m.get("outcome_parse") != "test-names":
            _req(m, "outcome_from", "manifest (runner=%s)" % m["runner"])
        m.setdefault("outcome_from", [])
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
    m.setdefault("mutants", {})
    m.setdefault("equivalent", {})
    if not m["mutants"]:
        raise ManifestError("manifest declares no mutants; there is nothing to measure")
    for group, entries in m["mutants"].items():
        for i, e in enumerate(entries):
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
        for i, e in enumerate(entries):
            for key in ("label", "reason"):
                _req(e, key, "equivalent[%s][%d]" % (group, i))
            if not str(e["reason"]).strip():
                raise ManifestError(
                    "equivalent[%s][%d] %r: an equivalence needs a stated reason, never a bare claim"
                    % (group, i, e["label"]))
    _require_unique_labels(m)
    return m


def _load_module(source: str, tag: str, tmp: Path):
    path = tmp / ("impl_%s.py" % tag)
    path.write_text(source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("adequacy_%s" % tag, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def _outcomes(fn, vectors: list[dict], m: dict) -> tuple[dict, list[str]]:
    """(outcome per vector id, ids that raised). A raise is a behaviour change."""
    outcomes, raised = {}, []
    for v in vectors:
        vid = v[m["id_key"]]
        try:
            outcomes[vid] = fn(*[v[k] for k in m["entrypoint_args"]])
        except Exception:  # noqa: BLE001 - any raise is the signal, not an error
            raised.append(vid)
    return outcomes, raised



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

    So the lock is taken BEFORE the dirty check, not after: a clean tree
    observed outside the lock can be mutated before the originals are captured,
    which is the same bug one step earlier.

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
                "cannot exclude a concurrent writer. Refusing before dirty "
                "check, source capture, build, or mutation of %s"
                % self.repo_root)
        self._fh = open(self.path, "w", encoding="utf-8")
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


def _tree_is_dirty(repo_root: Path, paths: list[Path]) -> list[str]:
    """Declared sources with uncommitted changes. Mutating those loses work."""
    try:
        out = subprocess.run(["git", "-C", str(repo_root), "status", "--porcelain", "--"]
                             + [str(p) for p in paths],
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return []          # no git: nothing to protect, and nothing to claim
    return [ln[3:] for ln in out.stdout.splitlines() if ln.strip()]


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


def _batch_outcome(m: dict) -> tuple[dict, list[str]]:
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
    except Exception:  # noqa: BLE001
        return {}, ["<batch>"]

    if m.get("outcome_parse") == "test-names":
        # The checker is a test binary, not a reporter. Its outcome is WHICH tests
        # failed, which discriminates per case exactly as a named failures list
        # does. A bare pass/fail would not: every mutant would kill everything or
        # nothing.
        out = p.stdout + p.stderr
        failed = sorted(set(re.findall(m.get("failed_test_pattern",
                                             r"^test (\S+) \.\.\. FAILED$"), out, re.M)))
        ran = sum(int(x) for x in re.findall(r"^test result: \w+\. (\d+) passed", out, re.M))
        if ran == 0 and not failed:
            # A filter that selected nothing exits 0 and would read as agreement.
            return {}, ["<batch>"]
        return {"<batch>": tuple(failed)}, []

    try:
        doc = json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        return {}, ["<batch>"]
    keys = m["outcome_from"]
    keylist = keys if isinstance(keys, list) else [keys]
    m.setdefault("_outcome_keys_seen", set()).update(k for k in keylist if k in doc)
    vals = [doc.get(k) for k in keylist]
    # lists are compared as tuples so a failures list discriminates per case
    norm = tuple(tuple(v) if isinstance(v, list) else v for v in vals)
    return {"<batch>": norm}, []


def _process_outcomes(m: dict, vectors: list[dict]) -> tuple[dict, list[str]]:
    """Run the built command once per vector. A vector that cannot be read is a raise."""
    if m["runner"] == "batch":
        return _batch_outcome(m)
    outcomes, raised = {}, []
    for v in vectors:
        vid = v[m["id_key"]]
        cmd = [str(x).replace("{vector}", str((m["_repo_root"] / v[m["vector_path_key"]]).resolve()))
               for x in m["entrypoint_command"]]
        try:
            p = _run_capped(cmd, m["_repo_root"], timeout=m["vector_timeout"])
            doc = json.loads(p.stdout)
            keys = m["outcome_from"]
            # A single key can collapse every rejection onto one value and lose all
            # discrimination, so a list is allowed and compared as a tuple.
            keylist = keys if isinstance(keys, list) else [keys]
            m.setdefault("_outcome_keys_seen", set()).update(k for k in keylist if k in doc)
            outcomes[vid] = (tuple(doc.get(k) for k in keys) if isinstance(keys, list)
                             else doc.get(keys))
        except Exception:  # noqa: BLE001 - unreadable output is a behaviour change
            raised.append(vid)
    return outcomes, raised



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
    known_holes = 0

    # Taken BEFORE the dirty check: a tree observed clean outside the lock can be
    # mutated by another run before the originals are captured, and then this run's
    # restore writes that mutant back as the original.
    lock = _TreeLock(m["_repo_root"])
    lock.__enter__()

    try:
        dirty = _tree_is_dirty(m["_repo_root"], m["_source_paths"])
        if dirty:
            raise ManifestError(
                "declared sources have uncommitted changes: %s. This adapter edits them in "
                "place, so it refuses to run rather than risk losing that work" % dirty)
        guard = _SourceGuard(m["_source_paths"], m["_repo_root"])
    except BaseException:
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
            base, raised = _process_outcomes(m, vectors)
            if raised:
                failures.append("%s: the UNMUTATED binary failed on %s" % (group, raised))
                continue
            baselines[group] = (vectors, base)

        # An outcome member the implementation never emits contributes a constant
        # None to every comparison, so it discriminates nothing and every score
        # after it is over-generous by however much that member would have caught.
        # `doc.get(k)` made that silent. Absent on SOME vectors is legitimate --
        # `verdict` appears only when integrity passes, `claims` only when the
        # verdict is valid -- so the rule is "present at least once", not "always".
        declared_keys = m["outcome_from"] if isinstance(m["outcome_from"], list) else [m["outcome_from"]]
        never_seen = [k for k in declared_keys if k not in m.get("_outcome_keys_seen", set())]
        if never_seen and baselines:
            failures.append(
                "outcome_from names %s, which the unmutated implementation never emits on any "
                "vector. Those members compare None to None on every mutant, so they discriminate "
                "nothing and this score is over-generous by whatever they would have caught. Read "
                "the corpus's own declaration of its comparison surface and match it." % never_seen)

        for group in sorted(m["mutants"]):
            if group not in baselines:
                continue
            vectors, baseline = baselines[group]
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
                    out, raised = _process_outcomes(m, vectors)
                finally:
                    target = _resolved_contained_source(target, m["_repo_root"])
                    target.write_text(original, encoding="utf-8")

                moved = [vid for vid, val in out.items() if baseline.get(vid) != val]
                if mut.get("control"):
                    # A control exists to prove the harness can detect ANYTHING. It is
                    # never scored: counting it would inflate the very number it exists
                    # to make trustworthy. A control that survives means the run says
                    # nothing at all about the corpus.
                    ok = bool(raised or moved)
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "control-killed" if ok else "control-SURVIVED",
                                    "scope": scope, "moved": len(moved),
                                    "how": ("harness detects a change on this path"
                                            if ok else "THE HARNESS DETECTS NOTHING")})
                    if not ok:
                        failures.append(
                            "control %r survived: the harness cannot detect a change on this "
                            "path, so every other verdict in this run is meaningless"
                            % mut["label"])
                    continue
                if raised or moved:
                    results.append({"group": group, "label": mut["label"], "verdict": "killed",
                                    "scope": scope, "moved": len(moved),
                                    "how": ("raises on %d vector(s)" % len(raised)) if raised
                                           else "%d vector(s) moved" % len(moved)})
                    killed += 1
                elif scope == "out_of_scope":
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "unexercised", "scope": scope, "moved": 0,
                                    "how": "out of scope: %s" % mut["reason"]})
                    out_of_scope += 1
                elif label_identity(mut) in acknowledged:
                    ack = acknowledged[label_identity(mut)]
                    # A KNOWN HOLE is not a scope statement. The corpus does claim this
                    # rule, the rule is genuinely unexercised, and that fact is recorded
                    # against ONE digest rather than fixed today. It stays loud.
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "known-hole", "scope": scope, "moved": 0,
                                    "how": "KNOWN HOLE against %s, recorded %s: %s"
                                           % (m["_corpus_digest"][:19], ack["recorded"],
                                              ack["reason"])})
                    known_holes += 1
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
            guard.restore()
            leaked = guard.verify_clean()
            if leaked:
                failures.append("SOURCES NOT RESTORED: %s" % leaked)
            _build(m)   # leave the tree with a binary built from the real source
        finally:
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
    denom = killed + survived
    # No denominator means no measurement. Printing 100% over zero is the same
    # defect as excluding everything and printing 100%.
    score = None if denom == 0 else round(100.0 * killed / denom, 1)
    if unproved:
        failures.append("%d mutant(s) never ran, so this corpus was not measured against them"
                        % unproved)
    if survived:
        failures.append("%d mutant(s) survived; the required score is 100%% of non-equivalent "
                        "mutants" % survived)
    if denom == 0:
        failures.append(null_result_reading(known_holes, equivalent, out_of_scope))

    return _with_tool_identity({
            "schema": "corpus-adequacy.report.v0", "manifest": str(manifest_path),
            "runner": m["runner"], "killed": killed, "survived": survived,
            "known_holes": known_holes, "corpus_digest": m.get("_corpus_digest"),
            "originals_unverified_against_head": guard.unverified,
            "acknowledged_digests": len(m.get("known_holes", {})),
            "hole_ratio": (None if (killed + survived) == 0
                           else round(known_holes / (killed + survived), 2)),
            "equivalent": equivalent, "unexercised_out_of_scope": out_of_scope,
            "unproved": unproved,
            "declared_total": (killed + survived + equivalent + out_of_scope + unproved
                               + known_holes),
            "out_of_scope_ratio": (None if denom == 0 else round(out_of_scope / denom, 2)),
            "score_percent": score,
            "score_means": ("percent of author-declared in-scope rules killed; NOT percent of "
                            "the rules the implementation actually has"),
            "mutants": results, "failures": failures, "adequate": not failures})


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
    unproved = known_holes = 0
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        base_mod = _load_module(source, "base", tmp)
        base_fn = getattr(base_mod, m["entrypoint"], None)
        if base_fn is None:
            raise ManifestError("implementation has no entrypoint %r" % m["entrypoint"])

        for group in sorted(m["mutants"]):
            vectors = [v for v in all_vectors if _group_of(v, m) == group]
            if not vectors:
                failures.append("%s: no vectors, so its mutants cannot be scored" % group)
                continue
            baseline, base_raised = _outcomes(base_fn, vectors, m)
            if base_raised:
                failures.append("%s: the UNMUTATED implementation raised on %s"
                                % (group, base_raised))
                continue

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
                try:
                    mod = _load_module(mutated, "%s_%d" % (group.replace("-", "_"), idx), tmp)
                    fn = getattr(mod, m["entrypoint"])
                except Exception as exc:  # noqa: BLE001
                    # A mutant that never loaded was never shown to the corpus, so the
                    # corpus said nothing about it. Counting that as a kill lets a typo
                    # in the substitution print as "rule covered". The same argument
                    # rules out treating a Rust build failure as a kill; measure a
                    # load-bearing rule with a variant that RUNS, or declare it equivalent.
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "unproved", "scope": scope, "moved": 0,
                                    "how": "the mutant does not load, so the corpus never "
                                           "saw it and said nothing about this rule: %r" % (exc,)})
                    unproved += 1
                    continue
                out, raised = _outcomes(fn, vectors, m)
                moved = [vid for vid, val in out.items() if baseline.get(vid) != val]
                if mut.get("control"):
                    ok = bool(raised or moved)
                    results.append({"group": group, "label": mut["label"],
                                    "verdict": "control-killed" if ok else "control-SURVIVED",
                                    "scope": scope, "moved": len(moved),
                                    "how": ("harness detects a change on this path"
                                            if ok else "THE HARNESS DETECTS NOTHING")})
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
    denom = killed + survived
    score = None if denom == 0 else round(100.0 * killed / denom, 1)
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

    return _with_tool_identity({
            "schema": "corpus-adequacy.report.v0", "manifest": str(manifest_path),
            "killed": killed, "survived": survived, "equivalent": equivalent,
            "known_holes": known_holes, "corpus_digest": m.get("_corpus_digest"),
            "acknowledged_digests": len(m.get("known_holes", {})),
            "hole_ratio": (None if (killed + survived) == 0
                           else round(known_holes / (killed + survived), 2)),
            "unexercised_out_of_scope": out_of_scope, "unproved": unproved,
            "declared_total": (killed + survived + equivalent + out_of_scope + unproved
                               + known_holes),
            "out_of_scope_ratio": (None if (killed + survived) == 0
                                   else round(out_of_scope / (killed + survived), 2)),
            "score_means": ("percent of author-declared in-scope rules killed; NOT percent of the "
                            "rules the implementation actually has"),
            "score_percent": score, "mutants": results, "failures": failures,
            "adequate": not failures})


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
    except (ManifestError, OSError, json.JSONDecodeError) as exc:
        print("could not measure: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print(format_tool_identity(rep))
        for r in rep["mutants"]:
            print("%-22s %-9s %s" % (r["group"], r["verdict"], r["label"]))
            if r["verdict"] != "killed":
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
