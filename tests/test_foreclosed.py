#!/usr/bin/env python3
"""Issue 256: a foreclosed disposition the tool proves on every run.

Each of tests 1-5 must fail on 6d1ff19827744934e57c0b799baa49b525a361e7 for
the named reason. Test 6 is the no-container compatibility pin against that
release: it is green on that commit and red if a later head changes reports
for manifests that never declared the container.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import corpus_adequacy as ca  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
BASE_COMMIT = "6d1ff19827744934e57c0b799baa49b525a361e7"
EXAMPLE_MANIFESTS = (
    "examples/reason-token-projections/outcome.manifest.json",
    "examples/reason-token-projections/decision-only.manifest.json",
    "examples/reason-token-projections/diagnostic.manifest.json",
    "examples/reason-token-projections/multi-guard.outcome.manifest.json",
    "examples/reason-token-projections/multi-guard.decision-only.manifest.json",
    "examples/reason-token-projections/multi-guard.diagnostic.manifest.json",
)

# L refuses an undeclared `flag` before R can read it. Corpus vector v_schema
# kills L; R stays unreached on every pinned vector.
FORECLOSED_CHECKER = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
accepted = True
reason = "ok"
if "flag" in vector:
    reason = "unknown-field"
elif vector.get("flag"):
    reason = "flag-set"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""

# L and R read different fields, so deleting L does not expose R on the witness.
INDEPENDENT_CHECKER = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
accepted = True
reason = "ok"
if "flag" in vector:
    reason = "unknown-field"
elif vector.get("value", 0) > 10:
    reason = "too-big"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""

# L's refusal flips both declared members, so F1 cannot attribute to reason alone.
TWO_MEMBER_CHECKER = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
accepted = True
reason = "ok"
if "flag" in vector:
    accepted = False
    reason = "unknown-field"
elif vector.get("flag"):
    reason = "flag-set"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""

# Witness trips an unexpected-exit before any declared outcome is parsed.
ABNORMAL_CHECKER = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
if vector.get("boom"):
    sys.exit(2)
accepted = True
reason = "ok"
if "flag" in vector:
    reason = "unknown-field"
elif vector.get("flag"):
    reason = "flag-set"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""

L_MUTANT = {
    "label": "L-schema",
    "anchor": 'if "flag" in vector:',
    "replacement": "if False:",
}
R_FLAG = {
    "label": "R-flag",
    "anchor": "elif vector.get(\"flag\"):",
    "replacement": "elif False:",
}
R_VALUE = {
    "label": "R-value",
    "anchor": "elif vector.get(\"value\", 0) > 10:",
    "replacement": "elif False:",
}
CONTROL = {
    "label": "CONTROL accepted",
    "control": True,
    "control_polarity": "positive",
    "anchor": "accepted = True",
    "replacement": "accepted = False",
}


def _entry(label, by, *, edit, refused_at=None):
    return {
        "label": label,
        "by": by,
        "witness": {"base": "v_ok", "edit": edit},
        "refused_at": refused_at or {"reason": "unknown-field"},
        "reason": "L refuses flag before R can decide on the declared "
                  "(accepted, reason) projection",
        "recorded": "2026-11-02",
    }


def _write_vectors(tmp: Path, rows: list[tuple[str, dict]]) -> None:
    catalog = []
    for vector_id, body in rows:
        name = "%s.json" % vector_id
        (tmp / name).write_text(json.dumps(body), encoding="utf-8")
        catalog.append({"vector_id": vector_id, "path": name})
    (tmp / "vectors.json").write_text(
        json.dumps({"vectors": catalog}), encoding="utf-8")


def _manifest(tmp: Path, *, checker: str, mutants: list, vectors: list,
              foreclosed=None) -> Path:
    (tmp / "check.py").write_text(checker, encoding="utf-8")
    _write_vectors(tmp, vectors)
    digest = ca._file_sha256((tmp / "vectors.json").read_bytes())
    (tmp / "digest.json").write_text(
        json.dumps({"corpus_digest": digest}), encoding="utf-8")
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "check.py",
        "implementation_sources": ["check.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "check.py", "{vector}"],
        "outcome_from": ["accepted", "reason"],
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "path",
        "default_group": "g",
        "corpus_digest_file": "digest.json",
        "corpus_digest_key": "corpus_digest",
        "mutants": {"g": list(mutants) + [CONTROL]},
    }
    if foreclosed is not None:
        raw["foreclosed"] = {"g": list(foreclosed)}
    path = tmp / "m.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _row(report: dict, label: str) -> dict:
    return next(item for item in report["mutants"] if item["label"] == label)


def _add_flag():
    return [{"op": "add", "path": "/flag", "value": True}]


V_OK = ("v_ok", {"value": 1})
V_SCHEMA = ("v_schema", {"value": 1, "flag": True})
V_BIG = ("v_big", {"value": 11})


def _identity_free(report: dict) -> dict:
    skip = {
        "tool_commit", "tool_source_state", "tool_content_sha256",
        "tool_version", "manifest", "originals_unverified_against_head",
    }
    out = {key: report[key] for key in report if key not in skip}
    out["mutants"] = [dict(row) for row in report.get("mutants", [])]
    return out


def _run_pinned(commit: str, manifest: Path) -> tuple[int, dict]:
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        for name in ca.TOOL_SOURCE_PATHS:
            blob = subprocess.check_output(
                ["git", "show", "%s:%s" % (commit, name)], cwd=str(REPO))
            (root / name).write_bytes(blob)
        proc = subprocess.run(
            [sys.executable, str(root / "corpus_adequacy.py"),
             str(manifest), "--json"],
            cwd=str(REPO), capture_output=True, timeout=120)
    if proc.returncode not in (0, 1):
        raise AssertionError(
            "pinned tool exit %s stderr=%s" % (proc.returncode, proc.stderr))
    return proc.returncode, json.loads(proc.stdout.decode("utf-8"))


@unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
class ForeclosedProof(unittest.TestCase):
    def test_1_synthetic_corpus_where_l_forecloses_r_is_foreclosed(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(
                tmp, checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-flag", "L-schema", edit=_add_flag())])
            before = (
                (tmp / "vectors.json").read_bytes(),
                (tmp / "v_ok.json").read_bytes(),
            )
            report = ca.run(path, execution_profile="trusted-local")
            after = (
                (tmp / "vectors.json").read_bytes(),
                (tmp / "v_ok.json").read_bytes(),
            )
            without_path = _manifest(
                Path(tempfile.mkdtemp(dir=tmp)), checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=None)
            without = ca.run(without_path, execution_profile="trusted-local")
        self.assertEqual(before, after)
        self.assertEqual(report["corpus_digest"], without["corpus_digest"])
        row = _row(report, "R-flag")
        self.assertEqual(row.get("verdict"), "foreclosed")
        self.assertEqual(report.get("foreclosed"), 1)
        self.assertIn("foreclosed_ratio", report)
        self.assertEqual(
            report["killed"] + report["survived"] + report["silent"], 1)
        self.assertEqual(_row(report, "L-schema")["verdict"], "killed")
        self.assertTrue(report["adequate"], report["failures"])
        self.assertNotIn("foreclosed", without)
        self.assertNotIn("foreclosed_ratio", without)

    def test_2_independent_l_and_r_is_foreclosure_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=INDEPENDENT_CHECKER,
                mutants=[L_MUTANT, R_VALUE],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-value", "L-schema", edit=_add_flag())]),
                execution_profile="trusted-local")
        self.assertTrue(
            any("foreclosure-unproved" in item for item in report["failures"]),
            report["failures"])
        self.assertEqual(_row(report, "R-value").get("verdict"), "survived")
        self.assertNotEqual(_row(report, "R-value").get("verdict"), "foreclosed")
        self.assertFalse(report["adequate"])

    def test_3_witness_moving_a_second_declared_member_is_foreclosure_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=TWO_MEMBER_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-flag", "L-schema", edit=_add_flag())]),
                execution_profile="trusted-local")
        self.assertTrue(
            any("foreclosure-unproved" in item for item in report["failures"]),
            report["failures"])
        self.assertNotEqual(_row(report, "R-flag").get("verdict"), "foreclosed")
        self.assertFalse(report["adequate"])

    def test_4_f4_killed_is_the_stale_foreclosure_failure(self):
        edit = _add_flag() + [{"op": "replace", "path": "/value", "value": 11}]
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=INDEPENDENT_CHECKER,
                mutants=[L_MUTANT, R_VALUE],
                vectors=[V_OK, V_SCHEMA, V_BIG],
                foreclosed=[_entry("R-value", "L-schema", edit=edit)]),
                execution_profile="trusted-local")
        self.assertEqual(_row(report, "R-value")["verdict"], "killed")
        self.assertTrue(
            any("should be removed" in item for item in report["failures"]),
            report["failures"])
        self.assertFalse(report["adequate"])

    def test_5_abnormal_end_in_f1_is_unproved_and_not_adequate(self):
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=ABNORMAL_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry(
                    "R-flag", "L-schema",
                    edit=[{"op": "add", "path": "/boom", "value": True}])]),
                execution_profile="trusted-local")
        self.assertEqual(_row(report, "R-flag").get("verdict"), "unproved")
        self.assertGreaterEqual(report["unproved"], 1)
        self.assertFalse(report["adequate"])
        self.assertFalse(
            any(item.startswith("control ") and "abnormally" in item
                for item in report["failures"]),
            report["failures"])


@unittest.skipIf(ca.fcntl is None, "process scoring requires an advisory lock")
class NoContainerCompatibility(unittest.TestCase):
    def test_6_manifest_without_container_matches_pinned_release_report(self):
        for rel in EXAMPLE_MANIFESTS:
            with self.subTest(rel=rel):
                path = REPO / rel
                current = ca.run(path, execution_profile="trusted-local")
                pinned_rc, pinned = _run_pinned(BASE_COMMIT, path)
                current_rc = 0 if current["adequate"] else 1
                self.assertEqual(current_rc, pinned_rc)
                self.assertNotIn("foreclosed", current)
                self.assertNotIn("foreclosed_ratio", current)
                self.assertEqual(_identity_free(current), _identity_free(pinned))


if __name__ == "__main__":
    unittest.main()
