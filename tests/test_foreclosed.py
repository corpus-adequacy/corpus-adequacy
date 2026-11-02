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
              foreclosed=None, extra=None) -> Path:
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
    if extra:
        raw.update(extra)
    path = tmp / "m.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def _stamp_child(tmp: Path, checker: str) -> str:
    """Rewrite the checker so a live child writes tmp/CHILD_RAN (absolute)."""
    stamp = tmp / "CHILD_RAN"
    return checker.replace(
        "import json, sys\n",
        "import json, sys\nopen(%r, 'w').write('1')\n" % str(stamp),
        1)


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

    def test_f3_anchor_interaction_is_unproved_with_a_report(self):
        # `by` replacement duplicates `label`'s anchor, so F3's second
        # lookup is not unique on the already-mutated tree.
        checker = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
accepted = True
reason = "ok"
# MARKER_A
if vector.get("a"):
    reason = "has-a"
# MARKER_B
if vector.get("b"):
    reason = "has-b"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""
        by_mut = {"label": "L-a", "anchor": "# MARKER_A",
                  "replacement": "# MARKER_B"}
        label_mut = {"label": "R-b", "anchor": "# MARKER_B",
                     "replacement": "# MARKER_X"}
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(
                tmp, checker=checker, mutants=[by_mut, label_mut],
                vectors=[("v_ok", {"value": 1}), ("v_a", {"a": True})],
                foreclosed=[_entry(
                    "R-b", "L-a",
                    edit=[{"op": "add", "path": "/b", "value": True}],
                    refused_at={"reason": "has-b"})])
            before = (tmp / "check.py").read_bytes()
            proc = subprocess.run(
                [sys.executable, str(REPO / "corpus_adequacy.py"),
                 str(path), "--json"],
                capture_output=True, timeout=60)
            after = (tmp / "check.py").read_bytes()
        self.assertEqual(before, after)
        self.assertNotIn(b"StopIteration", proc.stderr)
        self.assertNotIn(b"Traceback", proc.stderr)
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout.decode("utf-8"))
        row = _row(report, "R-b")
        self.assertIn(row.get("verdict"), ("unproved", "survived"))
        self.assertNotEqual(row.get("verdict"), "foreclosed")
        if row.get("verdict") != "unproved":
            self.assertTrue(
                any("foreclosure-unproved" in item
                    for item in report["failures"]),
                report["failures"])
        self.assertFalse(report["adequate"])

    def test_cross_group_witness_base_is_refused_before_a_child(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(
                tmp, checker=_stamp_child(tmp, FORECLOSED_CHECKER),
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                extra={
                    "group_key": "grp",
                    "mutants": {
                        "g": [dict(L_MUTANT), dict(R_FLAG),
                              dict(CONTROL, label="CONTROL g")],
                        "h": [dict(CONTROL, label="CONTROL h")],
                    },
                    "foreclosed": {"g": [_entry(
                        "R-flag", "L-schema", edit=_add_flag())]},
                })
            vectors = json.loads((tmp / "vectors.json").read_text())
            vectors["vectors"][0]["grp"] = "g"
            vectors["vectors"][1]["grp"] = "h"
            vectors["vectors"][1]["vector_id"] = "v_h"
            (tmp / "v_schema.json").rename(tmp / "v_h.json")
            vectors["vectors"][1]["path"] = "v_h.json"
            (tmp / "vectors.json").write_text(json.dumps(vectors), encoding="utf-8")
            digest = ca._file_sha256((tmp / "vectors.json").read_bytes())
            (tmp / "digest.json").write_text(
                json.dumps({"corpus_digest": digest}), encoding="utf-8")
            raw = json.loads(path.read_text())
            raw["foreclosed"]["g"][0]["witness"]["base"] = "v_h"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(ca.ManifestError) as cm:
                ca.run(path, execution_profile="trusted-local")
            self.assertIn("v_h", str(cm.exception))
            self.assertRegex(str(cm.exception), r"group|not a corpus vector")
            self.assertFalse((tmp / "CHILD_RAN").exists())

    def test_scalar_none_pinned_outcome_is_not_refused(self):
        checker = """\
import json, sys
vector = json.load(open(sys.argv[1], encoding="utf-8"))
doc = {}
if vector.get("emit"):
    doc["reason"] = "ok"
print(json.dumps(doc))
"""
        left = {"label": "L-x", "anchor": 'if vector.get("emit"):',
                "replacement": "if False:"}
        right = {"label": "R-y", "anchor": 'doc["reason"] = "ok"',
                 "replacement": 'doc["reason"] = "XX"'}
        control = {
            "label": "CONTROL s", "control": True,
            "control_polarity": "positive",
            "anchor": "doc = {}", "replacement": "doc = {'reason': 'ctl'}",
        }
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(
                tmp, checker=checker, mutants=[left, right],
                vectors=[("v_ok", {"value": 1}), ("v_emit", {"emit": True})],
                extra={
                    "outcome_from": "reason",
                    "mutants": {"g": [left, right, control]},
                    "foreclosed": {"g": [{
                        "label": "R-y", "by": "L-x",
                        "witness": {"base": "v_ok", "edit": [
                            {"op": "add", "path": "/emit", "value": True}]},
                        "refused_at": {"reason": "ok"},
                        "reason": "scalar none is a pinned outcome",
                        "recorded": "2026-11-02",
                    }]},
                })
            report = ca.run(path, execution_profile="trusted-local")
        self.assertIsInstance(report, dict)
        self.assertTrue(any(row["label"] == "R-y" for row in report["mutants"]))
        self.assertFalse(
            any("not accepting" in item for item in report["failures"]))

    def test_witness_edit_op_is_refused_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry(
                    "R-flag", "L-schema",
                    edit=[{"op": "bad", "path": "/flag", "value": True}])])
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(path)
        self.assertIn("RFC 6902", str(cm.exception))

    def test_witness_patch_failure_is_refused_before_a_child(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            path = _manifest(
                tmp, checker=_stamp_child(tmp, FORECLOSED_CHECKER),
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry(
                    "R-flag", "L-schema",
                    edit=[{"op": "remove", "path": "/nonexistent"}])])
            with self.assertRaises(ca.ManifestError) as cm:
                ca.run(path, execution_profile="trusted-local")
            self.assertIn("JSON Pointer", str(cm.exception))
            self.assertFalse((tmp / "CHILD_RAN").exists())

    def test_test_names_foreclosed_is_refused_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-flag", "L-schema", edit=_add_flag())],
                extra={
                    "runner": "batch",
                    "outcome_parse": "test-names",
                    "accepted_exit_codes": [0, 101],
                })
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(path)
        self.assertIn("test-names", str(cm.exception))

    def test_missing_f4_row_is_foreclosure_unproved(self):
        missing = {
            "label": "R-missing",
            "anchor": "THIS ANCHOR DOES NOT EXIST",
            "replacement": "xxx",
        }
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, missing],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry(
                    "R-missing", "L-schema", edit=_add_flag())]),
                execution_profile="trusted-local")
        self.assertEqual(
            [row for row in report["mutants"] if row["label"] == "R-missing"],
            [])
        self.assertTrue(
            any("foreclosure-unproved" in item for item in report["failures"]),
            report["failures"])
        self.assertFalse(report["adequate"])

    def test_known_hole_and_foreclosed_same_label_refused_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            path = _manifest(
                Path(d), checker=FORECLOSED_CHECKER,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-flag", "L-schema", edit=_add_flag())],
                extra={
                    "known_holes": {
                        "sha256:dead": [{
                            "label": "R-flag",
                            "reason": "acked hole",
                            "recorded": "2026-01-01",
                        }],
                    },
                })
            with self.assertRaises(ca.ManifestError) as cm:
                ca.load_manifest(path)
        self.assertIn("known hole", str(cm.exception))
        self.assertIn("R-flag", str(cm.exception))

    def test_f0_mismatch_is_foreclosure_unproved(self):
        checker = """\
import json, sys
from pathlib import Path
vector = json.load(open(sys.argv[1], encoding="utf-8"))
stamp = Path(__file__).with_name("f0-stamp.txt")
n = int(stamp.read_text()) if stamp.exists() else 0
stamp.write_text(str(n + 1))
accepted = True
reason = "ok" if n == 0 else "drifted"
if "flag" in vector:
    reason = "unknown-field"
elif vector.get("flag"):
    reason = "flag-set"
print(json.dumps({"accepted": accepted, "reason": reason}))
"""
        with tempfile.TemporaryDirectory() as d:
            report = ca.run(_manifest(
                Path(d), checker=checker,
                mutants=[L_MUTANT, R_FLAG],
                vectors=[V_OK, V_SCHEMA],
                foreclosed=[_entry("R-flag", "L-schema", edit=_add_flag())]),
                execution_profile="trusted-local")
        self.assertNotEqual(_row(report, "R-flag").get("verdict"), "foreclosed")
        self.assertTrue(
            any("foreclosure-unproved" in item for item in report["failures"]),
            report["failures"])
        self.assertFalse(report["adequate"])

    def test_f3_helper_applies_two_mutants_in_one_execution(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            source = tmp / "check.py"
            original = "KEEP\n# MARKER_A\n# MARKER_B\n"
            source.write_text(original, encoding="utf-8")
            seen = []

            class Session:
                manifest = {"_repo_root": tmp, "_source_paths": [source]}

                def execute(self, vectors, rebuild=True, step=None):
                    seen.append(source.read_text(encoding="utf-8"))

                    class Execution:
                        built = True
                        raised = {}
                        outcomes = {}
                        detail = None

                    return Execution()

            facts = ca._execute_mutations_observation(
                Session(), "g",
                [{"label": "A", "anchor": "# MARKER_A",
                  "replacement": "# REPL_A"},
                 {"label": "B", "anchor": "# MARKER_B",
                  "replacement": "# REPL_B"}],
                vectors=[])
            restored = source.read_text(encoding="utf-8")
        self.assertEqual(facts["application"], "applied")
        self.assertEqual(len(seen), 1)
        self.assertIn("# REPL_A", seen[0])
        self.assertIn("# REPL_B", seen[0])
        self.assertEqual(restored, original)


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
