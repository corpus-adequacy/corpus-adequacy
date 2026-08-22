#!/usr/bin/env python3
"""Phase A preregistration contract for issue #211. Standard library only.

Does not run aee-checker, the seven mutants, or corpus_adequacy.run() on
the pinned subject. Source-string equality is a structural guard, not
mutation proof. The biting tests mutate prereg artifacts.
"""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))
sys.path.insert(0, str(REPO_ROOT / "adapters"))

import bounded_run as br  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import aee_checker_sealed as wrapper  # noqa: E402
import aee_checker_sealed_prereg as prereg  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
ADAPTER = REPO_ROOT / "adapters" / "aee_checker_sealed.py"
ENUMERATOR = REPO_ROOT / "measurements" / "aee_checker_sealed_prereg.py"

# The seven conditions selected by source structure inside check_sealed.
PINNED_CONDITIONS = (
    "drop_count < 0",
    "!is_lower_hex64(observed_set)",
    "observed_set != ctx.observed_set",
    "!ctx.manifest_attacks.iter().any(|m| m == a)",
    "!still_armed",
    "!(drop_count == 0 || drop_bound.is_some_and(|b| drop_count <= b))",
    "posture != ctx.posture_digest",
)

# Synthetic source: unique check_sealed, the same seven ifs, two outside ifs.
SYNTHETIC = """\
fn other() {
    if leftover_outside {
        return;
    }
}
fn check_sealed(payload: &Value, ctx: &Ctx) -> R<(Vec<&'static str>, String)> {
    if drop_count < 0 {
        return Err(());
    }
    if !is_lower_hex64(observed_set) {
        return Err(());
    }
    if observed_set != ctx.observed_set {
        return Err(());
    }
    for a in &observed_attacks {
        if !ctx.manifest_attacks.iter().any(|m| m == a) {
            return Err(());
        }
    }
    if !still_armed {
        x();
    }
    if !(drop_count == 0 || drop_bound.is_some_and(|b| drop_count <= b)) {
        x();
    }
    if posture != ctx.posture_digest {
        x();
    }
    Ok(())
}
fn after() {
    if extra_outside {
        return;
    }
}
"""


def _load(name: str):
    return json.loads((PREREG / name).read_text(encoding="utf-8"))


def _dump(path: Path, doc) -> None:
    path.write_bytes(prereg.encode_json(doc))


class EnumeratorSelectsSeven(unittest.TestCase):
    def test_synthetic_source_emits_seven_sites_and_reports_outside(self):
        found = prereg.enumerate_source(SYNTHETIC.encode("utf-8"))
        self.assertEqual([s["condition"] for s in found["sites"]], list(PINNED_CONDITIONS))
        outside = [s["condition"] for s in found["complement"]]
        self.assertIn("leftover_outside", outside)
        self.assertIn("extra_outside", outside)
        self.assertEqual(len(found["sites"]), 7)

    def test_outside_complement_is_not_in_the_denominator(self):
        found = prereg.enumerate_source(SYNTHETIC.encode("utf-8"))
        den = {s["condition"] for s in found["sites"]}
        for item in found["complement"]:
            self.assertNotIn(item["condition"], den)


class BitingPreregMutations(unittest.TestCase):
    """These fail if the named prereg defect is introduced. Not source-string guards."""

    def _emit(self, tmp: Path) -> Path:
        dest = tmp / "prereg"
        dest.mkdir()
        prereg.emit_prereg(SYNTHETIC.encode("utf-8"), dest)
        return dest

    def test_removing_one_selected_site_fails_completeness(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            sites = json.loads((dest / "sites.json").read_text(encoding="utf-8"))
            sites["sites"].pop(3)
            _dump(dest / "sites.json", sites)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("completeness", str(ctx.exception).lower())

    def test_swapping_one_span_fails_before_running(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            sites = json.loads((dest / "sites.json").read_text(encoding="utf-8"))
            sites["sites"][0]["span"], sites["sites"][1]["span"] = (
                sites["sites"][1]["span"], sites["sites"][0]["span"])
            _dump(dest / "sites.json", sites)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertRegex(str(ctx.exception).lower(), r"span|anchor")

    def test_putting_an_outside_if_in_the_denominator_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            manifest["mutants"]["sealed"].append({
                "label": "outside leftover",
                "anchor": "if leftover_outside",
                "replacement": "if false",
            })
            _dump(dest / "manifest.json", manifest)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("complement", str(ctx.exception).lower())

    def test_control_absent_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            manifest["mutants"]["sealed"] = [
                e for e in manifest["mutants"]["sealed"] if not e.get("control")]
            _dump(dest / "manifest.json", manifest)
            (dest / "control.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("control", str(ctx.exception).lower())

    def test_regeneration_must_be_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            a, b = tmp / "a", tmp / "b"
            a.mkdir()
            b.mkdir()
            src = SYNTHETIC.encode("utf-8")
            prereg.emit_prereg(src, a)
            prereg.emit_prereg(src, b)
            for name in ("sites.json", "manifest.json", "control.json", "ceilings.json"):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)
            drifted = json.loads((b / "sites.json").read_text(encoding="utf-8"))
            drifted["sites"][0]["label"] = "drift"
            _dump(b / "sites.json", drifted)
            with self.assertRaises(prereg.PreregError):
                prereg.assert_byte_identical_prereg(a, b)

    def test_unproved_exit_not_exclusively_from_issue_45_policy_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            manifest["unproved_exit_codes"] = [1]
            _dump(dest / "manifest.json", manifest)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("unproved", str(ctx.exception).lower())


class FrozenPin(unittest.TestCase):
    """Frozen artifacts for aee-checker@25b9dfa. Structural, not mutation proof."""

    def test_frozen_dir_has_only_prereg_files(self):
        names = sorted(p.name for p in PREREG.iterdir())
        self.assertEqual(
            names,
            ["ceilings.json", "control.json", "manifest.json", "pins.json", "sites.json"],
        )
        for forbidden in ("report.v0.json", "result.json", "provenance.json"):
            self.assertFalse((PREREG / forbidden).exists(), forbidden)

    def test_frozen_sites_are_the_seven_conditions(self):
        sites = _load("sites.json")
        self.assertEqual([s["condition"] for s in sites["sites"]], list(PINNED_CONDITIONS))
        self.assertEqual(sites["selected_count"], 7)
        self.assertGreater(sites["complement_count"], 0)
        den = {s["condition"] for s in sites["sites"]}
        for item in sites["complement"]:
            self.assertNotIn(item.get("span"), [s["span"] for s in sites["sites"]])
            if item["condition"] not in den:
                continue
            self.assertNotEqual(item["span"], next(
                s["span"] for s in sites["sites"] if s["condition"] == item["condition"]))

    def test_frozen_manifest_pins_issue_45_unproved_policy(self):
        manifest = _load("manifest.json")
        self.assertEqual(manifest["runner"], "batch")
        self.assertEqual(manifest["accepted_exit_codes"], [0])
        self.assertEqual(manifest["unproved_exit_codes"], [75])
        self.assertEqual(manifest["build"], ["cargo", "build", "--locked", "--release"])
        self.assertEqual(
            manifest["outcome_from"],
            ["verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey"],
        )
        self.assertEqual(manifest["diagnostic_from"], ["reason"])
        self.assertNotIn("code", manifest["outcome_from"])
        self.assertNotIn("code", manifest["diagnostic_from"])
        mutants = manifest["mutants"]["sealed"]
        ordinary = [e for e in mutants if not e.get("control")]
        controls = [e for e in mutants if e.get("control")]
        self.assertEqual(len(ordinary), 7)
        self.assertEqual(len(controls), 1)
        for e in ordinary:
            self.assertEqual(e["scope"], "declared")
            self.assertNotIn("out_of_scope", e.get("scope", "declared"))
        self.assertNotIn("known_holes", manifest)
        self.assertFalse(manifest.get("equivalent"))

    def test_frozen_control_forces_immediate_refusal(self):
        control = _load("control.json")
        self.assertTrue(control["control"])
        self.assertIn("return Err", control["replacement"])
        self.assertNotIn(control["anchor"], PINNED_CONDITIONS)

    def test_each_mutant_replaces_only_its_condition_with_false(self):
        sites = _load("sites.json")
        for site in sites["sites"]:
            self.assertEqual(site["replacement"], "false")
            self.assertEqual(
                hashlib.sha256(site["bytes"].encode("utf-8")).hexdigest(),
                site["sha256"],
            )


class WrapperContract(unittest.TestCase):
    """Synthetic checker only. Does not invoke aee-checker or apply mutants."""

    def _fake(self, tmp: Path, body: str) -> Path:
        path = tmp / "fake_checker.py"
        path.write_text(body, encoding="utf-8")
        return path

    def _run(self, checker: Path, extra=None):
        cmd = [sys.executable, str(ADAPTER), "--checker", str(checker),
               "--expected-count", "1", str(checker.parent)]
        if extra:
            cmd.extend(extra)
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_wrapper_reads_json_file_not_human_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            checker = self._fake(tmp, r"""
import json, sys
from pathlib import Path
print('{"verdict":"FROM-STDOUT","result":null,"tiersWithPinnedKey":[],"tiersWithoutKey":[]}')
out = sys.argv[sys.argv.index("--json") + 1]
Path(out).write_text(json.dumps({
    "vectors": [{"id": "v1", "verdict": "valid", "result": "ok",
                 "reason": "prose", "code": "secret",
                 "tiersWithPinnedKey": ["t"], "tiersWithoutKey": []}]
}) + "\n", encoding="utf-8")
sys.exit(1)
""")
            proc = self._run(checker)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["verdict"], ["valid"])
        self.assertEqual(doc["result"], ["ok"])
        self.assertEqual(doc["reason"], ["prose"])
        self.assertNotEqual(doc["verdict"], ["FROM-STDOUT"])
        self.assertNotIn("code", doc)
        self.assertNotIn("secret", proc.stdout)

    def test_inner_protocol_failure_exits_the_issue_45_unproved_code(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            checker = self._fake(tmp, """
import sys
print("human table only")
sys.exit(0)
""")
            proc = self._run(checker)
        self.assertEqual(proc.returncode, wrapper.UNPROVED_EXIT)
        self.assertEqual(wrapper.UNPROVED_EXIT, 75)

    def test_wrapper_exit_policy_is_only_issue_45(self):
        self.assertEqual(wrapper.UNPROVED_EXIT, 75)
        self.assertEqual(wrapper.ACCEPTED_EXIT, 0)
        self.assertEqual(prereg.UNPROVED_EXIT_CODES, [75])


class ReviewFixes(unittest.TestCase):
    """Coordinator review at 52428a4. Synthetic checker only."""

    GOOD_ROW = {
        "id": "v1", "verdict": "valid", "result": "ok",
        "reason": "prose A", "code": "MUST-NOT-APPEAR",
        "tiersWithPinnedKey": ["t"], "tiersWithoutKey": [],
    }

    def _fake(self, tmp: Path, body: str) -> Path:
        path = tmp / "fake_checker.py"
        path.write_text(body, encoding="utf-8")
        return path

    def _writer(self, tmp: Path, doc, rc=0) -> Path:
        payload = json.dumps(doc)
        return self._fake(tmp, f"""
import sys
from pathlib import Path
print("human table")
Path(sys.argv[sys.argv.index("--json") + 1]).write_text({payload!r} + "\\n")
sys.exit({rc})
""")

    def _run(self, checker: Path, extra=None):
        # In-process so cap patches reach the same bounded_run / corpus_adequacy
        # names the wrapper uses. Child-exec coverage stays in WrapperContract.
        argv = ["--checker", str(checker), "--expected-count", "1",
                str(checker.parent)]
        if extra:
            argv.extend(extra)
        buf = io.StringIO()
        with mock.patch.object(sys, "stdout", buf):
            rc = wrapper.main(argv)
        return SimpleNamespace(returncode=rc, stdout=buf.getvalue(), stderr="")

    def test_inner_rc2_with_valid_json_is_unproved_before_parse(self):
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer(Path(d), {"vectors": [self.GOOD_ROW]}, rc=2)
            proc = self._run(checker)
        self.assertEqual(proc.returncode, 75, proc.stdout)
        self.assertFalse(proc.stdout.strip())

    def test_overcap_inner_stdout_uses_bounded_run(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            checker = self._fake(tmp, """
import sys
from pathlib import Path
print("x" * 200)
Path(sys.argv[sys.argv.index("--json") + 1]).write_text(
    '{"vectors":[{"id":"v1","verdict":"valid","result":"ok",'
    '"reason":"r","tiersWithPinnedKey":[],"tiersWithoutKey":[]}]}\\n')
sys.exit(0)
""")
            with mock.patch.object(br, "OUTPUT_CAP_BYTES", 32):
                proc = self._run(checker)
        self.assertEqual(proc.returncode, 75)
        src = ADAPTER.read_text(encoding="utf-8")
        self.assertIn("_run_capped", src)
        self.assertNotIn("subprocess.run(", src)

    def test_report_file_cap_uses_read_bounded_regular_file(self):
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer(Path(d), {"vectors": [self.GOOD_ROW]})
            with mock.patch.object(ca, "OUTPUT_CAP_BYTES", 16):
                proc = self._run(checker)
        self.assertEqual(proc.returncode, 75)
        self.assertIn("read_bounded_regular_file", ADAPTER.read_text(encoding="utf-8"))

    def test_build_missing_empty_or_unlocked_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prereg"
            dest.mkdir()
            prereg.emit_prereg(SYNTHETIC.encode("utf-8"), dest)
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            for bad in ([], ["cargo", "build"], ["cargo", "build", "--release"], None):
                raw = dict(manifest)
                if bad is None:
                    raw.pop("build", None)
                else:
                    raw["build"] = bad
                _dump(dest / "manifest.json", raw)
                with self.assertRaises(prereg.PreregError) as ctx:
                    prereg.validate_prereg(dest)
                self.assertIn("build", str(ctx.exception).lower(), bad)

    def test_missing_or_duplicate_row_identity_is_unproved(self):
        cases = [
            {"vectors": [dict(self.GOOD_ROW, id="")]},
            {"vectors": [dict(self.GOOD_ROW), dict(self.GOOD_ROW)]},
            {"vectors": [{k: v for k, v in self.GOOD_ROW.items()
                          if k != "tiersWithoutKey"}]},
            {"vectors": []},
        ]
        for doc in cases:
            with self.subTest(doc=doc):
                with tempfile.TemporaryDirectory() as d:
                    checker = self._writer(Path(d), doc)
                    proc = self._run(checker)
                self.assertEqual(proc.returncode, 75, proc.stdout)
                self.assertFalse(proc.stdout.strip())

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_diagnostic_only_reason_move_is_silent(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "check.py").write_text(
                "import json\n"
                'reason = "prose A"\n'
                "print(json.dumps({\n"
                '  "verdict": ["valid"], "result": ["ok"],\n'
                '  "tiersWithPinnedKey": [[]], "tiersWithoutKey": [[]],\n'
                '  "reason": [reason],\n'
                "}))\n",
                encoding="utf-8")
            (tmp / "vectors.json").write_text("{}", encoding="utf-8")
            raw = {
                "schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
                "implementation": "check.py",
                "implementation_sources": ["check.py"],
                "build": [],
                "entrypoint_command": [sys.executable, "check.py"],
                "outcome_from": [
                    "verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey",
                ],
                "diagnostic_from": ["reason"],
                "accepted_exit_codes": [0],
                "unproved_exit_codes": [75],
                "vectors": "vectors.json",
                "id_key": "vector_id",
                "default_group": "sealed",
                "mutants": {"sealed": [
                    {"label": "reason-only", "anchor": 'reason = "prose A"',
                     "replacement": 'reason = "prose B"'},
                    {"label": "CONTROL", "control": True,
                     "anchor": "print(json.dumps",
                     "replacement": "raise SystemExit(1)\nprint(json.dumps"}],
                },
            }
            manifest = tmp / "m.json"
            manifest.write_text(json.dumps(raw), encoding="utf-8")
            rep = ca.run(manifest)
        row = next(r for r in rep["mutants"] if r["label"] == "reason-only")
        self.assertEqual(row["verdict"], "silent")
        self.assertEqual(row["moved"], 0)
        self.assertGreaterEqual(row["moved_diagnostic"], 1)
        self.assertTrue(rep["diagnostic_channel_declared"])


if __name__ == "__main__":
    unittest.main()

