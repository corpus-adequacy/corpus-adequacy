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
import re
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
    if let Some(x) = y {
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
        self.assertTrue(any(c.startswith("let ") for c in outside), outside)
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
            for name in ("sites.json", "manifest.json", "control.json"):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes(), name)
            self.assertFalse((a / "ceilings.json").exists())
            self.assertFalse((b / "ceilings.json").exists())
            drifted = json.loads((b / "sites.json").read_text(encoding="utf-8"))
            drifted["sites"][0]["label"] = "drift"
            _dump(b / "sites.json", drifted)
            with self.assertRaises(prereg.PreregError):
                prereg.assert_byte_identical_prereg(a, b)

    def test_understated_complement_count_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            sites = json.loads((dest / "sites.json").read_text(encoding="utf-8"))
            sites["complement_count"] = sites["complement_count"] - 1
            _dump(dest / "sites.json", sites)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("complement", str(ctx.exception).lower())

    def test_unproved_exit_not_exclusively_from_issue_45_policy_fails(self):
        with tempfile.TemporaryDirectory() as d:
            dest = self._emit(Path(d))
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            manifest["unproved_exit_codes"] = [1]
            _dump(dest / "manifest.json", manifest)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("unproved", str(ctx.exception).lower())


class LexerKeepsExplicitIfs(unittest.TestCase):
    """#211 is every explicit if, including if-let. Complement is descriptive."""

    def _masked_has_if(self, src: str, cond: str) -> bool:
        return bool(re.search(r"\bif\s+" + re.escape(cond) + r"\b", prereg.code_mask(src)))

    def test_alphabetic_char_literal_does_not_hide_a_later_if(self):
        src = "let integral = !raw.contains(['.', 'e', 'E']);\nif later_guard {\n}\n"
        self.assertTrue(self._masked_has_if(src, "later_guard"), prereg.code_mask(src))
        found = prereg.enumerate_source(
            (src + SYNTHETIC[SYNTHETIC.index("fn check_sealed"):]).encode("utf-8"))
        self.assertIn("later_guard", [c["condition"] for c in found["complement"]])

    def test_lifetime_is_not_treated_as_a_char_literal(self):
        src = "fn f<'a>(x: &'a str) {\n    if lifetime_guard {\n    }\n}\n"
        self.assertTrue(self._masked_has_if(src, "lifetime_guard"), prereg.code_mask(src))

    def test_raw_string_does_not_contribute_an_if(self):
        src = 'const S: &str = r#" if hidden_raw { } "#;\nif raw_after {\n}\n'
        masked = prereg.code_mask(src)
        self.assertIsNone(re.search(r"\bif\s+hidden_raw\b", masked), masked)
        self.assertTrue(self._masked_has_if(src, "raw_after"), masked)

    def test_nested_block_comment_does_not_leak_or_hide_an_if(self):
        src = "/* outer /* inner */ if still_comment { } */\nif after_comment {\n}\n"
        masked = prereg.code_mask(src)
        self.assertIsNone(re.search(r"\bif\s+still_comment\b", masked), masked)
        self.assertTrue(self._masked_has_if(src, "after_comment"), masked)

    def test_if_let_belongs_to_the_explicit_if_complement(self):
        found = prereg.enumerate_source(SYNTHETIC.encode("utf-8"))
        lets = [c["condition"] for c in found["complement"] if c["condition"].startswith("let ")]
        self.assertEqual(lets, ["let Some(x) = y"])
        self.assertEqual(len(found["sites"]), 7)

    def test_format_macro_if_belongs_to_the_explicit_if_complement(self):
        src = (
            'fn other() {\n'
            '    failed.push(format!("arming record{} the rows resolve",\n'
            '        if n == 1 { "" } else { "s" }\n'
            '    ));\n'
            '}\n'
        )
        found = prereg.enumerate_source(
            (src + SYNTHETIC[SYNTHETIC.index("fn check_sealed"):]).encode("utf-8"))
        self.assertIn("n == 1", [c["condition"] for c in found["complement"]])
        self.assertEqual(len(found["sites"]), 7)


class FrozenPin(unittest.TestCase):
    """Frozen artifacts for aee-checker@25b9dfa. Structural, not mutation proof."""

    def test_every_explicit_if_including_if_let_is_the_outside_rule(self):
        pins = _load("pins.json")
        sites = _load("sites.json")
        rule = pins["enumeration"]
        self.assertEqual(rule["explicit_if_rule"], "every explicit if, including if-let")
        self.assertEqual(rule["if_let"], "included in complement; check_sealed has none")
        self.assertEqual(rule["complement_count"], 125)
        self.assertEqual(rule["selected_count"], 7)
        self.assertEqual(sites["complement_count"], 125)
        self.assertEqual(rule["syn_expr_if_outside"], 124)
        self.assertEqual(rule["macro_tokenstream_if"], 1)
        self.assertTrue(
            any(c["condition"].startswith("let ") for c in sites["complement"]),
            "outside inventory must include if-let",
        )
        self.assertTrue(
            any(c["condition"] == "n == 1" and c["line"] == 647
                for c in sites["complement"]),
            "format! token-if at check.rs:647 belongs in the complement",
        )

    def test_frozen_dir_has_only_prereg_files(self):
        names = sorted(p.name for p in PREREG.iterdir())
        self.assertEqual(
            names,
            ["control.json", "manifest.json", "pins.json", "sites.json"],
        )
        for forbidden in (
            "ceilings.json",
            "report.v0.json",
            "report.json",
            "result.json",
            "provenance.json",
        ):
            self.assertFalse((PREREG / forbidden).exists(), forbidden)

    def test_frozen_sites_are_the_seven_conditions(self):
        sites = _load("sites.json")
        self.assertEqual([s["condition"] for s in sites["sites"]], list(PINNED_CONDITIONS))
        self.assertEqual(sites["selected_count"], 7)
        self.assertEqual(sites["complement_count"], 125)
        self.assertEqual(len(sites["complement"]), 125)
        den = {s["condition"] for s in sites["sites"]}
        for item in sites["complement"]:
            self.assertNotIn(item.get("span"), [s["span"] for s in sites["sites"]])
            if item["condition"] not in den:
                continue
            self.assertNotEqual(item["span"], next(
                s["span"] for s in sites["sites"] if s["condition"] == item["condition"]))

    def test_frozen_manifest_pins_unproved_and_container_execution_contract(self):
        manifest = _load("manifest.json")
        self.assertEqual(manifest["runner"], "batch")
        self.assertEqual(manifest["accepted_exit_codes"], [0])
        self.assertEqual(manifest["unproved_exit_codes"], [75])
        self.assertEqual(
            manifest["build"],
            ["cargo", "build", "--release", "--locked", "--offline"],
        )
        pins = _load("pins.json")
        self.assertNotIn("vector_ids", pins["corpus"])
        self.assertNotIn("vector_count", pins["corpus"])
        self.assertEqual(
            pins["corpus"]["commit"],
            "59faf842098183ae7b5387ad13e6351c44687279")
        self.assertEqual(
            pins["corpus"]["corpusDigest"],
            "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579")
        self.assertEqual(pins["corpus"]["vectors"], "corpus/vectors/MANIFEST.json")
        self.assertEqual(manifest["vectors"], "corpus/vectors/MANIFEST.json")
        self.assertEqual(manifest["repo_root"], "subject")
        self.assertEqual(manifest["implementation"], "subject/src/check.rs")
        self.assertEqual(manifest["implementation_sources"],
                         ["subject/src/check.rs"])
        self.assertEqual(
            manifest["entrypoint_command"],
            ["/work/target/release/aee-checker", "/input/vectors",
             "--json", "/work/report.json"],
        )
        self.assertEqual(
            [row["id"] for row in manifest["mutants"]["sealed"]],
            [*("sealed-%d" % n for n in range(1, 8)), "control"],
        )
        self.assertEqual(manifest["outcome_from"], ["rows"])
        self.assertEqual(manifest["diagnostic_from"], ["diagnostics"])
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
        dest = checker.parent
        if not (dest / "MANIFEST.json").exists():
            (dest / "MANIFEST.json").write_text(
                json.dumps({"vectors": [{"id": "v1"}]}), encoding="utf-8")
        cmd = [sys.executable, str(ADAPTER), "--checker", str(checker), str(dest)]
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
        self.assertEqual(doc["rows"]["v1"]["verdict"], "valid")
        self.assertEqual(doc["rows"]["v1"]["result"], "ok")
        self.assertEqual(doc["diagnostics"]["v1"]["reason"], "prose")
        self.assertEqual(
            set(doc["rows"]["v1"]),
            {"verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey"},
        )
        self.assertEqual(set(doc["diagnostics"]["v1"]), {"reason"})
        self.assertNotIn("FROM-STDOUT", proc.stdout)
        self.assertNotIn("code", json.dumps(doc))
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

    def test_relative_checker_starts_from_wrapper_cwd_not_vectors_dir(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bin").mkdir()
            vectors = root / "corpus" / "vectors"
            vectors.mkdir(parents=True)
            (vectors / "MANIFEST.json").write_text(
                json.dumps({"vectors": [{"id": "v1"}]}), encoding="utf-8")
            (root / "bin" / "fake_checker.py").write_text(
                "import json, sys\n"
                "from pathlib import Path\n"
                "Path(sys.argv[sys.argv.index('--json') + 1]).write_text(json.dumps({\n"
                '  "vectors": [{"id": "v1", "verdict": "valid", "result": "ok",\n'
                '    "reason": "prose", "tiersWithPinnedKey": [], "tiersWithoutKey": []}]\n'
                "}) + '\\n')\n"
                "sys.exit(0)\n",
                encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ADAPTER),
                 "--checker", "./bin/fake_checker.py", "corpus/vectors"],
                cwd=root, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        doc = json.loads(proc.stdout)
        self.assertEqual(doc["rows"]["v1"]["verdict"], "valid")
        self.assertEqual(doc["diagnostics"]["v1"]["reason"], "prose")


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

    def _run(self, checker: Path, extra=None, ids=("v1",)):
        # In-process so cap patches reach the same bounded_run / corpus_adequacy
        # names the wrapper uses. Child-exec coverage stays in WrapperContract.
        dest = checker.parent
        if not (dest / "MANIFEST.json").exists():
            (dest / "MANIFEST.json").write_text(
                json.dumps({"vectors": [{"id": i} for i in ids]}), encoding="utf-8")
        argv = ["--checker", str(checker), str(dest)]
        if extra:
            argv.extend(extra)
        buf = io.StringIO()
        with mock.patch.object(sys, "stdout", buf):
            rc = wrapper.main(argv)
        return SimpleNamespace(returncode=rc, stdout=buf.getvalue(), stderr="")

    def test_emitted_maps_keep_reason_out_of_outcome(self):
        projected = wrapper.project({"vectors": [self.GOOD_ROW]}, ["v1"])
        self.assertEqual(set(projected), {"rows", "diagnostics"})
        self.assertEqual(
            set(projected["rows"]["v1"]),
            {"verdict", "result", "tiersWithPinnedKey", "tiersWithoutKey"},
        )
        self.assertEqual(set(projected["diagnostics"]["v1"]), {"reason"})
        self.assertEqual(projected["diagnostics"]["v1"]["reason"], "prose A")
        self.assertNotIn("reason", projected["rows"]["v1"])
        self.assertNotIn("code", projected["rows"]["v1"])
        self.assertNotIn("code", projected["diagnostics"]["v1"])
        self.assertNotIn(wrapper.DIAGNOSTIC_KEY, wrapper.OUTCOME_KEYS)
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer(Path(d), {"vectors": [self.GOOD_ROW]})
            proc = self._run(checker)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        emitted = json.loads(proc.stdout)
        self.assertEqual(set(emitted["rows"]["v1"]), set(projected["rows"]["v1"]))
        self.assertEqual(set(emitted["diagnostics"]["v1"]), {"reason"})

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

    def test_adapter_must_be_in_implementation_sources(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prereg"
            dest.mkdir()
            prereg.emit_prereg(SYNTHETIC.encode("utf-8"), dest)
            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            manifest["implementation_sources"] = ["src/check.rs"]
            _dump(dest / "manifest.json", manifest)
            with self.assertRaises(prereg.PreregError) as ctx:
                prereg.validate_prereg(dest)
            self.assertIn("implementation_sources", str(ctx.exception).lower())

    def _writer_raw(self, tmp: Path, payload: str, rc=0) -> Path:
        return self._fake(tmp, f"""
import sys
from pathlib import Path
Path(sys.argv[sys.argv.index("--json") + 1]).write_text({payload!r} + "\\n")
sys.exit({rc})
""")

    def test_reordered_rows_still_match_manifest_ids(self):
        rows = [
            dict(self.GOOD_ROW, id="v2", reason="b"),
            dict(self.GOOD_ROW, id="v1", reason="a"),
        ]
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            checker = self._writer(tmp, {"vectors": rows})
            proc = self._run(checker, ids=("v1", "v2"))
        self.assertEqual(proc.returncode, 0, proc.stdout)
        doc = json.loads(proc.stdout)
        self.assertEqual(set(doc["rows"]), {"v1", "v2"})
        self.assertEqual(doc["diagnostics"]["v1"]["reason"], "a")

    def test_unexpected_unique_id_is_unproved(self):
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer(Path(d), {"vectors": [dict(self.GOOD_ROW, id="v2")]})
            proc = self._run(checker, ids=("v1",))
        self.assertEqual(proc.returncode, 75, proc.stdout)
        self.assertFalse(proc.stdout.strip())

    def test_duplicate_json_key_is_unproved(self):
        payload = (
            '{"vectors":[{"id":"v1","id":"v1","verdict":"valid","result":"ok",'
            '"reason":"r","tiersWithPinnedKey":[],"tiersWithoutKey":[]}]}'
        )
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer_raw(Path(d), payload)
            proc = self._run(checker)
        self.assertEqual(proc.returncode, 75, proc.stdout)
        self.assertFalse(proc.stdout.strip())

    def test_nonfinite_json_number_is_unproved(self):
        payload = (
            '{"vectors":[{"id":"v1","verdict":"valid","result":1e999,'
            '"reason":"r","tiersWithPinnedKey":[],"tiersWithoutKey":[]}]}'
        )
        with tempfile.TemporaryDirectory() as d:
            checker = self._writer_raw(Path(d), payload)
            proc = self._run(checker)
        self.assertEqual(proc.returncode, 75, proc.stdout)
        self.assertFalse(proc.stdout.strip())

    @unittest.skipIf(ca.fcntl is None, "process/batch scoring requires an advisory lock")
    def test_id_keyed_batch_matching_sees_silent_reason_move(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            (tmp / "check.py").write_text(
                "import json\n"
                'verdict = "valid"\n'
                'reason = "prose A"\n'
                "print(json.dumps({\n"
                '  "rows": {"v1": {"verdict": verdict, "result": "ok",\n'
                '    "tiersWithPinnedKey": [], "tiersWithoutKey": []}},\n'
                '  "diagnostics": {"v1": {"reason": reason}},\n'
                "}, sort_keys=True))\n",
                encoding="utf-8")
            (tmp / "vectors.json").write_text("{}", encoding="utf-8")
            raw = {
                "schema": ca.SCHEMA, "runner": "batch", "repo_root": ".",
                "implementation": "check.py",
                "implementation_sources": ["check.py"],
                "build": [],
                "entrypoint_command": [sys.executable, "check.py"],
                "outcome_from": ["rows"],
                "diagnostic_from": ["diagnostics"],
                "accepted_exit_codes": [0],
                "unproved_exit_codes": [75],
                "vectors": "vectors.json",
                "id_key": "vector_id",
                "default_group": "sealed",
                "mutants": {"sealed": [
                    {"label": "reason-only", "anchor": 'reason = "prose A"',
                     "replacement": 'reason = "prose B"'},
                    {"label": "CONTROL", "control": True,
                     "anchor": 'verdict = "valid"',
                     "replacement": 'verdict = "invalid"'},
                ]},
            }
            manifest = tmp / "m.json"
            manifest.write_text(json.dumps(raw), encoding="utf-8")
            loaded = json.loads(manifest.read_text(encoding="utf-8"))
            loaded["accepted_exit_codes"] = [0]
            loaded["unproved_exit_codes"] = [75]
            loaded["runner"] = "batch"
            loaded["outcome_from"] = ["rows"]
            loaded["diagnostic_from"] = ["diagnostics"]
            value, _diag, kind = ca.child_outcome(
                loaded,
                type("P", (), {"returncode": 0, "stdout": json.dumps({
                    "rows": {"v1": {"verdict": "valid", "result": "ok",
                                    "tiersWithPinnedKey": [], "tiersWithoutKey": []}},
                    "diagnostics": {"v1": {"reason": "prose A"}},
                }), "stderr": ""})())
            self.assertIsNone(kind)
            self.assertIsInstance(value[0], dict)
            self.assertEqual(value[0]["v1"]["verdict"], "valid")
            rep = ca.run(manifest)
        self.assertIsNotNone(rep["score_percent"], rep["failures"])
        self.assertEqual(rep["control_status"], "killed")
        self.assertTrue(
            all("were silent" in f for f in rep["failures"]),
            rep["failures"])
        control = next(r for r in rep["mutants"] if r["label"] == "CONTROL")
        self.assertEqual(control["verdict"], "control-killed")
        row = next(r for r in rep["mutants"] if r["label"] == "reason-only")
        self.assertEqual(row["verdict"], "silent")
        self.assertEqual(row["moved"], 0)
        self.assertGreaterEqual(row["moved_diagnostic"], 1)
        self.assertTrue(rep["diagnostic_channel_declared"])


if __name__ == "__main__":
    unittest.main()
