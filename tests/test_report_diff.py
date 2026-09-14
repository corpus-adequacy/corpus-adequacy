#!/usr/bin/env python3
"""Issue #122: nonexecuting --diff projection over two report.v0 documents."""

from __future__ import annotations

import ast
import hashlib
import inspect
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

import corpus_adequacy as ca  # noqa: E402
from test_corpus_adequacy import (  # noqa: E402
    producer_shaped_report,
    producer_shaped_row,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "report-diff-v0"
OLD_FIXTURE = FIXTURE_DIR / "old.report.v0.json"
NEW_FIXTURE = FIXTURE_DIR / "new.report.v0.json"
EXPECTED_DIFF = FIXTURE_DIR / "expected.diff.v0.json"

DIFF_SCHEMA = "corpus-adequacy.diff.v0"
DIFF_TOP_KEYS = frozenset({
    "schema", "old_input", "new_input", "identity", "rows", "counts", "non_claims",
})
INPUT_KEYS = frozenset({"adequate", "control_status", "unproved"})
IDENTITY_KEYS = frozenset({"manifest_sha256", "corpus_digest", "tool"})
COMPONENT_KEYS = frozenset({"old", "new", "status"})
TOOL_COMPONENT_KEYS = frozenset({
    "tool_version", "tool_commit", "tool_source_state", "tool_content_sha256",
})
ROW_KEYS = frozenset({
    "label", "presence", "old", "new", "verdict_transition",
    "changed_fields", "acknowledgement_retired",
})
COUNT_KEYS = frozenset({
    "common", "added", "removed", "verdict_changed", "verdict_same",
    "acknowledgement_retired",
})
RETAINED_ROW_KEYS = frozenset({
    "group", "verdict", "moved", "how", "scope", "raised", "moved_diagnostic",
})

NON_CLAIMS = [
    "This projection does not establish causation for any verdict transition.",
    "This projection does not establish mutation identity beyond the report label.",
    "This projection does not recompute corpus identity; corpus_digest is an author-declared string.",
    "This projection does not establish that an inadequate or unproved input is a valid completed comparison.",
]

PRESERVED_FIXTURE_HASHES = {
    "tests/fixtures/publication/valid-tersign/report.v0.json":
        "c65f8a6c6dcc4a56dea31e7fc0de241a8cbbdcf36cd4cf98c220d23a894fe5ae",
    "tests/fixtures/publication/survived-silent/report.v0.json":
        "76cae24c322aff6b1eea39d840e4f1dc38eebc8411c3f8045a07f1b55cae33a8",
    "tests/fixtures/publication/unproved-control/report.v0.json":
        "b583a66d8c0e56fe35f627d6e713528bb476c25a05d53fc9796e2adba7bdddfa",
    "tests/fixtures/publication/void-run-attempt/report.v0.json":
        "a3fe7f1682dc81e6841c14d7017860a12f6396e892704bf518e919af47628889",
    "measurements/tersign-1cc5ea32/report.v0.json":
        "d7c9039da10bd444a4861ef9d9d62565ab7bd4aa29186583335ac8c08dbc7f65",
    "measurements/tersign-0e560c1/report.v0.json":
        "6b8a49ce5f63c2b5a38a6b336a601b5ef7feabe6611c2e44bf5d481702e1f2ee",
}
VALID_TERSIGH_REPORT = (
    REPO_ROOT / "tests" / "fixtures" / "publication" / "valid-tersign" / "report.v0.json"
)
VALID_SURVIVORS_SHA256 = (
    "caf3c2345a229d9f76367753ed7e856627fdd8f55aa00e6fbfad2ee502f9e9bb"
)

OLD_MANIFEST = "sha256:" + "1" * 64
NEW_MANIFEST = "sha256:" + "2" * 64
SAME_MANIFEST = "sha256:" + "3" * 64
CONTENT_A = "sha256:" + "4" * 64
CONTENT_B = "sha256:" + "5" * 64
COMMIT_A = "a" * 40
COMMIT_B = "b" * 40


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clone(doc):
    return json.loads(json.dumps(doc))


def _exact_identity(**over):
    identity = {
        "tool_version": ca.VERSION,
        "tool_commit": COMMIT_A,
        "tool_source_state": "exact",
        "tool_content_sha256": CONTENT_A,
    }
    identity.update(over)
    return identity


def _report(mutants, **over):
    extras = _exact_identity()
    extras.update(over)
    extras.setdefault("manifest_sha256", SAME_MANIFEST)
    extras.setdefault("corpus_digest", "declared-corpus")
    extras.setdefault("control_status", "killed")
    extras.setdefault("unproved", 0)
    extras.setdefault("adequate", True)
    return producer_shaped_report(mutants=mutants, **extras)


def _project(old, new):
    return ca.diff_reports(old, new)


def _cli(*argv, timeout=30):
    return subprocess.run(
        [sys.executable, str(ca.__file__), *argv],
        capture_output=True,
        timeout=timeout,
    )


def _write_report(directory: Path, name: str, report: dict) -> Path:
    path = directory / name
    path.write_bytes(ca.encode_report_v0(report))
    return path


def _assert_closed_diff(doc):
    unittest.TestCase().assertEqual(set(doc), DIFF_TOP_KEYS)
    unittest.TestCase().assertEqual(doc["schema"], DIFF_SCHEMA)
    unittest.TestCase().assertEqual(set(doc["old_input"]), INPUT_KEYS)
    unittest.TestCase().assertEqual(set(doc["new_input"]), INPUT_KEYS)
    unittest.TestCase().assertEqual(set(doc["identity"]), IDENTITY_KEYS)
    for key in ("manifest_sha256", "corpus_digest"):
        unittest.TestCase().assertEqual(set(doc["identity"][key]), COMPONENT_KEYS)
    unittest.TestCase().assertEqual(set(doc["identity"]["tool"]), TOOL_COMPONENT_KEYS)
    for key in TOOL_COMPONENT_KEYS:
        unittest.TestCase().assertEqual(
            set(doc["identity"]["tool"][key]), COMPONENT_KEYS)
    unittest.TestCase().assertEqual(set(doc["counts"]), COUNT_KEYS)
    unittest.TestCase().assertEqual(list(doc["non_claims"]), NON_CLAIMS)
    labels = []
    for row in doc["rows"]:
        unittest.TestCase().assertEqual(set(row), ROW_KEYS)
        labels.append(row["label"])
        unittest.TestCase().assertEqual(
            row["changed_fields"], sorted(row["changed_fields"]))
        extra = set(row["changed_fields"]) - RETAINED_ROW_KEYS
        unittest.TestCase().assertEqual(extra, set())
        unittest.TestCase().assertNotIn("label", row["changed_fields"])
    unittest.TestCase().assertEqual(labels, sorted(labels))
    unittest.TestCase().assertEqual(len(labels), len(set(labels)))
    counts = doc["counts"]
    unittest.TestCase().assertEqual(
        counts["verdict_same"] + counts["verdict_changed"], counts["common"])
    unittest.TestCase().assertEqual(
        counts["common"] + counts["added"] + counts["removed"], len(doc["rows"]))
    unittest.TestCase().assertLessEqual(
        counts["acknowledgement_retired"], counts["verdict_changed"])
    unittest.TestCase().assertLessEqual(
        counts["acknowledgement_retired"], counts["common"])
    # The six count fields are not one partition / denominator.
    unittest.TestCase().assertNotEqual(
        sum(counts.values()), counts["common"] + counts["added"] + counts["removed"])


class ReportDiffFixtureBytes(unittest.TestCase):
    def test_json_fixture_exact_bytes(self):
        proc = _cli("--diff", str(OLD_FIXTURE), str(NEW_FIXTURE), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, EXPECTED_DIFF.read_bytes())
        self.assertTrue(proc.stdout.endswith(b"\n"))

    def test_fixture_pair_retains_every_simultaneous_fact(self):
        expected = json.loads(EXPECTED_DIFF.read_text(encoding="utf-8"))
        by_label = {row["label"]: row for row in expected["rows"]}
        simultaneous = by_label["simultaneous"]
        self.assertEqual(simultaneous["presence"], "common")
        self.assertEqual(simultaneous["verdict_transition"], "changed")
        self.assertEqual(simultaneous["changed_fields"], ["group", "how", "moved", "verdict"])
        self.assertEqual(expected["identity"]["manifest_sha256"]["status"], "changed")
        self.assertEqual(expected["identity"]["corpus_digest"]["status"], "changed")
        self.assertEqual(expected["identity"]["tool"]["tool_commit"]["status"], "changed")
        self.assertEqual(expected["identity"]["tool"]["tool_content_sha256"]["status"], "changed")
        self.assertEqual(by_label["verdict-flip"]["verdict_transition"], "changed")
        self.assertEqual(by_label["add-me"]["presence"], "added")
        self.assertEqual(by_label["remove-me"]["presence"], "removed")
        self.assertEqual(by_label["remove-hole"]["acknowledgement_retired"], False)
        self.assertEqual(by_label["retire-hole"]["acknowledgement_retired"], True)
        _assert_closed_diff(expected)

    def test_existing_report_survivors_and_rules_bytes_are_preserved(self):
        for rel, digest in PRESERVED_FIXTURE_HASHES.items():
            path = REPO_ROOT / rel
            self.assertEqual(_sha256_file(path), digest, rel)
        valid = json.loads(VALID_TERSIGH_REPORT.read_text(encoding="utf-8"))
        encoded = ca.encode_survivors_v0(ca.survivor_findings(valid))
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), VALID_SURVIVORS_SHA256)
        self.assertEqual(ca.encode_report_v0(valid), VALID_TERSIGH_REPORT.read_bytes())
        raw_manifest = json.dumps({
            "schema": ca.SCHEMA, "runner": "module", "mutants": {},
        }).encode("utf-8")
        report = producer_shaped_report(
            runner="module",
            manifest_sha256="sha256:" + hashlib.sha256(raw_manifest).hexdigest(),
            **_exact_identity(),
        )
        projected = ca.rule_inventory_projection(report, raw_manifest)
        encoded_rules = ca.encode_rules_v0(projected)
        self.assertEqual(json.loads(encoded_rules)["schema"], ca.RULES_SCHEMA)
        self.assertIsNone(json.loads(encoded_rules)["inventory"])


class ReportDiffIdentical(unittest.TestCase):
    def test_byte_identical_reports_are_common_and_unresolved_where_null(self):
        report = producer_shaped_report(
            mutants=[producer_shaped_row("survived", "only")],
        )
        projected = _project(report, _clone(report))
        _assert_closed_diff(projected)
        self.assertEqual(projected["identity"]["manifest_sha256"]["status"], "same")
        self.assertEqual(projected["identity"]["corpus_digest"]["status"], "undeclared")
        self.assertIsNone(projected["identity"]["corpus_digest"]["old"])
        self.assertEqual(projected["identity"]["tool"]["tool_version"]["status"], "same")
        self.assertEqual(projected["identity"]["tool"]["tool_commit"]["status"], "unresolved")
        self.assertEqual(projected["identity"]["tool"]["tool_content_sha256"]["status"], "unresolved")
        self.assertEqual(projected["identity"]["tool"]["tool_source_state"]["status"], "same")
        self.assertEqual(len(projected["rows"]), 1)
        row = projected["rows"][0]
        self.assertEqual(row["presence"], "common")
        self.assertEqual(row["verdict_transition"], "same")
        self.assertEqual(row["changed_fields"], [])
        self.assertFalse(row["acknowledgement_retired"])
        self.assertEqual(projected["counts"]["common"], 1)
        self.assertEqual(projected["counts"]["added"], 0)
        self.assertEqual(projected["counts"]["removed"], 0)
        self.assertEqual(projected["counts"]["verdict_same"], 1)
        self.assertEqual(projected["counts"]["verdict_changed"], 0)


class ReportDiffAddedRemoved(unittest.TestCase):
    def test_added_and_removed_labels_with_changed_manifest(self):
        old = _report(
            [producer_shaped_row("killed", "gone", moved=1, how="1 vector(s) moved"),
             producer_shaped_row("survived", "keep")],
            manifest_sha256=OLD_MANIFEST,
        )
        new = _report(
            [producer_shaped_row("survived", "keep"),
             producer_shaped_row("survived", "fresh")],
            manifest_sha256=NEW_MANIFEST,
        )
        projected = _project(old, new)
        _assert_closed_diff(projected)
        by_label = {row["label"]: row for row in projected["rows"]}
        self.assertEqual(by_label["fresh"]["presence"], "added")
        self.assertIsNone(by_label["fresh"]["old"])
        self.assertEqual(by_label["fresh"]["new"]["label"], "fresh")
        self.assertEqual(by_label["fresh"]["verdict_transition"], "unavailable")
        self.assertEqual(
            by_label["fresh"]["changed_fields"],
            ["group", "how", "moved", "scope", "verdict"],
        )
        self.assertEqual(by_label["gone"]["presence"], "removed")
        self.assertIsNone(by_label["gone"]["new"])
        self.assertEqual(by_label["gone"]["verdict_transition"], "unavailable")
        self.assertEqual(
            by_label["gone"]["changed_fields"],
            ["group", "how", "moved", "scope", "verdict"],
        )
        self.assertEqual(by_label["keep"]["presence"], "common")
        self.assertEqual(projected["counts"]["added"], 1)
        self.assertEqual(projected["counts"]["removed"], 1)
        self.assertEqual(projected["counts"]["common"], 1)


class ReportDiffVerdictTransition(unittest.TestCase):
    def test_survived_to_killed_with_changed_manifest_and_equal_corpus_is_changed(self):
        old = _report(
            [producer_shaped_row("survived", "rule", how="no vector distinguishes it")],
            manifest_sha256=OLD_MANIFEST,
            corpus_digest="same-declared-corpus",
        )
        new = _report(
            [producer_shaped_row("killed", "rule", moved=1, how="1 vector(s) moved")],
            manifest_sha256=NEW_MANIFEST,
            corpus_digest="same-declared-corpus",
        )
        projected = _project(old, new)
        _assert_closed_diff(projected)
        row = projected["rows"][0]
        self.assertEqual(row["label"], "rule")
        self.assertEqual(row["presence"], "common")
        self.assertEqual(row["verdict_transition"], "changed")
        self.assertNotEqual(row["verdict_transition"], "same")
        self.assertIn("verdict", row["changed_fields"])
        self.assertEqual(projected["identity"]["corpus_digest"]["status"], "same")
        self.assertEqual(projected["identity"]["manifest_sha256"]["status"], "changed")
        self.assertEqual(projected["counts"]["verdict_changed"], 1)
        self.assertEqual(projected["counts"]["verdict_same"], 0)


class ReportDiffSimultaneousFacts(unittest.TestCase):
    def test_simultaneous_manifest_tool_corpus_group_and_diagnostic_changes_all_remain(self):
        old = _report(
            [producer_shaped_row(
                "silent", "rule", group="axis-a", moved_diagnostic=1,
                how="diagnostic only")],
            manifest_sha256=OLD_MANIFEST,
            corpus_digest="corpus-old",
            tool_commit=COMMIT_A,
            tool_content_sha256=CONTENT_A,
            tool_source_state="exact",
        )
        new = _report(
            [producer_shaped_row(
                "killed", "rule", group="axis-b", moved=2, how="1 vector(s) moved")],
            manifest_sha256=NEW_MANIFEST,
            corpus_digest="corpus-new",
            tool_commit=COMMIT_B,
            tool_content_sha256=CONTENT_B,
            tool_source_state="exact",
            tool_version="0.2.0",
        )
        projected = _project(old, new)
        _assert_closed_diff(projected)
        identity = projected["identity"]
        self.assertEqual(identity["manifest_sha256"]["status"], "changed")
        self.assertEqual(identity["corpus_digest"]["status"], "changed")
        self.assertEqual(identity["tool"]["tool_commit"]["status"], "changed")
        self.assertEqual(identity["tool"]["tool_content_sha256"]["status"], "changed")
        row = projected["rows"][0]
        self.assertEqual(row["presence"], "common")
        self.assertEqual(row["verdict_transition"], "changed")
        for field in ("group", "verdict", "moved", "how", "moved_diagnostic"):
            self.assertIn(field, row["changed_fields"], field)
        self.assertEqual(row["old"]["group"], "axis-a")
        self.assertEqual(row["new"]["group"], "axis-b")
        self.assertEqual(row["old"]["verdict"], "silent")
        self.assertEqual(row["new"]["verdict"], "killed")
        self.assertNotIn("implementation-or-tool-changed", json.dumps(projected))
        self.assertNotIn("corpus-changed", json.dumps(projected))


class ReportDiffDuplicateLabel(unittest.TestCase):
    def test_duplicate_label_refuses_before_matching(self):
        old = _report([
            producer_shaped_row("survived", "dup"),
            producer_shaped_row("killed", "dup", moved=1, how="1 vector(s) moved"),
        ])
        new = _report(
            [producer_shaped_row("survived", "dup")],
            manifest_sha256=NEW_MANIFEST,
        )
        with self.assertRaises(ca.ManifestError) as cm:
            _project(old, new)
        message = str(cm.exception).lower()
        self.assertIn("duplicate", message)
        self.assertIn("label", message)
        self.assertNotIn("added or removed", message)
        self.assertNotIn("changed manifest", message)


class ReportDiffGroupMove(unittest.TestCase):
    def test_group_move_remains_one_common_row(self):
        old = _report([producer_shaped_row("survived", "rule", group="axis-a")])
        new = _report([producer_shaped_row("survived", "rule", group="axis-b")])
        projected = _project(old, new)
        _assert_closed_diff(projected)
        self.assertEqual(len(projected["rows"]), 1)
        row = projected["rows"][0]
        self.assertEqual(row["presence"], "common")
        self.assertEqual(row["verdict_transition"], "same")
        self.assertEqual(row["changed_fields"], ["group"])
        self.assertEqual(projected["counts"]["common"], 1)
        self.assertEqual(projected["counts"]["added"], 0)
        self.assertEqual(projected["counts"]["removed"], 0)


class ReportDiffNullIdentity(unittest.TestCase):
    def test_null_tool_values_are_unresolved_never_same(self):
        old = producer_shaped_report(
            mutants=[producer_shaped_row("survived", "only")],
            tool_commit=None,
            tool_content_sha256=None,
            tool_source_state="unresolved",
            corpus_digest=None,
        )
        new = _clone(old)
        projected = _project(old, new)
        tool = projected["identity"]["tool"]
        self.assertEqual(tool["tool_commit"]["status"], "unresolved")
        self.assertEqual(tool["tool_content_sha256"]["status"], "unresolved")
        self.assertNotEqual(tool["tool_commit"]["status"], "same")
        self.assertNotEqual(tool["tool_content_sha256"]["status"], "same")
        self.assertEqual(projected["identity"]["corpus_digest"]["status"], "undeclared")
        self.assertNotEqual(projected["identity"]["corpus_digest"]["status"], "same")


class ReportDiffInvalidInputVisible(unittest.TestCase):
    def test_inadequate_control_and_unproved_state_remain_visible(self):
        old = _report(
            [producer_shaped_row("survived", "rule")],
            adequate=False,
            control_status="error",
            unproved=2,
        )
        new = _report(
            [producer_shaped_row("survived", "rule")],
            adequate=True,
            control_status="killed",
            unproved=0,
        )
        projected = _project(old, new)
        _assert_closed_diff(projected)
        self.assertEqual(projected["old_input"], {
            "adequate": False, "control_status": "error", "unproved": 2,
        })
        self.assertEqual(projected["new_input"], {
            "adequate": True, "control_status": "killed", "unproved": 0,
        })
        self.assertIs(projected["old_input"]["adequate"], False)
        self.assertEqual(type(projected["old_input"]["unproved"]), int)
        self.assertEqual(projected["rows"][0]["verdict_transition"], "same")


class ReportDiffRemovedKnownHole(unittest.TestCase):
    def test_removed_known_hole_is_not_acknowledgement_retired(self):
        old = _report(
            [producer_shaped_row("known-hole", "hole", how="acknowledged hole"),
             producer_shaped_row("survived", "keep")],
            manifest_sha256=OLD_MANIFEST,
        )
        new = _report(
            [producer_shaped_row("survived", "keep")],
            manifest_sha256=NEW_MANIFEST,
        )
        projected = _project(old, new)
        by_label = {row["label"]: row for row in projected["rows"]}
        self.assertEqual(by_label["hole"]["presence"], "removed")
        self.assertFalse(by_label["hole"]["acknowledgement_retired"])
        self.assertEqual(projected["counts"]["acknowledgement_retired"], 0)
        self.assertEqual(projected["counts"]["removed"], 1)


class ReportDiffMalformedRefusal(unittest.TestCase):
    def test_malformed_manifest_digest_refuses(self):
        report = _report(
            [producer_shaped_row("survived", "only")],
            manifest_sha256="sha256:DEADBEEF",
        )
        with self.assertRaises(ca.ManifestError) as cm:
            ca._require_report_rows(report)
        self.assertIn("sha256", str(cm.exception).lower())

    def test_malformed_tool_commit_refuses(self):
        report = _report(
            [producer_shaped_row("survived", "only")],
            tool_commit="A" * 40,
        )
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(report)

    def test_malformed_verdict_refuses(self):
        report = _report([producer_shaped_row("not-a-verdict", "only")])
        with self.assertRaises(ca.ManifestError) as cm:
            ca._require_report_rows(report)
        self.assertIn("verdict", str(cm.exception).lower())

    def test_empty_corpus_digest_refuses(self):
        report = _report(
            [producer_shaped_row("survived", "only")],
            corpus_digest="",
        )
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(report)

    def test_bool_adequate_and_unproved_forms_refuse(self):
        as_int = _report([producer_shaped_row("survived", "only")], adequate=1)
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(as_int)
        as_bool = _report([producer_shaped_row("survived", "only")], unproved=True)
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(as_bool)

    def test_exact_state_with_null_commit_refuses(self):
        report = _report(
            [producer_shaped_row("survived", "only")],
            tool_commit=None,
            tool_source_state="exact",
            tool_content_sha256=CONTENT_A,
        )
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(report)

    def test_dirty_state_with_commit_refuses(self):
        report = _report(
            [producer_shaped_row("survived", "only")],
            tool_commit=COMMIT_A,
            tool_source_state="dirty",
            tool_content_sha256=CONTENT_A,
        )
        with self.assertRaises(ca.ManifestError):
            ca._require_report_rows(report)


class ReportDiffSameManifestAddedRemoved(unittest.TestCase):
    def test_unchanged_manifest_with_added_label_refuses(self):
        old = _report([producer_shaped_row("survived", "keep")])
        new = _report([
            producer_shaped_row("survived", "keep"),
            producer_shaped_row("survived", "fresh"),
        ])
        with self.assertRaises(ca.ManifestError) as cm:
            _project(old, new)
        self.assertIn("manifest", str(cm.exception).lower())
        self.assertIn("added", str(cm.exception).lower())

    def test_unchanged_manifest_with_removed_label_refuses(self):
        old = _report([
            producer_shaped_row("survived", "keep"),
            producer_shaped_row("killed", "gone", moved=1, how="1 vector(s) moved"),
        ])
        new = _report([producer_shaped_row("survived", "keep")])
        with self.assertRaises(ca.ManifestError) as cm:
            _project(old, new)
        self.assertIn("manifest", str(cm.exception).lower())
        self.assertIn("removed", str(cm.exception).lower())


class ReportDiffSharedValidator(unittest.TestCase):
    def test_one_generalized_validator_is_shared(self):
        src = Path(ca.__file__).read_text(encoding="utf-8")
        tree = ast.parse(src)
        names = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
        self.assertIn("_require_report_rows", names)
        self.assertIn("diff_reports", names)
        self.assertIn("_require_report_rows", inspect.getsource(ca.survivor_findings))
        self.assertIn("_require_report_rows", inspect.getsource(ca.rule_inventory_projection))
        self.assertIn("_require_report_rows", inspect.getsource(ca.diff_reports))
        self.assertEqual(inspect.getsource(ca.survivor_findings).count("_require_report_rows"), 1)
        self.assertEqual(inspect.getsource(ca.diff_reports).count("_require_report_rows"), 2)

    def test_duplicate_label_is_refused_for_survivors_too(self):
        report = producer_shaped_report(mutants=[
            producer_shaped_row("survived", "dup"),
            producer_shaped_row("silent", "dup", moved_diagnostic=1),
        ])
        with self.assertRaises(ca.ManifestError) as cm:
            ca.survivor_findings(report)
        self.assertIn("duplicate", str(cm.exception).lower())


class ReportDiffCLI(unittest.TestCase):
    def test_diff_cli_does_not_call_run(self):
        report = _report([producer_shaped_row("survived", "only")])
        with tempfile.TemporaryDirectory() as d:
            path = _write_report(Path(d), "report.json", report)
            stdout = io.BytesIO()

            class BinaryStdout:
                buffer = stdout

                def write(self, _text):
                    raise AssertionError("diff JSON was routed through text encoding")

            with (mock.patch.object(sys, "argv", [
                    "corpus_adequacy.py", "--diff", str(path), str(path), "--json"]),
                  mock.patch.object(sys, "stdout", BinaryStdout()),
                  mock.patch.object(
                      ca, "run",
                      side_effect=AssertionError("--diff called run()"))):
                rc = ca.main()
        self.assertEqual(rc, 0)
        body = json.loads(stdout.getvalue())
        self.assertEqual(body["schema"], DIFF_SCHEMA)
        _assert_closed_diff(body)

    def test_diff_cli_json_matches_encoder(self):
        with tempfile.TemporaryDirectory() as d:
            old = _write_report(Path(d), "old.json", _report(
                [producer_shaped_row("survived", "rule")],
                manifest_sha256=OLD_MANIFEST,
            ))
            new = _write_report(Path(d), "new.json", _report(
                [producer_shaped_row("killed", "rule", moved=1, how="1 vector(s) moved")],
                manifest_sha256=NEW_MANIFEST,
            ))
            old_doc = json.loads(old.read_text(encoding="utf-8"))
            new_doc = json.loads(new.read_text(encoding="utf-8"))
            proc = _cli("--diff", str(old), str(new), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, ca.encode_diff_v0(_project(old_doc, new_doc)))

    def test_diff_json_malformed_envelope_uses_project_verb(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "nope.json"
            path.write_text('{"schema":"nope"}\n', encoding="utf-8")
            proc = _cli("--diff", str(path), str(path), "--json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("could not project", proc.stderr.decode("utf-8"))
        self.assertNotIn("could not measure", proc.stderr.decode("utf-8"))
        self.assertNotIn("Traceback", proc.stderr.decode("utf-8"))
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertIn("could not project", env["error"])

    def test_human_rendering_reports_facts_and_limitations_only(self):
        proc = _cli("--diff", str(OLD_FIXTURE), str(NEW_FIXTURE))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        text = proc.stdout.decode("utf-8")
        self.assertNotIn("%", text)
        self.assertNotIn("implementation-or-tool-changed", text)
        self.assertNotIn("new-mutant", text)
        self.assertNotIn("because", text.lower())
        for claim in NON_CLAIMS:
            self.assertIn(claim, text)
        self.assertIn("verdict_transition=changed", text)
        self.assertIn("acknowledgement_retired=true", text)
        self.assertIn("presence=added", text)
        self.assertIn("presence=removed", text)
        self.assertIn("old_input", text)
        self.assertIn("adequate=false", text)

    def test_encoder_does_not_call_report_or_survivors_encoder(self):
        projected = _project(
            _report([producer_shaped_row("survived", "only")]),
            _report([producer_shaped_row("survived", "only")]),
        )
        with mock.patch.object(
                ca, "encode_report_v0",
                side_effect=AssertionError("encode_diff_v0 called encode_report_v0")), \
                mock.patch.object(
                    ca, "encode_survivors_v0",
                    side_effect=AssertionError("encode_diff_v0 called encode_survivors_v0")):
            encoded = ca.encode_diff_v0(projected)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(json.loads(encoded)["schema"], DIFF_SCHEMA)


class ReportDiffEncoderClosure(unittest.TestCase):
    def _valid(self):
        old = _report(
            [producer_shaped_row("survived", "keep"),
             producer_shaped_row("known-hole", "retire", how="acknowledged hole"),
             producer_shaped_row("known-hole", "remove-hole", how="acknowledged hole")],
            manifest_sha256=OLD_MANIFEST,
        )
        new = _report(
            [producer_shaped_row("survived", "keep"),
             producer_shaped_row("killed", "retire", moved=1, how="1 vector(s) moved"),
             producer_shaped_row("survived", "fresh")],
            manifest_sha256=NEW_MANIFEST,
        )
        projected = _project(old, new)
        _assert_closed_diff(projected)
        return projected

    def _null_identity(self):
        report = producer_shaped_report(
            mutants=[producer_shaped_row("survived", "only")],
        )
        return _project(report, _clone(report))

    def _same_identity(self):
        report = _report([producer_shaped_row("survived", "only")])
        return _project(report, _clone(report))

    def test_encode_diff_v0_refuses_value_and_cross_field_corruptions(self):
        valid = self._valid()
        encoded = ca.encode_diff_v0(valid)
        self.assertEqual(json.loads(encoded)["schema"], DIFF_SCHEMA)
        self.assertIn("_require_diff_v0_document", inspect.getsource(ca.encode_diff_v0))
        self.assertEqual(
            inspect.getsource(ca.encode_diff_v0).count("_require_diff_v0_document"), 1)

        def mutate(doc, fn):
            cloned = _clone(doc)
            fn(cloned)
            return cloned

        keep = next(row for row in valid["rows"] if row["label"] == "keep")
        self.assertEqual(keep["presence"], "common")
        self.assertEqual(keep["changed_fields"], [])
        self.assertEqual(keep["verdict_transition"], "same")
        retire = next(row for row in valid["rows"] if row["label"] == "retire")
        remove_hole = next(row for row in valid["rows"] if row["label"] == "remove-hole")
        fresh = next(row for row in valid["rows"] if row["label"] == "fresh")
        self.assertTrue(retire["acknowledgement_retired"])
        self.assertEqual(remove_hole["presence"], "removed")
        self.assertFalse(remove_hole["acknowledgement_retired"])
        self.assertEqual(fresh["presence"], "added")

        corruptions = (
            ("certified-manifest-status", mutate(valid, lambda d: d["identity"]["manifest_sha256"].__setitem__("status", "certified"))),
            ("adequate-as-string", mutate(valid, lambda d: d["old_input"].__setitem__("adequate", "yes"))),
            ("negative-common-count", mutate(valid, lambda d: d["counts"].__setitem__("common", -99))),
            ("caused-by-tool-transition", mutate(valid, lambda d: d["rows"][0].__setitem__("verdict_transition", "caused-by-tool"))),
            ("unchanged-row-lists-verdict", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "keep").__setitem__(
                    "changed_fields", ["verdict"]))),
            ("bool-count", mutate(valid, lambda d: d["counts"].__setitem__("common", True))),
            ("unproved-as-bool", mutate(valid, lambda d: d["new_input"].__setitem__("unproved", True))),
            ("unsorted-changed-fields", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "retire").__setitem__(
                    "changed_fields", list(reversed(retire["changed_fields"]))))),
            ("reversed-row-order", mutate(valid, lambda d: d.__setitem__("rows", list(reversed(d["rows"]))))),
            ("duplicate-label", mutate(valid, lambda d: d.__setitem__("rows", [d["rows"][0], _clone(d["rows"][0])] + d["rows"][1:]))),
            ("added-with-same-manifest", mutate(valid, lambda d: (
                d["identity"]["manifest_sha256"].__setitem__("new", d["identity"]["manifest_sha256"]["old"]),
                d["identity"]["manifest_sha256"].__setitem__("status", "same")))),
            ("retired-on-removed-hole", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "remove-hole").__setitem__(
                    "acknowledgement_retired", True))),
            ("acknowledgement-as-int", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "keep").__setitem__(
                    "acknowledgement_retired", 1))),
            ("presence-common-without-old", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "keep").__setitem__("old", None))),
            ("extra-mutant-row-key", mutate(valid, lambda d: next(
                row for row in d["rows"] if row["label"] == "keep")["old"].__setitem__(
                    "extra", True))),
            ("recomputed-verdict-changed", mutate(valid, lambda d: d["counts"].__setitem__("verdict_changed", 0))),
            ("manifest-status-same-when-changed", mutate(valid, lambda d: d["identity"]["manifest_sha256"].__setitem__("status", "same"))),
            ("null-tool-marked-same", mutate(self._null_identity(), lambda d: d["identity"]["tool"]["tool_commit"].__setitem__("status", "same"))),
            ("null-corpus-marked-same", mutate(self._null_identity(), lambda d: d["identity"]["corpus_digest"].__setitem__("status", "same"))),
        )
        self.assertGreaterEqual(len(corruptions), 15)
        for name, malformed in corruptions:
            with self.subTest(name=name):
                with self.assertRaises(ca.ManifestError):
                    ca.encode_diff_v0(malformed)

    def test_encode_diff_v0_refuses_malformed_identity_values(self):
        valid = self._valid()
        same = self._same_identity()
        self.assertEqual(json.loads(ca.encode_diff_v0(valid))["schema"], DIFF_SCHEMA)
        self.assertEqual(json.loads(ca.encode_diff_v0(same))["schema"], DIFF_SCHEMA)
        self.assertEqual(
            json.loads(ca.encode_diff_v0(self._null_identity()))["schema"], DIFF_SCHEMA)
        self.assertEqual(same["counts"]["added"], 0)
        self.assertEqual(same["counts"]["removed"], 0)
        self.assertEqual(same["identity"]["manifest_sha256"]["status"], "same")
        with self.subTest(name="shared-identity-validators"):
            document_src = inspect.getsource(ca._require_diff_v0_document)
            self.assertIn("_require_diff_identity_values", document_src)
            self.assertIn("_require_diff_component_status", document_src)
            self.assertTrue(hasattr(ca, "_require_canonical_sha256"))
            self.assertTrue(hasattr(ca, "_require_corpus_digest"))
            self.assertTrue(hasattr(ca, "_require_diff_identity_values"))
            values_fn = getattr(ca, "_require_diff_identity_values", None)
            self.assertIsNotNone(values_fn)
            report_src = inspect.getsource(ca._require_report_rows)
            values_src = inspect.getsource(values_fn)
            for helper in (
                    "_require_canonical_sha256",
                    "_require_corpus_digest",
                    "_require_tool_identity_forms"):
                self.assertIn(helper, report_src)
                self.assertIn(helper, values_src)

        def mutate(doc, fn):
            cloned = _clone(doc)
            fn(cloned)
            return cloned

        def set_both(path, value, status):
            def fn(d):
                node = d["identity"]
                for key in path:
                    node = node[key]
                node["old"] = value
                node["new"] = value
                node["status"] = status
            return fn

        def exact_null_tool(d):
            tool = d["identity"]["tool"]
            for side in ("old", "new"):
                tool["tool_source_state"][side] = "exact"
                tool["tool_commit"][side] = None
                tool["tool_content_sha256"][side] = None
            tool["tool_source_state"]["status"] = "same"
            tool["tool_commit"]["status"] = "unresolved"
            tool["tool_content_sha256"]["status"] = "unresolved"

        corruptions = (
            ("both-manifest-bad", mutate(same, set_both(("manifest_sha256",), "bad", "same"))),
            ("corpus-values-int", mutate(same, set_both(("corpus_digest",), 7, "same"))),
            ("both-tool-commits-bad", mutate(
                same, set_both(("tool", "tool_commit"), "bad", "same"))),
            ("invented-tool-states", mutate(
                same, set_both(("tool", "tool_source_state"), "invented", "same"))),
            ("bad-content-digests", mutate(
                same, set_both(("tool", "tool_content_sha256"), "bad", "same"))),
            ("empty-tool-versions", mutate(
                same, set_both(("tool", "tool_version"), "", "same"))),
            ("exact-null-commit-content", mutate(same, exact_null_tool)),
            ("old-input-unproved-negative", mutate(
                same, lambda d: d["old_input"].__setitem__("unproved", -1))),
        )
        self.assertEqual(len(corruptions), 8)
        for name, malformed in corruptions:
            with self.subTest(name=name):
                with self.assertRaises(ca.ManifestError):
                    ca.encode_diff_v0(malformed)


class ReportDiffPositionalRefusal(unittest.TestCase):
    def test_diff_cli_refuses_nonexistent_positional_before_reading_reports(self):
        ignored = Path("/no-such-corpus-adequacy-ignored-positional.json")
        self.assertFalse(ignored.exists())
        proc = _cli(
            str(ignored), "--diff", str(OLD_FIXTURE), str(NEW_FIXTURE), "--json")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        stderr = proc.stderr.decode("utf-8")
        self.assertIn("could not project", stderr)
        self.assertIn("positional", stderr.lower())
        self.assertNotIn("could not measure", stderr)
        self.assertNotIn("Traceback", stderr)
        env = json.loads(proc.stdout)
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertEqual(env["exit"], 2)
        self.assertIn("could not project", env["error"])
        self.assertNotEqual(env.get("schema"), DIFF_SCHEMA)
        self.assertNotIn("corpus-adequacy.diff.v0", env.get("schema", ""))

        stdout = io.BytesIO()
        stderr_buf = io.StringIO()

        class BinaryStdout:
            buffer = stdout

            def write(self, text):
                stdout.write(text.encode("utf-8") if isinstance(text, str) else text)

        with (mock.patch.object(sys, "argv", [
                "corpus_adequacy.py", str(ignored), "--diff",
                str(OLD_FIXTURE), str(NEW_FIXTURE), "--json"]),
              mock.patch.object(sys, "stdout", BinaryStdout()),
              mock.patch.object(sys, "stderr", stderr_buf),
              mock.patch.object(
                  ca, "read_bounded_regular_file",
                  side_effect=AssertionError(
                      "read report before refusing positional"))):
            rc = ca.main()
        self.assertEqual(rc, 2)
        self.assertIn("could not project", stderr_buf.getvalue())
        self.assertNotIn("could not measure", stderr_buf.getvalue())
        self.assertNotIn("Traceback", stderr_buf.getvalue())
        env = json.loads(stdout.getvalue().decode("utf-8"))
        self.assertEqual(env["schema"], ca.ERROR_SCHEMA)
        self.assertEqual(env["exit"], 2)
        self.assertIn("positional", env["error"].lower())


class ReportDiffDocs(unittest.TestCase):

    def test_readme_documents_pinned_identities_only(self):
        text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("python3 corpus_adequacy.py --diff <old.report.v0> <new.report.v0>", text)
        self.assertIn("python3 corpus_adequacy.py --diff <old.report.v0> <new.report.v0> --json", text)
        self.assertIn("corpus-adequacy.diff.v0", text)
        self.assertIn("classifies by pinned identities only", text)
        self.assertIn("never reads the corpus or the manifest", text)
        self.assertIn("does not print a percentage delta", text)

    def test_changelog_records_the_projection(self):
        text = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## 0.2.0", 1)[0]
        self.assertIn("#122", unreleased)
        self.assertIn("corpus-adequacy.diff.v0", unreleased)
        self.assertIn("--diff", unreleased)


if __name__ == "__main__":
    unittest.main()
