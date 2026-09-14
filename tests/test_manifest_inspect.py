import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import corpus_adequacy as ca


FIXTURES = Path(__file__).parent / "fixtures" / "inspect-v0"


def fixture(name):
    return (FIXTURES / name).read_bytes()


class ManifestInspection(unittest.TestCase):
    def assert_refused_by_both_before_binding(self, manifest, token):
        raw = json.dumps(manifest).encode()
        with mock.patch.object(ca, "bind_manifest_files",
                               side_effect=AssertionError("binder reached")):
            with self.assertRaisesRegex(ca.ManifestError, token) as normal:
                ca.load_manifest_bytes(raw, Path("manifest.json"))
        with self.assertRaisesRegex(ca.ManifestError, token) as inspected:
            ca.inspect_manifest_declaration(raw)
        self.assertEqual(str(normal.exception), str(inspected.exception))

    def test_exact_v0_and_v1_bytes_are_closed_and_deterministic(self):
        for version in ("v0", "v1"):
            raw = fixture("manifest.%s.json" % version)
            expected = fixture("expected-%s.inspect.v0.json" % version)
            first = ca.encode_inspect_v0(ca.inspect_manifest_declaration(raw))
            second = ca.encode_inspect_v0(ca.inspect_manifest_declaration(raw))
            self.assertEqual(first, expected)
            self.assertEqual(second, expected)
        self.assertIsNone(json.loads(fixture("expected-v0.inspect.v0.json"))
                          ["declared"]["rule_inventory"])
        self.assertEqual(json.loads(fixture("expected-v1.inspect.v0.json"))
                         ["declared"]["rule_inventory"]["rules_declared"], 1)

    def test_parser_is_shared_by_inspection_and_normal_loading(self):
        raw = fixture("manifest.v0.json")
        original = ca.parse_manifest_declaration
        with mock.patch.object(ca, "parse_manifest_declaration", wraps=original) as parser:
            ca.inspect_manifest_declaration(raw)
            self.assertEqual(parser.call_count, 1)
        with mock.patch.object(ca, "parse_manifest_declaration", wraps=original) as parser:
            with mock.patch.object(ca, "bind_manifest_files", side_effect=lambda m, *a, **k: m):
                ca.load_manifest_bytes(raw, Path("manifest.json"))
            self.assertEqual(parser.call_count, 1)

    def test_binder_returns_a_distinct_mapping_without_mutating_declaration(self):
        raw = fixture("manifest.v0.json")
        declaration = ca.parse_manifest_declaration(raw)
        before = copy.deepcopy(declaration)
        bound = ca.bind_manifest_files(
            declaration, Path("manifest.json"), path_root=Path("fixture-root"))
        self.assertEqual(declaration, before)
        self.assertIsNot(bound, declaration)
        self.assertIs(bound["_rule_inventory"], declaration["_rule_inventory"])
        self.assertEqual(
            bound,
            ca.load_manifest_bytes(
                raw, Path("manifest.json"), path_root=Path("fixture-root")))

    def test_selector_presence_distinguishes_absent_empty_and_nonempty(self):
        manifest = json.loads(fixture("manifest.v0.json"))
        manifest.update({
            "runner": "batch",
            "entrypoint_command": ["python3", "runner.py"],
            "outcome_parse": "test-names",
            "accepted_exit_codes": [0, 101],
        })

        absent = ca.inspect_manifest_declaration(json.dumps(manifest).encode())
        manifest["outcome_from"] = []
        empty = ca.inspect_manifest_declaration(json.dumps(manifest).encode())
        manifest["outcome_from"] = ["verdict", "reason"]
        nonempty = ca.inspect_manifest_declaration(json.dumps(manifest).encode())

        self.assertEqual(absent["declared"]["selectors"]["outcome_from"], {
            "status": "absent", "value": None})
        self.assertEqual(empty["declared"]["selectors"]["outcome_from"], {
            "status": "declared", "value": []})
        self.assertEqual(nonempty["declared"]["selectors"]["outcome_from"], {
            "status": "declared", "value": ["verdict", "reason"]})
        self.assertNotEqual(absent["declared"]["selectors"],
                            empty["declared"]["selectors"])
        selector_bytes = [
            json.dumps(doc["declared"]["selectors"], sort_keys=True,
                       separators=(",", ":")).encode()
            for doc in (absent, empty, nonempty)
        ]
        self.assertEqual(selector_bytes, [
            (b'{"diagnostic_from":{"status":"absent","value":null},'
             b'"outcome_from":{"status":"absent","value":null},'
             b'"outcome_parse":{"status":"declared","value":"test-names"}}'),
            (b'{"diagnostic_from":{"status":"absent","value":null},'
             b'"outcome_from":{"status":"declared","value":[]},'
             b'"outcome_parse":{"status":"declared","value":"test-names"}}'),
            (b'{"diagnostic_from":{"status":"absent","value":null},'
             b'"outcome_from":{"status":"declared","value":["verdict","reason"]},'
             b'"outcome_parse":{"status":"declared","value":"test-names"}}'),
        ])

    def test_selector_status_value_grammar_is_closed(self):
        doc = ca.inspect_manifest_declaration(fixture("manifest.v1.json"))
        doc["declared"]["selectors"]["outcome_from"] = 7
        with self.assertRaisesRegex(ca.ManifestError, "inspection selector"):
            ca.encode_inspect_v0(doc)

        doc = ca.inspect_manifest_declaration(fixture("manifest.v1.json"))
        doc["declared"]["selectors"]["outcome_from"] = {
            "status": "declared", "value": {"unexpected": "shape"}}
        with self.assertRaisesRegex(ca.ManifestError, "inspection selector"):
            ca.encode_inspect_v0(doc)

        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        doc["declared"]["selectors"]["outcome_parse"] = {
            "status": "absent", "value": []}
        with self.assertRaisesRegex(ca.ManifestError, "inspection selector"):
            ca.encode_inspect_v0(doc)

    def test_control_timeout_and_command_shapes_refuse_before_binding(self):
        base = json.loads(fixture("manifest.v1.json"))
        cases = []

        malformed = copy.deepcopy(base)
        malformed["mutants"]["demo"][0]["control"] = "yes"
        cases.append((malformed, "control must be a boolean"))

        for key in ("build_timeout", "vector_timeout"):
            for value in ("soon", True, 0, -1, ca._MAX_EXACT_TIMEOUT_SECONDS + 1):
                malformed = copy.deepcopy(base)
                malformed[key] = value
                cases.append((malformed, "%s must be a positive integer" % key))

        for key, values in (("build", ("compile", [""], [7])),
                            ("entrypoint_command", ("run", [], [""], [7]))):
            for value in values:
                malformed = copy.deepcopy(base)
                malformed[key] = value
                cases.append((malformed, "%s must be" % key))

        for manifest, token in cases:
            with self.subTest(token=token, value=manifest):
                self.assert_refused_by_both_before_binding(manifest, token)

        boundary = copy.deepcopy(base)
        boundary["build_timeout"] = ca._MAX_EXACT_TIMEOUT_SECONDS
        boundary["vector_timeout"] = ca._MAX_EXACT_TIMEOUT_SECONDS
        parsed = ca.parse_manifest_declaration(json.dumps(boundary).encode())
        self.assertEqual(parsed["build_timeout"], ca._MAX_EXACT_TIMEOUT_SECONDS)
        self.assertEqual(parsed["vector_timeout"], ca._MAX_EXACT_TIMEOUT_SECONDS)
        ca.encode_inspect_v0(
            ca.inspect_manifest_declaration(json.dumps(boundary).encode()))

    def test_inspect_encoder_closes_controls_deadlines_and_commands(self):
        edits = (
            (("controls", 0, "group"), 7, "inspection control group"),
            (("deadlines", "vector_timeout"), "soon", "vector_timeout"),
            (("deadlines", "build_timeout"), 0, "build_timeout"),
            (("commands", "build"), "compile", "build"),
            (("commands", "build"), None, "build"),
            (("commands", "entrypoint_command"), [], "entrypoint_command"),
            (("commands", "entrypoint_command"), None, "entrypoint_command"),
        )
        for path, value, token in edits:
            doc = ca.inspect_manifest_declaration(fixture("manifest.v1.json"))
            target = doc["declared"]
            for member in path[:-1]:
                target = target[member]
            target[path[-1]] = value
            with self.subTest(path=path):
                with self.assertRaisesRegex(ca.ManifestError, token):
                    ca.encode_inspect_v0(doc)

    def test_declaration_refusal_precedes_binding(self):
        raw = json.dumps({"schema": ca.SCHEMA, "vectors": "missing", "implementation":
                          "missing", "mutants": {}}).encode()
        with mock.patch.object(ca, "bind_manifest_files",
                               side_effect=AssertionError("binder reached")):
            with self.assertRaisesRegex(ca.ManifestError, "declares no mutants"):
                ca.load_manifest_bytes(raw, Path("missing/manifest.json"))
        with self.assertRaisesRegex(ca.ManifestError, "declares no mutants"):
            ca.inspect_manifest_declaration(raw)

    def test_inspection_reaches_no_runtime_or_filesystem_boundary(self):
        raw = fixture("manifest.v1.json")

        def reached(*args, **kwargs):
            raise AssertionError("effect boundary reached")

        patches = (
            mock.patch.object(ca, "_git_bytes", side_effect=reached),
            mock.patch.object(ca.subprocess, "run", side_effect=reached),
            mock.patch.object(ca, "_run_capped", side_effect=reached),
            mock.patch.object(ca, "IsolatedMutationTree", side_effect=reached),
            mock.patch.object(ca, "_resolved_contained_source", side_effect=reached),
            mock.patch.object(ca, "load_vector_document", side_effect=reached),
            mock.patch.object(ca, "_TreeLock", side_effect=reached),
            mock.patch.object(Path, "resolve", side_effect=reached),
            mock.patch.object(Path, "is_file", side_effect=reached),
            mock.patch.object(Path, "read_bytes", side_effect=reached),
        )
        with contextlib.ExitStack() as stack:
            for patcher in patches:
                stack.enter_context(patcher)
            doc = ca.inspect_manifest_declaration(raw)
        self.assertFalse(doc["execution_authorized"])

    def test_known_hole_path_is_declared_but_never_read(self):
        manifest = json.loads(fixture("manifest.v0.json"))
        manifest["corpus_digest_file"] = "digest.json"
        manifest["corpus_digest_key"] = "sha256"
        manifest["known_holes"] = {
            "sha256:declared": [{"label": "remove demo guard", "reason": "known",
                                  "recorded": "2026-09-14"}]}
        raw = json.dumps(manifest).encode()
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("digest read")):
            doc = ca.inspect_manifest_declaration(raw)
        self.assertIn("corpus-digest-file", doc["runtime_unchecked"])
        self.assertEqual(doc["declared"]["corpus_digest_file"], {
            "status": "declared", "value": "digest.json"})
        self.assertEqual(ca.parse_manifest_declaration(raw)["corpus_digest_file"], "digest.json")

    def test_closed_encoder_rejects_missing_runtime_marker_and_authorization(self):
        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        doc["runtime_unchecked"].remove("baseline")
        with self.assertRaisesRegex(ca.ManifestError, "closed v0 vocabulary"):
            ca.encode_inspect_v0(doc)
        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        doc["execution_authorized"] = True
        with self.assertRaisesRegex(ca.ManifestError, "cannot authorize"):
            ca.encode_inspect_v0(doc)

    def test_v0_inventory_cannot_be_synthesized(self):
        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        self.assertIsNone(doc["declared"]["rule_inventory"])
        doc["declared"]["rule_inventory"] = {"rules_declared": 0}
        with self.assertRaisesRegex(ca.ManifestError, "manifest.v0 inventory must be null"):
            ca.encode_inspect_v0(doc)

    def test_duplicate_and_nonfinite_manifest_input_refuse_before_binding(self):
        for raw, token in ((b'{"schema":"corpus-adequacy.manifest.v0","schema":"x"}',
                            "duplicate JSON key"),
                           (b'{"schema":"corpus-adequacy.manifest.v0","x":NaN}',
                            "non-finite JSON number"),
                           (b'{"schema":"corpus-adequacy.manifest.v0","x":1e999}',
                            "non-finite JSON number")):
            with mock.patch.object(ca, "bind_manifest_files",
                                   side_effect=AssertionError("binder reached")):
                with self.assertRaisesRegex(ca.ManifestError, token):
                    ca.load_manifest_bytes(raw, Path("manifest.json"))
            with self.assertRaisesRegex(ca.ManifestError, token):
                ca.inspect_manifest_declaration(raw)

    def test_minimum_profile_is_checked_while_operator_profile_is_unavailable(self):
        manifest = json.loads(fixture("manifest.v0.json"))
        manifest["execution_profile"] = "trusted-local"
        with self.assertRaisesRegex(ca.ManifestError, "must not declare operator key"):
            ca.inspect_manifest_declaration(json.dumps(manifest).encode())
        manifest.pop("execution_profile")
        manifest["minimum_execution_profile"] = "unknown-profile"
        with self.assertRaisesRegex(ca.ManifestError, "unknown minimum_execution_profile"):
            ca.inspect_manifest_declaration(json.dumps(manifest).encode())
        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        self.assertEqual(doc["declared"]["minimum_execution_profile"], "trusted-local")
        self.assertEqual(doc["declared"]["operator_execution_profile"], {
            "status": "not-supplied-to-inspection", "value": None})

    def test_cli_reads_once_and_emits_no_measurement_result(self):
        original = ca.read_bounded_regular_file
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["corpus_adequacy.py", "--inspect", str(FIXTURES / "manifest.v0.json"),
                "--json"]
        with mock.patch.object(ca, "read_bounded_regular_file", wraps=original) as reader, \
                mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr), mock.patch.object(
                    ca, "run", side_effect=AssertionError("measurement reached")):
            self.assertEqual(ca.main(), 0)
        self.assertEqual(reader.call_count, 1)
        output = json.loads(stdout.getvalue())
        self.assertNotIn("adequate", output)
        self.assertNotIn("score", output)
        self.assertFalse(output["execution_authorized"])
        self.assertEqual(stderr.getvalue(), "")

    def test_cli_conflicts_refuse_without_measurement(self):
        for argv in (
                ["corpus_adequacy.py", "--inspect", "x", "manifest.json", "--json"],
                ["corpus_adequacy.py", "--inspect", "x", "--version", "--json"],
                ["corpus_adequacy.py", "--inspect", "x", "--manifest", "y", "--json"]):
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                    contextlib.redirect_stderr(stderr), mock.patch.object(
                        ca, "run", side_effect=AssertionError("measurement reached")):
                self.assertEqual(ca.main(), 2)
            self.assertEqual(json.loads(stdout.getvalue())["exit"], 2)
            self.assertIn("could not inspect", stderr.getvalue())

    def test_cli_refuses_missing_symlink_directory_fifo_and_oversize(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            regular = root / "manifest.json"
            regular.write_bytes(fixture("manifest.v0.json"))
            symlink = root / "link.json"
            symlink.symlink_to(regular)
            directory = root / "directory"
            directory.mkdir()
            fifo = root / "fifo"
            os.mkfifo(fifo)
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * (ca.OUTPUT_CAP_BYTES + 1))
            for path in (root / "missing", symlink, directory, fifo, oversized):
                stdout, stderr = io.StringIO(), io.StringIO()
                argv = ["corpus_adequacy.py", "--inspect", str(path), "--json"]
                with mock.patch.object(sys, "argv", argv), contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(stderr):
                    self.assertEqual(ca.main(), 2)
                self.assertEqual(json.loads(stdout.getvalue())["exit"], 2)
                self.assertIn("could not inspect", stderr.getvalue())

    def test_human_output_ends_with_nonexecution_statement(self):
        doc = ca.inspect_manifest_declaration(fixture("manifest.v0.json"))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            ca._render_inspect_v0(doc)
        self.assertTrue(stdout.getvalue().endswith(
            "Inspected only: nothing executed or authorized; every runtime_unchecked item "
            "remains unchecked.\n"))


if __name__ == "__main__":
    unittest.main()
