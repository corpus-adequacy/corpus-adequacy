import contextlib
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
