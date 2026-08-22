#!/usr/bin/env python3
"""Contract for the pinned AlgoVoi jcs_edge_v1 adapter. Standard library only.

The load-bearing test is the mechanism boundary, not output equality. On this
pinned file a whole-document `json.loads` then `json.dumps(ensure_ascii=True,
indent=2)` plus LF is byte-identical to the source, so source digest plus
emitted-byte equality does not by itself prove the adapter sliced `preimage`
structurally. `test_whole_document_round_trip_is_byte_identical` pins that
trap, and the raw-slice tests pin the mechanism independently.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "adapters"))
import corpus_adequacy as ca  # noqa: E402
import algovoi_jcs_edge as adapter  # noqa: E402

ADAPTER = REPO_ROOT / "adapters" / "algovoi_jcs_edge.py"
FIXTURE_DIR = REPO_ROOT / "fixtures" / "algovoi-jcs-edge-aa53149c"
ANCHOR = FIXTURE_DIR / "jcs_edge_v1.json"

FLOAT_ID = "jcs-edge-005-number-one-float"
INT_ID = "jcs-edge-006-number-one-int"

# The exact source slices, with the source's own indentation, plus one LF.
FLOAT_CASE_BYTES = b'{\n        "n": 1.0\n      }\n'
INT_CASE_BYTES = b'{\n        "n": 1\n      }\n'

SYNTHETIC_IMPL = '''\
import hashlib, json, sys
raw = open(sys.argv[1], "rb").read()
text = raw.decode("utf-8")
start = text.index(":") + 1
lexeme = text[start:text.index("\\n", start)].strip()
print(json.dumps({
    "raw_sha256": hashlib.sha256(raw).hexdigest(),
    "lexeme": lexeme,
}))
'''


ALLOWED_IMPORTS = frozenset({
    "__future__", "argparse", "hashlib", "json", "os", "shutil", "stat",
    "sys", "tempfile", "pathlib", "corpus_adequacy", "isolated_tree",
})


def adapter_imported_module_names(source_text: str | None = None) -> set[str]:
    """Every module name the adapter imports, by AST rather than substring.

    A substring check misses `from runner_python import run`; the AST does
    not. Dynamic import is refused separately, since no static walk can name
    a module chosen at runtime.
    """
    if source_text is None:
        source_text = ADAPTER.read_text(encoding="utf-8")
    names: set[str] = set()
    for node in ast.walk(ast.parse(source_text)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                names.add("." * node.level + (node.module or ""))
            elif node.module:
                names.add(node.module.split(".")[0])
    return names


def _adapt_to_temp(tmp: Path) -> Path:
    dest = tmp / "adapted"
    adapter.adapt(ANCHOR, dest)
    return dest


def _process_manifest(repo: Path, mutants: dict, outcome_from: list) -> Path:
    raw = {
        "schema": ca.SCHEMA,
        "runner": "process",
        "repo_root": ".",
        "implementation": "impl.py",
        "implementation_sources": ["impl.py"],
        "build": [],
        "entrypoint_command": [sys.executable, "impl.py", "{vector}"],
        "outcome_from": outcome_from,
        "vectors": "vectors.json",
        "id_key": "vector_id",
        "vector_path_key": "vector_path",
        "default_group": "algovoi",
        "mutants": mutants,
    }
    digest = hashlib.sha256(json.dumps(outcome_from).encode()).hexdigest()[:8]
    path = repo / ("m-%s.json" % digest)
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


class MechanismBoundary(unittest.TestCase):
    """Why emitted-byte equality alone cannot prove structural slicing."""

    def test_whole_document_round_trip_is_byte_identical(self):
        raw = ANCHOR.read_bytes()
        parsed = json.loads(raw.decode("utf-8"))
        rendered = (json.dumps(parsed, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
        self.assertEqual(
            rendered, raw,
            "the trap this suite exists for has changed; re-derive the RED")

    def test_raw_slices_preserve_the_two_numeric_lexemes(self):
        slices = adapter.raw_preimage_slices(ANCHOR.read_bytes())
        self.assertEqual(len(slices), adapter.PIN_VECTOR_COUNT)
        self.assertIn(b'"n": 1.0', slices[4])
        self.assertIn(b'"n": 1\n', slices[5])
        self.assertNotEqual(slices[4], slices[5])

    def test_emitted_case_bytes_are_the_exact_source_slices(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            self.assertEqual(
                (dest / "cases" / (FLOAT_ID + ".json")).read_bytes(),
                FLOAT_CASE_BYTES)
            self.assertEqual(
                (dest / "cases" / (INT_ID + ".json")).read_bytes(),
                INT_CASE_BYTES)

    def test_per_preimage_parse_and_reserialize_fails_this_contract(self):
        """MUTATION 2: re-serializing each preimage must turn this suite RED."""
        def reserializing(raw: bytes) -> list[bytes]:
            document = json.loads(raw.decode("utf-8"))
            return [json.dumps(v["preimage"], ensure_ascii=True, indent=2).encode("utf-8")
                    for v in document["vectors"]]

        with mock.patch.object(adapter, "raw_preimage_slices", reserializing):
            with tempfile.TemporaryDirectory() as d:
                dest = _adapt_to_temp(Path(d))
                emitted = (dest / "cases" / (FLOAT_ID + ".json")).read_bytes()
                self.assertNotEqual(
                    emitted, FLOAT_CASE_BYTES,
                    "a re-serializing scanner must not satisfy the byte contract")


class PinAndProvenance(unittest.TestCase):
    def test_vendored_anchor_matches_the_declared_digest_and_size(self):
        raw = ANCHOR.read_bytes()
        self.assertEqual(len(raw), adapter.PIN_SIZE_BYTES)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), LITERAL_ANCHOR_SHA256)

    def test_mutation_1_a_different_digest_is_refused(self):
        """The forgery is otherwise valid, so only the digest gate can catch it."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            raw = ANCHOR.read_bytes()
            drifted = tmp / "drifted.json"
            # One description byte. Same length, same structure, same vector
            # count, same labels: every gate except the digest still passes.
            forged_bytes = raw.replace(b"1.0 canonicalises", b"1,0 canonicalises", 1)
            self.assertNotEqual(forged_bytes, raw)
            self.assertEqual(len(forged_bytes), len(raw))
            drifted.write_bytes(forged_bytes)
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(drifted, tmp / "out")
            self.assertIn("does not match the pin", str(caught.exception))
            self.assertIn("digest", str(caught.exception))

    def test_mutation_1_a_different_canon_version_is_refused(self):
        """Pin the forged digest so the canon-version gate is the one under test."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["canon_version"] = "jcs-rfc8785-v2"
            forged_bytes = (json.dumps(document, ensure_ascii=True, indent=2)
                            + "\n").encode("utf-8")
            forged = tmp / "forged.json"
            forged.write_bytes(forged_bytes)
            with _producer(anchor_sha256=hashlib.sha256(forged_bytes).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(forged_bytes)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(forged, tmp / "out")
            self.assertIn("canon_version", str(caught.exception))

    def test_source_json_records_pin_licence_and_labels(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
            self.assertEqual(source["repository"], adapter.PIN_REPOSITORY)
            self.assertEqual(source["commit"], adapter.PIN_COMMIT)
            self.assertEqual(source["anchor_sha256"], LITERAL_ANCHOR_SHA256)
            self.assertEqual(source["manifest_version"], adapter.PIN_MANIFEST_VERSION)
            self.assertEqual(source["license"], "Apache-2.0")
            self.assertEqual(source["authored_sections"],
                             ["3.2.2.2", "3.2.2.3", "3.2.3", "3.2.4"])
            self.assertTrue(source["non_claims"])

    def test_upstream_licence_and_notice_are_retained(self):
        self.assertTrue((FIXTURE_DIR / "LICENSE").is_file())
        notice = (FIXTURE_DIR / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("AlgoVoi", notice)
        source_text = ADAPTER.read_text(encoding="utf-8")
        self.assertIn("Apache-2.0", source_text)


class VectorAccounting(unittest.TestCase):
    def test_ten_vectors_are_emitted_with_authored_sections(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            rows = json.loads((dest / "vectors.json").read_text(encoding="utf-8"))["vectors"]
            self.assertEqual(len(rows), 10)
            for row in rows:
                self.assertEqual(sorted(row),
                                 ["authored_section", "vector_id", "vector_path"])
                self.assertTrue((dest / row["vector_path"]).is_file())

    def test_mutation_3_a_dropped_vector_is_refused(self):
        """Pin the forged digest so the vector-count gate is the one under test."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["vectors"].pop()
            forged_bytes = (json.dumps(document, ensure_ascii=True, indent=2)
                            + "\n").encode("utf-8")
            short = tmp / "short.json"
            short.write_bytes(forged_bytes)
            with _producer(anchor_sha256=hashlib.sha256(forged_bytes).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(forged_bytes)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(short, tmp / "out")
            self.assertIn("expected 10 vectors", str(caught.exception))
            self.assertIn("found 9", str(caught.exception))

    def test_mutation_3_a_duplicate_vector_id_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        document["vectors"][1]["vector_id"] = document["vectors"][0]["vector_id"]
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._vector_rows(document)
        self.assertIn("duplicate vector_id", str(caught.exception))

    def test_a_traversing_vector_id_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        document["vectors"][0]["vector_id"] = "../escape"
        with self.assertRaises(adapter.AdapterError):
            adapter._vector_rows(document)

    def test_a_slice_count_mismatch_refuses_rather_than_guesses(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            with mock.patch.object(adapter, "raw_preimage_slices",
                                   lambda raw: [b"{}"] * 9):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertIn("refusing to guess", str(caught.exception))


class InvariantDisposition(unittest.TestCase):
    def _disposition(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
            return source["pair_invariants"]

    def test_exactly_two_invariants_are_accounted_for(self):
        self.assertEqual(len(self._disposition()), adapter.PIN_INVARIANT_COUNT)

    def test_mutation_5_the_unknown_relation_is_typed_refused_not_skipped(self):
        entries = self._disposition()
        refused = [e for e in entries if e["disposition"] == "refused"]
        self.assertEqual(len(refused), 1)
        self.assertEqual(refused[0]["relation"], "emoji_key_precedes_ffff")
        self.assertEqual(refused[0]["reason"], adapter.REFUSAL_REASON)
        self.assertNotIn("skipped", {e["disposition"] for e in entries})
        self.assertNotIn("passed", {e["disposition"] for e in entries})

    def test_mutation_6_equal_sha256_is_really_evaluated(self):
        entries = self._disposition()
        projected = [e for e in entries if e["disposition"] == "projected"]
        self.assertEqual(len(projected), 1)
        self.assertEqual(projected[0]["relation"], "equal_sha256")
        self.assertEqual(sorted(projected[0]["vectors"]), sorted([FLOAT_ID, INT_ID]))
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        declared = {v["vector_id"]: v["expected_sha256"] for v in document["vectors"]}
        self.assertEqual(projected[0]["declared_sha256"], declared[FLOAT_ID])

    def test_a_false_declared_equal_sha256_is_a_hard_error(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        by_id[INT_ID]["expected_sha256"] = "0" * 64
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("declared digests differ", str(caught.exception))

    def test_mutation_4_ignoring_invariants_changes_the_accounted_total(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"] = []
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("expected 2 pair invariants", str(caught.exception))

    def test_an_invariant_naming_a_missing_vector_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][0]["a"] = "jcs-edge-999-absent"
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("unknown vector", str(caught.exception))

    def test_a_duplicate_invariant_name_is_refused(self):
        """#28 names duplicate invariant names as a hard error."""
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][1]["name"] = document["pair_invariants"][0]["name"]
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("duplicate invariant name", str(caught.exception))

    def test_an_unknown_invariant_field_is_refused(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][0]["extra"] = True
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("unknown fields", str(caught.exception))


class HostileInput(unittest.TestCase):
    def test_mutation_9_a_symlinked_source_is_refused(self):
        if not hasattr(os, "symlink"):
            self.skipTest("no symlink support on this platform")
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            link = tmp / "link.json"
            try:
                os.symlink(ANCHOR, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not permitted here")
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(link, tmp / "out")
            self.assertIn("regular file", str(caught.exception))

    def test_the_source_cap_is_a_literal_contract(self):
        """Pinned independently of the constant. A probe sized from
        SOURCE_CAP_BYTES rises with the mutation and can never report it."""
        self.assertEqual(adapter.SOURCE_CAP_BYTES, 1 << 20)

    def test_mutation_9_an_oversized_source_is_refused_before_materialization(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            big = tmp / "big.json"
            big.write_bytes(b"{}" + b" " * ((1 << 20) + 1))
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(big, tmp / "out")
            self.assertIn("cap", str(caught.exception))
            self.assertFalse((tmp / "out").exists())

    def test_duplicate_metadata_keys_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            forged = tmp / "dup.json"
            forged.write_bytes(b'{"name": "jcs_edge_v1", "name": "other"}')
            with self.assertRaises(adapter.AdapterError):
                adapter.adapt(forged, tmp / "out")

    def test_non_finite_constants_are_refused(self):
        """Both classes: the named tokens and exponent overflow."""
        for raw in (b'{"name": "jcs_edge_v1", "vectors": [NaN]}',
                    b'{"name": "jcs_edge_v1", "vectors": [Infinity]}',
                    b'{"name": "jcs_edge_v1", "vectors": [1e999]}',
                    b'{"name": "jcs_edge_v1", "vectors": [[{"a": -1e999}]]}'):
            with self.subTest(raw=raw):
                with self.assertRaises(adapter.AdapterError):
                    adapter._parse_strict(raw)

    def test_malformed_utf8_is_refused(self):
        with self.assertRaises(adapter.AdapterError):
            adapter.raw_preimage_slices(b'{"preimage": "\xff\xfe"}')

    def test_an_unknown_document_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            document = json.loads(ANCHOR.read_text(encoding="utf-8"))
            document["surprise"] = 1
            forged = tmp / "forged.json"
            forged.write_bytes(json.dumps(document).encode("utf-8"))
            with self.assertRaises(adapter.AdapterError):
                adapter.adapt(forged, tmp / "out")

    def test_a_non_empty_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            dest.mkdir()
            (dest / "occupied").write_text("x", encoding="utf-8")
            with self.assertRaises(adapter.AdapterError) as caught:
                adapter.adapt(ANCHOR, dest)
            self.assertIn("not empty", str(caught.exception))

    def test_mutation_10_a_failure_leaves_no_consumable_partial_output(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            dest = tmp / "out"
            real = adapter._encode

            def explode(doc):
                if doc.get("schema") == adapter.SOURCE_SCHEMA:
                    raise adapter.AdapterError("injected failure after cases")
                return real(doc)

            with mock.patch.object(adapter, "_encode", explode):
                with self.assertRaises(adapter.AdapterError):
                    adapter.adapt(ANCHOR, dest)
            self.assertFalse(dest.exists(), "destination must not exist after failure")
            leftovers = [p for p in tmp.iterdir() if p.name.startswith("algovoi-adapt-")]
            self.assertEqual(leftovers, [], "temp directory must be removed")

    def test_cli_failure_exits_2_not_1(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            result = subprocess.run(
                [sys.executable, str(ADAPTER), str(tmp / "missing"), str(tmp / "out")],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


class NoUpstreamImport(unittest.TestCase):
    def test_mutation_7_the_adapter_imports_no_upstream_runner(self):
        source = ADAPTER.read_text(encoding="utf-8")
        for forbidden in ("import rfc8785", "from rfc8785", "import generate",
                          "from generate", "upstream_runner"):
            self.assertNotIn(forbidden, source)

    def test_the_adapter_does_not_reimplement_canonicalization(self):
        source = ADAPTER.read_text(encoding="utf-8")
        self.assertNotIn("def canonical", source)
        self.assertNotIn("utf16", source.lower().replace("utf-16", "utf16")
                         .replace("utf16 code-unit", ""))


@unittest.skipIf(ca.fcntl is None,
                 "process scoring requires an advisory lock; see the portability note")
class EndToEnd(unittest.TestCase):
    """The real `corpus_adequacy.run()` over the adapted corpus."""

    def _prepare(self, tmp: Path) -> Path:
        dest = _adapt_to_temp(tmp)
        repo = tmp / "impl"
        repo.mkdir()
        (repo / "impl.py").write_text(SYNTHETIC_IMPL, encoding="utf-8")
        shutil.copytree(dest / "cases", repo / "cases")
        shutil.copy(dest / "vectors.json", repo / "vectors.json")
        return repo

    def test_numeric_round_trip_mutant_is_killed_by_the_lexeme_vector(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._prepare(Path(d))
            mutants = {
                "algovoi": [
                    {
                        "label": "normalize the preimage through a JSON round trip",
                        "anchor": 'raw = open(sys.argv[1], "rb").read()',
                        # The trailing LF is preserved deliberately. Without it
                        # the mutant crashes and is killed as unexpected-exit,
                        # which proves the process died, not that the corpus
                        # distinguished a normalized preimage.
                        "replacement": (
                            'raw = json.dumps(json.loads('
                            'open(sys.argv[1], "rb").read().decode("utf-8"))'
                            ').encode("utf-8") + b"\\n"'),
                    },
                    {
                        "label": "CONTROL blank every lexeme",
                        "control": True,
                        "anchor": 'lexeme = text[start:text.index("\\n", start)].strip()',
                        "replacement": 'lexeme = ""',
                    },
                ]
            }
            manifest = _process_manifest(repo, mutants, ["raw_sha256", "lexeme"])
            report = ca.run(manifest)
            declared = next(r for r in report["mutants"]
                            if r["label"].startswith("normalize"))
            self.assertEqual(declared["verdict"], "killed")
            # A normal parsed movement, not a crash: the corpus distinguished
            # the normalized preimage on a declared outcome.
            self.assertNotEqual(declared["how"], "unexpected-exit")
            self.assertGreater(declared["moved"], 0)
            self.assertEqual(report["control_status"], "killed")
            # The control exercises the whole corpus, so this is the assertion
            # that fails if vectors.json is ever trimmed.
            control = next(r for r in report["mutants"]
                           if r["label"].startswith("CONTROL"))
            self.assertEqual(control["moved"], 10)

    def test_trimming_the_corpus_to_two_vectors_fails_the_control(self):
        """P1-3: the e2e must reach all ten cases, not only the numeric pair."""
        with tempfile.TemporaryDirectory() as d:
            repo = self._prepare(Path(d))
            rows = json.loads((repo / "vectors.json").read_text(encoding="utf-8"))
            rows["vectors"] = [r for r in rows["vectors"]
                               if r["vector_id"] in (FLOAT_ID, INT_ID)]
            (repo / "vectors.json").write_text(json.dumps(rows), encoding="utf-8")
            mutants = {
                "algovoi": [
                    {
                        "label": "CONTROL blank every lexeme",
                        "control": True,
                        "anchor": 'lexeme = text[start:text.index("\\n", start)].strip()',
                        "replacement": 'lexeme = ""',
                    },
                ]
            }
            manifest = _process_manifest(repo, mutants, ["raw_sha256", "lexeme"])
            report = ca.run(manifest)
            control = next(r for r in report["mutants"]
                           if r["label"].startswith("CONTROL"))
            self.assertEqual(control["moved"], 2)
            self.assertNotEqual(
                control["moved"], 10,
                "a trimmed corpus must not satisfy the ten-vector assertion")

    def test_all_ten_cases_are_consumed_by_the_real_runner(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._prepare(Path(d))
            outputs = {}
            for vector_id in (FLOAT_ID, INT_ID):
                result = subprocess.run(
                    [sys.executable, "impl.py", "cases/%s.json" % vector_id],
                    cwd=repo, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs[vector_id] = json.loads(result.stdout)
            self.assertEqual(outputs[FLOAT_ID]["lexeme"], "1.0")
            self.assertEqual(outputs[INT_ID]["lexeme"], "1")
            self.assertNotEqual(outputs[FLOAT_ID]["raw_sha256"],
                                outputs[INT_ID]["raw_sha256"])

    def test_mutation_8_bypassing_the_real_run_fails_this_suite(self):
        self.assertIn("ca.run(", Path(__file__).read_text(encoding="utf-8"))
        with mock.patch.object(ca, "run",
                               side_effect=AssertionError("run must be called")):
            with self.assertRaises(AssertionError):
                self.test_numeric_round_trip_mutant_is_killed_by_the_lexeme_vector()


class Portability(unittest.TestCase):
    def test_the_end_to_end_skip_is_declared_not_silent(self):
        source = Path(__file__).read_text(encoding="utf-8")
        self.assertIn("process scoring requires an advisory lock", source)

    def test_adapter_writes_no_platform_specific_path_separator(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            rows = json.loads((dest / "vectors.json").read_text(encoding="utf-8"))["vectors"]
            for row in rows:
                self.assertNotIn("\\", row["vector_path"])
                self.assertTrue(row["vector_path"].startswith("cases/"))


if __name__ == "__main__":
    unittest.main(verbosity=1)


# ---------------------------------------------------------------------------
# Preflight hardening (PR #36 review). RED first, one shared rule per gap.
# ---------------------------------------------------------------------------

MANIFEST = FIXTURE_DIR / "manifest.json"

# Independent literals. These are asserted against the emitted document, never
# compared to the adapter's own constants, so mutating a constant turns RED.
LITERAL_REPOSITORY = "chopmob-cloud/algovoi-jcs-conformance-vectors"
LITERAL_COMMIT = "aa53149c670f1659dad511755168ad5231dc04de"
LITERAL_MANIFEST_VERSION = "0.38.0"
LITERAL_MANIFEST_SHA256 = (
    "5e7c56fe353cd5c04adfc779191903d8cf79317301cc3402285a1881f1309865")
# Independent oracle. The adapter derives this from the manifest entry; the
# test asserts it against a literal, so dropping the derivation turns RED.
LITERAL_ANCHOR_SHA256 = (
    "a8a1a1a8839553ea5309c381b39ba156e6b6a23a5a3e6aab59b53940cc386033")


def _forged_source(tmp: Path, mutate) -> Path:
    """Write a forged anchor whose size and digest are recomputed.

    Without this the pin gate rejects the forgery first and the parser,
    document, vector and invariant guards under test never run.
    """
    document = json.loads(ANCHOR.read_text(encoding="utf-8"))
    raw = mutate(document)
    if raw is None:
        raw = (json.dumps(document, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
    path = tmp / "forged.json"
    path.write_bytes(raw)
    return path


def _producer(**overrides):
    """Patch the manifest-derived producer so a forged anchor reaches the
    guard under test instead of stopping at the digest gate."""
    base = {
        "manifest_sha256": LITERAL_MANIFEST_SHA256,
        "manifest_version": LITERAL_MANIFEST_VERSION,
        "anchor_sha256": LITERAL_ANCHOR_SHA256,
        "vector_count": 10,
        "pair_invariants": 2,
    }
    base.update(overrides)
    return mock.patch.object(adapter, "_manifest_entry", lambda: base)


class ManifestBinding(unittest.TestCase):
    """P1-1: provenance must be bound to loaded bytes, not to constants."""

    def test_vendored_manifest_matches_the_measured_digest(self):
        raw = MANIFEST.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), LITERAL_MANIFEST_SHA256)

    def test_mutating_the_repository_constant_breaks_the_literal_assertion(self):
        """Repository and commit are not in the manifest, so the literal in
        this file is what carries them. This proves that assertion bites."""
        with mock.patch.object(adapter, "PIN_REPOSITORY", "attacker/elsewhere"), \
             mock.patch.object(adapter, "PIN_COMMIT", "0" * 40):
            with tempfile.TemporaryDirectory() as d:
                dest = _adapt_to_temp(Path(d))
                source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
                self.assertNotEqual(source["repository"], LITERAL_REPOSITORY)
                self.assertNotEqual(source["commit"], LITERAL_COMMIT)

    def test_manifest_version_is_derived_not_asserted(self):
        with mock.patch.object(adapter, "PIN_MANIFEST_VERSION", "9.9.9"):
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(adapter.AdapterError) as caught:
                    _adapt_to_temp(Path(d))
                self.assertIn("manifest version", str(caught.exception))

    def test_counts_and_digest_come_from_the_manifest_entry(self):
        with tempfile.TemporaryDirectory() as d:
            dest = _adapt_to_temp(Path(d))
            source = json.loads((dest / "source.json").read_text(encoding="utf-8"))
            self.assertEqual(source["repository"], LITERAL_REPOSITORY)
            self.assertEqual(source["commit"], LITERAL_COMMIT)
            self.assertEqual(source["manifest_version"], LITERAL_MANIFEST_VERSION)
            self.assertEqual(source["manifest_sha256"], LITERAL_MANIFEST_SHA256)
            self.assertEqual(source["declared_vector_count"], 10)
            self.assertEqual(source["declared_pair_invariants"], 2)

    def test_a_substituted_manifest_is_refused_by_its_own_digest(self):
        """The manifest is the root of the chain, so it is bound to its digest.
        The substitute is otherwise valid, so only the digest gate can catch it."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            manifest["published_at"] = "1999-01-01"
            forged = tmp / "manifest.json"
            forged.write_bytes(json.dumps(manifest).encode("utf-8"))
            self.assertNotEqual(hashlib.sha256(forged.read_bytes()).hexdigest(),
                                LITERAL_MANIFEST_SHA256)
            with mock.patch.object(adapter, "MANIFEST_PATH", forged):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertIn("manifest digest", str(caught.exception))

    def test_the_anchor_digest_follows_the_manifest_declaration(self):
        """One root. If the manifest declares a different anchor digest, the
        real anchor must be refused against *that* declaration. A constant
        emitted in place of the derived value cannot fail this, which is what
        makes the derivation load-bearing rather than decorative."""
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            entry = next(e for e in manifest["anchor_sets"] if e["name"] == "jcs_edge_v1")
            entry["sha256"] = "sha256:" + ("b" * 64)
            forged = tmp / "manifest.json"
            forged.write_bytes(json.dumps(manifest).encode("utf-8"))
            with mock.patch.object(adapter, "MANIFEST_PATH", forged), \
                 mock.patch.object(adapter, "PIN_MANIFEST_SHA256",
                                   hashlib.sha256(forged.read_bytes()).hexdigest()):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            message = str(caught.exception)
            self.assertIn("b" * 64, message)
            self.assertIn(LITERAL_ANCHOR_SHA256, message)

    def test_a_manifest_declaring_another_vector_count_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            entry = next(e for e in manifest["anchor_sets"] if e["name"] == "jcs_edge_v1")
            entry["vector_count"] = 9
            forged = tmp / "manifest.json"
            forged.write_bytes(json.dumps(manifest).encode("utf-8"))
            with mock.patch.object(adapter, "MANIFEST_PATH", forged), \
                 mock.patch.object(adapter, "PIN_MANIFEST_SHA256",
                                   hashlib.sha256(forged.read_bytes()).hexdigest()):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertIn("vector", str(caught.exception))

    def test_anchors_to_prose_is_not_used_as_a_section_inventory(self):
        """Naming the key in the allowlist is fine; reading its value is not."""
        source_text = ADAPTER.read_text(encoding="utf-8")
        for read in ('entry["anchors_to"]', ".get(\"anchors_to\")",
                     "['anchors_to']", ".get('anchors_to')"):
            self.assertNotIn(read, source_text)


# HELD, not landed: the P1-2 exponent-overflow walk belongs in the shared
# `_parse_projection_json`, but editing any declared runtime source moves
# `tool_content_sha256` and breaks
# `test_tersign_verifier_measurement.test_current_tool_source_matches_the_measured_report`,
# which pins the tool bytes recorded in the committed Tersign measurement.
# Landing it requires re-measuring that report, which belongs to #30, not #28.
# The tests are written and pass with the one-line walk applied; they are held
# here rather than shipped red or shipped with a silent re-measurement.


class SingleBoundedRead(unittest.TestCase):
    """P2-5: one call site, proved behaviourally rather than by text scan."""

    def test_one_bounded_call_site_with_an_explicit_cap(self):
        source_text = ADAPTER.read_text(encoding="utf-8")
        self.assertEqual(source_text.count("read_bounded_regular_file("), 1)
        self.assertIn("cap=SOURCE_CAP_BYTES", source_text)

    @unittest.skipIf(not hasattr(os, "O_NOFOLLOW"), "O_NOFOLLOW is required")
    def test_the_manifest_load_refuses_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            link = tmp / "manifest.json"
            try:
                link.symlink_to(MANIFEST)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not permitted here")
            with mock.patch.object(adapter, "MANIFEST_PATH", link):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertRegex(str(caught.exception).lower(), r"regular|symlink|follow")

    def test_the_manifest_load_refuses_an_oversized_file(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            big = tmp / "manifest.json"
            big.write_bytes(b"{}" + b" " * ((1 << 20) + 1))
            with mock.patch.object(adapter, "MANIFEST_PATH", big):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(ANCHOR, tmp / "out")
            self.assertIn("cap", str(caught.exception))

    @unittest.skipIf(not hasattr(os, "mkfifo"), "os.mkfifo is unavailable")
    def test_the_manifest_load_refuses_a_fifo(self):
        import signal

        class _Blocked(BaseException):
            """Not an OSError, so the loader cannot convert it into a refusal."""

        def alarm(_signum, _frame):
            raise _Blocked("the manifest load blocked on a FIFO")

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pipe = tmp / "manifest.json"
            os.mkfifo(pipe)
            previous = signal.signal(signal.SIGALRM, alarm)
            signal.alarm(5)
            try:
                with mock.patch.object(adapter, "MANIFEST_PATH", pipe):
                    with self.assertRaises(adapter.AdapterError):
                        adapter.adapt(ANCHOR, tmp / "out")
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)


class InvariantArity(unittest.TestCase):
    """P2-6: equal_sha256 with one reference must not leak ValueError."""

    def test_equal_sha256_with_one_reference_raises_adapter_error(self):
        document = json.loads(ANCHOR.read_text(encoding="utf-8"))
        by_id = {v["vector_id"]: v for v in document["vectors"]}
        document["pair_invariants"][1] = {
            "name": "single-ref-equal",
            "vector": FLOAT_ID,
            "relation": "equal_sha256",
            "why": "one reference is not a pair",
        }
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter._invariant_disposition(document, by_id)
        self.assertIn("exactly two", str(caught.exception))

    def test_cli_exits_2_on_a_single_reference_equal_sha256(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)

            def mutate(document):
                document["pair_invariants"][1] = {
                    "name": "single-ref-equal",
                    "vector": FLOAT_ID,
                    "relation": "equal_sha256",
                    "why": "one reference is not a pair",
                }
                return None

            forged = _forged_source(tmp, mutate)
            raw = forged.read_bytes()
            with _producer(anchor_sha256=hashlib.sha256(raw).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(raw)):
                with self.assertRaises(adapter.AdapterError):
                    adapter.adapt(forged, tmp / "out")
            result = subprocess.run(
                [sys.executable, str(ADAPTER), str(forged), str(tmp / "out2")],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


class ImportAllowlist(unittest.TestCase):
    """P2-7: AST allowlist, not substring matching."""

    def test_only_allowlisted_modules_are_imported(self):
        names = adapter_imported_module_names()
        self.assertTrue(names)
        self.assertEqual(names - ALLOWED_IMPORTS, set())

    def test_a_from_runner_python_import_would_be_caught(self):
        extra = "from runner_python import run\n"
        names = adapter_imported_module_names(
            ADAPTER.read_text(encoding="utf-8") + extra)
        self.assertIn("runner_python", names)
        self.assertNotEqual(names - ALLOWED_IMPORTS, set())

    def test_dynamic_import_is_refused(self):
        source_text = ADAPTER.read_text(encoding="utf-8")
        for dynamic in ("__import__", "importlib"):
            self.assertNotIn(dynamic, source_text)


class ForgedSourceClosure(unittest.TestCase):
    """P2-4: forged-source tests must reach the guard they name."""

    def test_duplicate_document_key_reaches_the_parser_guard(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            raw = ANCHOR.read_bytes().replace(
                b'{\n  "name": "jcs_edge_v1",',
                b'{\n  "name": "jcs_edge_v1",\n  "name": "twice",', 1)
            forged = tmp / "dup.json"
            forged.write_bytes(raw)
            with _producer(anchor_sha256=hashlib.sha256(raw).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(raw)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(forged, tmp / "out")
            self.assertIn("duplicate JSON key", str(caught.exception))

    def test_unknown_document_field_reaches_the_document_guard(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)

            def mutate(document):
                document["surprise"] = 1
                return None

            forged = _forged_source(tmp, mutate)
            raw = forged.read_bytes()
            with _producer(anchor_sha256=hashlib.sha256(raw).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(raw)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(forged, tmp / "out")
            self.assertIn("unknown fields", str(caught.exception))

    def test_unknown_vector_field_reaches_the_vector_guard(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)

            def mutate(document):
                document["vectors"][0]["surprise"] = 1
                return None

            forged = _forged_source(tmp, mutate)
            raw = forged.read_bytes()
            with _producer(anchor_sha256=hashlib.sha256(raw).hexdigest()), \
                 mock.patch.object(adapter, "PIN_SIZE_BYTES", len(raw)):
                with self.assertRaises(adapter.AdapterError) as caught:
                    adapter.adapt(forged, tmp / "out")
            self.assertIn("vectors[0]", str(caught.exception))
