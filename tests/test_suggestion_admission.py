#!/usr/bin/env python3
"""Deterministic admission harness, non-execution gates (#200). No model, no candidate run."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import suggestion_admission as sa  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "suggestion-v0"
FROZEN = ROOT / "fixtures" / "contained-v1-owned" / "corpus" / "vectors"


def _good() -> dict:
    return json.loads((FIXTURES / "good.json").read_text(encoding="utf-8"))


def _review(**over):
    doc = {"schema": sa.REVIEW_SCHEMA, "proposal_id": "human-above-max-by-two",
           "reviewer": "fixture-reviewer", "decision": "accept", "minutes": 7}
    doc.update(over)
    return doc


def _write(tmp: Path, doc: dict, name="p.json") -> Path:
    path = tmp / name
    path.write_bytes((json.dumps(doc, indent=2, sort_keys=True) + "\n").encode())
    return path


class ProposalShape(unittest.TestCase):
    def test_fixtures(self):
        for name in ("good.json", "model-good.json"):
            with self.subTest(name=name):
                sa.load_proposal(FIXTURES / name)
        with self.assertRaises(sa.AdmissionError) as ctx:
            sa.load_proposal(FIXTURES / "detail-pinned.json")
        self.assertEqual(str(ctx.exception), "proposal-expects-diagnostic")

    def test_refusals(self):
        def mutate(fn):
            doc = _good()
            fn(doc)
            return doc

        cases = (
            (lambda d: d.update(extra=1), "proposal-shape"),
            (lambda d: d.update(schema="other"), "proposal-shape"),
            (lambda d: d.update(proposal_id="Upper Case"), "proposal-shape"),
            (lambda d: d.update(selection="owned-contained-v1"), "proposal-selection"),
            (lambda d: d["target"].update(mutation_id="upper-guard"), "proposal-target"),
            (lambda d: d["vector"].update(file="other.json"), "proposal-shape"),
            (lambda d: d["vector"].update(file="../escape.json", id="escape"), "proposal-shape"),
            (lambda d: d["vector"].update(id="../x", file="../x.json"), "proposal-shape"),
            (lambda d: d["vector"]["document"].update(value=2 ** 63), "proposal-shape"),
            (lambda d: d["vector"]["document"].update(value=True), "proposal-shape"),
            (lambda d: d["vector"]["document"].update(extra=1), "proposal-shape"),
            (lambda d: d["expected"].update(accepted="false"), "proposal-shape"),
            (lambda d: d["expected"].pop("reason"), "proposal-shape"),
            (lambda d: d["expected"].update(diagnostics={}), "proposal-shape"),
            (lambda d: d["authorship"].update(author_kind="agent"), "proposal-authorship"),
            (lambda d: d["authorship"].update(model_id="x"), "proposal-authorship"),
            (lambda d: d["authorship"].update(source_pin="HEAD"), "proposal-authorship"),
            (lambda d: d["authorship"].update(author="a\nb"), "proposal-authorship"),
            (lambda d: d.update(is_equivalent=True), "model-equivalence-claim"),
            (lambda d: d["expected"].update(Equivalence="same"), "model-equivalence-claim"),
        )
        for fn, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaises(sa.AdmissionError) as ctx:
                    sa.require_proposal(mutate(fn))
                self.assertEqual(str(ctx.exception), reason)

    def test_model_authorship_needs_all_three_fields(self):
        doc = json.loads((FIXTURES / "model-good.json").read_text())
        for field, value in (("model_id", None), ("prompt_sha256", "a" * 64),
                             ("input_sha256", None)):
            bad = copy.deepcopy(doc)
            bad["authorship"][field] = value
            with self.subTest(field=field), self.assertRaises(sa.AdmissionError):
                sa.require_proposal(bad)

    def test_bytes_are_bounded_and_must_be_json(self):
        with tempfile.TemporaryDirectory() as raw:
            big = Path(raw) / "big.json"
            big.write_bytes(b"{" + b" " * sa.MAX_PROPOSAL_BYTES + b"}")
            bad = Path(raw) / "bad.json"
            bad.write_bytes(b"not json")
            for path in (big, bad):
                with self.subTest(path=path.name), self.assertRaises(sa.AdmissionError) as ctx:
                    sa.load_proposal(path)
                self.assertEqual(str(ctx.exception), "proposal-shape")


class Freeze(unittest.TestCase):
    def _root_copy(self, tmp: Path) -> Path:
        root = tmp / "root"
        bundle = json.loads((ROOT / "measurements/owned-independent-v0/mutation-bundle.json")
                            .read_text())
        for relpath in list(bundle["candidate_freeze"]["sha256"]) + [
                "measurements/owned-independent-v0/mutation-bundle.json"]:
            (root / relpath).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relpath, root / relpath)
        return root

    def test_the_checkout_matches_the_freeze(self):
        self.assertEqual(sa.check_freeze(_good())["frozen_files"], 7)

    def test_a_changed_frozen_file_refuses_by_name(self):
        with tempfile.TemporaryDirectory() as raw:
            root = self._root_copy(Path(raw))
            target = root / "fixtures/contained-v1-owned/candidate/src/check.rs"
            target.write_bytes(target.read_bytes() + b"\n")
            with self.assertRaises(sa.AdmissionError) as ctx:
                sa.check_freeze(_good(), root=root)
            self.assertEqual(str(ctx.exception),
                             "freeze-drift:fixtures/contained-v1-owned/candidate/src/check.rs")


class CorpusSeparation(unittest.TestCase):
    def test_proposal_corpus_is_separate_and_digest_consistent(self):
        before = sorted((p.name, p.read_bytes()) for p in FROZEN.iterdir())
        with tempfile.TemporaryDirectory() as raw:
            dest = Path(raw) / "proposal-corpus"
            result = sa.build_proposal_corpus(_good(), dest)
            manifest = json.loads((dest / "MANIFEST.json").read_text())
            self.assertEqual([row["id"] for row in manifest["vectors"]],
                             ["allow", "boundary", "negative", "over-limit", "above-max-by-two"])
            self.assertEqual(json.loads((dest / "above-max-by-two.json").read_text()),
                             {"value": 12})
            digest = hashlib.sha256()
            for row in manifest["vectors"]:
                digest.update(row["file"].encode() + b"\0" + (dest / row["file"]).read_bytes())
            self.assertEqual(manifest["corpusDigest"], digest.hexdigest())
            self.assertEqual(result["proposal_corpus_digest"], manifest["corpusDigest"])
            self.assertEqual(result["vectors"], 5)
            with self.assertRaises(sa.AdmissionError) as ctx:
                sa.build_proposal_corpus(_good(), dest)
            self.assertEqual(str(ctx.exception), "proposal-corpus-exists")
        self.assertEqual(sorted((p.name, p.read_bytes()) for p in FROZEN.iterdir()), before)

    def test_a_proposal_reusing_a_frozen_id_or_file_refuses(self):
        duplicate = json.loads((FIXTURES / "duplicate-id.json").read_text())
        for doc in (duplicate,
                    dict(_good(), vector=dict(_good()["vector"], id="manifest",
                                              file="manifest.json"))):
            with self.subTest(vector=doc["vector"]["id"]), tempfile.TemporaryDirectory() as raw:
                with self.assertRaises(sa.AdmissionError) as ctx:
                    sa.build_proposal_corpus(doc, Path(raw) / "c")
                self.assertEqual(str(ctx.exception), "duplicate-vector-id")
                self.assertFalse((Path(raw) / "c").exists())

    def test_a_frozen_tree_that_changes_during_the_build_refuses(self):
        real = sa.tree_sha256
        calls = []

        def drifting(path, **kwargs):
            calls.append(path)
            return real(path, **kwargs) if len(calls) == 1 else "0" * 64

        with tempfile.TemporaryDirectory() as raw, \
                mock.patch.object(sa, "tree_sha256", side_effect=drifting):
            with self.assertRaises(sa.AdmissionError) as ctx:
                sa.build_proposal_corpus(_good(), Path(raw) / "c")
        self.assertEqual(str(ctx.exception), "frozen-corpus-touched")


class Review(unittest.TestCase):
    def test_review_rules(self):
        proposal = _good()
        sa.require_review(_review(), proposal)
        model = json.loads((FIXTURES / "model-good.json").read_text())
        for review, kwargs, reason in (
            (None, {}, "review-missing"),
            (_review(extra=1), {}, "review-shape"),
            (_review(proposal_id="other"), {}, "review-shape"),
            (_review(decision="maybe"), {}, "review-shape"),
            (_review(minutes=-1), {}, "review-shape"),
            (_review(reviewer="fixture-human"), {}, "review-by-author"),
            (_review(reviewer="packet-owner"), {"packet_author": "packet-owner"},
             "review-by-author"),
            (_review(equivalent=True), {}, "model-equivalence-claim"),
        ):
            with self.subTest(reason=reason, review=review):
                with self.assertRaises(sa.AdmissionError) as ctx:
                    sa.require_review(review, proposal, **kwargs)
                self.assertEqual(str(ctx.exception), reason)
        with self.assertRaises(sa.AdmissionError) as ctx:
            sa.require_review(_review(proposal_id="model-above-max",
                                      reviewer="vendor/model@fixture"), model)
        self.assertEqual(str(ctx.exception), "review-by-author")


class RecordAndJudge(unittest.TestCase):
    def test_a_passing_proposal_is_pending_execution_never_admitted(self):
        with tempfile.TemporaryDirectory() as raw:
            record = sa.judge(FIXTURES / "good.json", corpus_dest=Path(raw) / "c",
                              review=_review())
        self.assertEqual(record["decision"], "pending-execution")
        self.assertIsNone(record["refusal"])
        self.assertEqual([g["status"] for g in record["gates"]], [
            "passed", "passed", "passed", "not-run", "not-run", "not-run", "not-run",
            "passed", "passed"])
        raw_bytes = sa.encode_admission(record)
        self.assertTrue(raw_bytes.endswith(b"\n"))
        self.assertEqual(json.loads(raw_bytes), record)
        self.assertEqual(record["proposal_sha256"],
                         "sha256:" + hashlib.sha256((FIXTURES / "good.json").read_bytes())
                         .hexdigest())

    def test_the_first_refusal_is_named_and_later_gates_stop(self):
        with tempfile.TemporaryDirectory() as raw:
            record = sa.judge(FIXTURES / "duplicate-id.json", corpus_dest=Path(raw) / "c",
                              review=_review(proposal_id="duplicate-id"))
        self.assertEqual(record["decision"], "refused")
        self.assertEqual(record["refusal"], "duplicate-vector-id")
        gate7 = [g for g in record["gates"] if g["gate"] == 7][0]
        self.assertEqual((gate7["status"], gate7["refusal"]), ("refused", "stopped-after-refusal"))

    def test_a_missing_review_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            record = sa.judge(FIXTURES / "good.json", corpus_dest=Path(raw) / "c")
        self.assertEqual((record["decision"], record["refusal"]), ("refused", "review-missing"))

    def test_a_shape_refusal_raises_before_any_record(self):
        with tempfile.TemporaryDirectory() as raw:
            with self.assertRaises(sa.AdmissionError) as ctx:
                sa.judge(FIXTURES / "detail-pinned.json", corpus_dest=Path(raw) / "c")
            self.assertEqual(str(ctx.exception), "proposal-expects-diagnostic")
            self.assertFalse((Path(raw) / "c").exists())

    def test_the_encoder_refuses_an_execution_gate_claimed_passed(self):
        with tempfile.TemporaryDirectory() as raw:
            record = sa.judge(FIXTURES / "good.json", corpus_dest=Path(raw) / "c",
                              review=_review())
        forged = copy.deepcopy(record)
        forged["gates"][5]["status"] = "passed"
        with self.assertRaises(sa.AdmissionError):
            sa.encode_admission(forged)
        forged = copy.deepcopy(record)
        forged["decision"] = "admitted"
        with self.assertRaises(sa.AdmissionError):
            sa.encode_admission(forged)

    def test_the_record_refuses_an_unaccounted_gate(self):
        proposal = _good()
        with self.assertRaises(sa.AdmissionError) as ctx:
            sa.admission_record(b"{}", proposal, {0: ("passed", None)})
        self.assertEqual(str(ctx.exception), "accounting-gap")
        with self.assertRaises(sa.AdmissionError):
            sa.admission_record(b"{}", proposal, {n: ("refused", None)
                                                  for n in (0, 1, 2, 7, 8)})


class Accounting(unittest.TestCase):
    def test_every_proposal_reaches_one_terminal_state(self):
        result = sa.account(
            ["a", "b", "c"],
            {"a": "admitted", "b": "refused:witness-by-termination", "c": "no-improvement"},
            baseline_covers_survivor=True)
        self.assertEqual(result["counts"], {"admitted": 1, "refused": 1, "no-improvement": 1})
        for ids, states in (
            (["a", "a"], {"a": "admitted"}),
            (["a", "b"], {"a": "admitted"}),
            (["a"], {"a": "refused"}),
            (["a"], {"a": "admitted:extra"}),
            (["a"], {"a": "pending"}),
        ):
            with self.subTest(ids=ids, states=states), self.assertRaises(sa.AdmissionError):
                sa.account(ids, states, baseline_covers_survivor=False)


class Isolation(unittest.TestCase):
    def test_no_network_subprocess_or_model_client(self):
        source = Path(sa.__file__).read_text(encoding="utf-8")
        for token in ("urllib", "http.client", "socket", "subprocess", "requests",
                      "anthropic", "openai", "os.system"):
            self.assertNotIn(token, source)

    def test_the_selection_set_is_closed_and_code_owned(self):
        self.assertEqual(set(sa.SELECTIONS), {"owned-independent-v0"})
        import sealed_measurement_contract as smc
        contract = getattr(smc, "OWNED_INDEPENDENT_V0_CONTRACT", None)
        if contract is not None:
            selection = sa.SELECTIONS["owned-independent-v0"]
            self.assertEqual(selection["group"], contract.mutation_group)
            self.assertEqual((selection["mutation_id"],), contract.site_ids)


if __name__ == "__main__":
    unittest.main()
