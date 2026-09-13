"""Owned contained-v1 contract integration tests."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MEASUREMENTS = ROOT / "measurements"
for candidate in (str(ROOT), str(MEASUREMENTS)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import aee_checker_sealed_authorize as authorize  # noqa: E402
import aee_checker_sealed_candidate as candidate  # noqa: E402
import aee_checker_sealed_execute as execute  # noqa: E402
import aee_checker_sealed_materialize as materialize  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
import owned_contained_v1 as adapter  # noqa: E402
from sealed_measurement_contract import (  # noqa: E402
    AEE_CHECKER_SEALED_CONTRACT,
    OWNED_CONTAINED_V1_CONTRACT,
)


PINS = ROOT / "measurements" / "owned-contained-v1"
FIXTURE = ROOT / "fixtures" / "contained-v1-owned"


class OwnedContainedV1ContractTests(unittest.TestCase):
    def test_owned_contract_freezes_selected_fixture_subtrees(self):
        contract = OWNED_CONTAINED_V1_CONTRACT
        self.assertEqual(
            contract.subject_subdir,
            "fixtures/contained-v1-owned/candidate",
        )
        self.assertEqual(
            contract.corpus_subdir,
            "fixtures/contained-v1-owned/corpus",
        )
        self.assertEqual(contract.inert_control_ids, ("control-inert",))

    def test_contract_rejects_unsafe_subdir_and_overlapping_ids(self):
        for field in ("subject_subdir", "corpus_subdir", "container_context_relpath"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                dataclasses.replace(OWNED_CONTAINED_V1_CONTRACT, **{field: "../outside"})
        with self.assertRaisesRegex(ValueError, "disjoint"):
            dataclasses.replace(
                OWNED_CONTAINED_V1_CONTRACT,
                inert_control_ids=(OWNED_CONTAINED_V1_CONTRACT.control_id,),
            )

    def test_owned_pins_verify_real_fixture_bytes_and_trees(self):
        pins = run.verify_phase_a_frozen(
            PINS,
            adapter=ROOT / OWNED_CONTAINED_V1_CONTRACT.adapter_relpath,
            contract=OWNED_CONTAINED_V1_CONTRACT,
        )
        got = materialize.verify_materialized(
            pins,
            FIXTURE / "candidate",
            FIXTURE / "corpus",
            contract=OWNED_CONTAINED_V1_CONTRACT,
        )
        self.assertEqual(got["corpus_id_count"], 4)
        self.assertEqual(got["subject_tree_sha256"], OWNED_CONTAINED_V1_CONTRACT.subject_tree_sha256)
        self.assertEqual(got["corpus_tree_sha256"], OWNED_CONTAINED_V1_CONTRACT.corpus_tree_sha256)

    def test_adapter_keeps_reason_in_outcome_and_detail_in_diagnostic(self):
        expected = adapter.expected_ids(FIXTURE / "corpus" / "vectors")
        doc = {
            "vectors": [
                {"id": row_id, "accepted": row_id in ("allow", "boundary"),
                 "reason": "accepted" if row_id in ("allow", "boundary") else "refused",
                 "detail": "detail-%s" % row_id}
                for row_id in expected
            ]
        }
        projected = adapter.project(doc, expected)
        self.assertIn("reason", projected["rows"]["allow"])
        self.assertNotIn("detail", projected["rows"]["allow"])
        self.assertEqual(projected["diagnostics"]["allow"], {"detail": "detail-allow"})
        changed = json.loads(json.dumps(doc))
        changed["vectors"][0]["reason"] = "different"
        self.assertNotEqual(projected["rows"], adapter.project(changed, expected)["rows"])

    def test_adapter_refuses_wrong_row_shape_and_unknown_contract(self):
        expected = ["one"]
        for row in (
            {"id": "one", "accepted": True, "reason": "ok"},
            {"id": "one", "accepted": 1, "reason": "ok", "detail": "x"},
            {"id": "one", "accepted": True, "reason": "ok", "detail": "x", "extra": 1},
        ):
            with self.assertRaises(ValueError):
                adapter.project({"vectors": [row]}, expected)
        with self.assertRaisesRegex(run.PrepareError, "sealed measurement adapter"):
            candidate.sealed_adapter_for(object())

    def test_candidate_normalizer_uses_owned_adapter_for_owned_contract(self):
        expected = adapter.expected_ids(FIXTURE / "corpus" / "vectors")
        inner = {"vectors": [
            {"id": row_id, "accepted": True, "reason": "accepted", "detail": "ok"}
            for row_id in expected
        ]}
        completed = candidate.normalize_inner_event(
            returncode=0,
            stdout=json.dumps(inner, sort_keys=True, separators=(",", ":")) + "\n",
            vectors=FIXTURE / "corpus" / "vectors",
            contract=OWNED_CONTAINED_V1_CONTRACT,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(completed.stdout)["rows"]["allow"]["reason"], "accepted")

    def test_candidate_result_forwards_owned_contract_to_normalizer(self):
        expected = adapter.expected_ids(FIXTURE / "corpus" / "vectors")
        inner = {"vectors": [
            {"id": row_id, "accepted": True, "reason": "accepted", "detail": "ok"}
            for row_id in expected
        ]}
        raw = {
            "state": "completed",
            "oom_killed": False,
            "process": subprocess.CompletedProcess(
                [], 0, json.dumps(inner, sort_keys=True, separators=(",", ":")) + "\n", ""),
        }
        completed = candidate.candidate_result(
            raw,
            mounts={"input": FIXTURE / "corpus"},
            contract=OWNED_CONTAINED_V1_CONTRACT,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("reason", json.loads(completed.stdout)["rows"]["allow"])

    def test_authorized_order_is_baseline_positive_inert_then_mutants(self):
        steps = authorize.authorized_step_spec(contract=OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(
            [(row["id"], row["kind"]) for row in steps],
            [("baseline", "baseline"), ("control-positive", "must-die"),
             ("control-inert", "must-stay"), ("negative-guard", "mutant"),
             ("upper-guard", "mutant")],
        )
        manifest = json.loads((PINS / "manifest.json").read_text())
        sites = json.loads((PINS / "sites.json").read_text())
        control = json.loads((PINS / "control.json").read_text())
        self.assertEqual(
            authorize.required_sequence(sites, contract=OWNED_CONTAINED_V1_CONTRACT),
            steps,
        )
        self.assertEqual(
            execute.bind_authorized_mutation_order(
                manifest=manifest, sites=sites, control=control, steps=steps,
                contract=OWNED_CONTAINED_V1_CONTRACT),
            tuple(row["label"] for row in manifest["mutants"]["owned"]),
        )
        manifest["mutants"]["owned"][1].pop("control_polarity")
        with self.assertRaisesRegex(execute.ExecuteError, "inert control"):
            execute.bind_authorized_mutation_order(
                manifest=manifest, sites=sites, control=control, steps=steps,
                contract=OWNED_CONTAINED_V1_CONTRACT)

    def test_selected_archive_extracts_exact_component_subtree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, raw in (
                    ("repo/fixtures/contained-v1-owned/candidate/src/check.rs", b"owned"),
                    ("repo/fixtures/contained-v1-owned/candidate-other/no.txt", b"other"),
                    ("repo/unselected.txt", b"outside"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(raw)
                    tar.addfile(info, io.BytesIO(raw))
            dest = root / "dest"
            materialize.extract_pinned_archive(
                archive, dest,
                selected_subdir="fixtures/contained-v1-owned/candidate")
            self.assertEqual((dest / "src/check.rs").read_bytes(), b"owned")
            self.assertEqual(
                sorted(str(path.relative_to(dest)) for path in dest.rglob("*") if path.is_file()),
                ["src/check.rs"],
            )

    def test_selected_archive_charges_unselected_members_before_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                raw = b"outside"
                info = tarfile.TarInfo("repo/unselected.bin")
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            ceilings = dict(materialize.MATERIALIZE_CEILINGS)
            ceilings["disk_bytes"] = len(raw) - 1
            budget = materialize.MaterializeBudget(ceilings)
            with self.assertRaisesRegex(materialize.PrepareError, "byte ceiling"):
                materialize.extract_pinned_archive(
                    archive, root / "dest", budget=budget,
                    selected_subdir="fixtures/contained-v1-owned/candidate")

    def test_selected_archive_charges_unselected_headers_against_entry_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for index in range(4):
                    info = tarfile.TarInfo("repo/unselected-%d" % index)
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
            ceilings = dict(materialize.MATERIALIZE_CEILINGS)
            ceilings["entry_count"] = 3
            budget = materialize.MaterializeBudget(ceilings)
            with self.assertRaisesRegex(materialize.PrepareError, "entry ceiling"):
                materialize.extract_pinned_archive(
                    archive, root / "dest", budget=budget,
                    selected_subdir="fixtures/contained-v1-owned/candidate")

    def test_materializer_forwards_both_contract_subtrees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dest = root / "materialized"
            dest.mkdir()
            template = root / "config.toml"
            template.write_text("directory = \"../vendor\"\n")

            def extract(_archive, target, **_kwargs):
                Path(target).mkdir()
                return Path(target)

            with mock.patch.object(materialize, "download_bounded", return_value=root / "a.tar"), \
                    mock.patch.object(materialize, "extract_pinned_archive", side_effect=extract) as extraction, \
                    mock.patch.object(materialize.shutil, "rmtree"), \
                    mock.patch.object(materialize, "verify_materialized", return_value={}), \
                    mock.patch.object(materialize, "pull_rust_image", return_value={"image_id": "sha256:" + "1" * 64}), \
                    mock.patch.object(materialize, "vendor_locked", return_value={"toolchain": {}, "vendor_sha256": "2" * 64}), \
                    mock.patch.object(materialize, "bind_vendor_config", return_value="3" * 64):
                materialize.materialize_pinned(
                    {"subject": {"repository": "r", "commit": "c"},
                     "corpus": {"repository": "r", "commit": "c"}},
                    dest, template=template, contract=OWNED_CONTAINED_V1_CONTRACT)

            self.assertEqual(
                [call.kwargs["selected_subdir"] for call in extraction.call_args_list],
                [OWNED_CONTAINED_V1_CONTRACT.subject_subdir,
                 OWNED_CONTAINED_V1_CONTRACT.corpus_subdir],
            )

    def test_legacy_aee_inputs_and_workflows_remain_byte_identical(self):
        expected = {
            "adapters/aee_checker_sealed.py": "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769",
            "measurements/aee-checker-25b9dfa/control.json": "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71",
            "measurements/aee-checker-25b9dfa/manifest.json": "d21f4831c48a633009cafb0672c2d4e986bffda21a2c82508c1b32486d414eee",
            "measurements/aee-checker-25b9dfa/pins.json": "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4",
            "measurements/aee-checker-25b9dfa/sites.json": "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c",
            "measurements/aee-go-run/README.md": "524263d21593b770b6c0313e9ab36a57fe7c0f1d541d56509cbfe7fe6eac12d3",
            "measurements/aee-go-run/authorize.v0.json": "72326c68c57bdc591e445d9b1afbfcda6bd671d831a0faefc561dffde2fa7195",
            "measurements/aee-go-run/prepare.v0.json": "90674e74097d93d84e6794b4c6b3294ce702949f41af2e582807c3910ccf4c79",
            ".github/workflows/contained-hosted-prepare.yml": "b069c7f94ad52c5e38b4706f51ab817bca791b0012e91c20493784e49fcd4c45",
            ".github/workflows/contained-hosted-publication.yml": "9131258a39a6639c6be1a6b74e89853c18339b802b1c68484eb211a3f41addfa",
        }
        for rel, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), digest, rel)
        self.assertIsNone(AEE_CHECKER_SEALED_CONTRACT.subject_subdir)
        self.assertEqual(AEE_CHECKER_SEALED_CONTRACT.inert_control_ids, ())


if __name__ == "__main__":
    unittest.main()
