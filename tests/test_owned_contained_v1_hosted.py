"""Closed hosted-rail contract for the repository-owned contained-v1 fixture."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
for candidate in (str(ROOT), str(ROOT / "measurements")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

import contained_hosted_publication as publication  # noqa: E402
import contained_oci  # noqa: E402
import hosted_packet  # noqa: E402
import owned_contained_v1_hosted as owned  # noqa: E402
from hosted_rail_contract import LEGACY_RAIL, OWNED_V1_RAIL  # noqa: E402
from sealed_measurement_contract import OWNED_CONTAINED_V1_CONTRACT  # noqa: E402


class OwnedHostedRailContract(unittest.TestCase):
    @staticmethod
    def report(**overrides):
        report = {
            "schema": publication.ca.REPORT_SCHEMA,
            "control_status": "killed",
            "killed": 2,
            "survived": 0,
            "silent": 0,
            "equivalent": 0,
            "unexercised_out_of_scope": 0,
            "unproved": 0,
            "known_holes": 0,
            "declared_total": 2,
            "failures": [],
            "adequate": True,
        }
        report.update(overrides)
        return report

    def test_rails_are_closed_immutable_and_namespace_disjoint(self):
        self.assertIs(OWNED_V1_RAIL.measurement, OWNED_CONTAINED_V1_CONTRACT)
        self.assertEqual(OWNED_V1_RAIL.execution_profile, "contained-oci-v1")
        self.assertEqual(OWNED_V1_RAIL.prepare_filename, "prepare.v2.json")
        for field in ("workflow_prepare", "workflow_publication", "prepare_concurrency",
                      "publication_concurrency", "packet_dirname", "packet_manifest_filename",
                      "packet_release_prefix", "artifact_prefix"):
            self.assertNotEqual(getattr(LEGACY_RAIL, field), getattr(OWNED_V1_RAIL, field), field)
        with self.assertRaisesRegex(Exception, "cannot assign"):
            OWNED_V1_RAIL.execution_profile = "contained-oci-v0"

    def test_packet_parser_uses_the_selected_closed_rail(self):
        files = {name: "a" * 64 for name in OWNED_V1_RAIL.packet_filenames}
        raw = (json.dumps({"files": files, "schema": OWNED_V1_RAIL.packet_manifest_schema},
                          sort_keys=True) + "\n").encode()
        self.assertEqual(hosted_packet.parse_manifest(raw, rail=OWNED_V1_RAIL), files)
        with self.assertRaises(hosted_packet.PacketError):
            hosted_packet.parse_manifest(raw, rail=LEGACY_RAIL)

    def test_owned_facade_has_no_free_profile_schema_or_contract(self):
        parser = owned.build_parser()
        help_text = parser.format_help()
        for forbidden in ("--operator-profile", "--schema", "--contract", "--pins-dir"):
            self.assertNotIn(forbidden, help_text)
        self.assertIs(owned.RAIL, OWNED_V1_RAIL)

    def test_prepare_facade_calls_shared_prepare_v2_without_execution(self):
        with mock.patch.object(owned.sealed_run, "prepare", return_value=b"prepare") as prepare, \
                mock.patch.object(owned.hosted_packet, "record_prepare", return_value={
                    "prepare_sha256": "a" * 64}), \
                mock.patch.object(publication, "run_gate", side_effect=AssertionError(
                    "PREPARE reached execution")):
            result = owned.prepare_owned(image_id="sha256:" + "1" * 64)
        self.assertEqual(result["prepare_sha256"], "a" * 64)
        self.assertEqual(prepare.call_args.kwargs["schema"],
                         owned.sealed_run.PREPARE_V2_SCHEMA)
        self.assertIs(prepare.call_args.kwargs["contract"],
                      OWNED_CONTAINED_V1_CONTRACT)

    def test_crossed_prepare_refuses_before_driver(self):
        raw = json.dumps({"schema": owned.sealed_run.PREPARE_V1_SCHEMA}).encode()
        with self.assertRaisesRegex(owned.sealed_run.PrepareError,
                                    "contained-oci-v1 admits only prepare.v2"):
            owned.sealed_run.load_prepare_for_profile(
                raw, execution_profile=OWNED_V1_RAIL.execution_profile,
                contract=OWNED_V1_RAIL.measurement)

    def test_owned_packet_fetch_uses_only_owned_names_and_pins(self):
        files = {name: (name + "\n").encode() for name in OWNED_V1_RAIL.packet_filenames}
        manifest = (json.dumps({
            "files": {name: hashlib.sha256(raw).hexdigest()
                      for name, raw in files.items()},
            "schema": OWNED_V1_RAIL.packet_manifest_schema,
        }, sort_keys=True) + "\n").encode()
        assets = {OWNED_V1_RAIL.packet_manifest_filename: manifest, **files}

        def fetch(url, _cap):
            return assets[url.rsplit("/", 1)[-1]]

        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            (workspace / ".git").mkdir()
            with mock.patch.object(hosted_packet, "resolve_workspace", return_value=workspace), \
                    mock.patch.object(hosted_packet, "_tracked_under", return_value=False), \
                    mock.patch.object(hosted_packet, "read_pins_source", return_value=[
                        ("pins.json", b"{}\n")]):
                result = hosted_packet.fetch_packet(
                    repository="corpus-adequacy/corpus-adequacy",
                    tag=OWNED_V1_RAIL.packet_release_prefix + "1",
                    manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                    workspace_root=workspace, dest=OWNED_V1_RAIL.packet_dirname,
                    open_url=fetch, rail=OWNED_V1_RAIL)
            self.assertEqual(set(result["files"]), set(OWNED_V1_RAIL.packet_filenames))
            self.assertTrue((workspace / OWNED_V1_RAIL.packet_dirname /
                             OWNED_V1_RAIL.packet_manifest_filename).is_file())

    def test_owned_execute_forwards_one_contract_and_profile_and_returns_report(self):
        expected = self.report()
        with mock.patch("aee_checker_sealed_driver.run_authorized", return_value=expected) as call, \
                mock.patch.object(publication.ca, "read_bounded_regular_file", return_value=b"{}"):
            result = publication.default_sealed_execute(
                authorize_path="a", prepare_path="p", pins_dir="pins", root=ROOT,
                envelope_dest="envelopes", materialize_dest="materialize",
                rail=OWNED_V1_RAIL)
        self.assertIs(result, expected)
        self.assertEqual(call.call_args.kwargs["execution_profile"], "contained-oci-v1")
        self.assertIs(call.call_args.kwargs["contract"], OWNED_CONTAINED_V1_CONTRACT)

    def test_owned_profile_reaches_final_create_argv_with_cpu_and_nofile(self):
        profile = dict(contained_oci.CANDIDATE_RESOURCE_PROFILE_V2)
        profile.update(cpu_rate_millicpu=2500, nofile_soft=512, nofile_hard=2048)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("input", "vendor", "tool"):
                (root / name).mkdir()
            argv = contained_oci.docker_create_argv(
                image_id="sha256:" + "1" * 64,
                name="owned-v1-forward-path",
                mounts={name: root / name for name in ("input", "vendor", "tool")},
                command=("/work/target/release/check",),
                resource_profile=profile)
        self.assertEqual(argv[argv.index("--cpu-period") + 1], "100000")
        self.assertEqual(argv[argv.index("--cpu-quota") + 1], "250000")
        self.assertEqual(argv[argv.index("--ulimit") + 1], "nofile=512:2048")
        self.assertNotIn("--cpus", argv)

    def test_owned_envelope_binding_requires_v1_profile_and_v2_limits(self):
        bindings = {
            "candidate_revision": "a" * 40,
            "runner_revision": "b" * 40,
            "image_digest": "sha256:" + "c" * 64,
        }
        prepare_sha = "d" * 64
        requested = {
            "execution_profile": "contained-oci-v1",
            "image_id": bindings["image_digest"],
            "sealed": True,
            "resource_profile": dict(contained_oci.CANDIDATE_RESOURCE_PROFILE_V2),
            "mount_spec": sorted(destination for _name, destination
                                 in publication.CANDIDATE_MOUNT_SPEC),
        }
        envelope = {"execution_commit": bindings["runner_revision"],
                    "prepare_sha256": prepare_sha, "requested": requested}
        publication.check_envelope_bindings(
            envelope, bindings=bindings, prepare_sha256=prepare_sha,
            rail=OWNED_V1_RAIL)
        requested["resource_profile"] = dict(contained_oci.CANDIDATE_RESOURCE_PROFILE)
        with self.assertRaisesRegex(publication.HostedPublicationError,
                                    "resource_profile_binding"):
            publication.check_envelope_bindings(
                envelope, bindings=bindings, prepare_sha256=prepare_sha,
                rail=OWNED_V1_RAIL)
        setup = publication.setup_status_doc(
            status="ready", reason="test", bindings=bindings,
            rail=OWNED_V1_RAIL)
        self.assertEqual(setup["operator_profile"], "contained-oci-v1")

    def test_safe_result_projection_binds_collection_and_keeps_only_declared_outcomes(self):
        report = self.report()
        loaded = {
            "index": {"report_sha256": hashlib.sha256(
                publication.ca.encode_report_v0(report)).hexdigest(),
                "members": [{"ordinal": 0}, {"ordinal": 3}]},
            "members": [
                {"candidate_outcome": "completed", "host_path": "/private/tmp/secret"},
                {"candidate_outcome": "refused", "runtime_version": "host-only"},
            ],
        }
        projected = publication.safe_candidate_projection(
            report, loaded, bindings={"candidate_revision": "a" * 40},
            rail=OWNED_V1_RAIL)
        self.assertEqual(projected["control_status"], "killed")
        self.assertEqual(projected["unproved"], 0)
        self.assertIs(projected["adequate"], True)
        self.assertEqual(projected["outcomes"], [
            {"ordinal": 0, "candidate_outcome": "completed"},
            {"ordinal": 3, "candidate_outcome": "refused"},
        ])
        self.assertNotIn("host_path", json.dumps(projected))
        self.assertEqual(set(projected), {
            "schema", "kind", "decision", "score_status", "bindings",
            "dispatch_bindings", "report_sha256", "control_status", "unproved",
            "adequate", "outcomes", "non_claims",
        })

    def test_safe_result_projection_withholds_invalid_run_states(self):
        loaded = {"index": {"report_sha256": "0" * 64, "members": []},
                  "members": []}
        for report in (
            self.report(control_status="survived"),
            self.report(unproved=1, declared_total=3),
            self.report(failures=["failure"], adequate=False),
        ):
            with self.subTest(report=report):
                loaded["index"]["report_sha256"] = hashlib.sha256(
                    publication.ca.encode_report_v0(report)).hexdigest()
                projected = publication.safe_candidate_projection(
                    report, loaded, bindings={}, rail=OWNED_V1_RAIL)
                self.assertEqual(projected["decision"], "withhold")

    def test_projection_refuses_incoherent_counts_and_digest(self):
        report = self.report(declared_total=999)
        loaded = {"index": {"report_sha256": hashlib.sha256(
            publication.ca.encode_report_v0(report)).hexdigest(), "members": []},
            "members": []}
        with self.assertRaisesRegex(publication.HostedPublicationError,
                                    "candidate_report_total"):
            publication.safe_candidate_projection(
                report, loaded, bindings={}, rail=OWNED_V1_RAIL)
        report = self.report()
        loaded["index"]["report_sha256"] = "0" * 64
        with self.assertRaisesRegex(publication.HostedPublicationError,
                                    "candidate_report_binding"):
            publication.safe_candidate_projection(
                report, loaded, bindings={}, rail=OWNED_V1_RAIL)

    def test_new_workflows_are_disjoint_and_legacy_bytes_stay_fixed(self):
        expected = {
            ".github/workflows/contained-hosted-prepare.yml":
                "b069c7f94ad52c5e38b4706f51ab817bca791b0012e91c20493784e49fcd4c45",
            ".github/workflows/contained-hosted-publication.yml":
                "9131258a39a6639c6be1a6b74e89853c18339b802b1c68484eb211a3f41addfa",
        }
        for rel, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / rel).read_bytes()).hexdigest(), digest)
        prepare = (ROOT / ".github/workflows/owned-contained-v1-prepare.yml").read_text()
        publish = (ROOT / ".github/workflows/owned-contained-v1-publication.yml").read_text()
        joined = prepare + publish
        self.assertIn("owned-contained-v1", joined)
        self.assertIn("prepare.v2.json", joined)
        self.assertNotIn("--operator-profile", joined)
        self.assertNotIn("--schema", joined)
        legacy = ((ROOT / ".github/workflows/contained-hosted-prepare.yml").read_text()
                  + (ROOT / ".github/workflows/contained-hosted-publication.yml").read_text())
        for token in (OWNED_V1_RAIL.workflow_prepare,
                      OWNED_V1_RAIL.workflow_publication,
                      OWNED_V1_RAIL.packet_dirname,
                      OWNED_V1_RAIL.packet_manifest_filename):
            self.assertNotIn(token, legacy)


if __name__ == "__main__":
    unittest.main()
