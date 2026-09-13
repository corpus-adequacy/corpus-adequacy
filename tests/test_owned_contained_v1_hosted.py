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
from tests.test_contained_hosted_workflow_contract import (  # noqa: E402
    CHECKOUT_ACTION,
    SETUP_PYTHON_ACTION,
    UPLOAD_ACTION,
    parse_workflow_yaml,
)


OWNED_PREPARE_WORKFLOW = {
    "name": "owned-contained-v1-prepare",
    "on": {"workflow_dispatch": None},
    "permissions": {"contents": "read"},
    "concurrency": {
        "group": "owned-contained-v1-prepare",
        "cancel-in-progress": False,
    },
    "env": {"PYTHON_VERSION": "3.13"},
    "jobs": {"owned-prepare": {
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 30,
        "steps": [
            {"name": "Checkout", "uses": CHECKOUT_ACTION,
             "with": {"persist-credentials": False}},
            {"name": "Set up Python", "uses": SETUP_PYTHON_ACTION,
             "with": {"python-version": "${{ env.PYTHON_VERSION }}"}},
            {"name": "Prepare owned contained-v1 packet input", "shell": "bash",
             "run": "python measurements/owned_contained_v1_hosted.py prepare"},
            {"name": "Upload owned prepare", "uses": UPLOAD_ACTION,
             "with": {
                 "name": "owned-contained-v1-prepare-${{ github.run_id }}-${{ github.run_attempt }}",
                 "path": "owned-contained-v1-prepare/prepare.v2.json",
                 "retention-days": 14, "if-no-files-found": "error"}},
            {"name": "Upload owned prepare record", "uses": UPLOAD_ACTION,
             "with": {
                 "name": "owned-contained-v1-prepare-record-${{ github.run_id }}-${{ github.run_attempt }}",
                 "path": "owned-contained-v1-prepare-record/owned-contained-v1-prepare-record.v1.json",
                 "retention-days": 14, "if-no-files-found": "error"}},
        ],
    }},
}


OWNED_PUBLICATION_WORKFLOW = {
    "name": "owned-contained-v1-publication",
    "on": {"workflow_dispatch": {"inputs": {
        name: {"required": True, "type": "string"}
        for name in (
            "candidate_revision", "runner_revision", "image_digest",
            "packet_release_tag", "packet_manifest_sha256",
        )
    }}},
    "permissions": {"contents": "read"},
    "concurrency": {
        "group": "owned-contained-v1-publication",
        "cancel-in-progress": False,
    },
    "env": {"PYTHON_VERSION": "3.13"},
    "jobs": {"owned-contained": {
        "runs-on": "ubuntu-24.04",
        "timeout-minutes": 30,
        "steps": [
            {"name": "Checkout immutable runner", "uses": CHECKOUT_ACTION,
             "with": {"persist-credentials": False, "fetch-depth": 0,
                      "ref": "${{ inputs.runner_revision }}"}},
            {"name": "Set up Python", "uses": SETUP_PYTHON_ACTION,
             "with": {"python-version": "${{ env.PYTHON_VERSION }}"}},
            {"name": "Fetch owned packet", "shell": "bash",
             "env": {
                 "PACKET_RELEASE_TAG": "${{ inputs.packet_release_tag }}",
                 "PACKET_MANIFEST_SHA256": "${{ inputs.packet_manifest_sha256 }}",
             },
             "run": "python measurements/owned_contained_v1_hosted.py fetch --repository \"$GITHUB_REPOSITORY\" --tag \"$PACKET_RELEASE_TAG\" --manifest-sha256 \"$PACKET_MANIFEST_SHA256\""},
            {"name": "Gate owned publication", "id": "gate", "shell": "bash",
             "env": {
                 "CANDIDATE_REVISION": "${{ inputs.candidate_revision }}",
                 "RUNNER_REVISION": "${{ inputs.runner_revision }}",
                 "IMAGE_DIGEST": "${{ inputs.image_digest }}",
                 "PACKET_MANIFEST_SHA256": "${{ inputs.packet_manifest_sha256 }}",
             },
             "run": "python measurements/owned_contained_v1_hosted.py gate --candidate-revision \"$CANDIDATE_REVISION\" --runner-revision \"$RUNNER_REVISION\" --image-digest \"$IMAGE_DIGEST\" --packet-manifest-sha256 \"$PACKET_MANIFEST_SHA256\" --out owned-contained-v1-artifacts"},
            {"name": "Upload setup", "if": "always() && !cancelled()",
             "uses": UPLOAD_ACTION,
             "with": {"name": "owned-contained-v1-setup",
                      "path": "owned-contained-v1-artifacts/setup-status.json",
                      "retention-days": 14, "if-no-files-found": "error"}},
            {"name": "Upload verified collection",
             "if": "steps.gate.outcome == 'success' && !cancelled()",
             "uses": UPLOAD_ACTION,
             "with": {"name": "owned-contained-v1-effective-envelope",
                      "path": "owned-contained-v1-artifacts/effective-envelope-collection.v0/",
                      "retention-days": 14, "if-no-files-found": "error"}},
            {"name": "Upload candidate result", "if": "always() && !cancelled()",
             "uses": UPLOAD_ACTION,
             "with": {"name": "owned-contained-v1-candidate-result",
                      "path": "owned-contained-v1-artifacts/candidate-result.json",
                      "retention-days": 14, "if-no-files-found": "error"}},
            {"name": "Upload rerun evidence", "if": "always() && !cancelled()",
             "uses": UPLOAD_ACTION,
             "with": {
                 "name": "owned-contained-v1-rerun-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
                 "path": "owned-contained-v1-artifacts/rerun-evidence.jsonl",
                 "retention-days": 14, "if-no-files-found": "error"}},
        ],
    }},
}


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

    def test_crossed_prepare_refuses_through_real_gate_before_execute(self):
        bindings = {
            "candidate_revision": "a" * 40,
            "runner_revision": "b" * 40,
            "image_digest": "sha256:" + "c" * 64,
        }
        prepare_raw = json.dumps({"schema": owned.sealed_run.PREPARE_V1_SCHEMA}).encode()
        authorize_raw = b"authorize"
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            packet = workspace / OWNED_V1_RAIL.packet_dirname
            packet.mkdir()
            (packet / OWNED_V1_RAIL.prepare_filename).write_bytes(prepare_raw)
            (packet / OWNED_V1_RAIL.authorize_filename).write_bytes(authorize_raw)
            (packet / "pins").mkdir()
            packet_files = {
                OWNED_V1_RAIL.prepare_filename: hashlib.sha256(prepare_raw).hexdigest(),
                OWNED_V1_RAIL.authorize_filename: hashlib.sha256(authorize_raw).hexdigest(),
            }
            reached = []

            def execute(**_kwargs):
                reached.append(True)
                raise AssertionError("crossed PREPARE reached execute")

            with mock.patch.object(publication, "check_packet_manifest",
                                   return_value=packet_files), \
                    mock.patch.object(publication, "load_dispatch_bindings"), \
                    mock.patch.object(publication, "check_prepare_bindings"):
                with self.assertRaisesRegex(publication.HostedPublicationError,
                                            "prepare_profile:.*contained-oci-v1 admits only prepare.v2"):
                    publication.run_gate(
                        **bindings, operator_profile=OWNED_V1_RAIL.execution_profile,
                        out_dir=workspace / "out", workspace_root=workspace,
                        packet_root=OWNED_V1_RAIL.packet_dirname,
                        authorize_path=OWNED_V1_RAIL.authorize_filename,
                        prepare_path=OWNED_V1_RAIL.prepare_filename, pins_dir="pins",
                        packet_manifest_sha256="d" * 64, docker_ready=lambda: "ready",
                        sealed_execute=execute,
                        environ={"GITHUB_SHA": bindings["runner_revision"],
                                 "GITHUB_WORKFLOW_SHA": bindings["runner_revision"]},
                        rail=OWNED_V1_RAIL)
            self.assertEqual(reached, [])

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

    def test_owned_gate_facade_forwards_the_closed_rail_exactly(self):
        with mock.patch.object(publication, "run_gate",
                               return_value={"decision": "publish"}) as call:
            owned.gate_owned(
                candidate_revision="a" * 40, runner_revision="b" * 40,
                image_digest="sha256:" + "c" * 64,
                packet_manifest_sha256="d" * 64, out_dir="out")
        self.assertEqual(call.call_args.kwargs, {
            "candidate_revision": "a" * 40,
            "runner_revision": "b" * 40,
            "image_digest": "sha256:" + "c" * 64,
            "operator_profile": OWNED_V1_RAIL.execution_profile,
            "out_dir": "out",
            "workspace_root": ROOT,
            "packet_root": OWNED_V1_RAIL.packet_dirname,
            "authorize_path": OWNED_V1_RAIL.authorize_filename,
            "prepare_path": OWNED_V1_RAIL.prepare_filename,
            "pins_dir": "pins",
            "packet_manifest_sha256": "d" * 64,
            "rail": OWNED_V1_RAIL,
        })

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

    def test_real_owned_gate_propagates_collection_withhold_and_quarantines_bytes(self):
        from tests.test_effective_envelope import _requested_v2, _v2_effective

        requested = _requested_v2()
        bindings = {
            "candidate_revision": "a" * 40,
            "runner_revision": "b" * 40,
            "image_digest": requested["image_id"],
        }
        report = self.report()
        report_sha = hashlib.sha256(publication.ca.encode_report_v0(report)).hexdigest()
        prepare_raw = json.dumps({"schema": owned.sealed_run.PREPARE_V2_SCHEMA}).encode()
        authorize_raw = b"authorize"
        prepare_sha = hashlib.sha256(prepare_raw).hexdigest()
        member = publication.effective_envelope.build_envelope_record(
            requested=requested, setup_status="ready", envelope_status="verified",
            unverified_field=None, effective=_v2_effective(),
            candidate_outcome="completed", cleanup="removed-and-absent",
            prepare_sha256=prepare_sha,
            execution_commit=bindings["runner_revision"], report_sha256=None,
            schema=publication.effective_envelope.ENVELOPE_SCHEMA_V1)
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw)
            packet = workspace / OWNED_V1_RAIL.packet_dirname
            packet.mkdir()
            (packet / OWNED_V1_RAIL.prepare_filename).write_bytes(prepare_raw)
            (packet / OWNED_V1_RAIL.authorize_filename).write_bytes(authorize_raw)
            (packet / "pins").mkdir()
            out = workspace / "out"

            def execute(**kwargs):
                live = Path(kwargs["envelope_dest"])
                ledger = publication.collection.Ledger()
                recorded = ledger.register()
                ledger.recorded(recorded, member)
                raised = ledger.register()
                ledger.raised(raised, "SyntheticRaised")
                publication.collection.write_collection(
                    ledger, live, report_sha256=report_sha)
                return report

            packet_files = {
                OWNED_V1_RAIL.prepare_filename: prepare_sha,
                OWNED_V1_RAIL.authorize_filename: hashlib.sha256(authorize_raw).hexdigest(),
            }
            with mock.patch.object(publication, "check_packet_manifest",
                                   return_value=packet_files), \
                    mock.patch.object(publication, "load_dispatch_bindings"), \
                    mock.patch.object(publication, "check_prepare_bindings"), \
                    mock.patch.object(owned.sealed_run, "load_prepare_for_profile",
                                      return_value={}):
                decision = publication.run_gate(
                    **bindings, operator_profile=OWNED_V1_RAIL.execution_profile,
                    out_dir=out, workspace_root=workspace,
                    packet_root=OWNED_V1_RAIL.packet_dirname,
                    authorize_path=OWNED_V1_RAIL.authorize_filename,
                    prepare_path=OWNED_V1_RAIL.prepare_filename, pins_dir="pins",
                    packet_manifest_sha256="d" * 64, docker_ready=lambda: "ready",
                    sealed_execute=execute,
                    environ={"GITHUB_SHA": bindings["runner_revision"],
                             "GITHUB_WORKFLOW_SHA": bindings["runner_revision"]},
                    rail=OWNED_V1_RAIL)
            self.assertEqual(decision["decision"], "withhold")
            self.assertFalse((out / publication.COLLECTION_DIRNAME).exists())
            retained = (out / publication.WITHHELD_COLLECTION_DIRNAME
                        / "attempt-0000")
            loaded = publication.collection.load_collection(retained)
            self.assertEqual(publication.collection.withheld_reason(loaded),
                             "attempt_raised")
            candidate = json.loads((out / publication.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(candidate["decision"], "withhold")
            self.assertEqual(candidate["outcomes"], [
                {"ordinal": 0, "candidate_outcome": "completed"},
            ])

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

    def test_new_workflows_match_their_exact_parsed_contracts(self):
        prepare_text = (ROOT / ".github/workflows/owned-contained-v1-prepare.yml").read_text()
        publication_text = (
            ROOT / ".github/workflows/owned-contained-v1-publication.yml").read_text()
        self.assertEqual(parse_workflow_yaml(prepare_text), OWNED_PREPARE_WORKFLOW)
        self.assertEqual(parse_workflow_yaml(publication_text), OWNED_PUBLICATION_WORKFLOW)

    def test_readme_names_both_hosted_rails_without_the_retired_v1_absence_claim(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("separate repository-owned `contained-oci-v1` rail", readme)
        for retired in (
            "hosted v1 execution remains unavailable",
            "no command or hosted lane selects",
            "the hosted lane stays `contained-oci-v0`",
            "the hosted lane stays v0-only",
        ):
            self.assertNotIn(retired, readme)

    def test_owned_workflow_boundary_mutations_are_red(self):
        prepare_text = (ROOT / ".github/workflows/owned-contained-v1-prepare.yml").read_text()
        publication_text = (
            ROOT / ".github/workflows/owned-contained-v1-publication.yml").read_text()
        mutations = (
            (publication_text,
             "steps.gate.outcome == 'success' && !cancelled()", "always()"),
            (publication_text, "          ref: ${{ inputs.runner_revision }}\n", ""),
            (publication_text, "persist-credentials: false", "persist-credentials: true"),
            (publication_text, "cancel-in-progress: false", "cancel-in-progress: true"),
            (prepare_text, "persist-credentials: false", "persist-credentials: true"),
            (prepare_text, "cancel-in-progress: false", "cancel-in-progress: true"),
        )
        for text, old, new in mutations:
            with self.subTest(old=old, new=new):
                self.assertIn(old, text)
                expected = (OWNED_PREPARE_WORKFLOW if text is prepare_text
                            else OWNED_PUBLICATION_WORKFLOW)
                self.assertNotEqual(parse_workflow_yaml(text.replace(old, new, 1)), expected)


if __name__ == "__main__":
    unittest.main()
