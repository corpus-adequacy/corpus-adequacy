#!/usr/bin/env python3
"""Behavioral tests and mutations for consumer envelope semantic validation (#106)."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import contained_hosted_publication as hosted  # noqa: E402
import contained_oci as contained  # noqa: E402
import effective_envelope as env_mod  # noqa: E402

CANDIDATE = "a" * 40
RUNNER = "b" * 40
IMAGE = "sha256:" + ("ab" * 32)
PROBE_IMAGE = "sha256:" + ("11" * 32)
PREPARE_SHA256 = "e" * 64
BINDINGS = {
    "candidate_revision": CANDIDATE,
    "runner_revision": RUNNER,
    "image_digest": IMAGE,
}


def _requested(*, image=IMAGE, sealed=True):
    return env_mod.requested_envelope(
        execution_profile="contained-oci-v0",
        image_id=image,
        mount_spec=[
            ("/input", "/input"),
            ("/subject", "/subject"),
            ("/tool", "/tool"),
            ("/vendor", "/vendor"),
        ],
        resource_profile=contained.CANDIDATE_RESOURCE_PROFILE,
        sealed=sealed,
    )


def _effective(*, image=IMAGE, runtime_version="27.1.1", sealed=True, extra_env=()):
    profile = contained.CANDIDATE_RESOURCE_PROFILE
    env_names = ["CARGO_HOME", "PATH", "RUSTUP_HOME"]
    if sealed:
        env_names.append("CARGO_NET_OFFLINE")
    env_names.extend(extra_env)
    return {
        "cap_add": [],
        "cap_drop": ["ALL"],
        "devices": [],
        "env_names": sorted(env_names),
        "image": image,
        "image_env_names": ["CARGO_HOME", "PATH", "RUSTUP_HOME"] + list(extra_env),
        "memory": profile["memory_bytes"],
        "memory_swap": profile["memory_swap_bytes"],
        "mounts": [
            {"destination": "/input", "rw": False, "type": "bind"},
            {"destination": "/subject", "rw": False, "type": "bind"},
            {"destination": "/tool", "rw": False, "type": "bind"},
            {"destination": "/vendor", "rw": False, "type": "bind"},
        ],
        "network_mode": "none" if sealed else "",
        "no_new_privileges": True,
        "pid_mode": "",
        "pids_limit": profile["pids"],
        "privileged": False,
        "read_only_root": True,
        "runtime_version": runtime_version,
        "tmpfs": {
            "/tmp": {
                "exec": False,
                "nr_inodes": profile["tmp_inodes"],
                "size": profile["tmp_bytes"],
            },
            "/work": {
                "exec": profile["work_exec"],
                "nr_inodes": profile["work_inodes"],
                "size": profile["work_bytes"],
            },
        },
        "user": contained.CONTAINED_USER,
        "userns_mode": "",
    }


def _valid_envelope_record(**over):
    fields = {
        "requested": _requested(),
        "setup_status": "ready",
        "envelope_status": "verified",
        "unverified_field": None,
        "effective": _effective(),
        "candidate_outcome": "completed",
        "cleanup": "removed-and-absent",
        "prepare_sha256": PREPARE_SHA256,
        "execution_commit": RUNNER,
        "report_sha256": None,
    }
    fields.update(over)
    return env_mod.build_envelope_record(**fields)


def _prepare_doc(*, bindings=None, subject_commit=None, prepare_commit=None,
                 prepare_image=None, toolchain_image=None):
    bindings = dict(bindings or BINDINGS)
    subject = subject_commit if subject_commit is not None else bindings["candidate_revision"]
    prepare_commit = prepare_commit if prepare_commit is not None else bindings["runner_revision"]
    prepare_image = prepare_image if prepare_image is not None else PROBE_IMAGE
    toolchain_image = toolchain_image if toolchain_image is not None else bindings["image_digest"]
    return {
        "schema": "corpus-adequacy.prepare.v1",
        "execution": {"commit": prepare_commit, "content_sha256": "f" * 64},
        "image": {"id": prepare_image},
        "toolchain": {"image_id": toolchain_image},
        "pins": {"subject_commit": subject},
    }


def _write_packet(root: Path, *, bindings=None):
    bindings = dict(bindings or BINDINGS)
    (root / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
        json.dumps(bindings, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "authorize.v0").write_bytes(b"authorize-bytes")
    raw = (json.dumps(_prepare_doc(bindings=bindings)) + "\n").encode("utf-8")
    (root / "prepare.v1").write_bytes(raw)
    pins = root / "pins"
    pins.mkdir(exist_ok=True)
    (pins / "manifest.json").write_text("{}\n", encoding="utf-8")
    return {
        "authorize": "authorize.v0",
        "prepare": "prepare.v1",
        "pins_dir": "pins",
        "prepare_sha256": hashlib.sha256(raw).hexdigest(),
        "packet_rel": root.name,
    }


def _load_mutated_module(source: str, module_name: str, file_name: str):
    root = Path(tempfile.mkdtemp())
    path = root / file_name
    path.write_text(source, encoding="utf-8")
    measurements = REPO_ROOT / "measurements"
    sys.path.insert(0, str(measurements))
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(module_name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    return mod


class ConsumerMemberValidationTests(unittest.TestCase):
    """Consumer boundary semantic validation of execution envelopes."""

    def test_positive_control_valid_envelope_loads(self):
        doc = _valid_envelope_record()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            loaded = hosted.load_envelope(path)
            self.assertEqual(loaded, doc)
            decision = hosted.publication_decision(loaded, setup_status="ready")
            self.assertEqual(decision["decision"], "publish")

    def test_stale_permission_after_cleanup_failed_refuses(self):
        doc = _valid_envelope_record()
        # Probe mutation: cleanup failed, but permission left permitted.
        doc["cleanup"] = "remove-failed"
        self.assertEqual(doc["publication_permission"], "permitted")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_stale_withheld_reason_refuses(self):
        doc = _valid_envelope_record()
        doc["cleanup"] = "remove-failed"
        doc["publication_permission"] = "withheld"
        doc["withheld_reason"] = "unearned-reason"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_forged_schema_refuses(self):
        doc = _valid_envelope_record()
        doc["schema"] = "corpus-adequacy.execution-envelope.v999"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_forged_non_claims_refuses(self):
        doc = _valid_envelope_record()
        doc["non_claims"] = ["Altered claim"]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_invalid_candidate_outcome_refuses(self):
        doc = _valid_envelope_record()
        doc["candidate_outcome"] = "unrecognized-outcome"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_impossible_state_tuple_refuses(self):
        doc = _valid_envelope_record()
        # setup_status != ready requires candidate_outcome == "not-run"
        doc["setup_status"] = "unavailable"
        doc["candidate_outcome"] = "completed"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_consistent_withheld_diagnostic_envelope_loads_and_withholds(self):
        doc = env_mod.build_envelope_record(
            requested=_requested(),
            setup_status="ready",
            envelope_status="unverified",
            unverified_field="runtime_version",
            effective=None,
            candidate_outcome="completed",
            cleanup="removed-and-absent",
            prepare_sha256=PREPARE_SHA256,
            execution_commit=RUNNER,
            report_sha256=None,
        )
        self.assertEqual(doc["publication_permission"], "withheld")
        self.assertEqual(doc["withheld_reason"], "envelope_status")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            loaded = hosted.load_envelope(path)
            self.assertEqual(loaded, doc)
            decision = hosted.publication_decision(loaded, setup_status="ready")
            self.assertEqual(decision["decision"], "withhold")

    def test_full_hosted_gate_refuses_inconsistent_envelope_and_materializes_refusal(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            inconsistent_doc = _valid_envelope_record(
                prepare_sha256=rels["prepare_sha256"],
                execution_commit=RUNNER,
            )
            # Stale permitted: cleanup failed but permission permitted.
            inconsistent_doc["cleanup"] = "remove-failed"
            self.assertEqual(inconsistent_doc["publication_permission"], "permitted")

            def mock_execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(inconsistent_doc, indent=2), encoding="utf-8"
                )

            out_dir = base / "out"
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile="contained-oci-v0",
                    out_dir=out_dir,
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path="authorize.v0",
                    prepare_path="prepare.v1",
                    pins_dir="pins",
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=mock_execute,
                )
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

            # Verify post-execute refusal artifacts were materialized
            setup_doc = json.loads((out_dir / hosted.SETUP_STATUS_FILENAME).read_text("utf-8"))
            self.assertEqual(setup_doc["setup_status"], "refused")
            self.assertEqual(setup_doc["reason"], "envelope_corrupt")

            env_doc = json.loads((out_dir / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text("utf-8"))
            self.assertEqual(env_doc["publication_permission"], "withheld")
            self.assertEqual(env_doc["withheld_reason"], "envelope_corrupt")

            cand_doc = json.loads((out_dir / hosted.CANDIDATE_RESULT_FILENAME).read_text("utf-8"))
            self.assertEqual(cand_doc["kind"], "void-hosted-result")
            self.assertEqual(cand_doc["reason"], "envelope_corrupt")

    def test_confined_path_and_byte_ceilings_defenses_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            # Non-existent file
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(Path(td) / "absent.json")
            self.assertEqual(str(ctx.exception), "confined_path")

            # Oversized file
            oversized = Path(td) / "big.json"
            oversized.write_bytes(b" " * 100)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(oversized, max_bytes=50)
            self.assertEqual(str(ctx.exception), "max_input_bytes")

    def test_malformed_nested_members_produce_envelope_error_and_hosted_refusal(self):
        """F1/F4: Malformed nested structures must raise EnvelopeError and map to envelope_corrupt."""
        def _mutate_unsorted_matching(doc):
            doc["requested"]["mount_spec"] = ["/vendor", "/input"]
            doc["effective"]["mounts"] = [
                {"destination": "/vendor", "rw": False, "type": "bind"},
                {"destination": "/input", "rw": False, "type": "bind"},
            ]

        def _mutate_duplicate_matching(doc):
            doc["requested"]["mount_spec"] = ["/input", "/input"]
            doc["effective"]["mounts"] = [
                {"destination": "/input", "rw": False, "type": "bind"},
                {"destination": "/input", "rw": False, "type": "bind"},
            ]

        test_cases = [
            ("resource_profile string", lambda doc: doc["requested"].__setitem__("resource_profile", "not-a-dict")),
            ("resource_profile empty", lambda doc: doc["requested"].__setitem__("resource_profile", {})),
            ("resource_profile None", lambda doc: doc["requested"].__setitem__("resource_profile", None)),
            ("mount_spec int", lambda doc: doc["requested"].__setitem__("mount_spec", 123)),
            ("mount_spec empty", lambda doc: doc["requested"].__setitem__("mount_spec", [])),
            ("mount_spec unsorted", lambda doc: doc["requested"].__setitem__("mount_spec", ["/vendor", "/input"])),
            ("mount_spec unsorted with matching mounts", _mutate_unsorted_matching),
            ("mount_spec duplicate", lambda doc: doc["requested"].__setitem__("mount_spec", ["/input", "/input"])),
            ("mount_spec duplicate with matching mounts", _mutate_duplicate_matching),
            ("mount_spec not-slash", lambda doc: doc["requested"].__setitem__("mount_spec", ["input"])),
            ("env_names int", lambda doc: doc["effective"].__setitem__("env_names", 123)),
            ("image_env_names int", lambda doc: doc["effective"].__setitem__("image_env_names", 123)),
            ("mounts rw int 0", lambda doc: doc["effective"]["mounts"][0].__setitem__("rw", 0)),
            ("memory float", lambda doc: doc["effective"].__setitem__("memory", float(doc["effective"]["memory"]))),
            ("tmpfs /tmp exec int 0", lambda doc: doc["effective"]["tmpfs"]["/tmp"].__setitem__("exec", 0)),
            ("tmpfs /work exec int 1", lambda doc: doc["effective"]["tmpfs"]["/work"].__setitem__("exec", 1)),
            ("requested sealed int 1", lambda doc: doc["requested"].__setitem__("sealed", 1)),
        ]
        for name, mutator in test_cases:
            with self.subTest(name=name):
                doc = _valid_envelope_record()
                mutator(doc)
                with self.assertRaises(env_mod.EnvelopeError, msg=f"validate_envelope_record should raise EnvelopeError for {name}"):
                    env_mod.validate_envelope_record(doc)

                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "envelope.v0.json"
                    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
                    with self.assertRaises(hosted.HostedPublicationError, msg=f"load_envelope should raise HostedPublicationError for {name}") as ctx:
                        hosted.load_envelope(path)
                    self.assertEqual(str(ctx.exception), "envelope_corrupt")

    def test_full_hosted_gate_malformed_nested_shape_materializes_post_execute_refusal(self):
        """F1: Malformed nested shape in envelope must materialize post-execute refusal, not infrastructure failure."""
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            corrupt_doc = _valid_envelope_record(
                prepare_sha256=rels["prepare_sha256"],
                execution_commit=RUNNER,
            )
            corrupt_doc["requested"]["resource_profile"] = "string-instead-of-dict"

            def mock_execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(corrupt_doc, indent=2), encoding="utf-8"
                )

            out_dir = base / "out"
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile="contained-oci-v0",
                    out_dir=out_dir,
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path="authorize.v0",
                    prepare_path="prepare.v1",
                    pins_dir="pins",
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=mock_execute,
                )
            self.assertEqual(str(ctx.exception), "envelope_corrupt")

            # Must materialize post-execute refusal, NOT infrastructure failure!
            setup_doc = json.loads((out_dir / hosted.SETUP_STATUS_FILENAME).read_text("utf-8"))
            self.assertEqual(setup_doc["setup_status"], "refused")
            self.assertEqual(setup_doc["reason"], "envelope_corrupt")

            rerun_lines = [
                json.loads(line)
                for line in (out_dir / hosted.RERUN_EVIDENCE_FILENAME).read_text("utf-8").splitlines()
            ]
            self.assertTrue(any(entry.get("kind") == "post-execute-refusal" for entry in rerun_lines))
            self.assertFalse(any(entry.get("kind") == "infrastructure-failure" for entry in rerun_lines))

    def test_hosted_gate_strictly_binds_candidate_policy_constants(self):
        """F2: Hosted gate must bind sealed=True and CANDIDATE_RESOURCE_PROFILE to executor policy."""
        sha = PREPARE_SHA256

        # Unsealed / networked envelope
        unsealed_env = _valid_envelope_record(
            prepare_sha256=sha,
            execution_commit=RUNNER,
            requested=_requested(sealed=False),
            effective=_effective(sealed=False),
        )
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(unsealed_env, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "sealed_binding")

        # Forged resource profile (pids=999999)
        forged_prof = dict(contained.CANDIDATE_RESOURCE_PROFILE)
        forged_prof["pids"] = 999999
        forged_env = _valid_envelope_record(
            prepare_sha256=sha,
            execution_commit=RUNNER,
        )
        forged_env["requested"]["resource_profile"] = forged_prof
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(forged_env, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "resource_profile_binding")

        # Wrong execution profile
        wrong_prof_env = _valid_envelope_record(
            prepare_sha256=sha,
            execution_commit=RUNNER,
        )
        wrong_prof_env["requested"]["execution_profile"] = "other-profile"
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(wrong_prof_env, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "execution_profile_binding")

    def test_require_requested_record_empty_mount_spec_refused(self):
        """F3: Stored requested declaration must refuse empty mount_spec."""
        req = _requested()
        req["mount_spec"] = []
        with self.assertRaises(env_mod.EnvelopeError) as ctx:
            env_mod.require_requested_record(req)
        self.assertEqual(str(ctx.exception), "mount_spec")

    def test_unverified_record_requested_schema_validated_in_builder(self):
        """F4/M4: build_envelope_record must validate requested schema even when effective is None."""
        base_req = _requested()

        # Bad resource profile in unverified record
        bad_req = dict(base_req, resource_profile="not-a-dict")
        with self.assertRaises(env_mod.EnvelopeError) as ctx:
            env_mod.build_envelope_record(
                requested=bad_req,
                setup_status="ready",
                envelope_status="unverified",
                unverified_field="candidate_exit",
                effective=None,
                candidate_outcome="completed",
                cleanup="removed-and-absent",
                prepare_sha256="0" * 64,
                execution_commit="0" * 40,
                report_sha256="0" * 64,
            )
        self.assertEqual(str(ctx.exception), "resource_profile")

        # Bad mount_spec in unverified record
        bad_req = dict(base_req, mount_spec=123)
        with self.assertRaises(env_mod.EnvelopeError) as ctx:
            env_mod.build_envelope_record(
                requested=bad_req,
                setup_status="ready",
                envelope_status="unverified",
                unverified_field="candidate_exit",
                effective=None,
                candidate_outcome="completed",
                cleanup="removed-and-absent",
                prepare_sha256="0" * 64,
                execution_commit="0" * 40,
                report_sha256="0" * 64,
            )
        self.assertEqual(str(ctx.exception), "mount_spec")

        # Empty mount_spec in unverified record
        bad_req = dict(base_req, mount_spec=[])
        with self.assertRaises(env_mod.EnvelopeError) as ctx:
            env_mod.build_envelope_record(
                requested=bad_req,
                setup_status="ready",
                envelope_status="unverified",
                unverified_field="candidate_exit",
                effective=None,
                candidate_outcome="completed",
                cleanup="removed-and-absent",
                prepare_sha256="0" * 64,
                execution_commit="0" * 40,
                report_sha256="0" * 64,
            )
        self.assertEqual(str(ctx.exception), "mount_spec")

        # Bad sealed in unverified record
        bad_req = dict(base_req, sealed=1)
        with self.assertRaises(env_mod.EnvelopeError) as ctx:
            env_mod.build_envelope_record(
                requested=bad_req,
                setup_status="ready",
                envelope_status="unverified",
                unverified_field="candidate_exit",
                effective=None,
                candidate_outcome="completed",
                cleanup="removed-and-absent",
                prepare_sha256="0" * 64,
                execution_commit="0" * 40,
                report_sha256="0" * 64,
            )
        self.assertEqual(str(ctx.exception), "sealed")


class MemberValidationMutations(unittest.TestCase):
    """Mutation and deletion controls for consumer validation."""

    def test_mutation_delete_consumer_validation_call_is_red(self):
        """M-REVALIDATION-BYPASS: bypassing validate_envelope_record in load_envelope must fail."""
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        call_snippet = (
            "    try:\n"
            "        effective_envelope.validate_envelope_record(doc)\n"
            "    except effective_envelope.EnvelopeError as exc:\n"
            '        raise HostedPublicationError("envelope_corrupt") from exc\n'
        )
        self.assertIn(
            call_snippet, original,
            "call snippet not found in source; harness maintenance required",
        )
        mutated = original.replace(call_snippet, "    pass  # mutated: validation bypassed\n", 1)
        bad_mod = _load_mutated_module(
            mutated, "mut_bypass_validation", "contained_hosted_publication.py"
        )

        doc = _valid_envelope_record()
        doc["cleanup"] = "remove-failed"  # stale permitted

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")

            # The unmutated module rejects the stale envelope
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.load_envelope(path)

            # The mutated module bypasses validation and accepts the stale envelope
            leaked = bad_mod.load_envelope(path)
            self.assertEqual(leaked["publication_permission"], "permitted")

    def test_mutation_omit_rebuilt_comparison_is_red(self):
        """Omission of rebuilt-vs-original equality check in validate_envelope_record must fail."""
        original = Path(env_mod.__file__).read_text(encoding="utf-8")
        cmp_snippet = (
            "    if rebuilt != record:\n"
            '        raise EnvelopeError("envelope_semantic_mismatch")\n'
        )
        self.assertIn(
            cmp_snippet, original,
            "comparison snippet not found in source; harness maintenance required",
        )
        mutated = original.replace(cmp_snippet, "    pass  # mutated: comparison omitted\n", 1)
        bad_mod = _load_mutated_module(
            mutated, "mut_omit_comparison", "effective_envelope.py"
        )

        doc = _valid_envelope_record()
        doc["cleanup"] = "remove-failed"  # stale permitted

        # Unmutated module rejects stale permission
        with self.assertRaises(env_mod.EnvelopeError):
            env_mod.validate_envelope_record(doc)

        # Mutated module accepts stale permission
        passed = bad_mod.validate_envelope_record(doc)
        self.assertEqual(passed["publication_permission"], "permitted")

    def test_mutation_noop_comment_control_stays_green(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"""Hosted contained publication gate (#107).',
            '"""Hosted contained publication gate (#107).\n# noop consumer validation control',
            1,
        )
        mod = _load_mutated_module(
            mutated, "noop_consumer_control", "contained_hosted_publication.py"
        )
        doc = _valid_envelope_record()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
            loaded = mod.load_envelope(path)
            self.assertEqual(loaded, doc)


if __name__ == "__main__":
    unittest.main()
