#!/usr/bin/env python3
"""Behavioral RED/GREEN + mutations for the hosted publication gate (#107)."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import contained_hosted_publication as hosted  # noqa: E402
import contained_oci as contained  # noqa: E402

CANDIDATE = "a" * 40
RUNNER = "b" * 40
IMAGE = "sha256:" + ("c" * 64)
OTHER_RUNNER = "d" * 40
OTHER_IMAGE = "sha256:" + ("e" * 64)
BINDINGS = {
    "candidate_revision": CANDIDATE,
    "runner_revision": RUNNER,
    "image_digest": IMAGE,
}

SAFE_ENV = {
    "RUNNER_ENVIRONMENT": "github-hosted",
    "HOSTED_FORWARDED_ENV_NAMES": "CANDIDATE_REVISION,RUNNER_REVISION,IMAGE_DIGEST",
}


def _permitted_envelope(**over):
    doc = {
        "schema": "corpus-adequacy.execution-envelope.v0",
        "setup_status": "ready",
        "envelope_status": "verified",
        "publication_permission": "permitted",
        "candidate_outcome": "completed",
        "cleanup": "removed-and-absent",
        "withheld_reason": None,
        "execution_commit": RUNNER,
        "requested": {"image_id": IMAGE, "execution_profile": "contained-oci-v0"},
    }
    doc.update(over)
    return doc


def _safe_environ(**over):
    env = dict(SAFE_ENV)
    env.update(over)
    return env


def _write_packet(root: Path, *, bindings=None, prepare_commit=None,
                  prepare_image=None, authorize="authorize-bytes",
                  prepare_extra=None):
    bindings = dict(bindings or BINDINGS)
    prepare_commit = prepare_commit if prepare_commit is not None else bindings["runner_revision"]
    prepare_image = prepare_image if prepare_image is not None else bindings["image_digest"]
    (root / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
        json.dumps(bindings, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "authorize.v0").write_bytes(authorize.encode("utf-8") if isinstance(authorize, str) else authorize)
    prepare = {
        "schema": "corpus-adequacy.prepare.v1",
        "execution": {"commit": prepare_commit, "content_sha256": "f" * 64},
        "image": {"id": prepare_image},
    }
    if prepare_extra:
        prepare.update(prepare_extra)
    (root / "prepare.v1").write_text(json.dumps(prepare) + "\n", encoding="utf-8")
    pins = root / "pins"
    pins.mkdir(exist_ok=True)
    (pins / "manifest.json").write_text("{}\n", encoding="utf-8")
    return {
        "authorize": "authorize.v0",
        "prepare": "prepare.v1",
        "pins_dir": "pins",
    }


def _load_mutated_module(source: str, name: str):
    root = Path(tempfile.mkdtemp())
    path = root / "contained_hosted_publication.py"
    path.write_text(source, encoding="utf-8")
    measurements = REPO_ROOT / "measurements"
    sys.path.insert(0, str(measurements))
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class BindingsAndProfile(unittest.TestCase):
    def test_bindings_require_candidate_runner_and_image_digests(self):
        self.assertEqual(hosted.require_bindings(CANDIDATE, RUNNER, IMAGE), BINDINGS)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings("short", RUNNER, IMAGE)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings(CANDIDATE, "short", IMAGE)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_bindings(CANDIDATE, RUNNER, "sha256:dead")

    def test_operator_profile_refuses_trusted_local(self):
        self.assertEqual(
            hosted.require_operator_profile(hosted.REQUIRED_PROFILE),
            hosted.REQUIRED_PROFILE,
        )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.require_operator_profile("trusted-local")


class ConfinedInputResolver(unittest.TestCase):
    def test_resolve_rejects_absolute_traversal_symlink_and_oversize(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            good = root / "ok.json"
            good.write_text('{"a": 1}\n', encoding="utf-8")
            self.assertEqual(
                hosted.resolve_confined_input(root, "ok.json", max_bytes=100),
                good,
            )
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_confined_input(root, str(good), max_bytes=100)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_confined_input(root, "../ok.json", max_bytes=100)
            outside = Path(raw + "-outside")
            outside.mkdir()
            secret = outside / "secret.json"
            secret.write_text('{"secret": true}\n', encoding="utf-8")
            link = root / "link.json"
            link.symlink_to(secret)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_confined_input(root, "link.json", max_bytes=100)
            parent_link = root / "sub"
            parent_link.symlink_to(outside)
            (outside / "nested.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_confined_input(root, "sub/nested.json", max_bytes=100)
            big = root / "big.json"
            big.write_bytes(b"{" + (b"a" * 200) + b"}")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.resolve_confined_input(root, "big.json", max_bytes=50)
            self.assertEqual(str(ctx.exception), "max_input_bytes")

    def test_load_json_confined_ceilings_before_parse(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "doc.json"
            # Closed-key oversized document: size check must refuse before loads.
            payload = json.dumps({"runs_on": "ubuntu-latest", "x": "y" * 100})
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.load_json_confined(root, "doc.json", max_bytes=40)
            self.assertEqual(
                hosted.load_json_confined(root, "doc.json", max_bytes=10_000)["runs_on"],
                "ubuntu-latest",
            )


class HostileWorkflowRefusals(unittest.TestCase):
    def test_refuse_hostile_surfaces(self):
        hosted.refuse_hostile_workflow(
            runner_environment="github-hosted",
            forwarded_env_names=("CANDIDATE_REVISION",),
            mounts=(),
        )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runner_environment="self-hosted",
                forwarded_env_names=("CANDIDATE_REVISION",),
                mounts=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runner_environment="github-hosted",
                forwarded_env_names=None,
                mounts=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runner_environment="github-hosted",
                forwarded_env_names=("GITHUB_TOKEN",),
                mounts=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runner_environment="github-hosted",
                forwarded_env_names=(),
                mounts=[{"source": "/var/run/docker.sock", "destination": "/var/run/docker.sock"}],
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                runner_environment="github-hosted",
                forwarded_env_names=(),
                mounts=[{"destination": "/github/workspace", "rw": True}],
            )

    def test_observe_requires_explicit_forwarded_env_names(self):
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.observe_runtime_workflow(
                environ={"RUNNER_ENVIRONMENT": "github-hosted"}
            )
        observed = hosted.observe_runtime_workflow(environ=SAFE_ENV)
        self.assertEqual(observed["runner_environment"], "github-hosted")
        self.assertIn("CANDIDATE_REVISION", observed["forwarded_env_names"])


class PublicationDecisionAndArtifacts(unittest.TestCase):
    def test_verified_envelope_only_publication_guard(self):
        self.assertEqual(
            hosted.publication_decision(_permitted_envelope(), setup_status="ready")["decision"],
            "publish",
        )
        self.assertEqual(
            hosted.publication_decision(
                _permitted_envelope(envelope_status="unverified"), setup_status="ready"
            )["decision"],
            "withhold",
        )
        absent = _permitted_envelope()
        del absent["envelope_status"]
        self.assertEqual(
            hosted.publication_decision(absent, setup_status="ready")["decision"],
            "withhold",
        )
        self.assertEqual(
            hosted.publication_decision(None, setup_status="ready")["decision"],
            "withhold",
        )

    def test_unverified_and_absent_status_independently_withhold(self):
        unverified = hosted.publication_decision(
            _permitted_envelope(envelope_status="unverified"), setup_status="ready"
        )
        self.assertEqual(unverified["decision"], "withhold")
        self.assertEqual(unverified["envelope_status"], "unverified")
        absent_status = _permitted_envelope()
        del absent_status["envelope_status"]
        absent = hosted.publication_decision(absent_status, setup_status="ready")
        self.assertEqual(absent["decision"], "withhold")
        self.assertIsNone(absent["envelope_status"])

    def test_missing_containment_is_unavailable_void_never_score(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"

            def boom():
                raise contained.DockerUnavailable("docker executable is not available")

            decision = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out,
                runtime_environ=_safe_environ(),
                docker_ready=boom,
            )
            self.assertEqual(decision["decision"], "unavailable")
            self.assertEqual(decision["score_status"], "none")
            cand = json.loads((out / hosted.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(cand["kind"], "void-hosted-result")
            self.assertEqual(cand["dispatch_bindings"], BINDINGS)
            self.assertNotIn("score_percent", cand)
            self.assertTrue((out / hosted.RERUN_EVIDENCE_FILENAME).is_file())

    def test_publish_requires_separate_setup_envelope_candidate_artifacts(self):
        setup = hosted.setup_status_doc(
            status="unavailable", reason="x", bindings=BINDINGS
        )
        env = hosted.withheld_envelope_stub(reason="x", bindings=BINDINGS)
        cand = hosted.void_candidate_result(reason="x", bindings=BINDINGS)
        with tempfile.TemporaryDirectory() as raw:
            hosted.write_separate_artifacts(raw, setup, env, cand)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(raw, setup, None, cand)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.write_separate_artifacts(raw, setup, setup, cand)

    def test_append_only_rerun_preserves_first_infrastructure_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun.jsonl"
            hosted.append_rerun_evidence(log, {"reason": "first"})
            before = log.read_bytes()
            hosted.append_rerun_evidence(log, {"reason": "second"})
            self.assertTrue(log.read_bytes().startswith(before))
            self.assertEqual(json.loads(log.read_text().splitlines()[0])["reason"], "first")

    def test_sealed_execute_path_publishes_only_verified_permitted(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            out = base / "artifacts"

            def ready():
                return "27.0.0"

            def execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope()), encoding="utf-8"
                )

            decision = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out,
                packet_root=packet,
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                runtime_environ=_safe_environ(),
                docker_ready=ready,
                sealed_execute=execute,
            )
            self.assertEqual(decision["decision"], "publish")
            setup = json.loads((out / hosted.SETUP_STATUS_FILENAME).read_text())
            cand = json.loads((out / hosted.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(setup["dispatch_bindings"], BINDINGS)
            self.assertEqual(cand["dispatch_bindings"], BINDINGS)
            # Envelope remains AEE schema (no dispatch_bindings stamp).
            envelope = json.loads((out / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text())
            self.assertNotIn("dispatch_bindings", envelope)
            self.assertEqual(envelope["schema"], "corpus-adequacy.execution-envelope.v0")

            def execute_unverified(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(envelope_status="unverified")),
                    encoding="utf-8",
                )

            out2 = base / "artifacts2"
            decision2 = hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=out2,
                packet_root=packet,
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                runtime_environ=_safe_environ(),
                docker_ready=ready,
                sealed_execute=execute_unverified,
            )
            self.assertEqual(decision2["decision"], "withhold")

    def test_dispatch_bindings_mismatch_and_prepare_swap_bite(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            # Bindings file disagrees with CLI candidate.
            bad_bindings = dict(BINDINGS)
            bad_bindings["candidate_revision"] = "f" * 40
            rels = _write_packet(packet, bindings=bad_bindings)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out1",
                    packet_root=packet,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=lambda **k: None,
                )

            packet2 = base / "packet2"
            packet2.mkdir()
            rels2 = _write_packet(packet2, prepare_commit=OTHER_RUNNER)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out2",
                    packet_root=packet2,
                    authorize_path=rels2["authorize"],
                    prepare_path=rels2["prepare"],
                    pins_dir=rels2["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=lambda **k: None,
                )
            self.assertEqual(str(ctx.exception), "runner_revision_binding")

            packet3 = base / "packet3"
            packet3.mkdir()
            rels3 = _write_packet(packet3, prepare_image=OTHER_IMAGE)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out3",
                    packet_root=packet3,
                    authorize_path=rels3["authorize"],
                    prepare_path=rels3["prepare"],
                    pins_dir=rels3["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=lambda **k: None,
                )
            self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_envelope_binding_mismatch_after_execute_bites(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_commit(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(execution_commit=OTHER_RUNNER)),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out",
                    packet_root=packet,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_wrong_commit,
                )

            def execute_wrong_image(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            requested={"image_id": OTHER_IMAGE, "execution_profile": "contained-oci-v0"}
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out2",
                    packet_root=packet,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_wrong_image,
                )

    def test_absolute_authorize_path_never_reaches_execute(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            outside = base / "outside"
            outside.mkdir()
            secret = outside / "secret.v0"
            secret.write_bytes(b"SECRET")
            seen = []

            def spy(**kwargs):
                seen.append(kwargs["authorize_path"])

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out",
                    packet_root=packet,
                    authorize_path=str(secret),
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=spy,
                )
            self.assertEqual(seen, [])

    def test_oversized_bindings_fail_before_execute(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            # Oversize the bindings file after writing a valid small one.
            (packet / hosted.DISPATCH_BINDINGS_FILENAME).write_bytes(
                b'{"candidate_revision":"' + (b"a" * 40) + b'","pad":"' + (b"x" * 200) + b'"}'
            )
            seen = []

            def spy(**kwargs):
                seen.append(True)

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out",
                    packet_root=packet,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=spy,
                    max_input_bytes=80,
                )
            self.assertEqual(seen, [])


class SourceMutations(unittest.TestCase):
    def test_mutation_delete_verified_envelope_guard_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = 'envelope_status != "verified"'
        mutated = original.replace(
            needle,
            'False and envelope_status != "verified"',
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_guard")
        leaked = bad.publication_decision(
            _permitted_envelope(envelope_status="unverified"), setup_status="ready"
        )
        self.assertEqual(leaked["decision"], "publish")
        self.assertEqual(
            hosted.publication_decision(
                _permitted_envelope(envelope_status="unverified"), setup_status="ready"
            )["decision"],
            "withhold",
        )

    def test_mutation_delete_refuse_hostile_call_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        call = (
            "    refuse_hostile_workflow(\n"
            '        runner_environment=observed["runner_environment"],\n'
            '        forwarded_env_names=observed["forwarded_env_names"],\n'
            '        mounts=observed["mounts"],\n'
            "    )\n"
        )
        self.assertEqual(original.count(call), 1)
        mutated = original.replace(call, "    pass  # mutated: refuse unwired\n", 1)
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_refuse")
        hostile = _safe_environ(RUNNER_ENVIRONMENT="self-hosted")
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=Path(tempfile.mkdtemp()) / "good",
                runtime_environ=hostile,
                docker_ready=lambda: (_ for _ in ()).throw(
                    contained.DockerUnavailable("x")
                ),
            )

        def boom():
            raise contained.DockerUnavailable("docker executable is not available")

        decision = bad.run_gate(
            candidate_revision=CANDIDATE,
            runner_revision=RUNNER,
            image_digest=IMAGE,
            operator_profile=hosted.REQUIRED_PROFILE,
            out_dir=Path(tempfile.mkdtemp()) / "bad",
            runtime_environ=hostile,
            docker_ready=boom,
        )
        self.assertEqual(decision["decision"], "unavailable")

    def test_mutation_hardcode_safe_runtime_literals_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = "    observed = observe_runtime_workflow(environ=runtime_environ)\n"
        replacement = (
            "    observed = {\n"
            '        "runner_environment": "github-hosted",\n'
            '        "forwarded_env_names": (),\n'
            '        "mounts": [],\n'
            "    }\n"
        )
        self.assertEqual(original.count(needle), 1)
        mutated = original.replace(needle, replacement, 1)
        bad = _load_mutated_module(mutated, "mut_safe_literals")
        hostile = {
            "RUNNER_ENVIRONMENT": "self-hosted",
            "HOSTED_FORWARDED_ENV_NAMES": "GITHUB_TOKEN",
        }
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=Path(tempfile.mkdtemp()) / "good",
                runtime_environ=hostile,
                docker_ready=lambda: (_ for _ in ()).throw(
                    contained.DockerUnavailable("x")
                ),
            )

        def boom():
            raise contained.DockerUnavailable("docker executable is not available")

        decision = bad.run_gate(
            candidate_revision=CANDIDATE,
            runner_revision=RUNNER,
            image_digest=IMAGE,
            operator_profile=hosted.REQUIRED_PROFILE,
            out_dir=Path(tempfile.mkdtemp()) / "bad",
            runtime_environ=hostile,
            docker_ready=boom,
        )
        self.assertEqual(decision["decision"], "unavailable")

    def test_mutation_skip_prepare_binding_check_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = "    check_prepare_bindings(prepare_doc, bindings=bindings)\n"
        self.assertEqual(original.count(needle), 1)
        mutated = original.replace(needle, "    pass  # mutated: prepare unbound\n", 1)
        bad = _load_mutated_module(mutated, "mut_prepare_bind")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet, prepare_commit=OTHER_RUNNER)
            executed = []

            def spy(**kwargs):
                executed.append(True)
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope()), encoding="utf-8"
                )

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "good",
                    packet_root=packet,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    runtime_environ=_safe_environ(),
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=spy,
                )
            decision = bad.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=base / "bad",
                packet_root=packet,
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                runtime_environ=_safe_environ(),
                docker_ready=lambda: "27.0.0",
                sealed_execute=spy,
            )
            self.assertEqual(decision["decision"], "publish")
            self.assertTrue(executed)

    def test_mutation_turn_unavailable_into_score_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"decision": "unavailable",\n            "score_status": "none",',
            '"decision": "unavailable",\n            "score_status": "scored", "score_percent": 100.0,',
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_score")
        decision = bad.publication_decision(None, setup_status="unavailable")
        self.assertEqual(decision["score_status"], "scored")
        self.assertEqual(
            hosted.publication_decision(None, setup_status="unavailable")["score_status"],
            "none",
        )

    def test_mutation_erase_first_failure_on_rerun_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            'with path.open("ab") as handle:\n        handle.write(line)',
            "path.write_bytes(line)",
            1,
        )
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_rerun")
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "rerun.jsonl"
            bad.append_rerun_evidence(log, {"reason": "first"})
            bad.append_rerun_evidence(log, {"reason": "second"})
            self.assertEqual(len(log.read_text().splitlines()), 1)
            good = Path(raw) / "good.jsonl"
            hosted.append_rerun_evidence(good, {"reason": "first"})
            before = good.read_bytes()
            hosted.append_rerun_evidence(good, {"reason": "second"})
            self.assertTrue(good.read_bytes().startswith(before))

    def test_python_comment_only_noop_control_stays_green(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"""Hosted contained publication gate (#107).',
            '"""Hosted contained publication gate (#107).\n# noop',
            1,
        )
        mod = _load_mutated_module(mutated, "noop")
        self.assertEqual(
            mod.publication_decision(None, setup_status="unavailable")["decision"],
            "unavailable",
        )


class ExportedConstants(unittest.TestCase):
    def test_closed_constants(self):
        self.assertEqual(hosted.REQUIRED_PROFILE, "contained-oci-v0")
        self.assertEqual(hosted.RETENTION_DAYS, 14)
        self.assertEqual(hosted.MAX_ARTIFACT_BYTES, 5242880)
        self.assertEqual(hosted.ARTIFACT_RERUN, "rerun-evidence")
        self.assertEqual(hosted.DISPATCH_BINDINGS_FILENAME, "hosted-dispatch-bindings.v0.json")
        self.assertEqual(hosted.REQUIRED_RUNNER_ENVIRONMENT, "github-hosted")


if __name__ == "__main__":
    unittest.main()
