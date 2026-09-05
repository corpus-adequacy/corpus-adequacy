#!/usr/bin/env python3
"""Behavioral RED/GREEN + mutations for the hosted publication gate (#107)."""

from __future__ import annotations

import hashlib
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
# Option 2: IMAGE is candidate/toolchain B; PROBE_IMAGE is inert probe A.
IMAGE = "sha256:" + ("c" * 64)
PROBE_IMAGE = "sha256:" + ("11" * 32)
OTHER_CANDIDATE = "f" * 40
OTHER_RUNNER = "d" * 40
OTHER_IMAGE = "sha256:" + ("e" * 64)
BINDINGS = {
    "candidate_revision": CANDIDATE,
    "runner_revision": RUNNER,
    "image_digest": IMAGE,
}


def _canonical(path):
    return Path(os.path.realpath(path))


def _prepare_doc(*, bindings=None, subject_commit=None, prepare_commit=None,
                 prepare_image=None, toolchain_image=None, prepare_extra=None):
    bindings = dict(bindings or BINDINGS)
    subject = (
        subject_commit if subject_commit is not None
        else bindings["candidate_revision"])
    prepare_commit = (
        prepare_commit if prepare_commit is not None
        else bindings["runner_revision"])
    # Probe A defaults distinct from dispatch B (bindings image_digest).
    prepare_image = (
        prepare_image if prepare_image is not None
        else PROBE_IMAGE)
    toolchain_image = (
        toolchain_image if toolchain_image is not None
        else bindings["image_digest"])
    prepare = {
        "schema": "corpus-adequacy.prepare.v1",
        "execution": {"commit": prepare_commit, "content_sha256": "f" * 64},
        "image": {"id": prepare_image},
        "toolchain": {"image_id": toolchain_image},
        "pins": {"subject_commit": subject},
    }
    if prepare_extra:
        prepare.update(prepare_extra)
    return prepare


def _prepare_raw(**kwargs) -> bytes:
    return (json.dumps(_prepare_doc(**kwargs)) + "\n").encode("utf-8")


def _prepare_sha256(**kwargs) -> str:
    return hashlib.sha256(_prepare_raw(**kwargs)).hexdigest()


def _permitted_envelope(*, prepare_sha256=None, **over):
    if prepare_sha256 is None:
        prepare_sha256 = _prepare_sha256()
    doc = {
        "schema": "corpus-adequacy.execution-envelope.v0",
        "setup_status": "ready",
        "envelope_status": "verified",
        "publication_permission": "permitted",
        "candidate_outcome": "completed",
        "cleanup": "removed-and-absent",
        "withheld_reason": None,
        "execution_commit": RUNNER,
        "prepare_sha256": prepare_sha256,
        "requested": {"image_id": IMAGE, "execution_profile": "contained-oci-v0"},
        "effective": {
            "env_names": ["PATH", "HOME"],
            "image_env_names": ["PATH", "HOME"],
            "mounts": [{"destination": "/in", "rw": False, "type": "bind"}],
        },
    }
    doc.update(over)
    return doc


def _write_packet(root: Path, *, bindings=None, prepare_commit=None,
                  prepare_image=None, toolchain_image=None, subject_commit=None,
                  authorize="authorize-bytes", prepare_extra=None):
    bindings = dict(bindings or BINDINGS)
    (root / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
        json.dumps(bindings, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "authorize.v0").write_bytes(
        authorize.encode("utf-8") if isinstance(authorize, str) else authorize
    )
    raw = _prepare_raw(
        bindings=bindings,
        subject_commit=subject_commit,
        prepare_commit=prepare_commit,
        prepare_image=prepare_image,
        toolchain_image=toolchain_image,
        prepare_extra=prepare_extra,
    )
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



def _assert_non_success_refusal_artifacts(testcase, out: Path, *, reason: str):
    """All three uploadable artifacts present and non-success-shaped."""
    setup_path = out / hosted.SETUP_STATUS_FILENAME
    envelope_path = out / hosted.EFFECTIVE_ENVELOPE_FILENAME
    candidate_path = out / hosted.CANDIDATE_RESULT_FILENAME
    testcase.assertTrue(setup_path.is_file(), "setup-status.json missing")
    testcase.assertTrue(envelope_path.is_file(), "effective-envelope missing")
    testcase.assertTrue(candidate_path.is_file(), "candidate-result missing")
    setup = json.loads(setup_path.read_text(encoding="utf-8"))
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    testcase.assertEqual(setup.get("kind"), "setup-status")
    testcase.assertEqual(setup.get("setup_status"), "refused")
    testcase.assertEqual(setup.get("reason"), reason)
    testcase.assertEqual(envelope.get("kind"), "withheld-envelope-stub")
    testcase.assertEqual(envelope.get("publication_permission"), "withheld")
    testcase.assertEqual(envelope.get("envelope_status"), "unverified")
    testcase.assertNotEqual(envelope.get("publication_permission"), "permitted")
    testcase.assertNotEqual(envelope.get("envelope_status"), "verified")
    testcase.assertNotIn("GITHUB_TOKEN", json.dumps(envelope))
    testcase.assertEqual(candidate.get("kind"), "void-hosted-result")
    testcase.assertEqual(candidate.get("score_status"), "none")
    testcase.assertEqual(candidate.get("reason"), reason)
    testcase.assertNotEqual(candidate.get("decision"), "publish")
    rerun = out / hosted.RERUN_EVIDENCE_FILENAME
    testcase.assertTrue(rerun.is_file())
    entries = [
        json.loads(line)
        for line in rerun.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    testcase.assertTrue(
        any(
            e.get("kind") == "post-execute-refusal" and e.get("reason") == reason
            for e in entries
        ),
        entries,
    )


def _run_ok(base, packet_name, rels, *, candidate=CANDIDATE, bindings=None,
            execute=None, out_name="artifacts", **over):
    bindings = dict(bindings or BINDINGS)
    if execute is None:
        sha = rels["prepare_sha256"]

        def execute(**kwargs):
            Path(kwargs["envelope_dest"]).write_text(
                json.dumps(_permitted_envelope(prepare_sha256=sha)),
                encoding="utf-8",
            )

    return hosted.run_gate(
        candidate_revision=candidate,
        runner_revision=bindings["runner_revision"],
        image_digest=bindings["image_digest"],
        operator_profile=hosted.REQUIRED_PROFILE,
        out_dir=base / out_name,
        workspace_root=base,
        packet_root=packet_name,
        authorize_path=rels["authorize"],
        prepare_path=rels["prepare"],
        pins_dir=rels["pins_dir"],
        docker_ready=lambda: "27.0.0",
        sealed_execute=execute,
        **over,
    )


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
            got = hosted.resolve_confined_input(root, "ok.json", max_bytes=100)
            self.assertTrue(hosted.paths_equal(got, good))
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

    def test_canonical_path_comparison_cross_platform(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            good = root / "ok.json"
            good.write_text('{"a": 1}\n', encoding="utf-8")
            # Compare unsresolved alias form against canonical return.
            alias = Path(os.path.realpath(good))
            got = hosted.resolve_confined_input(root, "ok.json", max_bytes=100)
            self.assertTrue(hosted.paths_equal(got, alias))
            self.assertTrue(hosted.paths_equal(got, good))
            # Genuine outside-root still refuses even when alias-normalized.
            outside = Path(raw + "-out")
            outside.mkdir()
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_confined_input(root, str(outside / "x"), max_bytes=100)

    def test_load_json_confined_ceilings_before_parse(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "doc.json"
            payload = json.dumps({"runs_on": "ubuntu-latest", "x": "y" * 100})
            path.write_text(payload, encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.load_json_confined(root, "doc.json", max_bytes=40)
            self.assertEqual(
                hosted.load_json_confined(root, "doc.json", max_bytes=10_000)["runs_on"],
                "ubuntu-latest",
            )

    def test_packet_root_confined_under_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            got = hosted.resolve_packet_root(base, "packet")
            self.assertTrue(hosted.paths_equal(got, packet))
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_packet_root(base, str(packet))
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_packet_root(base, "../packet")
            outside = Path(raw + "-outside")
            outside.mkdir()
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_packet_root(base, str(outside))
            link = base / "escape"
            link.symlink_to(outside)
            with self.assertRaises(hosted.HostedPublicationError):
                hosted.resolve_packet_root(base, "escape")


class HostileWorkflowRefusals(unittest.TestCase):
    def test_refuse_hostile_surfaces_from_child_env(self):
        hosted.refuse_hostile_workflow(
            env_names=("PATH",),
            mounts=(),
        )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                env_names=None,
                mounts=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                env_names=("GITHUB_TOKEN",),
                mounts=(),
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                env_names=(),
                mounts=[{"source": "/var/run/docker.sock", "destination": "/var/run/docker.sock"}],
            )
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.refuse_hostile_workflow(
                env_names=(),
                mounts=[{"destination": "/github/workspace", "rw": True}],
            )

    def test_observe_child_environment_from_envelope_only(self):
        env = _permitted_envelope()
        observed = hosted.observe_child_environment(env)
        self.assertEqual(observed["env_names"], ("PATH", "HOME"))
        self.assertEqual(len(observed["mounts"]), 1)
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.observe_child_environment({"effective": {}})
        # Self-declared HOSTED_FORWARDED_ENV_NAMES must not exist as evidence.
        self.assertFalse(hasattr(hosted, "HOSTED_FORWARDED_ENV_NAMES"))
        src = Path(hosted.__file__).read_text(encoding="utf-8")
        self.assertNotIn("HOSTED_FORWARDED_ENV_NAMES", src)


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

            decision = _run_ok(base, "packet", rels)
            self.assertEqual(decision["decision"], "publish")
            setup = json.loads((base / "artifacts" / hosted.SETUP_STATUS_FILENAME).read_text())
            cand = json.loads((base / "artifacts" / hosted.CANDIDATE_RESULT_FILENAME).read_text())
            self.assertEqual(setup["dispatch_bindings"], BINDINGS)
            self.assertEqual(cand["dispatch_bindings"], BINDINGS)
            envelope = json.loads(
                (base / "artifacts" / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text()
            )
            self.assertNotIn("dispatch_bindings", envelope)
            self.assertEqual(envelope["schema"], "corpus-adequacy.execution-envelope.v0")
            self.assertEqual(envelope["prepare_sha256"], rels["prepare_sha256"])

            def execute_unverified(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            envelope_status="unverified",
                        )
                    ),
                    encoding="utf-8",
                )

            decision2 = _run_ok(
                base, "packet", rels, execute=execute_unverified, out_name="artifacts2"
            )
            self.assertEqual(decision2["decision"], "withhold")

    def test_candidate_revision_must_match_prepare_subject_commit(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            # Same prepare/authorize bytes; only candidate + sidecar swap to ffff.
            rels = _write_packet(packet)  # subject aaaa
            prepare_hash = rels["prepare_sha256"]
            auth_hash = hashlib.sha256((packet / "authorize.v0").read_bytes()).hexdigest()

            executed = []

            def execute(**kwargs):
                executed.append({
                    "auth": hashlib.sha256(Path(kwargs["authorize_path"]).read_bytes()).hexdigest(),
                    "prep": hashlib.sha256(Path(kwargs["prepare_path"]).read_bytes()).hexdigest(),
                })
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(prepare_sha256=prepare_hash)),
                    encoding="utf-8",
                )

            d1 = _run_ok(base, "packet", rels, execute=execute, out_name="o1")
            self.assertEqual(d1["decision"], "publish")
            self.assertEqual(executed[-1]["auth"], auth_hash)
            self.assertEqual(executed[-1]["prep"], prepare_hash)

            bad_bindings = dict(BINDINGS)
            bad_bindings["candidate_revision"] = OTHER_CANDIDATE
            (packet / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
                json.dumps(bad_bindings, sort_keys=True) + "\n", encoding="utf-8"
            )
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(
                    base, "packet", rels, candidate=OTHER_CANDIDATE,
                    bindings=bad_bindings, execute=execute, out_name="o2",
                )
            self.assertEqual(str(ctx.exception), "candidate_revision_binding")
            # Prepare/authorize bytes unchanged; refusal is identity binding.
            self.assertEqual(
                hashlib.sha256((packet / "prepare.v1").read_bytes()).hexdigest(),
                prepare_hash,
            )

    def test_envelope_prepare_sha256_binds_checked_prepare_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_prep(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(prepare_sha256="ab" * 32)),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, execute=execute_wrong_prep, out_name="o")
            self.assertEqual(str(ctx.exception), "prepare_sha256_binding")
            _assert_non_success_refusal_artifacts(
                self, base / "o", reason="prepare_sha256_binding")

    def test_dispatch_bindings_mismatch_and_prepare_swap_bite(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            bad_bindings = dict(BINDINGS)
            bad_bindings["candidate_revision"] = OTHER_CANDIDATE
            rels = _write_packet(packet, bindings=bad_bindings)
            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, out_name="out1")

            packet2 = base / "packet2"
            packet2.mkdir()
            rels2 = _write_packet(packet2, prepare_commit=OTHER_RUNNER)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet2", rels2, out_name="out2")
            self.assertEqual(str(ctx.exception), "runner_revision_binding")

            packet3 = base / "packet3"
            packet3.mkdir()
            rels3 = _write_packet(packet3, toolchain_image=OTHER_IMAGE)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet3", rels3, out_name="out3")
            self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_envelope_binding_mismatch_after_execute_bites(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_commit(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            execution_commit=OTHER_RUNNER,
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_wrong_commit, out_name="out")

            def execute_wrong_image(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            requested={
                                "image_id": OTHER_IMAGE,
                                "execution_profile": "contained-oci-v0",
                            },
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_wrong_image, out_name="out2")

    def test_absolute_packet_root_and_authorize_never_reach_execute(self):
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
                    workspace_root=base,
                    packet_root=str(packet),  # absolute
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=spy,
                )
            self.assertEqual(seen, [])

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "out2",
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path=str(secret),
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
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
            (packet / hosted.DISPATCH_BINDINGS_FILENAME).write_bytes(
                b'{"candidate_revision":' + (b'"' + b"a" * 40 + b'"')
                + b',"pad":"' + (b"x" * 200) + b'"}'
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
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=spy,
                    max_input_bytes=80,
                )
            self.assertEqual(seen, [])

    def test_credential_env_in_envelope_refuses_publish(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["PATH", "GITHUB_TOKEN"],
                                "image_env_names": ["PATH", "GITHUB_TOKEN"],
                                "mounts": [
                                    {"destination": "/in", "rw": False, "type": "bind"}
                                ],
                            },
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, execute=execute_cred, out_name="cred")
            self.assertEqual(str(ctx.exception), "credential_env")
            _assert_non_success_refusal_artifacts(
                self, base / "cred", reason="credential_env")

    def test_pre_execute_refusal_does_not_fabricate_success_artifacts(self):
        """Pre-execute fail-closed stays refuse-only (no post-execute sanitize)."""
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet, prepare_commit=OTHER_RUNNER)
            seen = []

            def spy(**kwargs):
                seen.append(True)

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, execute=spy, out_name="pre")
            self.assertEqual(str(ctx.exception), "runner_revision_binding")
            self.assertEqual(seen, [])
            out = base / "pre"
            self.assertFalse((out / hosted.SETUP_STATUS_FILENAME).exists())
            self.assertFalse((out / hosted.EFFECTIVE_ENVELOPE_FILENAME).exists())
            self.assertFalse((out / hosted.CANDIDATE_RESULT_FILENAME).exists())


class CandidateImageBinding(unittest.TestCase):
    """Option 2: image_digest is candidate/toolchain B; probe A is prepare-bound."""

    def test_real_helpers_distinct_ab_prepare_and_envelope_green(self):
        import aee_checker_sealed_candidate as cand
        self.assertNotEqual(PROBE_IMAGE, IMAGE)
        self.assertEqual(
            cand.require_candidate_image(
                image_id=IMAGE, toolchain_image_id=IMAGE, probe_image_id=PROBE_IMAGE),
            IMAGE,
        )
        prepare = _prepare_doc()
        self.assertEqual(prepare["image"]["id"], PROBE_IMAGE)
        self.assertEqual(prepare["toolchain"]["image_id"], IMAGE)
        hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        sha = _prepare_sha256()
        hosted.check_envelope_bindings(
            _permitted_envelope(prepare_sha256=sha),
            bindings=BINDINGS,
            prepare_sha256=sha,
        )

    def test_valid_distinct_ab_run_gate_publishes(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            decision = _run_ok(base, "packet", rels)
            self.assertEqual(decision["decision"], "publish")

    def test_dispatch_probe_a_refused(self):
        prepare = _prepare_doc()
        bad = dict(BINDINGS)
        bad["image_digest"] = PROBE_IMAGE
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=bad)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_absent_toolchain_b_refused(self):
        prepare = _prepare_doc()
        del prepare["toolchain"]
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_wrong_toolchain_b_refused(self):
        prepare = _prepare_doc(toolchain_image=OTHER_IMAGE)
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_wrong_envelope_b_refused(self):
        sha = _prepare_sha256()
        env = _permitted_envelope(
            prepare_sha256=sha,
            requested={"image_id": OTHER_IMAGE, "execution_profile": "contained-oci-v0"},
        )
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(
                env, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_a_equals_b_refused(self):
        prepare = _prepare_doc(prepare_image=IMAGE, toolchain_image=IMAGE)
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_missing_probe_a_refused(self):
        prepare = _prepare_doc()
        prepare["image"] = {}
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_invalid_probe_a_refused(self):
        prepare = _prepare_doc(prepare_image="sha256:dead")
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")

    def test_unrelated_revision_and_prepare_sha256_still_bite(self):
        prepare = _prepare_doc(prepare_commit=OTHER_RUNNER)
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "runner_revision_binding")
        prepare2 = _prepare_doc(subject_commit=OTHER_CANDIDATE)
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_prepare_bindings(prepare2, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "candidate_revision_binding")
        sha = _prepare_sha256()
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(
                _permitted_envelope(prepare_sha256="ab" * 32),
                bindings=BINDINGS,
                prepare_sha256=sha,
            )
        self.assertEqual(str(ctx.exception), "prepare_sha256_binding")

    def test_mutation_restore_probe_comparison_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        delegated = (
            "    try:\n"
            "        require_candidate_image(\n"
            '            image_id=bindings["image_digest"],\n'
            '            toolchain_image_id=toolchain.get("image_id"),\n'
            '            probe_image_id=image.get("id"),\n'
            "        )\n"
            "    except contained.PrepareError as exc:\n"
            '        raise HostedPublicationError("image_digest_binding") from exc\n'
        )
        restored = (
            '    if image.get("id") != bindings["image_digest"]:\n'
            '        raise HostedPublicationError("image_digest_binding")\n'
        )
        self.assertEqual(original.count(delegated), 1)
        mutated = original.replace(delegated, restored, 1)
        bad = _load_mutated_module(mutated, "mut_restore_probe_cmp")
        prepare = _prepare_doc()
        with self.assertRaises(bad.HostedPublicationError) as ctx:
            bad.check_prepare_bindings(prepare, bindings=BINDINGS)
        self.assertEqual(str(ctx.exception), "image_digest_binding")
        hosted.check_prepare_bindings(prepare, bindings=BINDINGS)

    def test_mutation_delete_require_candidate_image_call_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        delegated = (
            "    try:\n"
            "        require_candidate_image(\n"
            '            image_id=bindings["image_digest"],\n'
            '            toolchain_image_id=toolchain.get("image_id"),\n'
            '            probe_image_id=image.get("id"),\n'
            "        )\n"
            "    except contained.PrepareError as exc:\n"
            '        raise HostedPublicationError("image_digest_binding") from exc\n'
        )
        self.assertEqual(original.count(delegated), 1)
        mutated = original.replace(
            delegated, "    pass  # mutated: candidate image unbound\n", 1)
        bad = _load_mutated_module(mutated, "mut_delete_require_cand")
        prepare = _prepare_doc()
        bad_bindings = dict(BINDINGS)
        bad_bindings["image_digest"] = PROBE_IMAGE
        with self.assertRaises(hosted.HostedPublicationError):
            hosted.check_prepare_bindings(prepare, bindings=bad_bindings)
        bad.check_prepare_bindings(prepare, bindings=bad_bindings)

    def test_mutation_noop_comment_control_stays_green(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        mutated = original.replace(
            '"""Hosted contained publication gate (#107).',
            '"""Hosted contained publication gate (#107).\n# noop image-binding',
            1,
        )
        mod = _load_mutated_module(mutated, "noop_image_binding")
        prepare = _prepare_doc()
        mod.check_prepare_bindings(prepare, bindings=BINDINGS)


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
            "        observed_child = observe_child_environment(envelope)\n"
            "        refuse_hostile_workflow(\n"
            '            env_names=observed_child["env_names"],\n'
            '            mounts=observed_child["mounts"],\n'
            "        )\n"
        )
        self.assertEqual(original.count(call), 1)
        mutated = original.replace(call, "        pass  # mutated: refuse unwired\n", 1)
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_refuse")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["GITHUB_TOKEN"],
                                "image_env_names": ["GITHUB_TOKEN"],
                                "mounts": [],
                            },
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_cred, out_name="good")

            decision = bad.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=base / "bad",
                workspace_root=base,
                packet_root="packet",
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                docker_ready=lambda: "27.0.0",
                sealed_execute=execute_cred,
            )
            self.assertEqual(decision["decision"], "publish")

    def test_mutation_skip_subject_commit_binding_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = (
            "    if pins.get(\"subject_commit\") != bindings[\"candidate_revision\"]:\n"
            '        raise HostedPublicationError("candidate_revision_binding")\n'
        )
        self.assertEqual(original.count(needle), 1)
        mutated = original.replace(needle, "    pass  # mutated: subject unbound\n", 1)
        bad = _load_mutated_module(mutated, "mut_subject")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            # Prepare subject stays aaaa; CLI+sidecar say ffff.
            rels = _write_packet(packet, subject_commit=CANDIDATE)
            bad_bindings = dict(BINDINGS)
            bad_bindings["candidate_revision"] = OTHER_CANDIDATE
            (packet / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
                json.dumps(bad_bindings, sort_keys=True) + "\n", encoding="utf-8"
            )

            def execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(prepare_sha256=rels["prepare_sha256"])),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=OTHER_CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "good",
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute,
                )
            decision = bad.run_gate(
                candidate_revision=OTHER_CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=base / "bad",
                workspace_root=base,
                packet_root="packet",
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                docker_ready=lambda: "27.0.0",
                sealed_execute=execute,
            )
            self.assertEqual(decision["decision"], "publish")

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
                    json.dumps(_permitted_envelope(prepare_sha256=rels["prepare_sha256"])),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=spy, out_name="good")
            decision = bad.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=base / "bad",
                workspace_root=base,
                packet_root="packet",
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                docker_ready=lambda: "27.0.0",
                sealed_execute=spy,
            )
            self.assertEqual(decision["decision"], "publish")
            self.assertTrue(executed)

    def test_mutation_skip_packet_root_workspace_bind_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = "    packet = resolve_packet_root(workspace_root, packet_root)\n"
        self.assertEqual(original.count(needle), 1)
        mutated = original.replace(
            needle, "    packet = Path(packet_root)  # mutated: unbound root\n", 1
        )
        bad = _load_mutated_module(mutated, "mut_packet_root")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            abs_root = str(packet.resolve())

            def execute(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(prepare_sha256=rels["prepare_sha256"])),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                hosted.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "good",
                    workspace_root=base,
                    packet_root=abs_root,
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute,
                )
            decision = bad.run_gate(
                candidate_revision=CANDIDATE,
                runner_revision=RUNNER,
                image_digest=IMAGE,
                operator_profile=hosted.REQUIRED_PROFILE,
                out_dir=base / "bad",
                workspace_root=base,
                packet_root=abs_root,
                authorize_path=rels["authorize"],
                prepare_path=rels["prepare"],
                pins_dir=rels["pins_dir"],
                docker_ready=lambda: "27.0.0",
                sealed_execute=execute,
            )
            self.assertEqual(decision["decision"], "publish")

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

    def test_mutation_delete_post_execute_sanitization_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        call = (
            "        if execute_began:\n"
            "            materialize_post_execute_refusal(\n"
            "                out=out,\n"
            "                reason=str(exc),\n"
            "                bindings=bindings,\n"
            "                rerun_log=rerun_log,\n"
            "                identity=identity,\n"
            "                max_artifact_bytes=max_artifact_bytes,\n"
            "            )\n"
        )
        self.assertEqual(original.count(call), 1)
        mutated = original.replace(call, "        pass  # mutated: no sanitize\n", 1)
        bad = _load_mutated_module(mutated, "mut_no_sanitize")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(
                        _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["GITHUB_TOKEN"],
                                "image_env_names": ["GITHUB_TOKEN"],
                                "mounts": [],
                            },
                        )
                    ),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_cred, out_name="good")
            _assert_non_success_refusal_artifacts(
                self, base / "good", reason="credential_env")

            with self.assertRaises(bad.HostedPublicationError):
                bad.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "bad",
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_cred,
                )
            leaked = json.loads(
                (base / "bad" / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(leaked.get("publication_permission"), "permitted")
            self.assertEqual(leaked.get("envelope_status"), "verified")
            self.assertIn("GITHUB_TOKEN", json.dumps(leaked))
            self.assertFalse((base / "bad" / hosted.SETUP_STATUS_FILENAME).exists())
            self.assertFalse(
                (base / "bad" / hosted.CANDIDATE_RESULT_FILENAME).exists()
            )

    def test_mutation_restore_stale_success_envelope_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        needle = (
            '    setup_doc = setup_status_doc(\n'
            '        status="refused", reason=reason, bindings=bindings)\n'
            '    envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)\n'
        )
        self.assertEqual(original.count(needle), 1)
        restored = (
            '    setup_doc = setup_status_doc(\n'
            '        status="refused", reason=reason, bindings=bindings)\n'
            '    envelope_doc = {\n'
            '        "schema": HOSTED_SCHEMA,\n'
            '        "kind": "stale-success-restored",\n'
            '        "publication_permission": "permitted",\n'
            '        "envelope_status": "verified",\n'
            '        "bindings": dict(bindings),\n'
            '    }  # mutated: restore stale success envelope\n'
        )
        mutated = original.replace(needle, restored, 1)
        bad = _load_mutated_module(mutated, "mut_restore_envelope")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_prep(**kwargs):
                Path(kwargs["envelope_dest"]).write_text(
                    json.dumps(_permitted_envelope(prepare_sha256="ab" * 32)),
                    encoding="utf-8",
                )

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(
                    base, "packet", rels, execute=execute_wrong_prep, out_name="good"
                )
            good_env = json.loads(
                (base / "good" / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(good_env.get("publication_permission"), "withheld")

            with self.assertRaises(bad.HostedPublicationError):
                bad.run_gate(
                    candidate_revision=CANDIDATE,
                    runner_revision=RUNNER,
                    image_digest=IMAGE,
                    operator_profile=hosted.REQUIRED_PROFILE,
                    out_dir=base / "bad",
                    workspace_root=base,
                    packet_root="packet",
                    authorize_path=rels["authorize"],
                    prepare_path=rels["prepare"],
                    pins_dir=rels["pins_dir"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_wrong_prep,
                )
            leaked = json.loads(
                (base / "bad" / hosted.EFFECTIVE_ENVELOPE_FILENAME).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(leaked.get("publication_permission"), "permitted")
            self.assertEqual(leaked.get("envelope_status"), "verified")

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
        self.assertNotIn("HOSTED_FORWARDED_ENV_NAMES", dir(hosted))


if __name__ == "__main__":
    unittest.main()
