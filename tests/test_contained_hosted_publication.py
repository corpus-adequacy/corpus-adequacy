#!/usr/bin/env python3
"""Behavioral RED/GREEN + mutations for the hosted publication gate (#107)."""

from __future__ import annotations

import hashlib
import importlib.util
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
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import contained_hosted_publication as hosted
import envelope_collection as collection  # noqa: E402
import contained_oci as contained  # noqa: E402
import effective_envelope as env_mod  # noqa: E402
from aee_checker_sealed_candidate import CANDIDATE_MOUNT_SPEC  # noqa: E402
import aee_checker_sealed_run as sealed_run  # noqa: E402
import hosted_packet as packet_mod  # noqa: E402
from tests.test_aee_checker_sealed_run import _committed_execution_root  # noqa: E402

CANDIDATE = "a" * 40
RUNNER = "b" * 40
# Option 2: IMAGE is candidate/toolchain B; PROBE_IMAGE is inert probe A.
IMAGE = "sha256:" + ("c" * 64)
PROBE_IMAGE = "sha256:" + ("11" * 32)
OTHER_CANDIDATE = "f" * 40
OTHER_RUNNER = "d" * 40
OTHER_IMAGE = "sha256:" + ("e" * 64)

def _read_only_member(artifacts_dir):
    """Read the one member of a written collection, refusing any other cardinality.

    A test that silently took `members[0]` would pass on a multi-member collection it did not
    intend, so the count is asserted rather than assumed.
    """
    coll = Path(artifacts_dir) / hosted.COLLECTION_DIRNAME
    files = sorted(p for p in coll.iterdir() if p.name != collection.INDEX_FILENAME)
    assert len(files) == 1, "expected exactly one member, found %d" % len(files)
    return json.loads(files[0].read_text(encoding="utf-8"))


def _write_collection(dest, doc, *, report_sha256=None):
    """Write a one-member collection where a single envelope file used to be written.

    The hosted consumer requires a collection now: a lone record is refused rather than read,
    so these fixtures produce the shape a real driver produces.
    """
    ledger = collection.Ledger()
    ledger.recorded(ledger.register(), doc)
    collection.write_collection(ledger, Path(dest), report_sha256=report_sha256)


def _write_collection_raw(dest, doc, raw_text):
    """Same, then overwrite the member with deliberately malformed bytes and re-digest them,
    so the refusal under test is about the CONTENT and not about a stale digest."""
    _write_collection(dest, doc)
    dest = Path(dest)
    member = sorted(dest.glob("member-*.json"))[0]
    raw = raw_text.encode("utf-8")
    member.write_bytes(raw)
    index_path = dest / collection.INDEX_FILENAME
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["members"][0]["sha256"] = collection.member_digest(raw)
    index_path.write_text(
        json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")


BINDINGS = {
    "candidate_revision": CANDIDATE,
    "runner_revision": RUNNER,
    "image_digest": IMAGE,
}

# The gate reads GITHUB_SHA and GITHUB_WORKFLOW_SHA from the process environment. Every run in
# this module that is not about that binding is dispatched at R, so the module pins both to R;
# the tests about the binding pass an explicit `environ` instead. A CI runner's own GITHUB_SHA
# must never leak into these runs.
_WORKFLOW_ENV = mock.patch.dict(
    os.environ, {"GITHUB_SHA": RUNNER, "GITHUB_WORKFLOW_SHA": RUNNER})


def setUpModule():
    _WORKFLOW_ENV.start()


def tearDownModule():
    _WORKFLOW_ENV.stop()


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


def _base_envelope_requested(*, image=IMAGE, sealed=True):
    return env_mod.requested_envelope(
        execution_profile="contained-oci-v0",
        image_id=image,
        mount_spec=CANDIDATE_MOUNT_SPEC,
        resource_profile=contained.CANDIDATE_RESOURCE_PROFILE,
        sealed=sealed,
    )


def _base_envelope_effective(*, image=IMAGE, runtime_version="27.1.1", sealed=True):
    profile = contained.CANDIDATE_RESOURCE_PROFILE
    env_names = ["CARGO_NET_OFFLINE", "HOME", "PATH"] if sealed else ["HOME", "PATH"]
    image_env_names = ["HOME", "PATH"]
    return {
        "cap_add": [],
        "cap_drop": ["ALL"],
        "devices": [],
        "env_names": sorted(env_names),
        "image": image,
        "image_env_names": sorted(image_env_names),
        "memory": profile["memory_bytes"],
        "memory_swap": profile["memory_swap_bytes"],
        "mounts": [
            {"destination": destination, "rw": False, "type": "bind"}
            for destination in sorted(d for _, d in CANDIDATE_MOUNT_SPEC)
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


def _permitted_envelope(*, prepare_sha256=None, **over):
    if prepare_sha256 is None:
        prepare_sha256 = _prepare_sha256()
    req = _base_envelope_requested()
    if "requested" in over:
        custom_req = over.pop("requested")
        if isinstance(custom_req, dict):
            req.update(custom_req)
        else:
            req = custom_req
    image = req.get("image_id", IMAGE) if isinstance(req, dict) else IMAGE
    sealed = req.get("sealed", True) if isinstance(req, dict) else True
    eff = _base_envelope_effective(image=image, sealed=sealed)
    if "effective" in over:
        custom_eff = over.pop("effective")
        if isinstance(custom_eff, dict):
            eff.update(custom_eff)
            if "mounts" in custom_eff and isinstance(req, dict):
                req["mount_spec"] = [m["destination"] for m in custom_eff["mounts"]]
            if "env_names" in custom_eff:
                if "image_env_names" not in custom_eff:
                    eff["image_env_names"] = list(custom_eff["env_names"])
                else:
                    eff["image_env_names"] = list(custom_eff["image_env_names"])
                if sealed:
                    if "CARGO_NET_OFFLINE" not in eff["env_names"]:
                        eff["env_names"] = sorted(list(eff["env_names"]) + ["CARGO_NET_OFFLINE"])
                    if "CARGO_NET_OFFLINE" not in eff["image_env_names"]:
                        eff["image_env_names"] = sorted(list(eff["image_env_names"]) + ["CARGO_NET_OFFLINE"])
        else:
            eff = custom_eff

    setup_status = over.pop("setup_status", "ready")
    envelope_status = over.pop("envelope_status", "verified")
    candidate_outcome = over.pop("candidate_outcome", "completed")
    cleanup = over.pop("cleanup", "removed-and-absent")
    execution_commit = over.pop("execution_commit", RUNNER)
    report_sha256 = over.pop("report_sha256", None)
    unverified_field = over.pop("unverified_field", None)

    if envelope_status != "verified":
        eff = None
        if unverified_field is None:
            unverified_field = "runtime_version"

    doc = env_mod.build_envelope_record(
        requested=req,
        setup_status=setup_status,
        envelope_status=envelope_status,
        unverified_field=unverified_field,
        effective=eff,
        candidate_outcome=candidate_outcome,
        cleanup=cleanup,
        prepare_sha256=prepare_sha256,
        execution_commit=execution_commit,
        report_sha256=report_sha256,
    )
    doc.update(over)
    return doc


def _write_packet(root: Path, *, bindings=None, prepare_commit=None,
                  prepare_image=None, toolchain_image=None, subject_commit=None,
                  authorize="authorize-bytes", prepare_extra=None):
    bindings = dict(bindings or BINDINGS)
    (root / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
        json.dumps(bindings, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / packet_mod.AUTHORIZE_FILENAME).write_bytes(
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
    (root / packet_mod.PREPARE_FILENAME).write_bytes(raw)
    pins = root / packet_mod.PINS_DIRNAME
    pins.mkdir(exist_ok=True)
    (pins / "manifest.json").write_text("{}\n", encoding="utf-8")
    return {
        "authorize": packet_mod.AUTHORIZE_FILENAME,
        "prepare": packet_mod.PREPARE_FILENAME,
        "pins_dir": packet_mod.PINS_DIRNAME,
        "prepare_sha256": hashlib.sha256(raw).hexdigest(),
        "packet_rel": root.name,
        "manifest_sha256": _seal_packet(root),
    }


def _manifest_bytes(root: Path) -> bytes:
    files = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in packet_mod.PACKET_FILENAMES
    }
    return (json.dumps({"files": files, "schema": packet_mod.MANIFEST_SCHEMA},
                       indent=2, sort_keys=True) + "\n").encode("utf-8")


def _seal_packet(root: Path) -> str:
    """Write the manifest over the packet's current bytes, as the owner does in phase 2.

    A test that edits a packet file to exercise a later check reseals it, so the refusal it
    asserts is the check under test and not the earlier manifest binding.
    """
    raw = _manifest_bytes(root)
    (root / packet_mod.MANIFEST_FILENAME).write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


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



def _assert_upload_surface_carries_no_success_members(testcase, out: Path):
    """The collection directory the workflow uploads must hold no permitted/verified member.

    Sanitizing the legacy stub stopped being sufficient when the upload was retargeted at the
    collection: a refused run whose members still say `permitted`/`verified` publishes exactly
    the bytes the refusal rejected. Raw observations are not rewritten -- they are moved out of
    the upload selection and kept as diagnostics.
    """
    live = out / hosted.COLLECTION_DIRNAME
    surviving = sorted(p.name for p in live.iterdir()) if live.is_dir() else []
    for name in surviving:
        doc = json.loads((live / name).read_text(encoding="utf-8"))
        testcase.assertNotEqual(
            doc.get("publication_permission"), "permitted",
            "refused run left a permitted member on the upload surface: %s" % name)
        testcase.assertNotEqual(doc.get("envelope_status"), "verified", name)
    quarantine = out / hosted.WITHHELD_COLLECTION_DIRNAME
    if quarantine.is_dir():
        # Diagnostic retention, deliberately outside every upload selection.
        testcase.assertNotEqual(quarantine.name, hosted.COLLECTION_DIRNAME)


def _assert_non_success_refusal_artifacts(testcase, out: Path, *, reason: str):
    """All three uploadable artifacts present and non-success-shaped."""
    _assert_upload_surface_carries_no_success_members(testcase, out)
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
            _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256=sha))

    over.setdefault("packet_manifest_sha256", rels["manifest_sha256"])
    over.setdefault("docker_ready", lambda: "27.0.0")
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

    def test_default_sealed_execute_passes_the_required_profile_to_the_driver(self):
        """#102 A3: the lane stays v0 by passing it, not by leaning on a driver default.

        `autospec` keeps `run_authorized`'s real signature, so a call that omitted the required
        keyword would raise TypeError here instead of being accepted by a permissive mock.
        """
        import aee_checker_sealed_driver as driver
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            (base / "authorize.json").write_bytes(b"authorize-bytes")
            (base / "prepare.json").write_bytes(b"prepare-bytes")
            with mock.patch.object(driver, "run_authorized", autospec=True) as run_authorized:
                hosted.default_sealed_execute(
                    authorize_path=base / "authorize.json",
                    prepare_path=base / "prepare.json",
                    pins_dir=base / "pins", root=base,
                    envelope_dest=base / "envelope", materialize_dest=base / "mat")
        run_authorized.assert_called_once()
        kwargs = run_authorized.call_args.kwargs
        self.assertIn("execution_profile", kwargs)
        self.assertEqual(kwargs["execution_profile"], hosted.REQUIRED_PROFILE)
        self.assertEqual(kwargs["execution_profile"], "contained-oci-v0")
        self.assertEqual(kwargs["authorize_raw"], b"authorize-bytes")
        self.assertEqual(kwargs["prepare_raw"], b"prepare-bytes")


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
        self.assertEqual(observed["env_names"], ("CARGO_NET_OFFLINE", "HOME", "PATH"))
        self.assertEqual(len(observed["mounts"]), len(CANDIDATE_MOUNT_SPEC))
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

    def test_publish_requires_separate_setup_and_candidate_artifacts(self):
        """Separation still binds, but the envelope slot now has a legitimate empty case.

        `envelope_doc=None` means the collection directory is authoritative, so it is not a
        collapse. Setup and candidate remain mandatory and must stay distinct documents, and a
        collection document is refused at the legacy single-envelope path outright.
        """
        setup = {"kind": "setup"}
        cand = {"kind": "candidate"}
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            for bad in ((None, cand), (setup, None)):
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    hosted.write_separate_artifacts(out, bad[0], None, bad[1])
                self.assertEqual(str(ctx.exception), "collapsed_artifacts")
            shared = {"kind": "shared"}
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.write_separate_artifacts(out, shared, None, shared)
            self.assertEqual(str(ctx.exception), "collapsed_artifacts")

            # A collection document may never sit at the legacy single-envelope path.
            for masquerade in ({"schema": collection.COLLECTION_SCHEMA},
                               {"members": [], "attempts": 0}):
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    hosted.write_separate_artifacts(out, setup, masquerade, cand)
                self.assertEqual(str(ctx.exception),
                                 "collection_at_legacy_envelope_path")

            # The authoritative-collection case writes setup and candidate, and no legacy file.
            written = hosted.write_separate_artifacts(out, setup, None, cand)
            self.assertEqual(sorted(written), sorted(
                [hosted.SETUP_STATUS_FILENAME, hosted.CANDIDATE_RESULT_FILENAME]))
            self.assertFalse((out / hosted.EFFECTIVE_ENVELOPE_FILENAME).exists())

    def test_stale_legacy_envelope_is_removed_not_reused(self):
        """A leftover single envelope beside a fresh collection is a false record."""
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            out.mkdir(parents=True)
            stale = out / hosted.EFFECTIVE_ENVELOPE_FILENAME
            stale.write_text('{"stale": true}', encoding="utf-8")
            hosted.write_separate_artifacts(out, {"kind": "s"}, None, {"kind": "c"})
            self.assertFalse(stale.exists(), "stale legacy envelope survived the run")

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
            # The collection directory is the authoritative artifact; the single legacy file
            # is no longer the envelope's home, so read the member that was actually observed.
            envelope = _read_only_member(base / "artifacts")
            self.assertNotIn("dispatch_bindings", envelope)
            self.assertEqual(envelope["schema"], "corpus-adequacy.execution-envelope.v0")
            self.assertEqual(envelope["prepare_sha256"], rels["prepare_sha256"])

            def execute_unverified(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            envelope_status="unverified",
                        ))

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
            auth_hash = hashlib.sha256(
                (packet / packet_mod.AUTHORIZE_FILENAME).read_bytes()).hexdigest()

            executed = []

            def execute(**kwargs):
                executed.append({
                    "auth": hashlib.sha256(Path(kwargs["authorize_path"]).read_bytes()).hexdigest(),
                    "prep": hashlib.sha256(Path(kwargs["prepare_path"]).read_bytes()).hexdigest(),
                })
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256=prepare_hash))

            d1 = _run_ok(base, "packet", rels, execute=execute, out_name="o1")
            self.assertEqual(d1["decision"], "publish")
            self.assertEqual(executed[-1]["auth"], auth_hash)
            self.assertEqual(executed[-1]["prep"], prepare_hash)

            bad_bindings = dict(BINDINGS)
            bad_bindings["candidate_revision"] = OTHER_CANDIDATE
            (packet / hosted.DISPATCH_BINDINGS_FILENAME).write_text(
                json.dumps(bad_bindings, sort_keys=True) + "\n", encoding="utf-8"
            )
            rels["manifest_sha256"] = _seal_packet(packet)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(
                    base, "packet", rels, candidate=OTHER_CANDIDATE,
                    bindings=bad_bindings, execute=execute, out_name="o2",
                )
            self.assertEqual(str(ctx.exception), "candidate_revision_binding")
            # Prepare/authorize bytes unchanged; refusal is identity binding.
            self.assertEqual(
                hashlib.sha256((packet / packet_mod.PREPARE_FILENAME).read_bytes()).hexdigest(),
                prepare_hash,
            )

    def test_envelope_prepare_sha256_binds_checked_prepare_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_prep(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256="ab" * 32))

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
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            execution_commit=OTHER_RUNNER,
                        ))

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_wrong_commit, out_name="out")

            def execute_wrong_image(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            requested={
                                "image_id": OTHER_IMAGE,
                                "execution_profile": "contained-oci-v0",
                            },
                        ))

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
                    packet_manifest_sha256=rels["manifest_sha256"],
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
                    packet_manifest_sha256=rels["manifest_sha256"],
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
            rels["manifest_sha256"] = _seal_packet(packet)
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
                    packet_manifest_sha256=rels["manifest_sha256"],
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
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["PATH", "GITHUB_TOKEN"],
                                "image_env_names": ["PATH", "GITHUB_TOKEN"],
                            },
                        ))

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

    def test_unsealed_and_forged_profile_envelope_refused(self):
        sha = _prepare_sha256()
        env_unsealed = _permitted_envelope(
            prepare_sha256=sha,
            requested=_base_envelope_requested(sealed=False),
            effective=_base_envelope_effective(sealed=False),
        )
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(env_unsealed, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "sealed_binding")

        env_forged_prof = _permitted_envelope(prepare_sha256=sha)
        env_forged_prof["requested"]["resource_profile"] = {
            **contained.CANDIDATE_RESOURCE_PROFILE,
            "pids": 999999,
        }
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(env_forged_prof, bindings=BINDINGS, prepare_sha256=sha)
        self.assertEqual(str(ctx.exception), "resource_profile_binding")

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
            _permitted_envelope(
                envelope_status="unverified", publication_permission="permitted"
            ),
            setup_status="ready",
        )
        self.assertEqual(leaked["decision"], "publish")
        self.assertEqual(
            hosted.publication_decision(
                _permitted_envelope(
                    envelope_status="unverified", publication_permission="permitted"
                ),
                setup_status="ready",
            )["decision"],
            "withhold",
        )

    def test_mutation_delete_refuse_hostile_call_is_red(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        # Anchored on the per-member loop: the call moved inside it when the gate began
        # quantifying over every observation instead of one envelope.
        call = (
            "            observed_child = observe_child_environment(member)\n"
            "            refuse_hostile_workflow(\n"
            '                env_names=observed_child["env_names"],\n'
            '                mounts=observed_child["mounts"],\n'
            "            )\n"
        )
        self.assertEqual(original.count(call), 1)
        mutated = original.replace(call, "            pass  # mutated: refuse unwired\n", 1)
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_refuse")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["GITHUB_TOKEN"],
                                "image_env_names": ["GITHUB_TOKEN"],
                            },
                        ))

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
                packet_manifest_sha256=rels["manifest_sha256"],
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
            rels["manifest_sha256"] = _seal_packet(packet)

            def execute(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))

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
                    packet_manifest_sha256=rels["manifest_sha256"],
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
                packet_manifest_sha256=rels["manifest_sha256"],
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
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))

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
                packet_manifest_sha256=rels["manifest_sha256"],
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
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256=rels["prepare_sha256"]))

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
                    packet_manifest_sha256=rels["manifest_sha256"],
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
                packet_manifest_sha256=rels["manifest_sha256"],
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
        # The whole sanitization block is the control: slicing it from the source keeps the
        # mutation honest as the block moves, instead of pinning a brittle literal.
        begin = original.index("            try:\n"
                               "                materialize_post_execute_refusal(")
        stop = original.index("raise exc from cleanup_exc\n", begin) + len(
            "raise exc from cleanup_exc\n")
        call = original[begin:stop]
        self.assertEqual(original.count(call), 1)
        self.assertIn("materialize_post_execute_refusal", call)
        mutated = original.replace(call, "            pass  # mutated: no sanitize\n", 1)
        self.assertNotEqual(mutated, original)
        bad = _load_mutated_module(mutated, "mut_no_sanitize")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                            prepare_sha256=rels["prepare_sha256"],
                            effective={
                                "env_names": ["GITHUB_TOKEN"],
                                "image_env_names": ["GITHUB_TOKEN"],
                            },
                        ))

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
                    packet_manifest_sha256=rels["manifest_sha256"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_cred,
                )
            leaked = _read_only_member(base / "bad")
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
            '        status="refused", reason=reason, bindings=bindings,\n'
            '        workflow_identity=workflow_identity)\n'
            '    envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)\n'
        )
        self.assertEqual(original.count(needle), 1)
        restored = (
            '    setup_doc = setup_status_doc(\n'
            '        status="refused", reason=reason, bindings=bindings,\n'
            '        workflow_identity=workflow_identity)\n'
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
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(prepare_sha256="ab" * 32))

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
                    packet_manifest_sha256=rels["manifest_sha256"],
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

    def test_load_envelope_huge_integer_refuses_json_input(self):
        doc = _permitted_envelope()
        raw = json.dumps(doc)
        huge_int = "9" * 10000
        mem = doc["effective"]["memory"]
        raw_mutated = raw.replace(f'"memory": {mem}', f'"memory": {huge_int}', 1)
        self.assertIn(huge_int, raw_mutated)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "envelope.v0.json"
            path.write_text(raw_mutated, encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope(path)
            self.assertEqual(str(ctx.exception), "json_input")

    def test_run_gate_huge_integer_envelope_materializes_post_execute_refusal(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            base = Path(raw_dir)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            huge_int = "9" * 10000

            def execute_huge_int_envelope(**kwargs):
                env = _permitted_envelope(prepare_sha256=rels["prepare_sha256"])
                serialized = json.dumps(env)
                mem = env["effective"]["memory"]
                mutated = serialized.replace(f'"memory": {mem}', f'"memory": {huge_int}', 1)
                _write_collection_raw(kwargs["envelope_dest"], env, mutated)

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(
                    base,
                    "packet",
                    rels,
                    execute=execute_huge_int_envelope,
                    out_name="out_huge_int",
                )
            self.assertEqual(str(ctx.exception), "json_input")
            out_dir = base / "out_huge_int"
            rerun_lines = [
                json.loads(line)
                for line in (out_dir / hosted.RERUN_EVIDENCE_FILENAME).read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]
            self.assertTrue(
                any(
                    entry.get("kind") == "post-execute-refusal"
                    and entry.get("reason") == "json_input"
                    for entry in rerun_lines
                ),
                f"expected post-execute-refusal in rerun lines, got: {rerun_lines}",
            )
            self.assertFalse(
                any(entry.get("kind") == "infrastructure-failure" for entry in rerun_lines),
                f"must not escape as infrastructure-failure: {rerun_lines}",
            )

    def test_run_gate_huge_integer_prepare_refuses_json_input(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            base = Path(raw_dir)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            prepare_file = packet / rels["prepare"]
            huge_int = "9" * 10000
            raw_prep = prepare_file.read_text(encoding="utf-8")
            mutated_prep = raw_prep.replace(
                '{"schema":', f'{{"huge": {huge_int}, "schema":', 1
            )
            self.assertIn(huge_int, mutated_prep)
            prepare_file.write_text(mutated_prep, encoding="utf-8")
            rels["manifest_sha256"] = _seal_packet(packet)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, out_name="out_prep_huge")
            self.assertEqual(str(ctx.exception), "json_input")

    def test_envelope_mount_spec_binding_enforced(self):
        doc = _permitted_envelope()
        bindings = {
            "candidate_revision": CANDIDATE,
            "runner_revision": doc["execution_commit"],
            "image_digest": doc["requested"]["image_id"],
        }
        prep_sha = doc["prepare_sha256"]

        # Valid candidate mount spec passes
        hosted.check_envelope_bindings(doc, bindings=bindings, prepare_sha256=prep_sha)

        # Forged /etc mount refused
        forged_doc = json.loads(json.dumps(doc))
        forged_doc["requested"]["mount_spec"] = [
            "/etc", "/input", "/subject", "/tool", "/vendor"
        ]
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(
                forged_doc, bindings=bindings, prepare_sha256=prep_sha
            )
        self.assertEqual(str(ctx.exception), "mount_spec_binding")

        # Empty mount spec refused
        empty_doc = json.loads(json.dumps(doc))
        empty_doc["requested"]["mount_spec"] = []
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(
                empty_doc, bindings=bindings, prepare_sha256=prep_sha
            )
        self.assertEqual(str(ctx.exception), "mount_spec_binding")

        # Missing mount refused
        missing_doc = json.loads(json.dumps(doc))
        missing_doc["requested"]["mount_spec"] = ["/input", "/subject", "/tool"]
        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            hosted.check_envelope_bindings(
                missing_doc, bindings=bindings, prepare_sha256=prep_sha
            )
        self.assertEqual(str(ctx.exception), "mount_spec_binding")

    def test_run_gate_forged_mount_spec_refused_post_execute(self):
        with tempfile.TemporaryDirectory() as raw_dir:
            base = Path(raw_dir)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_forged_mounts(**kwargs):
                env = _permitted_envelope(prepare_sha256=rels["prepare_sha256"])
                env["requested"]["mount_spec"] = [
                    "/etc", "/input", "/subject", "/tool", "/vendor"
                ]
                env["effective"]["mounts"] = [
                    {"destination": "/etc", "rw": False, "type": "bind"},
                    {"destination": "/input", "rw": False, "type": "bind"},
                    {"destination": "/subject", "rw": False, "type": "bind"},
                    {"destination": "/tool", "rw": False, "type": "bind"},
                    {"destination": "/vendor", "rw": False, "type": "bind"},
                ]
                _write_collection(kwargs["envelope_dest"], env)

            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(
                    base,
                    "packet",
                    rels,
                    execute=execute_forged_mounts,
                    out_name="out_forged_mounts",
                )
            self.assertEqual(str(ctx.exception), "mount_spec_binding")
            out_dir = base / "out_forged_mounts"
            rerun_lines = [
                json.loads(line)
                for line in (out_dir / hosted.RERUN_EVIDENCE_FILENAME).read_text(
                    encoding="utf-8"
                ).splitlines()
                if line.strip()
            ]
            self.assertTrue(
                any(
                    entry.get("kind") == "post-execute-refusal"
                    and entry.get("reason") == "mount_spec_binding"
                    for entry in rerun_lines
                )
            )

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


class QuarantineRetainsEveryRefusal(unittest.TestCase):
    """The out root is reusable, so a second refusal must not cost the first one's evidence."""

    def _refuse_once(self, out, marker):
        ledger = collection.Ledger()
        doc = dict(_permitted_envelope(prepare_sha256="a" * 64))
        doc["execution_commit"] = marker
        ledger.recorded(ledger.register(), doc)
        collection.write_collection(
            ledger, out / hosted.COLLECTION_DIRNAME, report_sha256="e" * 64)
        hosted.write_separate_artifacts(
            out, {"kind": "setup-status"},
            hosted.withheld_envelope_stub(reason="r", bindings=BINDINGS),
            {"kind": "void-hosted-result"})

    def test_two_successive_refusals_retain_both_byte_sets(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw) / "artifacts"
            out.mkdir(parents=True)
            self._refuse_once(out, "c" * 40)
            self._refuse_once(out, "d" * 40)
            parent = out / hosted.WITHHELD_COLLECTION_DIRNAME
            attempts = sorted(p.name for p in parent.iterdir() if p.is_dir())
            self.assertEqual(attempts, ["attempt-0000", "attempt-0001"],
                             "a repeated refusal overwrote the first retained evidence")
            commits = set()
            for name in attempts:
                member = json.loads(
                    (parent / name / (collection.MEMBER_TEMPLATE % 0)).read_text("utf-8"))
                commits.add(member["execution_commit"])
            self.assertEqual(commits, {"c" * 40, "d" * 40},
                             "both refusals must keep their own observed bytes")
            self.assertFalse((out / hosted.COLLECTION_DIRNAME).exists())


class QuarantineFailureKeepsThePrimaryRefusal(unittest.TestCase):
    """A cleanup failure is context on the refusal, never a replacement for it."""

    def test_rename_failure_does_not_mask_the_refusal_reason(self):
        original = Path(hosted.__file__).read_text(encoding="utf-8")
        anchor = "    live.rename(attempt)\n"
        self.assertEqual(original.count(anchor), 1)
        mutated = original.replace(
            anchor, '    raise OSError("injected rename failure")\n', 1)
        bad = _load_mutated_module(mutated, "mut_rename_fail")
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_cred(**kwargs):
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                    prepare_sha256=rels["prepare_sha256"],
                    effective={"env_names": ["GITHUB_TOKEN"],
                               "image_env_names": ["GITHUB_TOKEN"]}))

            out = base / "artifacts"
            with self.assertRaises(bad.HostedPublicationError) as ctx:
                bad.run_gate(
                    candidate_revision=CANDIDATE, runner_revision=RUNNER,
                    image_digest=IMAGE, operator_profile="contained-oci-v0",
                    out_dir=out, workspace_root=base, packet_root="packet",
                    authorize_path=packet_mod.AUTHORIZE_FILENAME,
                    prepare_path=packet_mod.PREPARE_FILENAME,
                    pins_dir=packet_mod.PINS_DIRNAME,
                    packet_manifest_sha256=rels["manifest_sha256"],
                    docker_ready=lambda: "27.0.0",
                    sealed_execute=execute_cred)
            # The refusal reason survives; the cleanup failure is only its cause chain.
            self.assertEqual(str(ctx.exception), "credential_env")
            self.assertIsInstance(ctx.exception.__cause__, OSError)
            # And the permitted members are still on disk, which is exactly why the published
            # upload is authorized by gate success rather than by always().
            self.assertTrue((out / bad.COLLECTION_DIRNAME).is_dir())


PINS_SOURCE = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
RELEASE_REPOSITORY = "corpus-adequacy/corpus-adequacy"
RELEASE_TAG = "hosted-packet-r1"


def _git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          text=True, env=env).stdout


class _FakeRelease:
    """Release assets by exact URL; no network."""

    def __init__(self, assets):
        self.assets = dict(assets)
        self.prefix = "https://github.com/%s/releases/download/%s/" % (
            RELEASE_REPOSITORY, RELEASE_TAG)

    def __call__(self, url, max_bytes):
        assert url.startswith(self.prefix), url
        return self.assets[url[len(self.prefix):]]


def _publish_and_fetch(workspace: Path, files: dict) -> str:
    """Publish `files` as a release with a manifest, fetch it into the fixed directory, and
    return the manifest digest the fetch was bound to."""
    digests = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    manifest = (json.dumps({"files": digests, "schema": packet_mod.MANIFEST_SCHEMA},
                           indent=2, sort_keys=True) + "\n").encode("utf-8")
    sha = hashlib.sha256(manifest).hexdigest()
    packet_mod.fetch_packet(
        repository=RELEASE_REPOSITORY, tag=RELEASE_TAG, manifest_sha256=sha,
        workspace_root=workspace, dest=packet_mod.PACKET_DIRNAME,
        open_url=_FakeRelease({packet_mod.MANIFEST_FILENAME: manifest, **files}))
    return sha


def _packet_files(bindings, prepare_raw):
    return {
        packet_mod.AUTHORIZE_FILENAME: b"authorize-bytes",
        packet_mod.BINDINGS_FILENAME: (json.dumps(bindings, sort_keys=True) + "\n").encode(),
        packet_mod.PREPARE_FILENAME: prepare_raw,
    }


def _fetched_workspace(base: Path):
    """A git workspace holding R's pins, with a packet fetched into the fixed directory."""
    ws = base / "ws"
    ws.mkdir()
    _git(ws, "init", "-q")
    pins = ws / "measurements" / "aee-checker-25b9dfa"
    pins.mkdir(parents=True)
    for name in os.listdir(PINS_SOURCE):
        shutil.copyfile(PINS_SOURCE / name, pins / name)
    prepare_raw = _prepare_raw()
    sha = _publish_and_fetch(ws, _packet_files(BINDINGS, prepare_raw))
    return ws, sha, hashlib.sha256(prepare_raw).hexdigest()


def _gate_fetched(ws, sha, *, execute, out_name="artifacts", **over):
    kwargs = dict(
        candidate_revision=CANDIDATE, runner_revision=RUNNER, image_digest=IMAGE,
        operator_profile=hosted.REQUIRED_PROFILE, out_dir=ws / out_name,
        workspace_root=ws, packet_root=packet_mod.PACKET_DIRNAME,
        authorize_path=packet_mod.AUTHORIZE_FILENAME,
        prepare_path=packet_mod.PREPARE_FILENAME, pins_dir=packet_mod.PINS_DIRNAME,
        packet_manifest_sha256=sha, docker_ready=lambda: "27.0.0", sealed_execute=execute)
    kwargs.update(over)
    return hosted.run_gate(**kwargs)


class HostedPacketDelivery(unittest.TestCase):
    """#107 packet delivery: the fetched packet is bound by its manifest digest in the gate."""

    def test_untracked_packet_accepted_at_head_and_execution_identity_unchanged(self):
        with tempfile.TemporaryDirectory() as raw:
            root = _committed_execution_root(Path(raw))
            # R carries its pins in-tree; the fetch copies them from the checked-out tree.
            pins = root / "measurements" / "aee-checker-25b9dfa"
            for name in os.listdir(PINS_SOURCE):
                shutil.copyfile(PINS_SOURCE / name, pins / name)
            _git(root, "add", "-A")
            _git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "pins")
            head = _git(root, "rev-parse", "HEAD").strip()
            before = sealed_run.execution_identity(root)
            self.assertEqual(before["commit"], head)

            bindings = {"candidate_revision": CANDIDATE, "runner_revision": head,
                        "image_digest": IMAGE}
            prepare_raw = _prepare_raw(bindings=bindings, prepare_extra={"execution": before})
            sha = _publish_and_fetch(root, _packet_files(bindings, prepare_raw))

            status = _git(root, "status", "--porcelain", "--untracked-files=normal")
            self.assertIn("?? %s/" % packet_mod.PACKET_DIRNAME, status.splitlines())
            self.assertEqual(sealed_run.execution_identity(root), before,
                             "an untracked packet changed the execution identity")

            observed = []

            def execute(**kwargs):
                # The driver's own identity comparison, against the tree the packet sits in.
                prepared = json.loads(Path(kwargs["prepare_path"]).read_bytes())
                observed.append(
                    sealed_run.execution_identity(Path(kwargs["root"])) == prepared["execution"])
                _write_collection(kwargs["envelope_dest"], _permitted_envelope(
                    prepare_sha256=hashlib.sha256(prepare_raw).hexdigest(),
                    execution_commit=head))

            decision = _gate_fetched(
                root, sha, execute=execute, runner_revision=head, root=root,
                environ={"GITHUB_SHA": head, "GITHUB_WORKFLOW_SHA": head})
            self.assertEqual(decision["decision"], "publish")
            self.assertEqual(observed, [True])
            setup = json.loads((root / "artifacts" / hosted.SETUP_STATUS_FILENAME).read_text())
            self.assertEqual(setup["workflow_identity"]["github_sha"], head)
            self.assertEqual(setup["workflow_identity"]["github_workflow_sha"], head)
            self.assertEqual(sealed_run.execution_identity(root), before)

    def _refused_before_execute(self, ws, sha, reason, **over):
        seen = []

        def spy(**kwargs):
            seen.append(True)

        with self.assertRaises(hosted.HostedPublicationError) as ctx:
            _gate_fetched(ws, sha, execute=spy, **over)
        self.assertEqual(str(ctx.exception), reason)
        self.assertEqual(seen, [], "a packet refusal reached execution")

    def test_fetched_packet_publishes_at_its_bound_digest(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, prepare_sha = _fetched_workspace(Path(raw))

            def execute(**kwargs):
                _write_collection(kwargs["envelope_dest"],
                                  _permitted_envelope(prepare_sha256=prepare_sha))

            self.assertEqual(_gate_fetched(ws, sha, execute=execute)["decision"], "publish")

    def test_gate_refuses_other_manifest_digest_even_though_the_fetch_passed(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            other = hashlib.sha256(b"a different manifest").hexdigest()
            self.assertNotEqual(other, sha)
            self._refused_before_execute(ws, other, "packet_manifest_binding")

    def test_gate_refuses_manifest_rewritten_after_the_fetch(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            path = ws / packet_mod.PACKET_DIRNAME / packet_mod.MANIFEST_FILENAME
            path.write_bytes(path.read_bytes() + b"\n")
            self._refused_before_execute(ws, sha, "packet_manifest_binding")

    def test_gate_compares_the_manifest_digest_before_parsing_it(self):
        """Unparseable bytes under the manifest name refuse for their digest, not their syntax."""
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            path = ws / packet_mod.PACKET_DIRNAME / packet_mod.MANIFEST_FILENAME
            path.write_bytes(b"{not json")
            self._refused_before_execute(ws, sha, "packet_manifest_binding")

    def test_gate_refuses_a_packet_file_changed_after_the_fetch(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            path = ws / packet_mod.PACKET_DIRNAME / packet_mod.AUTHORIZE_FILENAME
            path.write_bytes(b"other-authorize-bytes")
            self._refused_before_execute(ws, sha, "packet_file_binding")

    def test_gate_refuses_an_extra_packet_entry(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            (ws / packet_mod.PACKET_DIRNAME / "extra.json").write_bytes(b"{}\n")
            self._refused_before_execute(ws, sha, "packet_entries")

    def test_gate_refuses_a_symlinked_packet_file(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            path = ws / packet_mod.PACKET_DIRNAME / packet_mod.PREPARE_FILENAME
            elsewhere = Path(raw) / "prepare-elsewhere"
            elsewhere.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(elsewhere)
            self._refused_before_execute(ws, sha, "confined_path")

    def test_gate_refuses_swapped_roles_even_with_every_digest_intact(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            self._refused_before_execute(
                ws, sha, "packet_role_binding",
                authorize_path=packet_mod.PREPARE_FILENAME,
                prepare_path=packet_mod.AUTHORIZE_FILENAME)

    def test_gate_names_a_manifest_the_shared_parser_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, _sha, _ = _fetched_workspace(Path(raw))
            path = ws / packet_mod.PACKET_DIRNAME / packet_mod.MANIFEST_FILENAME
            doc = json.loads(path.read_bytes())
            text = json.dumps(doc, sort_keys=True)
            dup = text.replace('"schema":', '"schema": "x", "schema":', 1).encode("utf-8")
            path.write_bytes(dup)
            self._refused_before_execute(
                ws, hashlib.sha256(dup).hexdigest(),
                "packet_manifest:manifest_duplicate_key")

    def test_gate_requires_a_well_formed_manifest_digest_when_a_packet_is_present(self):
        with tempfile.TemporaryDirectory() as raw:
            ws, sha, _ = _fetched_workspace(Path(raw))
            for bad in (None, "", sha.upper(), sha[:-1]):
                with self.subTest(bad=bad):
                    self._refused_before_execute(
                        ws, bad, "packet_manifest_sha256",
                        out_name="out-%s" % (bad or "none")[:8])

    def test_cli_carries_the_packet_manifest_flag_to_the_gate(self):
        seen = {}

        def fake_gate(**kwargs):
            seen.update(kwargs)
            return {}

        with mock.patch.object(hosted, "run_gate", fake_gate):
            code = hosted.main([
                "gate", "--candidate-revision", CANDIDATE, "--runner-revision", RUNNER,
                "--image-digest", IMAGE, "--out", "x", "--packet-manifest-sha256", "0" * 64,
                "--packet-root", packet_mod.PACKET_DIRNAME])
        self.assertEqual(code, 0)
        self.assertEqual(seen["packet_manifest_sha256"], "0" * 64)
        self.assertEqual(seen["packet_root"], packet_mod.PACKET_DIRNAME)


class WorkflowIdentityBinding(unittest.TestCase):
    """GITHUB_SHA == GITHUB_WORKFLOW_SHA == runner_revision, read from the environment."""

    def _refused(self, environ, reason):
        probed, executed = [], []

        def probe():
            probed.append(True)
            return "27.0.0"

        def spy(**kwargs):
            executed.append(True)

        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                _run_ok(base, "packet", rels, execute=spy, docker_ready=probe,
                        environ=environ)
            self.assertEqual(str(ctx.exception), reason)
            self.assertEqual((probed, executed), ([], []),
                             "the workflow identity must refuse before containment is probed")
            entries = [json.loads(line) for line in
                       (base / "artifacts" / hosted.RERUN_EVIDENCE_FILENAME)
                       .read_text(encoding="utf-8").splitlines() if line.strip()]
            start = [e for e in entries if e.get("kind") == "run-attempt-start"]
            self.assertEqual(len(start), 1)
            recorded = start[0]["workflow_identity"]
            self.assertEqual(recorded["github_sha"], environ.get("GITHUB_SHA"))
            self.assertEqual(recorded["github_workflow_sha"],
                             environ.get("GITHUB_WORKFLOW_SHA"))

    def test_workflow_sha_other_than_runner_revision_refuses(self):
        self._refused({"GITHUB_SHA": RUNNER, "GITHUB_WORKFLOW_SHA": OTHER_RUNNER},
                      "workflow_sha_binding")

    def test_github_sha_other_than_runner_revision_refuses(self):
        self._refused({"GITHUB_SHA": OTHER_RUNNER, "GITHUB_WORKFLOW_SHA": RUNNER},
                      "github_sha_binding")

    def test_both_equal_to_each_other_but_not_to_runner_revision_refuses(self):
        self._refused({"GITHUB_SHA": OTHER_RUNNER, "GITHUB_WORKFLOW_SHA": OTHER_RUNNER},
                      "github_sha_binding")

    def test_absent_workflow_sha_refuses(self):
        self._refused({"GITHUB_SHA": RUNNER}, "workflow_identity_absent")

    def test_absent_github_sha_refuses(self):
        self._refused({"GITHUB_WORKFLOW_SHA": RUNNER}, "workflow_identity_absent")

    def test_empty_values_refuse(self):
        self._refused({"GITHUB_SHA": "", "GITHUB_WORKFLOW_SHA": ""},
                      "workflow_identity_absent")

    def test_default_reads_the_process_environment(self):
        with mock.patch.dict(os.environ, {"GITHUB_WORKFLOW_SHA": OTHER_RUNNER}):
            with tempfile.TemporaryDirectory() as raw:
                base = Path(raw)
                packet = base / "packet"
                packet.mkdir()
                rels = _write_packet(packet)
                with self.assertRaises(hosted.HostedPublicationError) as ctx:
                    _run_ok(base, "packet", rels)
                self.assertEqual(str(ctx.exception), "workflow_sha_binding")

    def test_success_records_both_in_the_setup_artifact(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)
            environ = {"GITHUB_SHA": RUNNER, "GITHUB_WORKFLOW_SHA": RUNNER,
                       "ImageOS": "ubuntu24", "ImageVersion": "20260901.1.0"}
            decision = _run_ok(base, "packet", rels, environ=environ)
            self.assertEqual(decision["decision"], "publish")
            setup = json.loads(
                (base / "artifacts" / hosted.SETUP_STATUS_FILENAME).read_text())
            self.assertEqual(setup["workflow_identity"], {
                "github_sha": RUNNER, "github_workflow_sha": RUNNER,
                "image_os": "ubuntu24", "image_version": "20260901.1.0"})

    def test_refused_post_execute_setup_also_records_the_identity(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw)
            packet = base / "packet"
            packet.mkdir()
            rels = _write_packet(packet)

            def execute_wrong_prep(**kwargs):
                _write_collection(kwargs["envelope_dest"],
                                  _permitted_envelope(prepare_sha256="ab" * 32))

            with self.assertRaises(hosted.HostedPublicationError):
                _run_ok(base, "packet", rels, execute=execute_wrong_prep, out_name="o")
            setup = json.loads((base / "o" / hosted.SETUP_STATUS_FILENAME).read_text())
            self.assertEqual(setup["setup_status"], "refused")
            self.assertEqual(setup["workflow_identity"]["github_workflow_sha"], RUNNER)
