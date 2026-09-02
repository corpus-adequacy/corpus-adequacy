#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI contract for issue #211. Standard library only.

Does not invoke aee-checker against aee-conformance. Does not emit a report.
Source-string equality is a structural guard. Biting tests feed hostile
input, wrong digests, abnormal exits, and live inert probes.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import unittest.mock as mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_materialize as mat  # noqa: E402
import aee_checker_sealed_oci as oci  # noqa: E402
import aee_checker_sealed_run as run  # noqa: E402
import bounded_run as br  # noqa: E402
import contained_oci as contained  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
ADAPTER = REPO_ROOT / "adapters" / "aee_checker_sealed.py"
CONTAINERFILE = REPO_ROOT / "execution" / "aee-checker-sealed" / "Containerfile"

PHASE_A_DIGESTS = {
    "adapters/aee_checker_sealed.py": (
        "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
    ),
    "measurements/aee-checker-25b9dfa/manifest.json": (
        "d21f4831c48a633009cafb0672c2d4e986bffda21a2c82508c1b32486d414eee"
    ),
    "measurements/aee-checker-25b9dfa/pins.json": (
        "e2456cbfcbbda17800318703e296e72fcaf138037178bad1fe237bc2c460c7e4"
    ),
    "measurements/aee-checker-25b9dfa/sites.json": (
        "6223a15c5db5a7c19c4633474875615ec61f3d710e092939f46b80ee986e0c4c"
    ),
    "measurements/aee-checker-25b9dfa/control.json": (
        "5a85c46054240a4470da7c6a82e3f13b5f1c30ea301809a2500a47a6e2f91f71"
    ),
}

FORBIDDEN_PUBLIC = (
    "report.v0",
    "GO-RUN",
    "certification",
    "leaderboard",
    "partnership",
    "sandbox",
)
EMPTY_VENDOR = hashlib.sha256(b"").hexdigest()
MEMORY_4G = 4 * 1024 * 1024 * 1024
AEE_LF_ATTRS = (
    "bounded_run.py text eol=lf",
    "corpus_adequacy.py text eol=lf",
    "isolated_tree.py text eol=lf",
    "module_child.py text eol=lf",
    "adapters/aee_checker_sealed.py text eol=lf",
    "measurements/aee-checker-25b9dfa/** text eol=lf",
    "measurements/aee_checker_sealed_common.py text eol=lf",
    "measurements/contained_oci.py text eol=lf",
    "measurements/aee_checker_sealed_materialize.py text eol=lf",
    "measurements/aee_checker_sealed_oci.py text eol=lf",
    "measurements/aee_checker_sealed_candidate.py text eol=lf",
    "measurements/aee_checker_sealed_driver.py text eol=lf",
    "measurements/aee_checker_sealed_runtime.py text eol=lf",
    "tests/test_aee_checker_sealed_driver.py text eol=lf",
    "tests/test_aee_checker_sealed_runtime.py text eol=lf",
    "measurements/aee_checker_sealed_run.py text eol=lf",
    "tests/test_aee_checker_sealed_run.py text eol=lf",
    "execution/aee-checker-sealed/** text eol=lf",
)
AEE_LF_PATHS = (
    "bounded_run.py",
    "corpus_adequacy.py",
    "isolated_tree.py",
    "module_child.py",
    "adapters/aee_checker_sealed.py",
    "measurements/aee-checker-25b9dfa/control.json",
    "measurements/aee-checker-25b9dfa/manifest.json",
    "measurements/aee-checker-25b9dfa/pins.json",
    "measurements/aee-checker-25b9dfa/sites.json",
    "measurements/aee_checker_sealed_common.py",
    "measurements/contained_oci.py",
    "measurements/aee_checker_sealed_materialize.py",
    "measurements/aee_checker_sealed_oci.py",
    "measurements/aee_checker_sealed_candidate.py",
    "measurements/aee_checker_sealed_driver.py",
    "measurements/aee_checker_sealed_runtime.py",
    "tests/test_aee_checker_sealed_driver.py",
    "tests/test_aee_checker_sealed_runtime.py",
    "measurements/aee_checker_sealed_run.py",
    "tests/test_aee_checker_sealed_run.py",
    "execution/aee-checker-sealed/Containerfile",
    "execution/aee-checker-sealed/probe.sh",
    "execution/aee-checker-sealed/cargo-config.toml",
)
REQUIRED_EXECUTION_PATHS = (
    "bounded_run.py",
    "corpus_adequacy.py",
    "isolated_tree.py",
    "module_child.py",
    "adapters/aee_checker_sealed.py",
    "measurements/aee-checker-25b9dfa/manifest.json",
    "measurements/aee_checker_sealed_run.py",
    "measurements/aee_checker_sealed_common.py",
    "measurements/contained_oci.py",
    "measurements/aee_checker_sealed_oci.py",
    "measurements/aee_checker_sealed_candidate.py",
    "measurements/aee_checker_sealed_materialize.py",
    "measurements/aee_checker_sealed_authorize.py",
    "measurements/aee_checker_sealed_execute.py",
    "measurements/aee_checker_sealed_driver.py",
    "measurements/aee_checker_sealed_runtime.py",
    "execution/aee-checker-sealed/Containerfile",
    "execution/aee-checker-sealed/probe.sh",
    "execution/aee-checker-sealed/cargo-config.toml",
)


def _traceback_frames(exc: BaseException) -> list[str]:
    frames = []
    traceback = exc.__traceback__
    while traceback is not None:
        frames.append(traceback.tb_frame.f_code.co_name)
        traceback = traceback.tb_next
    return frames


PHASE_B_PY = (
    "measurements/aee_checker_sealed_run.py",
    "measurements/aee_checker_sealed_common.py",
    "measurements/contained_oci.py",
    "measurements/aee_checker_sealed_oci.py",
    "measurements/aee_checker_sealed_materialize.py",
)


def _fixture_contract(*, network_mode: str, offline: bool) -> dict:
    return {
        "cap_drop": ["ALL"],
        "memory": MEMORY_4G,
        "memory_swap": MEMORY_4G,
        "network_mode": network_mode,
        "no_new_privileges": True,
        "offline_env": offline,
        "pids": 512,
        "read_only_root": True,
        "readonly_mounts": ["/input", "/tool", "/vendor"],
        "tmpfs": {
            "/tmp": {"nr_inodes": 128, "size": 1048576},
            "/work": {"nr_inodes": 128, "size": 1048576},
        },
        "user": "65532:65532",
    }


def _probe_row(mechanism: str, refusal: str, *, control_net="none") -> dict:
    return {
        "mechanism": mechanism,
        "control": "completed",
        "refusal": refusal,
        "inspect": {
            "control": _fixture_contract(network_mode=control_net, offline=True),
            "refusal": _fixture_contract(network_mode="none", offline=True),
        },
    }


def _committed_execution_root(tmp: Path) -> Path:
    root = tmp / "exec-root"
    for rel in run.EXECUTION_PATHS:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, dest)
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "exec"],
        cwd=root, check=True, capture_output=True,
    )
    return root


def _write_corpus(corpus: Path, digest: str, count: int = 250) -> bytes:
    vectors = []
    for i in range(count):
        rel = "accept/%03d.json" % i
        path = corpus / "vectors" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}\n")
        vectors.append({"id": "v-%03d" % i, "file": rel})
    manifest = {"corpusDigest": digest, "vectors": vectors}
    raw = (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8")
    (corpus / "vectors" / "MANIFEST.json").write_bytes(raw)
    return raw


def _tiny_tar(dest: Path, files: dict[str, bytes], prefix: str = "repo-abc", extras=()) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dest, "w:gz") as tar:
        for rel, data in files.items():
            info = tarfile.TarInfo("%s/%s" % (prefix, rel))
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for info, data in extras:
            payload = io.BytesIO(data) if data is not None else None
            tar.addfile(info, payload)
    return dest


def _git_eol(root: Path, rel: str) -> str:
    out = subprocess.check_output(
        ["git", "check-attr", "eol", "--", rel], cwd=root, text=True)
    line = out.strip().splitlines()[-1]
    name, attr, value = line.split(": ")
    if attr != "eol" or name != rel:
        raise AssertionError("check-attr %r" % line)
    return value


def _local_git_repo(tmp: Path, name: str, files: dict[str, bytes]):
    repo = tmp / name
    repo.mkdir()
    for rel, data in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", name],
        cwd=repo, check=True, capture_output=True,
    )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    return repo, commit


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _docker_ready() -> bool:
    try:
        run.require_docker_ready()
        return True
    except run.DockerUnavailable:
        return False


CARGO = shutil.which("cargo") is not None


class PhaseAImmutable(unittest.TestCase):
    def test_frozen_phase_a_bytes_match_preregistration_digests(self):
        for rel, digest in PHASE_A_DIGESTS.items():
            raw = (REPO_ROOT / rel).read_bytes()
            self.assertEqual(_sha256(raw), digest, rel)
        run.verify_phase_a_frozen(PREREG, adapter=ADAPTER)

    def test_prepare_refuses_mutated_phase_a_pins(self):
        with tempfile.TemporaryDirectory() as d:
            pins = Path(d) / "pins"
            shutil.copytree(PREREG, pins)
            sites = json.loads((pins / "sites.json").read_text(encoding="utf-8"))
            sites["selected_count"] = 6
            (pins / "sites.json").write_text(json.dumps(sites), encoding="utf-8")
            dest = Path(d) / "out"
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_phase_a_frozen(pins)
            self.assertIn("phase-a", str(ctx.exception).lower())
            with self.assertRaises(run.PrepareError):
                run.prepare(pins, dest, root=REPO_ROOT)
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(d).glob(".out.partial-*")), [])

    def test_frozen_dir_still_has_only_prereg_files(self):
        names = sorted(p.name for p in PREREG.iterdir())
        self.assertEqual(
            names,
            ["control.json", "manifest.json", "pins.json", "sites.json"],
        )
        for forbidden in (
            "ceilings.json",
            "report.v0.json",
            "prepare.v0.json",
            "result.json",
        ):
            self.assertFalse((PREREG / forbidden).exists(), forbidden)


class StrictPinsBuffer(unittest.TestCase):
    def test_verify_phase_a_returns_parsed_pins_and_ignores_later_overwrite(self):
        pins = run.verify_phase_a_frozen(PREREG, adapter=ADAPTER)
        self.assertEqual(pins["instrument"]["commit"], run.PHASE_A_INSTRUMENT_COMMIT)
        with tempfile.TemporaryDirectory() as d:
            copy = Path(d) / "pins"
            shutil.copytree(PREREG, copy)
            parsed = run.verify_phase_a_frozen(copy)
            (copy / "pins.json").write_text("{}\n", encoding="utf-8")
            self.assertEqual(
                parsed["instrument"]["commit"], run.PHASE_A_INSTRUMENT_COMMIT)

    def test_strict_parse_refuses_duplicate_and_nonfinite(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.load_strict(b'{"a":1,"a":2}')
        self.assertIn("duplicate", str(ctx.exception).lower())
        with self.assertRaises(run.PrepareError) as ctx:
            run.load_strict(b'{"n":1e999}')
        self.assertRegex(str(ctx.exception).lower(), r"non-finite|finite")


class VendorOutsideSubject(unittest.TestCase):
    def test_vendor_inside_subject_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            subject = Path(d) / "subject"
            vendor = subject / "vendor"
            subject.mkdir()
            vendor.mkdir()
            with self.assertRaises(run.PrepareError) as ctx:
                run.require_vendor_outside(subject, vendor)
            self.assertIn("outside", str(ctx.exception).lower())

    def test_vendor_outside_subject_is_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            subject = root / "subject"
            vendor = root / "vendor"
            subject.mkdir()
            vendor.mkdir()
            run.require_vendor_outside(subject, vendor)


class ImageIdentity(unittest.TestCase):
    def test_mutable_tag_is_refused(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.require_image_id("busybox:latest")
        self.assertIn("sha256", str(ctx.exception).lower())

    def test_digest_reference_is_accepted(self):
        digest = "sha256:" + ("ab" * 32)
        self.assertEqual(run.require_image_id(digest), digest)

    def test_short_or_non_hex_digest_is_refused(self):
        with self.assertRaises(run.PrepareError):
            run.require_image_id("sha256:abcd")
        with self.assertRaises(run.PrepareError):
            run.require_image_id("sha256:" + ("g" * 64))


class ClassifyAbnormal(unittest.TestCase):
    def test_valid_json_plus_exit_2_is_abnormal_never_success(self):
        raw = b'{"ok":true,"rows":{}}\n'
        result = run.classify_container_result(2, raw)
        self.assertEqual(result["state"], "abnormal")
        self.assertNotEqual(result["state"], "completed")
        self.assertNotIn("rows", result)
        self.assertIsNone(result.get("parsed"))
        self.assertNotIn("ok", result)

    def test_accepting_parseable_exit_2_as_completed_is_a_false_green(self):
        raw = b'{"ok":true,"schema":"not-a-success"}\n'
        result = run.classify_container_result(2, raw)
        self.assertEqual(result["state"], "abnormal")
        self.assertIsNone(result.get("parsed"))
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = PrepareEvidence()._parts()
            parts["probe_evidence"] = [
                row if row["mechanism"] != "protocol-exit"
                else {**row, "refusal": "completed"}
                for row in parts["probe_evidence"]
            ]
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"abnormal|protocol|pair|refusal")

    def test_exit_0_small_output_is_completed_without_scoring(self):
        result = run.classify_container_result(0, b'{"probe":"ok"}\n')
        self.assertEqual(result["state"], "completed")
        self.assertNotIn("score", result)
        self.assertNotIn("verdict", result)

    def test_boolean_exit_is_harness_failure(self):
        result = run.classify_container_result(True, b"{}\n")
        self.assertEqual(result["state"], "harness_failure")


class DockerArgvContract(unittest.TestCase):
    def test_mount_spec_rejects_every_invalid_shape(self):
        invalid_specs = (
            (),
            (("input",),),
            ((1, "/input"),),
            (("", "/input"),),
            (("input", "input"),),
            (("input", "/input"), ("input", "/other")),
            (("input", "/input"), ("other", "/input")),
        )
        for mount_spec in invalid_specs:
            with self.subTest(mount_spec=mount_spec):
                with self.assertRaisesRegex(
                        run.PrepareError, "^mount specification$"):
                    oci._require_mount_spec(mount_spec)

    def test_create_argv_names_a_missing_required_mount_source(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = {name: Path(d) / name for name in ("input", "vendor")}
            for path in mounts.values():
                path.mkdir()
            with self.assertRaisesRegex(
                    run.PrepareError, "^mount source missing: tool$"):
                run.docker_create_argv(
                    image_id="sha256:" + ("cd" * 32),
                    name="aee-sealed-inert-missing-mount",
                    mounts=mounts,
                    command=["ok"],
                )

    def test_create_argv_binds_immutable_id_and_resource_contract(self):
        image = "sha256:" + ("cd" * 32)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mounts = {name: root / name for name in ("input", "vendor", "tool")}
            for path in mounts.values():
                path.mkdir()
            argv = run.docker_create_argv(
                image_id=image,
                name="aee-sealed-inert-ok",
                mounts=mounts,
                command=["ok"],
            )
        text = " ".join(argv)
        self.assertEqual(argv[:2], ["docker", "create"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges:true", text)
        self.assertIn("65532:65532", text)
        self.assertEqual(argv[argv.index("--memory") + 1], "4g")
        self.assertEqual(argv[argv.index("--memory-swap") + 1], "4g")
        self.assertEqual(argv[argv.index("--pids-limit") + 1], "512")
        self.assertNotIn("--cpus", argv)
        self.assertNotIn("nofile", text)
        self.assertTrue(
            any(item.startswith("/tmp:") and "nr_inodes=" in item for item in argv),
            argv,
        )
        self.assertTrue(
            any(item.startswith("/work:") and "nr_inodes=" in item for item in argv),
            argv,
        )
        self.assertIn(str(run.TMPFS_BYTES), text)
        self.assertIn(str(run.TMPFS_INODES), text)
        self.assertIn(image, argv)
        self.assertNotIn("busybox", text)
        self.assertLess(argv.index("--network"), argv.index(image))
        for dest in ("/input", "/vendor", "/tool"):
            self.assertIn("destination=%s,readonly" % dest, text.replace(" ", ""))

    def test_network_control_argv_does_not_use_network_none(self):
        image = "sha256:" + ("cd" * 32)
        with tempfile.TemporaryDirectory() as d:
            mounts = {name: Path(d) / name for name in ("input", "vendor", "tool")}
            for path in mounts.values():
                path.mkdir()
            argv = run.docker_create_argv(
                image_id=image,
                name="aee-sealed-inert-net",
                mounts=mounts,
                command=["network"],
                sealed=False,
            )
        self.assertNotIn("none", argv[argv.index("--network") + 1] if "--network" in argv else "")
        self.assertNotIn("CARGO_NET_OFFLINE=true", " ".join(argv))

    def test_create_argv_refuses_tag_even_if_caller_bypasses_require(self):
        with tempfile.TemporaryDirectory() as d:
            mounts = {name: Path(d) / name for name in ("input", "vendor", "tool")}
            for path in mounts.values():
                path.mkdir()
            with self.assertRaises(run.PrepareError):
                run.docker_create_argv(
                    image_id="busybox:1.37",
                    name="aee-sealed-inert-bad",
                    mounts=mounts,
                    command=["ok"],
                )


class PrepareEvidence(unittest.TestCase):
    def _parts(self) -> dict:
        return {
            "pins": {
                "subject_commit": "25b9dfa797986624f2d680530a7228232aa3ddda",
                "corpus_commit": "59faf842098183ae7b5387ad13e6351c44687279",
                "corpus_digest": (
                    "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579"
                ),
                "instrument_commit": "1347651c2087cbd5c2e958a758b380a9a6cfc67d",
                "phase_a": dict(PHASE_A_DIGESTS),
            },
            "execution": {
                "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "content_sha256": "cc" * 32,
                "paths": list(run.EXECUTION_PATHS),
            },
            "materialized": {
                "subject_check_rs_sha256": (
                    "1623780ae759c070a85b74e2de6df6dac28f13f068cecbc1ea4b10e070e7a86f"
                ),
                "corpus_digest": (
                    "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579"
                ),
                "corpus_id_count": 250,
                "corpus_id_set_sha256": "dd" * 32,
                "corpus_manifest_sha256": run.FROZEN_CORPUS_MANIFEST_SHA256,
                "corpus_tree_sha256": run.FROZEN_CORPUS_TREE_SHA256,
                "subject_tree_sha256": run.FROZEN_SUBJECT_TREE_SHA256,
                "tool_config_sha256": "ee" * 32,
                "vendor_sha256": "aa" * 32,
                "vendor_outside_subject": True,
                "subject_binary": False,
            },
            "image": {"id": "sha256:" + ("ab" * 32), "kind": "inert-probe"},
            "toolchain": {
                "cargo_V": "cargo 1.92.0 (test)",
                "image_id": "sha256:" + ("cd" * 32),
                "index": run.RUST_IMAGE,
                "observation": "vendor-image; checker was not run",
                "platform": "linux/arm64",
                "rustc_Vv": "rustc 1.92.0 (test)\n",
            },
            "runtime": {
                "docker": "test",
                "observation": "host-local; not a portable bound",
            },
            "ceilings": dict(run.DECLARED_CEILINGS),
            "materialize_ceilings": dict(run.MATERIALIZE_CEILINGS),
            "probe_evidence": [
                _probe_row("deadline", "deadline"),
                _probe_row("disk", "abnormal"),
                _probe_row("file-count", "abnormal"),
                _probe_row("network-off", "abnormal", control_net="bridge"),
                _probe_row("output", "output_cap"),
                _probe_row("protocol-exit", "abnormal"),
            ],
            "network": dict(run.NETWORK_CUTOFF),
            "oci": run.OCI_CONTRACT,
            "non_claims": list(run.NON_CLAIMS),
        }

    def test_prepare_v0_has_exact_keys_and_is_not_a_report(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            raw = run.emit_prepare_v0(self._parts(), dest)
            doc = json.loads(raw.decode("utf-8"))
            self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)
            self.assertEqual(doc["phase"], "prepare")
            self.assertEqual(set(doc), set(run.PREPARE_KEYS))
            self.assertNotEqual(doc["schema"], "corpus-adequacy.report.v0")
            self.assertNotIn("result", doc)
            self.assertNotIn("score", doc)
            self.assertNotIn("rows", doc)
            self.assertNotIn("vectors", doc["materialized"])
            self.assertIn("not a scientific measurement", " ".join(doc["non_claims"]))
            self.assertEqual(
                doc["pins"]["instrument_commit"], run.PHASE_A_INSTRUMENT_COMMIT)
            self.assertNotEqual(
                doc["execution"]["commit"], doc["pins"]["instrument_commit"])
            self.assertNotIn("instrument_commit", doc["execution"])
            self.assertFalse(doc["materialized"]["subject_binary"])

    def test_execution_must_not_reuse_the_frozen_instrument_commit(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["execution"]["commit"] = run.PHASE_A_INSTRUMENT_COMMIT
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"conflat|instrument|execution")

    def test_network_cutoff_is_named_and_prepare_is_not_offline(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
        self.assertEqual(doc["network"]["materialization"], "online")
        self.assertEqual(doc["network"]["sealed_oci"], "none")
        self.assertEqual(doc["network"]["cutoff"], "after_materialization")
        self.assertNotEqual(doc["network"]["materialization"], "none")

    def test_network_positive_runs_before_materialize_cutoff(self):
        src = inspect.getsource(run.prepare)
        cutoff = src.index("materialize_pinned")
        self.assertLess(src.index("sealed=False"), cutoff)
        self.assertEqual(src.count("sealed=False"), 1)
        self.assertNotIn("sealed=False", src[cutoff:])
        self.assertIn("sealed=True", src[cutoff:])
        self.assertEqual(list(run.PROBE_MECHANISMS)[3], "network-off")
        self.assertNotIn("network-off", run.SEALED_PROBE_PAIRS)

    def test_prepare_v0_stores_no_timings(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
        self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
        self.assertNotIn("host_evidence", doc)
        forbidden = {"elapsed_seconds", "elapsed", "duration", "timing", "wall_ms"}
        stack = [doc]
        while stack:
            item = stack.pop()
            if isinstance(item, dict):
                self.assertTrue(forbidden.isdisjoint(item), item)
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)

    def test_declared_ceilings_cannot_be_replaced_by_host_timing(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["ceilings"] = dict(run.DECLARED_CEILINGS)
            parts["ceilings"]["deadline_seconds"] = 0.4
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"declared|ceiling")

    def test_materialize_ceilings_are_separate_from_probe_tmpfs(self):
        self.assertNotEqual(run.MATERIALIZE_CEILINGS, run.DECLARED_CEILINGS)
        self.assertNotEqual(
            run.MATERIALIZE_CEILINGS["disk_bytes"], run.DECLARED_CEILINGS["disk_bytes"])
        self.assertNotEqual(
            run.MATERIALIZE_CEILINGS["entry_count"], run.DECLARED_CEILINGS["file_count"])
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
            self.assertEqual(doc["materialize_ceilings"], run.MATERIALIZE_CEILINGS)
            self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
            parts = self._parts()
            parts["materialize_ceilings"] = dict(run.DECLARED_CEILINGS)
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"materialize|ceiling")

    def test_probe_mechanisms_include_protocol_exit(self):
        self.assertIn("protocol-exit", run.PROBE_MECHANISMS)
        self.assertEqual(run.PROBE_MECHANISMS[-1], "protocol-exit")

    def test_omitting_protocol_exit_row_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["probe_evidence"] = [
                row for row in parts["probe_evidence"] if row["mechanism"] != "protocol-exit"
            ]
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"protocol|pair|evidence")

    def test_protocol_exit_refusal_must_be_exactly_abnormal(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["probe_evidence"] = [
                {**row, "refusal": "output_cap"} if row["mechanism"] == "protocol-exit" else row
                for row in parts["probe_evidence"]
            ]
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"abnormal|protocol-exit")

    def test_neighboring_refusal_cannot_satisfy_a_pinned_mechanism(self):
        self.assertEqual(run.EXPECTED_REFUSALS["deadline"], "deadline")
        self.assertEqual(run.EXPECTED_REFUSALS["output"], "output_cap")
        self.assertEqual(run.EXPECTED_REFUSALS["disk"], "abnormal")
        self.assertEqual(run.EXPECTED_REFUSALS["file-count"], "abnormal")
        self.assertEqual(run.EXPECTED_REFUSALS["network-off"], "abnormal")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["probe_evidence"] = [
                {**row, "refusal": "deadline"} if row["mechanism"] == "disk" else row
                for row in parts["probe_evidence"]
            ]
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"disk|abnormal|refusal")

    def test_probe_evidence_refuses_a_refusal_without_its_control(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["probe_evidence"] = [
                {**row, "control": None} if row["mechanism"] == "network-off" else row
                for row in parts["probe_evidence"]
            ]
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"control|pair")

    def test_empty_vendor_digest_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["materialized"]["vendor_sha256"] = EMPTY_VENDOR
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"empty|vendor")

    def test_oci_drops_unexercised_cpus_and_nofile(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            doc = json.loads(run.emit_prepare_v0(self._parts(), dest).decode("utf-8"))
        self.assertNotIn("cpus", doc["oci"])
        self.assertNotIn("nofile", doc["oci"])
        self.assertEqual(doc["oci"]["memory_swap_pids_claim"], "inspect-verified; not efficacy-tested")

    def test_per_vector_outcomes_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["materialized"]["vectors"] = {"v1": {"verdict": "valid"}}
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"outcome|vector")

    def test_subject_binary_record_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["materialized"]["subject_binary"] = True
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertIn("binary", str(ctx.exception).lower())

    def test_emit_prepare_v0_parts_only_is_byte_identical(self):
        """Parts-only emit. Not a production-path prepare() proof."""
        with tempfile.TemporaryDirectory() as d:
            left = Path(d) / "a.json"
            right = Path(d) / "b.json"
            parts = self._parts()
            self.assertEqual(
                run.emit_prepare_v0(parts, left),
                run.emit_prepare_v0(parts, right),
            )

    def test_host_path_or_timestamp_in_artifact_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["runtime"]["docker"] = "28.0.0 from /Users/x/.docker"
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"host path")
            parts = self._parts()
            parts["runtime"]["mtime"] = 1
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"timing")

    def test_extra_prepare_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["score"] = 1
            with self.assertRaises(run.PrepareError):
                run.emit_prepare_v0(parts, dest)


class PublicStrings(unittest.TestCase):
    def test_run_module_does_not_claim_a_result(self):
        texts = {
            rel: (REPO_ROOT / rel).read_text(encoding="utf-8") for rel in PHASE_B_PY
        }
        joined = "\n".join(texts.values())
        for rel, text in texts.items():
            for word in FORBIDDEN_PUBLIC:
                self.assertNotIn(word, text, "%s:%s" % (rel, word))
        self.assertIn("not a scientific measurement", joined)
        self.assertIn("checker was not run", joined)
        self.assertIn("vendor-image; checker was not run", joined)
        self.assertNotIn("host; checker was not run", joined)
        self.assertIn("after_materialization", joined)
        self.assertIn("subject binary is not produced here", joined)
        self.assertIn("not efficacy-tested", joined)
        self.assertNotIn("cargo build", joined)
        self.assertIn("cargo vendor --locked", joined)
        self.assertNotIn("entirely offline", joined)
        self.assertNotIn("--cpus", joined)
        self.assertNotIn("nofile", joined)
        self.assertNotIn("cleanup_named_containers", joined)
        self.assertNotIn("load_prepare_request", joined)
        self.assertNotIn("REQUEST_SCHEMA", joined)
        self.assertNotIn("git fetch", joined)
        self.assertNotIn("git clone", joined)
        self.assertFalse(hasattr(run, "fetch_commit"))

    def test_containerfile_is_inert_probe_not_aee_checker(self):
        text = CONTAINERFILE.read_text(encoding="utf-8")
        self.assertNotIn("aee-checker", text)
        self.assertNotIn("aee-conformance", text)
        self.assertNotIn("cargo run", text)
        self.assertIn("@sha256:", text)
        self.assertIn("COPY --chmod=0755", text)
        self.assertNotIn("RUN ", text)


class InspectContract(unittest.TestCase):
    def _ok(self, *, network_mode="none", offline=True, mounts=None,
            config_over=None, **host_over):
        host = {
            "NetworkMode": network_mode,
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": MEMORY_4G,
            "MemorySwap": MEMORY_4G,
            "PidsLimit": 512,
            "Tmpfs": {
                "/tmp": "rw,size=1048576,nr_inodes=128,mode=1777",
                "/work": "rw,size=1048576,nr_inodes=128,mode=1777",
            },
        }
        host.update(host_over)
        env = ["PATH=/usr/bin"]
        if offline:
            env.append("CARGO_NET_OFFLINE=true")
        config = {"User": "65532:65532", "Env": env}
        config.update(config_over or {})
        return {
            "HostConfig": host,
            "Config": config,
            "Mounts": mounts if mounts is not None else [
                {"Destination": "/input", "RW": False, "Type": "bind"},
                {"Destination": "/vendor", "RW": False, "Type": "bind"},
                {"Destination": "/tool", "RW": False, "Type": "bind"},
            ],
        }

    def test_omitted_readonly_root_is_refused(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.validate_inspect_contract(
                self._ok(ReadonlyRootfs=False), sealed=True)
        self.assertRegex(str(ctx.exception).lower(), r"readonly|read-only")

    def test_sealed_requires_network_none(self):
        with self.assertRaises(run.PrepareError):
            run.validate_inspect_contract(
                self._ok(network_mode="bridge"), sealed=True)

    def test_control_refuses_network_none(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.validate_inspect_contract(
                self._ok(network_mode="none", offline=False), sealed=False)
        self.assertRegex(str(ctx.exception).lower(), r"network")

    def test_empty_or_wrong_shape_inspect_is_refused(self):
        with self.assertRaises(run.PrepareError):
            run.parse_inspect_payload(b"")
        with self.assertRaises(run.PrepareError):
            run.parse_inspect_payload(b"[]")
        with self.assertRaises(run.PrepareError):
            run.parse_inspect_payload(b"{}")
        with self.assertRaises(run.PrepareError):
            run.parse_inspect_payload(b"null")

    def test_valid_sealed_inspect_records_the_contract(self):
        snap = run.validate_inspect_contract(self._ok(), sealed=True)
        self.assertEqual(snap["cap_drop"], ["ALL"])
        self.assertEqual(snap["memory"], MEMORY_4G)
        self.assertEqual(snap["memory_swap"], MEMORY_4G)
        self.assertEqual(snap["network_mode"], "none")
        self.assertTrue(snap["no_new_privileges"])
        self.assertEqual(snap["pids"], 512)
        self.assertTrue(snap["read_only_root"])
        self.assertEqual(snap["readonly_mounts"], ["/input", "/tool", "/vendor"])
        self.assertEqual(snap["user"], "65532:65532")
        self.assertTrue(snap["offline_env"])

    def test_every_fixed_projected_field_has_a_biting_guard(self):
        bad_tmpfs = {
            "/tmp": "rw,size=1,nr_inodes=%d,mode=1777" % run.TMPFS_INODES,
            "/work": "rw,size=%d,nr_inodes=%d,mode=1777" % (
                run.TMPFS_BYTES, run.TMPFS_INODES),
        }
        cases = (
            ("read-only root", {"ReadonlyRootfs": False}, None),
            ("cap drop", {"CapDrop": []}, None),
            ("security option", {"SecurityOpt": []}, None),
            ("memory", {"Memory": MEMORY_4G - 1}, None),
            ("memory type", {"Memory": float(MEMORY_4G)}, None),
            ("memory swap", {"MemorySwap": MEMORY_4G - 1}, None),
            ("memory swap type", {"MemorySwap": float(MEMORY_4G)}, None),
            ("pids", {"PidsLimit": 511}, None),
            ("pids type", {"PidsLimit": 512.0}, None),
            ("network", {"NetworkMode": "bridge"}, None),
            ("tmpfs", {"Tmpfs": bad_tmpfs}, None),
            ("user", {}, {"User": "0:0"}),
            ("offline environment", {}, {"Env": ["PATH=/usr/bin"]}),
        )
        for name, host_over, config_over in cases:
            with self.subTest(name=name):
                with self.assertRaises(run.PrepareError):
                    run.validate_inspect_contract(
                        self._ok(config_over=config_over, **host_over), sealed=True)

    def test_malformed_tmpfs_is_a_contract_error(self):
        bad = self._ok()
        bad["HostConfig"]["Tmpfs"]["/tmp"] = (
            "rw,size=not-a-number,nr_inodes=128,mode=1777")
        with self.assertRaises(run.PrepareError):
            run.validate_inspect_contract(bad, sealed=True)

    def test_mount_contract_drives_argv_validation_and_projection(self):
        custom = run.DEFAULT_MOUNT_SPEC + (("subject", "/subject"),)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            mounts = {key: root / key for key, _ in custom}
            for path in mounts.values():
                path.mkdir()
            argv = run.docker_create_argv(
                image_id="sha256:" + ("cd" * 32),
                name="aee-sealed-custom-mount",
                mounts=mounts,
                command=["ok"],
                mount_spec=custom,
            )
        mount_args = [argv[i + 1] for i, value in enumerate(argv) if value == "--mount"]
        self.assertEqual(
            [arg.split("destination=", 1)[1].split(",", 1)[0] for arg in mount_args],
            ["/input", "/vendor", "/tool", "/subject"],
        )
        observed = [
            {"Destination": dest, "RW": False, "Type": "bind"}
            for _, dest in custom
        ]
        snap = run.validate_inspect_contract(
            self._ok(mounts=observed), sealed=True, mount_spec=custom)
        self.assertEqual(
            snap["readonly_mounts"], ["/input", "/subject", "/tool", "/vendor"])

    def test_mount_validation_refuses_extra_non_bind_and_duplicate_rows(self):
        good = self._ok()["Mounts"]
        malformed = (
            good[:-1],
            good + [{"Destination": "/other", "RW": False, "Type": "bind"}],
            [{**row, "Type": "volume"} if row["Destination"] == "/tool" else row
             for row in good],
            good + [{"Destination": "/input", "RW": False, "Type": "bind"}],
            [{**row, "RW": True} if row["Destination"] == "/vendor" else row
             for row in good],
        )
        for mounts in malformed:
            with self.subTest(mounts=mounts):
                with self.assertRaises(run.PrepareError):
                    run.validate_inspect_contract(
                        self._ok(mounts=mounts), sealed=True)

    def test_missing_container_is_absent_not_an_infrastructure_failure(self):
        self.assertEqual(
            run.classify_inspect_status(1, "", "Error: No such object: aee-x"),
            "absent")
        self.assertEqual(
            run.classify_inspect_status(1, "", "Error: No such container: aee-x"),
            "absent")

    def test_daemon_or_unparseable_inspect_is_not_treated_as_absent(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.classify_inspect_status(
                1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
        self.assertRegex(str(ctx.exception).lower(), r"inspect|infrastructure")
        with self.assertRaises(run.PrepareError):
            run.classify_inspect_status(0, "", "")
        with self.assertRaises(run.PrepareError):
            run.parse_inspect_payload(b"not-json")
        src = (REPO_ROOT / "measurements" / "contained_oci.py").read_text(
            encoding="utf-8")
        self.assertNotIn("except PrepareError:\n        return False", src)


class ExecutionIdentityDirty(unittest.TestCase):
    def test_dirty_execution_path_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = _committed_execution_root(Path(d))
            target = root / "execution" / "aee-checker-sealed" / "probe.sh"
            target.write_bytes(target.read_bytes() + b"# dirty\n")
            with self.assertRaises(run.PrepareError) as ctx:
                run.execution_identity(root)
            self.assertRegex(str(ctx.exception).lower(), r"dirty|untracked|head")

    def test_committed_execution_paths_bind_head_blobs(self):
        with tempfile.TemporaryDirectory() as d:
            root = _committed_execution_root(Path(d))
            identity = run.execution_identity(root)
            self.assertEqual(len(identity["commit"]), 40)
            self.assertNotEqual(identity["commit"], run.PHASE_A_INSTRUMENT_COMMIT)

    def test_execution_inventory_is_complete_and_omission_mutation_bites(self):
        self.assertEqual(run.EXECUTION_PATHS, REQUIRED_EXECUTION_PATHS)
        self.assertIn("measurements/aee_checker_sealed_common.py", run.EXECUTION_PATHS)
        self.assertIn("measurements/contained_oci.py", run.EXECUTION_PATHS)
        self.assertIn("measurements/aee_checker_sealed_oci.py", run.EXECUTION_PATHS)
        self.assertIn("measurements/aee_checker_sealed_materialize.py", run.EXECUTION_PATHS)
        self.assertIn("execution/aee-checker-sealed/cargo-config.toml", run.EXECUTION_PATHS)
        with tempfile.TemporaryDirectory() as d:
            root = _committed_execution_root(Path(d))
            target = root / "measurements" / "contained_oci.py"
            target.write_bytes(target.read_bytes() + b"# dirty\n")
            with self.assertRaises(run.PrepareError) as ctx:
                run.execution_identity(root)
            self.assertRegex(str(ctx.exception).lower(), r"dirty|untracked|head")
            missing = [p for p in REQUIRED_EXECUTION_PATHS if "contained_oci.py" not in p]
            self.assertNotEqual(missing, list(REQUIRED_EXECUTION_PATHS))


class MaterializeBytes(unittest.TestCase):
    def test_download_baseexception_removes_partial_and_preserves_primary(self):
        class FlightSignal(BaseException):
            pass

        class PartialResponse:
            def __init__(self, primary):
                self.primary = primary
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                self.reads += 1
                if self.reads == 1:
                    return b"partial"
                raise self.primary

        primary = FlightSignal("stop download")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "download"
            with mock.patch.object(
                    mat.urllib.request, "urlopen",
                    return_value=PartialResponse(primary)):
                try:
                    mat.download_bounded("https://example.invalid/archive", dest)
                except BaseException as actual:
                    self.assertIs(actual, primary)
                else:
                    self.fail("download primary did not propagate")
            self.assertFalse(dest.exists())
        self.assertEqual(_traceback_frames(primary).count("download_bounded"), 1)

    def test_download_exception_is_wrapped_with_exact_cause(self):
        class RefusingResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                raise underlying

        underlying = OSError("read refused")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "download"
            with mock.patch.object(
                    mat.urllib.request, "urlopen",
                    return_value=RefusingResponse()):
                with self.assertRaises(run.PrepareError) as ctx:
                    mat.download_bounded("https://example.invalid/archive", dest)
            self.assertFalse(dest.exists())
        self.assertEqual(str(ctx.exception), "download failed")
        self.assertIs(ctx.exception.__cause__, underlying)

    def test_download_prepare_refusal_survives_unlink_failure(self):
        class RefusingBudget:
            ceilings = {"deadline_seconds": 1}

            def charge(self, *, entries=0, bytes=0):
                if bytes:
                    raise primary

            def check_deadline(self):
                pass

        primary = run.PrepareError("download byte refusal")
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "download"
            with mock.patch.object(mat.urllib.request, "urlopen", return_value=io.BytesIO(b"x")), \
                    mock.patch.object(Path, "unlink", side_effect=OSError("unlink refused")):
                with self.assertRaises(run.PrepareError) as ctx:
                    mat.download_bounded("https://example.invalid/archive", dest,
                                         budget=RefusingBudget())
        self.assertIs(ctx.exception, primary)
        failures = getattr(primary, "cleanup_failures", ())
        self.assertEqual(str(failures[0][1]), "unlink refused")

    def test_download_empty_refusal_survives_unlink_failure(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "download"
            with mock.patch.object(mat.urllib.request, "urlopen", return_value=io.BytesIO(b"")), \
                    mock.patch.object(Path, "unlink", side_effect=OSError("unlink refused")):
                with self.assertRaises(run.PrepareError) as ctx:
                    mat.download_bounded("https://example.invalid/archive", dest)
        self.assertEqual(str(ctx.exception), "download empty")
        failures = getattr(ctx.exception, "cleanup_failures", ())
        self.assertEqual(str(failures[0][1]), "unlink refused")

    def test_empty_vendor_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            vendor = Path(d) / "vendor"
            vendor.mkdir()
            with self.assertRaises(run.PrepareError) as ctx:
                run.tree_sha256(vendor)
            self.assertRegex(str(ctx.exception).lower(), r"empty|vendor")

    def test_tree_digest_changes_when_a_file_changes(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "vendor"
            tree.mkdir()
            (tree / "a").write_bytes(b"one")
            first = run.tree_sha256(tree)
            (tree / "a").write_bytes(b"two")
            self.assertNotEqual(first, run.tree_sha256(tree))
            self.assertNotEqual(first, EMPTY_VENDOR)

    def test_symlink_in_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "vendor"
            tree.mkdir()
            (tree / "a").write_bytes(b"one")
            (tree / "link").symlink_to("a")
            with self.assertRaises(run.PrepareError) as ctx:
                run.tree_sha256(tree)
            self.assertRegex(str(ctx.exception).lower(), r"symlink")

    def test_chmod_does_not_change_tree_digest(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "vendor"
            tree.mkdir()
            path = tree / "a"
            path.write_bytes(b"one")
            path.chmod(0o644)
            first = run.tree_sha256(tree)
            path.chmod(0o600)
            self.assertEqual(first, run.tree_sha256(tree))

    def test_tree_read_uses_bounded_regular_file_not_stat_then_read(self):
        src = inspect.getsource(run.tree_sha256)
        self.assertIn("read_bounded_regular_file", src)
        self.assertNotIn("read_bytes()", src)
        self.assertNotIn(".stat()", src)

    def test_tree_over_byte_cap_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "vendor"
            tree.mkdir()
            (tree / "a").write_bytes(b"abcdef")
            with self.assertRaises(run.PrepareError) as ctx:
                run.tree_sha256(tree, cap_bytes=3)
            self.assertRegex(str(ctx.exception).lower(), r"ceiling|cap|exceed")

    def test_frozen_manifest_sha_mismatch_is_refused(self):
        with self.assertRaises(run.PrepareError) as ctx:
            run.require_frozen_manifest_sha(b'{"corpusDigest":"b5aa5fdb"}\n')
        self.assertRegex(str(ctx.exception).lower(), r"manifest sha")
        src = inspect.getsource(run.verify_materialized)
        self.assertIn("require_frozen_manifest_sha", src)
        self.assertEqual(
            run.FROZEN_CORPUS_MANIFEST_SHA256,
            "aaee0241d5f92a65ecfa603113f5c313b3f0593aa97ce8a54732287f0dc26c67")

    def test_omitting_frozen_manifest_compare_is_refused_by_emit(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = PrepareEvidence()._parts()
            parts["materialized"]["corpus_manifest_sha256"] = "00" * 32
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"manifest sha")

    def test_empty_directories_count_against_entry_ceiling(self):
        with tempfile.TemporaryDirectory() as d:
            extras = []
            for name in ("empty-a", "empty-b", "empty-c"):
                info = tarfile.TarInfo("repo-abc/%s" % name)
                info.type = tarfile.DIRTYPE
                extras.append((info, None))
            archive = _tiny_tar(Path(d) / "dirs.tgz", {"keep": b"x"}, extras=extras)
            dest = Path(d) / "out"
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(archive, dest, cap_files=2)
            self.assertRegex(str(ctx.exception).lower(), r"entry|ceiling")
            self.assertFalse((dest / "empty-c").exists())

    def test_shared_materialize_budget_covers_extract_stages(self):
        with tempfile.TemporaryDirectory() as d:
            first = _tiny_tar(Path(d) / "one.tgz", {"a": b"12345"})
            second = _tiny_tar(Path(d) / "two.tgz", {"b": b"12345"})
            spec = dict(run.MATERIALIZE_CEILINGS)
            spec["disk_bytes"] = 8
            spec["entry_count"] = 10
            budget = run.MaterializeBudget(spec)
            run.extract_pinned_archive(first, Path(d) / "one", budget=budget)
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(second, Path(d) / "two", budget=budget)
            self.assertRegex(str(ctx.exception).lower(), r"ceiling|exceed")
            self.assertFalse((Path(d) / "two" / "b").exists())

    def test_empty_directory_changes_canonical_tree_digest(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "subject"
            tree.mkdir()
            (tree / "Cargo.toml").write_bytes(b"[package]\n")
            first = run.tree_sha256(tree)
            (tree / "empty").mkdir()
            self.assertNotEqual(first, run.tree_sha256(tree))
            (tree / "Cargo.toml").write_bytes(b"[package]\nname=\"x\"\n")
            self.assertNotEqual(first, run.tree_sha256(tree))

    def test_unlisted_corpus_bytes_change_tree_digest(self):
        with tempfile.TemporaryDirectory() as d:
            tree = Path(d) / "corpus"
            (tree / "vectors").mkdir(parents=True)
            (tree / "vectors" / "MANIFEST.json").write_bytes(b"{}\n")
            first = run.tree_sha256(tree)
            (tree / "vectors" / "extra.json").write_bytes(b"sneak\n")
            self.assertNotEqual(first, run.tree_sha256(tree))

    def test_emit_refuses_unfrozen_tree_digests(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = PrepareEvidence()._parts()
            parts["materialized"]["subject_tree_sha256"] = "00" * 32
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"subject tree")
            parts = PrepareEvidence()._parts()
            parts["materialized"]["corpus_tree_sha256"] = "00" * 32
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"corpus tree")

    def test_matching_check_rs_does_not_skip_frozen_tree_digest(self):
        src = inspect.getsource(run.verify_materialized)
        self.assertIn("require_frozen_trees", src)
        self.assertEqual(
            run.FROZEN_SUBJECT_TREE_SHA256,
            "393d742154918f640593fe9962cf87a273a28c93b24c0569ee4bef3a039fdc3d")
        self.assertEqual(
            run.FROZEN_CORPUS_TREE_SHA256,
            "4bd2f2bf1208beb613fef0e6cc4728483cecae1097b74b54baaf54ce22569c42")
        with tempfile.TemporaryDirectory() as d:
            subject = Path(d) / "subject"
            corpus = Path(d) / "corpus"
            (subject / "src").mkdir(parents=True)
            (subject / "src" / "check.rs").write_text("fn pinned() {}\n", encoding="utf-8")
            (subject / "Cargo.toml").write_bytes(b"[package]\nname=\"mutated\"\n")
            digest = _sha256((subject / "src" / "check.rs").read_bytes())
            _write_corpus(
                corpus,
                "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579")
            pins = {
                "subject": {"path": "src/check.rs", "check_rs_sha256": digest},
                "corpus": {
                    "corpusDigest": "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579",
                },
            }
            fixture = _sha256((corpus / "vectors" / "MANIFEST.json").read_bytes())
            original = mat.FROZEN_CORPUS_MANIFEST_SHA256
            mat.FROZEN_CORPUS_MANIFEST_SHA256 = fixture
            try:
                with self.assertRaises(run.PrepareError) as ctx:
                    run.verify_materialized(pins, subject, corpus)
                self.assertRegex(str(ctx.exception).lower(), r"tree digest")
            finally:
                mat.FROZEN_CORPUS_MANIFEST_SHA256 = original

    def test_verify_materialized_refuses_unfrozen_manifest_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            subject = Path(d) / "subject"
            corpus = Path(d) / "corpus"
            (subject / "src").mkdir(parents=True)
            (subject / "src" / "check.rs").write_text("fn pinned() {}\n", encoding="utf-8")
            digest = _sha256((subject / "src" / "check.rs").read_bytes())
            _write_corpus(
                corpus,
                "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579")
            pins = {
                "subject": {"path": "src/check.rs", "check_rs_sha256": digest},
                "corpus": {
                    "corpusDigest": "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579",
                },
            }
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_materialized(pins, subject, corpus)
            self.assertRegex(str(ctx.exception).lower(), r"manifest sha")
            (subject / "src" / "check.rs").write_text("fn other() {}\n", encoding="utf-8")
            with self.assertRaises(run.PrepareError):
                run.verify_file_digest(subject / "src" / "check.rs", digest)

    def test_corpus_id_set_requires_exactly_250_unique_listed_files(self):
        with tempfile.TemporaryDirectory() as d:
            corpus = Path(d) / "corpus"
            _write_corpus(corpus, "x", count=2)
            run.require_corpus_id_set(["v-%03d" % i for i in range(250)])
            with self.assertRaises(run.PrepareError) as ctx:
                run.require_corpus_id_set(["v-001", "v-001"] + ["v-%03d" % i for i in range(2, 250)])
            self.assertRegex(str(ctx.exception).lower(), r"250|unique")
            with self.assertRaises(run.PrepareError):
                run.require_corpus_id_set(["only-one"])

    def test_extract_refuses_oversize_header_before_member_allocation(self):
        with tempfile.TemporaryDirectory() as d:
            archive = _tiny_tar(Path(d) / "a.tgz", {"big": b"x" * 64})
            dest = Path(d) / "out"
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(archive, dest, cap_bytes=8)
            self.assertRegex(str(ctx.exception).lower(), r"ceiling|size")
            self.assertFalse((dest / "big").exists())
        src = inspect.getsource(run.stream_archive_member)
        self.assertIn("header_size > remaining", src)
        self.assertNotIn("source.read()", inspect.getsource(run.extract_pinned_archive))

    def test_extract_refuses_path_traversal_symlink_hardlink_and_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            with self.assertRaises(run.PrepareError) as ctx:
                run.archive_member_rel("repo-abc/../../etc/passwd")
            self.assertRegex(str(ctx.exception).lower(), r"traversal")
            link = tarfile.TarInfo("repo-abc/escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc/passwd"
            archive = _tiny_tar(
                Path(d) / "link.tgz", {"ok": b"1"}, extras=((link, None),))
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(archive, dest)
            self.assertRegex(str(ctx.exception).lower(), r"link")
            self.assertFalse((dest / "escape").exists())
            hard = tarfile.TarInfo("repo-abc/hard")
            hard.type = tarfile.LNKTYPE
            hard.linkname = "repo-abc/ok"
            dest2 = Path(d) / "out2"
            archive2 = _tiny_tar(
                Path(d) / "hard.tgz", {"ok": b"1"}, extras=((hard, None),))
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(archive2, dest2)
            self.assertRegex(str(ctx.exception).lower(), r"link")
            dest3 = Path(d) / "out3"
            archive3 = _tiny_tar(Path(d) / "dup.tgz", {"a": b"1", "a": b"2"})
            # dict last-write wins; add a real duplicate member
            with tarfile.open(Path(d) / "dup2.tgz", "w:gz") as tar:
                for data in (b"one", b"two"):
                    info = tarfile.TarInfo("repo-abc/a")
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            with self.assertRaises(run.PrepareError) as ctx:
                run.extract_pinned_archive(Path(d) / "dup2.tgz", dest3)
            self.assertRegex(str(ctx.exception).lower(), r"duplicate")

    def test_vendor_oci_enforces_disk_and_inode_ceilings_during_write(self):
        argv = run.vendor_create_argv(
            name="aee-vendor-t", subject=Path("."), vendor=Path("vendor"))
        text = " ".join(argv)
        self.assertIn("docker", argv[0])
        self.assertIn("/vendor:", text)
        self.assertIn("size=%d" % run.MATERIALIZE_CAP_BYTES, text)
        self.assertIn("nr_inodes=%d" % run.MATERIALIZE_CAP_FILES, text)
        self.assertIn("destination=/out", text)
        self.assertIn("sleep", argv)
        src = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        self.assertNotIn('["cargo", "vendor", "--locked", str(vendor', src)
        self.assertIn("vendor_create_argv", inspect.getsource(run.vendor_locked))

    def test_rust_vendor_image_is_the_192_bookworm_index(self):
        self.assertEqual(
            run.RUST_IMAGE,
            "docker.io/library/rust@sha256:"
            "e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2")
        src = (REPO_ROOT / "measurements" / "aee_checker_sealed_materialize.py").read_text(
            encoding="utf-8")
        self.assertNotIn(
            "a45bf1f5d9af0a23b26703b3500d70af1abff7f984a7abef5a104b42c02a292b", src)
        self.assertNotIn("rust:1-bookworm", src)
        self.assertNotIn("rust:1.92-bookworm", src)

    def test_vendor_pulls_digest_before_inspect_and_does_not_cache_skip(self):
        pull = inspect.getsource(run.pull_rust_image)
        vendor = inspect.getsource(run.vendor_locked)
        materialize = inspect.getsource(run.materialize_pinned)
        self.assertIn("docker", pull)
        self.assertIn("pull", pull)
        self.assertLess(pull.index("pull"), pull.index("inspect"))
        self.assertIn("@sha256:", pull)
        self.assertIn("pull_rust_image", vendor)
        self.assertLess(vendor.index("pull_rust_image"), vendor.index("vendor_create_argv"))
        self.assertNotIn('docker_bounded(["image", "inspect", RUST_IMAGE])', vendor)
        self.assertIn('["start", name]', vendor)
        self.assertNotIn("start\", \"-a\"", vendor)
        self.assertIn("docker_run_capped", vendor)
        self.assertIn('["exec", name, "cargo", "vendor"', vendor)
        self.assertLess(vendor.index("host_bind_owner"), vendor.index("vendor_create_argv"))
        self.assertLess(vendor.index("cargo\", \"vendor\""), vendor.index("copy_tmpfs_argv"))
        self.assertLess(vendor.index("copy_tmpfs_argv"), vendor.index("rm"))
        self.assertNotIn("chown", vendor)
        self.assertNotIn("reclaim_bind_owner", vendor)
        self.assertNotIn("stat\", \"-c\"", vendor)
        owner_src = inspect.getsource(run.host_bind_owner)
        self.assertIn("st_uid", owner_src)
        self.assertIn("st_gid", owner_src)
        self.assertNotIn("docker", owner_src)
        self.assertNotIn("stat\", \"-c\"", owner_src)
        copy = inspect.getsource(run.copy_tmpfs_argv)
        self.assertIn('"/vendor/."', copy)
        self.assertIn("--user", copy)
        self.assertIn("--no-preserve=ownership", copy)
        self.assertIn("cp\", \"-R\"", copy)
        self.assertNotIn("chown", copy)
        self.assertNotIn("sudo", copy)
        self.assertNotIn("except", copy)
        self.assertNotIn("docker\", \"cp\"", copy)
        self.assertNotIn("stat\", \"-c\"", copy)
        self.assertIn("pull_rust_image", materialize)
        self.assertIn("require_container_absent", vendor)
        live = inspect.getsource(
            LiveInertProbes.test_prepare_emits_artifact_without_subject_binary_or_outcomes)
        self.assertNotIn("skipTest", live)
        self.assertNotIn("image inspect", live)

    def test_copy_argv_carries_host_dest_owner(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            dest.mkdir()
            owner = run.host_bind_owner(dest)
            self.assertEqual(owner, "%d:%d" % (dest.stat().st_uid, dest.stat().st_gid))
            argv = run.copy_tmpfs_argv("aee-x", owner)
            self.assertEqual(argv[argv.index("--user") + 1], owner)
            self.assertIn("--no-preserve=ownership", argv)

    def test_forced_copy_failure_leaves_owner_removable_partial_output(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            dest.mkdir()
            partial = dest / "keep"
            nested = dest / "sub" / "LICENSE-APACHE"
            nested.parent.mkdir()
            partial.write_text("partial", encoding="utf-8")
            nested.write_text("x", encoding="utf-8")
            with mock.patch.object(mat, "docker_ok", side_effect=run.PrepareError("copy failed")):
                with self.assertRaises(run.PrepareError):
                    run.copy_tmpfs_as_bind_owner("aee-x", dest)
            if hasattr(os, "getuid"):
                self.assertEqual(partial.stat().st_uid, os.getuid())
                self.assertEqual(nested.stat().st_uid, os.getuid())
            partial.unlink()
            nested.unlink()
            nested.parent.rmdir()

    def test_emit_refuses_host_or_unprovenanced_toolchain(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = PrepareEvidence()._parts()
            parts["toolchain"]["observation"] = "host; checker was not run"
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"vendor-image|toolchain")
            parts = PrepareEvidence()._parts()
            parts["toolchain"]["rustc_Vv"] = "rustc 1.91.0 (old)\n"
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"rustc|provenance")
            parts = PrepareEvidence()._parts()
            parts["toolchain"]["index"] = (
                "docker.io/library/rust@sha256:"
                "a45bf1f5d9af0a23b26703b3500d70af1abff7f984a7abef5a104b42c02a292b")
            with self.assertRaises(run.PrepareError) as ctx:
                run.emit_prepare_v0(parts, dest)
            self.assertRegex(str(ctx.exception).lower(), r"index|image")

    def test_exclusive_lease_refuses_a_second_concurrent_claimer(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            claimed = []
            errors = []

            def claim():
                try:
                    claimed.append(run.begin_atomic_dest(dest))
                except run.PrepareError:
                    errors.append(1)

            first = threading.Thread(target=claim)
            second = threading.Thread(target=claim)
            first.start()
            second.start()
            first.join()
            second.join()
            self.assertEqual(len(claimed), 1)
            self.assertEqual(len(errors), 1)
            self.assertFalse(dest.exists())
            self.assertTrue(claimed[0]["lease"].is_file())
            self.assertTrue(claimed[0]["staging"].is_dir())
            run.abort_atomic_dest(claimed[0])
            self.assertFalse(dest.exists())
            self.assertFalse(claimed[0]["lease"].exists())
            self.assertFalse(claimed[0]["staging"].exists())

    def test_commit_does_not_rmtree_a_foreign_dest_created_after_lease(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            state = run.begin_atomic_dest(dest)
            dest.mkdir()
            sentinel = dest / "foreign-sentinel"
            sentinel.write_text("keep\n", encoding="utf-8")
            with self.assertRaises(run.PrepareError) as ctx:
                run.commit_atomic_dest(state)
            self.assertRegex(str(ctx.exception).lower(), r"dest exists")
            self.assertTrue(sentinel.is_file())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")
            self.assertFalse(state["staging"].exists())
            self.assertFalse(state["lease"].exists())
            run.abort_atomic_dest(state)
            self.assertTrue(sentinel.is_file())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep\n")
            src = inspect.getsource(run.abort_atomic_dest)
            self.assertNotIn("rmtree(dest)", src)
            self.assertNotIn("shutil.rmtree(dest)", src)
            commit = inspect.getsource(run.commit_atomic_dest)
            self.assertNotIn("os.replace(", commit)
            self.assertIn("os.rename(", commit)

    def test_dest_precheck_primary_survives_abort_failure(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            state = run.begin_atomic_dest(dest)
            dest.mkdir()
            with mock.patch.object(
                    mat, "abort_atomic_dest", side_effect=OSError("abort refused")):
                with self.assertRaises(run.PrepareError) as ctx:
                    run.commit_atomic_dest(state)
        self.assertEqual(str(ctx.exception), "dest exists")
        failures = getattr(ctx.exception, "cleanup_failures", ())
        self.assertEqual(str(failures[0][1]), "abort refused")

    def test_rename_primary_survives_abort_failure(self):
        with tempfile.TemporaryDirectory() as d:
            state = run.begin_atomic_dest(Path(d) / "bundle")
            rename_error = OSError("rename refused")
            with mock.patch.object(mat.os, "rename", side_effect=rename_error), \
                    mock.patch.object(
                        mat, "abort_atomic_dest", side_effect=OSError("abort refused")):
                with self.assertRaises(run.PrepareError) as ctx:
                    run.commit_atomic_dest(state)
        self.assertEqual(str(ctx.exception), "dest exists")
        self.assertIs(ctx.exception.__cause__, rename_error)
        failures = getattr(ctx.exception, "cleanup_failures", ())
        self.assertEqual(str(failures[0][1]), "abort refused")

    def test_fsync_failure_is_best_effort_and_commit_succeeds(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            state = run.begin_atomic_dest(dest)
            (state["staging"] / "content").write_text("ready\n", encoding="utf-8")
            with mock.patch.object(mat.os, "fsync", side_effect=OSError("fsync refused")):
                committed = run.commit_atomic_dest(state)
            self.assertEqual(committed, dest)
            self.assertEqual((dest / "content").read_text(encoding="utf-8"), "ready\n")

    def test_dest_precheck_wins_before_fsync(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            state = run.begin_atomic_dest(dest)
            dest.mkdir()
            with mock.patch.object(
                    mat, "_fsync_tree", side_effect=AssertionError("fsync ran")):
                with self.assertRaisesRegex(run.PrepareError, "dest exists"):
                    run.commit_atomic_dest(state)

    def test_commit_order_is_precheck_then_fsync_then_rename(self):
        with tempfile.TemporaryDirectory() as d:
            state = run.begin_atomic_dest(Path(d) / "bundle")
            events = []
            original_exists = Path.exists

            def exists(path):
                if path == state["dest"]:
                    events.append("precheck")
                return original_exists(path)

            with mock.patch.object(Path, "exists", autospec=True, side_effect=exists), \
                    mock.patch.object(
                        mat, "_fsync_tree", side_effect=lambda _path: events.append("fsync")), \
                    mock.patch.object(
                        mat.os, "rename", side_effect=lambda _src, _dest: events.append("rename")):
                run.commit_atomic_dest(state)
        self.assertEqual(events[:3], ["precheck", "fsync", "rename"])

    def test_atomic_rename_nonclaim_names_windows_existing_target_refusal(self):
        comment = inspect.getsource(run.commit_atomic_dest)
        self.assertIn("Windows refuses an existing target", comment)

    def test_fsync_docstring_disclaims_durability_and_power_loss(self):
        doc = (mat._fsync_tree.__doc__ or "").lower()
        self.assertIn("no durability", doc)
        self.assertIn("crash", doc)
        self.assertIn("power-loss", doc)

    def test_mid_materialize_failure_leaves_no_consumable_final(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            state = run.begin_atomic_dest(dest)
            (state["staging"] / "prepare.v0.json").write_text("{partial}\n", encoding="utf-8")
            (state["staging"] / "subject").mkdir()
            run.abort_atomic_dest(state)
            self.assertFalse(dest.exists())
            self.assertFalse((dest / "prepare.v0.json").exists())
            leftovers = [p.name for p in Path(d).iterdir() if p.name.startswith("bundle")]
            self.assertEqual(leftovers, [])

    def test_concurrent_commit_produces_only_one_final_dest(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            outcomes = []

            def worker():
                try:
                    state = run.begin_atomic_dest(dest)
                    (state["staging"] / "ok").write_text("1", encoding="utf-8")
                    run.commit_atomic_dest(state)
                    outcomes.append("commit")
                except run.PrepareError:
                    outcomes.append("refuse")

            first = threading.Thread(target=worker)
            second = threading.Thread(target=worker)
            first.start()
            second.start()
            first.join()
            second.join()
            self.assertEqual(outcomes.count("commit"), 1)
            self.assertEqual(outcomes.count("refuse"), 1)
            self.assertTrue((dest / "ok").is_file())
            self.assertFalse((Path(d) / "bundle.lease").exists())
            self.assertEqual(
                [p.name for p in Path(d).iterdir() if ".tmp-" in p.name], [])

    def test_prepare_uses_staging_rename_and_fail_closed_daemon(self):
        src = inspect.getsource(run.prepare)
        self.assertLess(src.index("require_docker_ready"), src.index("resolve_prepare_image"))
        self.assertLess(src.index("begin_atomic_dest"), src.index("materialize_pinned"))
        self.assertLess(src.index("emit_prepare_v0"), src.index("commit_atomic_dest"))
        self.assertIn("abort_atomic_dest", src)
        self.assertNotIn("claim_exclusive_dest", src)
        self.assertIn("state[\"staging\"]", src)
        ready = inspect.getsource(run.require_docker_ready)
        launch = inspect.getsource(contained.docker_run_capped)
        self.assertIn("docker", ready)
        self.assertIn("info", ready)
        self.assertIn("ServerVersion", ready)
        self.assertIn("FileNotFoundError", launch)
        self.assertIn("DockerUnavailable", launch)
        self.assertNotIn("shutil.which", ready)
        self.assertNotIn("shutil.which", inspect.getsource(_docker_ready))
        self.assertIn("require_docker_ready", inspect.getsource(_docker_ready))
        cap = inspect.getsource(run.require_live_oci_capability)
        self.assertIn("require_docker_ready", cap)
        self.assertIn("build_inert_image", cap)
        self.assertNotIn("shutil.which", cap)
        live_setup = inspect.getsource(LiveInertProbes.setUpClass)
        self.assertLess(
            live_setup.index("require_live_oci_capability"), live_setup.index("TemporaryDirectory"))
        self.assertIn("GITHUB_ACTIONS", live_setup)
        self.assertIn("Linux", live_setup)
        self.assertLess(live_setup.index("Linux"), live_setup.index("SkipTest"))
        self.assertFalse(getattr(LiveInertProbes, "__unittest_skip__", False))

    def test_missing_docker_executable_is_unavailable_not_an_import_crash(self):
        with mock.patch.object(br, "_run_capped", side_effect=FileNotFoundError("docker")):
            with self.assertRaises(run.DockerUnavailable) as ctx:
                run.require_docker_ready()
            self.assertFalse(_docker_ready())
        self.assertIsInstance(ctx.exception, run.PrepareError)
        self.assertEqual(str(ctx.exception), "docker executable is not available")

    def test_daemon_not_ready_stays_distinct_from_unavailable(self):
        fake = mock.Mock(returncode=1, stdout="", stderr="Cannot connect")
        with mock.patch.object(br, "_run_capped", return_value=fake):
            with self.assertRaises(run.PrepareError) as ctx:
                run.require_docker_ready()
        self.assertNotIsInstance(ctx.exception, run.DockerUnavailable)
        self.assertEqual(str(ctx.exception), "docker daemon is not ready")

    def test_live_class_skips_with_exact_reason_when_daemon_not_ready(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "macOS"}):
            with mock.patch.object(
                    run, "require_live_oci_capability",
                    side_effect=run.PrepareError("docker daemon is not ready")):
                with self.assertRaises(unittest.SkipTest) as ctx:
                    LiveInertProbes.setUpClass()
        self.assertEqual(str(ctx.exception), "docker daemon is not ready")

    def test_hosted_windows_skips_unavailable_with_exact_reason(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows"}):
            with mock.patch.object(
                    run, "require_live_oci_capability",
                    side_effect=run.DockerUnavailable("docker executable is not available")):
                with self.assertRaises(unittest.SkipTest) as ctx:
                    LiveInertProbes.setUpClass()
        self.assertEqual(str(ctx.exception), "docker executable is not available")

    def test_hosted_linux_capability_failure_is_not_a_skip(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"}):
            with mock.patch.object(
                    run, "require_live_oci_capability",
                    side_effect=run.PrepareError("docker daemon is not ready")):
                try:
                    LiveInertProbes.setUpClass()
                except unittest.SkipTest as skip:
                    self.fail("hosted Linux skipped: %s" % skip)
                except run.PrepareError as exc:
                    daemon = exc
                else:
                    self.fail("hosted Linux capability failure must raise")
            with mock.patch.object(
                    run, "require_live_oci_capability",
                    side_effect=run.DockerUnavailable("docker executable is not available")):
                try:
                    LiveInertProbes.setUpClass()
                except unittest.SkipTest as skip:
                    self.fail("hosted Linux skipped: %s" % skip)
                except run.DockerUnavailable as exc:
                    unavailable = exc
                else:
                    self.fail("hosted Linux unavailable must raise")
        self.assertEqual(str(daemon), "docker daemon is not ready")
        self.assertEqual(str(unavailable), "docker executable is not available")

    def _readiness_timeout(self):
        return subprocess.TimeoutExpired(
            ["docker", "info", "--format", "{{.ServerVersion}}"], 15)

    def test_readiness_timeout_is_prepare_error_distinct_from_missing_and_daemon(self):
        with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
            with self.assertRaises(run.PrepareError) as ctx:
                run.require_docker_ready()
        self.assertNotIsInstance(ctx.exception, run.DockerUnavailable)
        self.assertNotIsInstance(ctx.exception, subprocess.TimeoutExpired)
        self.assertEqual(str(ctx.exception), "docker readiness timed out")
        self.assertNotEqual(str(ctx.exception), "docker daemon is not ready")
        self.assertNotEqual(str(ctx.exception), "docker executable is not available")

    def test_hosted_windows_skips_readiness_timeout_with_exact_reason(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows"}):
            with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
                with self.assertRaises(unittest.SkipTest) as ctx:
                    LiveInertProbes.setUpClass()
        self.assertEqual(str(ctx.exception), "docker readiness timed out")

    def test_hosted_macos_skips_readiness_timeout_with_exact_reason(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "macOS"}):
            with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
                with self.assertRaises(unittest.SkipTest) as ctx:
                    LiveInertProbes.setUpClass()
        self.assertEqual(str(ctx.exception), "docker readiness timed out")

    def test_hosted_linux_readiness_timeout_is_not_a_skip(self):
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "RUNNER_OS": "Linux"}):
            with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
                try:
                    LiveInertProbes.setUpClass()
                except unittest.SkipTest as skip:
                    self.fail("hosted Linux skipped: %s" % skip)
                except run.PrepareError as exc:
                    timed_out = exc
                else:
                    self.fail("hosted Linux readiness timeout must raise")
        self.assertNotIsInstance(timed_out, run.DockerUnavailable)
        self.assertEqual(str(timed_out), "docker readiness timed out")

    def test_deleting_timeout_mapping_lets_timeout_escape(self):
        src = inspect.getsource(run.require_docker_ready)
        self.assertIn("TimeoutExpired", src)
        mutated = src.replace("except subprocess.TimeoutExpired as exc:", "except ZeroDivisionError as exc:")
        self.assertNotEqual(src, mutated)
        ns = {
            "docker_run_capped": contained.docker_run_capped,
            "PrepareError": run.PrepareError,
            "subprocess": subprocess,
        }
        exec(compile(mutated, "<mutated-require_docker_ready>", "exec"), ns)
        with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
            with self.assertRaises(subprocess.TimeoutExpired):
                ns["require_docker_ready"]()

    def test_noop_loaded_copy_keeps_timeout_mapping(self):
        src = inspect.getsource(run.require_docker_ready)
        ns = {
            "docker_run_capped": contained.docker_run_capped,
            "PrepareError": run.PrepareError,
            "subprocess": subprocess,
        }
        exec(compile(src, "<noop-require_docker_ready>", "exec"), ns)
        with mock.patch.object(br, "_run_capped", side_effect=self._readiness_timeout()):
            with self.assertRaises(run.PrepareError) as ctx:
                ns["require_docker_ready"]()
        self.assertEqual(str(ctx.exception), "docker readiness timed out")
        fake = mock.Mock(returncode=1, stdout="", stderr="Cannot connect")
        with mock.patch.object(br, "_run_capped", return_value=fake):
            with self.assertRaises(run.PrepareError) as ctx:
                ns["require_docker_ready"]()
        self.assertEqual(str(ctx.exception), "docker daemon is not ready")
        with mock.patch.object(br, "_run_capped", side_effect=FileNotFoundError("docker")):
            with self.assertRaises(run.DockerUnavailable) as ctx:
                ns["require_docker_ready"]()
        self.assertEqual(str(ctx.exception), "docker executable is not available")

    def test_prepare_injected_materialize_failure_leaves_no_final(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            root = Path(d) / "root"
            pins = Path(d) / "pins"

            def exploding(_pins, staging, **_kwargs):
                Path(staging).mkdir(exist_ok=True)
                (Path(staging) / "prepare.v0.json").write_text("{partial}\n", encoding="utf-8")
                raise run.PrepareError("injected mid-materialize")

            with mock.patch.object(run, "verify_phase_a_frozen", return_value={"corpus": {}}), \
                    mock.patch.object(run, "require_docker_ready", return_value="test"), \
                    mock.patch.object(run, "build_inert_image", return_value="sha256:" + ("00" * 32)), \
                    mock.patch.object(run, "run_inert_probe", return_value={"state": "completed"}), \
                    mock.patch.object(run, "materialize_pinned", exploding):
                with self.assertRaises(run.PrepareError) as ctx:
                    run.prepare(pins, dest, root=root)
            self.assertRegex(str(ctx.exception).lower(), r"injected|mid-materialize")
            self.assertFalse(dest.exists())
            leftovers = [p.name for p in Path(d).iterdir() if p.name.startswith("bundle")]
            self.assertEqual(leftovers, [])

    def test_prepare_outer_abort_never_replaces_materialize_or_commit_primary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            pins = Path(d) / "pins"
            template = root / "execution" / "aee-checker-sealed"
            template.mkdir(parents=True)
            parts = PrepareEvidence()._parts()
            mats = dict(parts["materialized"])
            mats.update({
                "corpus": Path(d) / "corpus",
                "tool": Path(d) / "tool",
                "toolchain": parts["toolchain"],
                "vendor": Path(d) / "vendor",
            })
            for stage in ("materialize", "commit"):
                with self.subTest(stage=stage):
                    primary = run.PrepareError("%s primary" % stage)
                    dest = Path(d) / stage
                    materialize_effect = primary if stage == "materialize" else mats
                    commit_effect = primary if stage == "commit" else None
                    with mock.patch.object(
                            run, "verify_phase_a_frozen", return_value={
                                "corpus": {"commit": "corpus", "corpusDigest": "digest"},
                                "instrument": {"commit": "instrument"},
                                "subject": {"commit": "subject"},
                            }), \
                            mock.patch.object(run, "require_docker_ready", return_value="test"), \
                            mock.patch.object(
                                run, "resolve_prepare_image",
                                return_value="sha256:" + ("00" * 32)), \
                            mock.patch.object(run, "run_inert_probe", return_value={}), \
                            mock.patch.object(run, "materialize_pinned", side_effect=(
                                materialize_effect if isinstance(materialize_effect, BaseException)
                                else None), return_value=(
                                None if isinstance(materialize_effect, BaseException)
                                else materialize_effect)), \
                            mock.patch.object(run, "PROBE_MECHANISMS", ()), \
                            mock.patch.object(run, "execution_identity", return_value={}), \
                            mock.patch.object(run, "image_platform", return_value="linux/amd64"), \
                            mock.patch.object(run, "docker_bounded", return_value=b"test"), \
                            mock.patch.object(run, "record_toolchain", return_value={}), \
                            mock.patch.object(run, "emit_prepare_v0", return_value=b"prepare"), \
                            mock.patch.object(run, "commit_atomic_dest", side_effect=commit_effect), \
                            mock.patch.object(
                                run, "abort_atomic_dest", side_effect=OSError("abort cleanup")):
                        try:
                            run.prepare(pins, dest, root=root)
                        except BaseException as actual:
                            self.assertIs(actual, primary)
                        else:
                            self.fail("%s primary did not propagate" % stage)
                    failures = getattr(primary, "cleanup_failures", ())
                    self.assertEqual(str(failures[0][1]), "abort cleanup")

    def test_prepare_baseexception_aborts_atomic_staging_and_preserves_primary(self):
        class FlightSignal(BaseException):
            pass

        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"
            pins = Path(d) / "pins"
            template = root / "execution" / "aee-checker-sealed"
            template.mkdir(parents=True)
            primary = FlightSignal("stop prepare")
            abort = mock.Mock()
            with mock.patch.object(run, "verify_phase_a_frozen", return_value={
                    "corpus": {"commit": "corpus", "corpusDigest": "digest"},
                    "instrument": {"commit": "instrument"},
                    "subject": {"commit": "subject"},
            }), \
                    mock.patch.object(run, "require_docker_ready", return_value="test"), \
                    mock.patch.object(
                        run, "resolve_prepare_image",
                        return_value="sha256:" + ("00" * 32)), \
                    mock.patch.object(run, "run_inert_probe", return_value={}), \
                    mock.patch.object(run, "materialize_pinned", side_effect=primary), \
                    mock.patch.object(run, "abort_atomic_dest", abort):
                try:
                    run.prepare(pins, Path(d) / "bundle", root=root)
                except BaseException as actual:
                    self.assertIs(actual, primary)
                else:
                    self.fail("prepare primary did not propagate")
            abort.assert_called_once()
        self.assertEqual(_traceback_frames(primary).count("prepare"), 1)


@unittest.skipUnless(CARGO, "cargo is not available")
class DurableVendorConfig(unittest.TestCase):
    def test_offline_fixture_build_uses_only_the_durable_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bundle = root / "bundle"
            subject = bundle / "subject"
            vendor = root / "vendor"
            tool = bundle / "tool"
            (subject / "src").mkdir(parents=True)
            (subject / "Cargo.toml").write_text(
                "[package]\nname = \"inert-vendor-fixture\"\n"
                "version = \"0.1.0\"\nedition = \"2021\"\n\n"
                "[dependencies]\ncfg-if = \"1.0.0\"\n",
                encoding="utf-8")
            (subject / "src" / "lib.rs").write_text("pub fn n() -> u8 { 1 }\n", encoding="utf-8")
            subprocess.run(
                ["cargo", "generate-lockfile"], cwd=subject, check=True,
                capture_output=True)
            subprocess.run(
                ["cargo", "vendor", "--locked", str(vendor)], cwd=subject,
                check=True, capture_output=True)
            cargo_home = subject / ".cargo"
            if cargo_home.exists():
                shutil.rmtree(cargo_home)
            run.bind_vendor_config(
                tool, REPO_ROOT / "execution" / "aee-checker-sealed" / "cargo-config.toml")
            env = dict(os.environ)
            env["CARGO_HOME"] = str(tool)
            env["CARGO_NET_OFFLINE"] = "true"
            built = subprocess.run(
                ["cargo", "build", "--offline", "--manifest-path",
                 str(subject / "Cargo.toml")],
                cwd=subject, env=env, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            self.assertNotIn("aee-checker", str(subject))
            self.assertTrue((tool / "config.toml").is_file())
            self.assertTrue(any(vendor.iterdir()))


class LiveInertProbes(unittest.TestCase):
    image_id = ""
    prefix = "aee-sealed-inert-"
    created_names: list[str] = []

    @classmethod
    def setUpClass(cls):
        try:
            cls.image_id = run.require_live_oci_capability(CONTAINERFILE.parent)
        except run.PrepareError as exc:
            if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_OS") == "Linux":
                raise
            raise unittest.SkipTest(str(exc)) from exc
        run.require_image_id(cls.image_id)
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.mounts = {name: root / name for name in ("input", "vendor", "tool")}
        for path in cls.mounts.values():
            path.mkdir()
        cls.created_names = []

    @classmethod
    def tearDownClass(cls):
        for name in cls.created_names:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        tmp = getattr(cls, "_tmp", None)
        if tmp is not None:
            tmp.cleanup()

    def _run(self, mode: str, **kwargs):
        result = run.run_inert_probe(
            image_id=self.image_id,
            mode=mode,
            mounts=self.mounts,
            name_prefix=self.prefix,
            **kwargs,
        )
        self.created_names.append(result["name"])
        return result

    def test_network_none_refuses_the_same_outbound_that_works_with_network(self):
        good = self._run("network", sealed=False)
        bad = self._run("network", sealed=True)
        row = run.record_probe_pair("network-off", good, bad)
        self.assertEqual(row["control"], "completed")
        self.assertNotEqual(row["refusal"], "completed")
        self.assertNotEqual(row["inspect"]["control"]["network_mode"], "none")
        self.assertFalse(row["inspect"]["control"]["offline_env"])
        self.assertEqual(row["inspect"]["refusal"]["network_mode"], "none")

    def test_tmpfs_bytes_refuse_over_limit_and_allow_under_limit(self):
        good = self._run("tmpfs-bytes-ok")
        bad = self._run("tmpfs-bytes")
        row = run.record_probe_pair("disk", good, bad)
        self.assertEqual(row["control"], "completed")
        self.assertNotEqual(row["refusal"], "completed")

    def test_tmpfs_inodes_refuse_over_limit_and_allow_under_limit(self):
        good = self._run("tmpfs-inodes-ok")
        bad = self._run("tmpfs-inodes")
        row = run.record_probe_pair("file-count", good, bad)
        self.assertEqual(row["control"], "completed")
        self.assertNotEqual(row["refusal"], "completed")

    def test_output_cap_refuses_over_4mib_and_allows_small(self):
        good = self._run("output-ok")
        bad = self._run("output")
        row = run.record_probe_pair("output", good, bad)
        self.assertEqual(row["mechanism"], "output")
        self.assertEqual(row["control"], "completed")
        self.assertEqual(row["refusal"], "output_cap")
        self.assertEqual(set(row["inspect"]), {"control", "refusal"})

    def test_deadline_kills_descendant_and_short_child_completes(self):
        good = self._run("deadline-ok")
        bad = self._run("deadline")
        row = run.record_probe_pair("deadline", good, bad)
        self.assertEqual(row["control"], "completed")
        self.assertEqual(row["refusal"], "deadline")
        self.assertNotIn("elapsed_seconds", row)

    def test_exit_2_json_is_abnormal_and_exit_0_json_is_completed(self):
        good = self._run("ok")
        bad = self._run("exit2-json")
        row = run.record_probe_pair("protocol-exit", good, bad)
        self.assertEqual(row["control"], "completed")
        self.assertEqual(row["refusal"], "abnormal")
        self.assertIsNone(good.get("parsed"))
        self.assertIsNone(bad.get("parsed"))

    def test_image_digest_mismatch_is_refused_and_match_runs(self):
        good = self._run("ok")
        self.assertEqual(good["state"], "completed", good)
        fake = "sha256:" + ("00" * 32)
        with self.assertRaises(run.PrepareError) as ctx:
            run.run_inert_probe(
                image_id=fake,
                mode="ok",
                mounts=self.mounts,
                name_prefix=self.prefix,
            )
        self.assertEqual(good["state"], "completed")
        self.assertRegex(str(ctx.exception).lower(), r"image|digest")

    def test_cleanup_absence_is_verified_after_successful_remove(self):
        good = self._run("ok")
        self.assertTrue(good["container_absent_after"])
        self.assertFalse(run.container_exists(good["name"]))
        self.assertIsNotNone(good["inspect"])
        run.require_container_absent(good["name"])
        self.assertIsNone(inspect.signature(run.require_container_absent).parameters.get("exists"))
        src = inspect.getsource(run.require_container_absent)
        self.assertIn("inspect_lookup", src)
        self.assertNotIn("return", src)

    def test_prepare_emits_artifact_without_subject_binary_or_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "bundle"
            root = _committed_execution_root(Path(d) / "exec")
            raw = run.prepare(PREREG, dest, root=root, adapter=ADAPTER)
            doc = json.loads(raw.decode("utf-8"))
            self.assertTrue((dest / "prepare.v0.json").is_file())
            self.assertTrue((dest / "subject").is_dir())
            self.assertTrue((dest / "corpus").is_dir())
            self.assertTrue((dest / "vendor").is_dir())
            self.assertTrue((dest / "tool" / "config.toml").is_file())
            self.assertFalse((dest / "archives").exists())
            artifact = (dest / "prepare.v0.json").read_bytes()
            self.assertEqual(artifact, raw)
            self.assertNotIn(b"/Users/", artifact)
            self.assertNotIn(b"/home/", artifact)
            self.assertEqual(doc["materialized"]["corpus_id_count"], 250)
            self.assertEqual(
                doc["materialized"]["corpus_manifest_sha256"],
                run.FROZEN_CORPUS_MANIFEST_SHA256)
            for row in doc["probe_evidence"]:
                self.assertEqual(row["refusal"], run.EXPECTED_REFUSALS[row["mechanism"]], row)
        self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)
        self.assertFalse(doc["materialized"]["subject_binary"])
        self.assertNotIn("vectors", doc["materialized"])
        self.assertNotEqual(doc["materialized"]["vendor_sha256"], EMPTY_VENDOR)
        self.assertEqual(doc["pins"]["instrument_commit"], run.PHASE_A_INSTRUMENT_COMMIT)
        self.assertNotEqual(doc["execution"]["commit"], doc["pins"]["instrument_commit"])
        self.assertEqual(doc["network"]["cutoff"], "after_materialization")
        self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
        self.assertEqual(doc["materialize_ceilings"], run.MATERIALIZE_CEILINGS)
        self.assertNotEqual(doc["materialize_ceilings"], doc["ceilings"])
        self.assertEqual(
            doc["materialized"]["subject_tree_sha256"], run.FROZEN_SUBJECT_TREE_SHA256)
        self.assertEqual(
            doc["materialized"]["corpus_tree_sha256"], run.FROZEN_CORPUS_TREE_SHA256)
        self.assertEqual(doc["toolchain"]["index"], run.RUST_IMAGE)
        self.assertEqual(doc["toolchain"]["observation"], "vendor-image; checker was not run")
        self.assertIn("1.92.0", doc["toolchain"]["rustc_Vv"])
        self.assertIn("1.92.0", doc["toolchain"]["cargo_V"])
        run.require_image_id(doc["toolchain"]["image_id"])
        self.assertRegex(doc["toolchain"]["platform"], r"^linux/")
        self.assertEqual(doc["image"]["kind"], "inert-probe")
        self.assertEqual(doc["image"]["id_scope"], "host-local")
        self.assertRegex(doc["image"]["platform"], r"^linux/")
        self.assertNotIn("host_evidence", doc)
        self.assertNotIn("cpus", doc["oci"])
        self.assertNotIn("nofile", doc["oci"])
        run.require_image_id(doc["image"]["id"])
        mechanisms = [row["mechanism"] for row in doc["probe_evidence"]]
        self.assertEqual(mechanisms, list(run.PROBE_MECHANISMS))
        for row in doc["probe_evidence"]:
            self.assertEqual(row["control"], "completed", row)
            self.assertNotEqual(row["refusal"], "completed", row)
            self.assertEqual(set(row["inspect"]), {"control", "refusal"}, row)
            self.assertEqual(row["inspect"]["refusal"]["network_mode"], "none", row)
        network = next(row for row in doc["probe_evidence"] if row["mechanism"] == "network-off")
        self.assertNotEqual(network["inspect"]["control"]["network_mode"], "none")
        protocol = next(row for row in doc["probe_evidence"] if row["mechanism"] == "protocol-exit")
        self.assertEqual(protocol["control"], "completed")
        self.assertEqual(protocol["refusal"], "abnormal")

    def test_memory_swap_pids_are_inspect_verified_not_efficacy_probed(self):
        good = self._run("ok")
        host = run.defense_in_depth_from_inspect(good["inspect"])
        self.assertEqual(host["memory"], 4 * 1024 * 1024 * 1024)
        self.assertEqual(host["memory_swap"], 4 * 1024 * 1024 * 1024)
        self.assertEqual(host["pids"], 512)
        self.assertEqual(host["claim"], "inspect-verified; not efficacy-tested")

    def test_tmpfs_copy_after_stop_is_empty_copy_while_running_is_not(self):
        live_name = "aee-tmpfs-live-%s" % hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        stop_name = "aee-tmpfs-stop-%s" % hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        with tempfile.TemporaryDirectory() as d:
            live = Path(d) / "live"
            stopped = Path(d) / "stopped"
            live.mkdir()
            stopped.mkdir()
            created = []
            try:
                owner = run.host_bind_owner(live)
                run.pull_rust_image()
                run.docker_bounded([
                    "create", "--name", live_name,
                    "--tmpfs", "/vendor:rw,size=1048576,nr_inodes=128",
                    "--mount", "type=bind,source=%s,destination=/out" % live,
                    run.RUST_IMAGE, "sleep", "60",
                ])
                created.append(live_name)
                run.docker_bounded(["start", live_name])
                run.docker_ok(["exec", live_name, "sh", "-c", "echo packed > /vendor/keep"])
                argv = run.copy_tmpfs_argv(live_name, owner)
                self.assertEqual(argv[argv.index("--user") + 1], owner)
                run.docker_ok(argv)
                self.assertTrue((live / "keep").is_file())
                run.docker_bounded([
                    "create", "--name", stop_name,
                    "--tmpfs", "/vendor:rw,size=1048576,nr_inodes=128",
                    self.image_id, "sleep", "60",
                ])
                created.append(stop_name)
                run.docker_bounded(["start", stop_name])
                run.docker_ok(["exec", stop_name, "sh", "-c", "echo packed > /vendor/keep"])
                run.docker_ok(["stop", stop_name])
                run.docker_ok(["cp", "%s:/vendor/." % stop_name, str(stopped)])
                self.assertFalse((stopped / "keep").exists())
            finally:
                for name in created:
                    run.docker_ok(["rm", "-f", name])
                    run.require_container_absent(name)

    def test_container_written_host_bytes_are_owner_removable(self):
        name = "aee-tmpfs-owner-%s" % hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        run.pull_rust_image()
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            dest.mkdir()
            owner = run.host_bind_owner(dest)
            try:
                run.docker_bounded([
                    "create", "--name", name,
                    "--tmpfs", "/vendor:rw,size=1048576,nr_inodes=128",
                    "--mount", "type=bind,source=%s,destination=/out" % dest,
                    run.RUST_IMAGE, "sleep", "60",
                ])
                run.docker_bounded(["start", name])
                run.docker_ok([
                    "exec", name, "sh", "-c",
                    "mkdir -p /vendor/sub && echo packed > /vendor/keep "
                    "&& echo x > /vendor/sub/LICENSE-APACHE",
                ])
                argv = run.copy_tmpfs_argv(name, owner)
                self.assertEqual(argv[argv.index("--user") + 1], owner)
                run.docker_ok(argv)
                with mock.patch.object(mat, "docker_ok", side_effect=run.PrepareError("copy failed")):
                    with self.assertRaises(run.PrepareError):
                        run.copy_tmpfs_as_bind_owner(name, dest)
                keep = dest / "keep"
                license_apache = dest / "sub" / "LICENSE-APACHE"
                self.assertTrue(keep.is_file())
                self.assertTrue(license_apache.is_file())
                if hasattr(os, "getuid"):
                    self.assertEqual(keep.stat().st_uid, os.getuid())
                    self.assertEqual(license_apache.stat().st_uid, os.getuid())
                keep.unlink()
                license_apache.unlink()
                (dest / "sub").rmdir()
                self.assertFalse(keep.exists())
                self.assertFalse((dest / "sub").exists())
            finally:
                run.docker_ok(["rm", "-f", name])
                run.require_container_absent(name)

    @unittest.skipUnless(CARGO, "cargo is not available")
    def test_vendor_locked_live_copy_is_nonempty_and_builds_offline(self):
        with tempfile.TemporaryDirectory() as d:
            bundle = Path(d) / "bundle"
            subject = bundle / "subject"
            vendor = Path(d) / "vendor"
            tool = bundle / "tool"
            (subject / "src").mkdir(parents=True)
            (subject / "Cargo.toml").write_text(
                "[package]\nname = \"inert-vendor-fixture\"\n"
                "version = \"0.1.0\"\nedition = \"2021\"\n\n"
                "[dependencies]\ncfg-if = \"1.0.0\"\n",
                encoding="utf-8")
            (subject / "src" / "lib.rs").write_text("pub fn n() -> u8 { 1 }\n", encoding="utf-8")
            subprocess.run(
                ["cargo", "generate-lockfile"], cwd=subject, check=True,
                capture_output=True)
            result = run.vendor_locked(subject, vendor)
            self.assertNotEqual(result["vendor_sha256"], EMPTY_VENDOR)
            self.assertTrue(any(vendor.iterdir()))
            owned = [path for path in vendor.rglob("*") if path.is_file()]
            self.assertTrue(owned)
            if hasattr(os, "getuid"):
                self.assertTrue(all(path.stat().st_uid == os.getuid() for path in owned))
            run.bind_vendor_config(
                tool, REPO_ROOT / "execution" / "aee-checker-sealed" / "cargo-config.toml")
            env = dict(os.environ)
            env["CARGO_HOME"] = str(tool)
            env["CARGO_NET_OFFLINE"] = "true"
            built = subprocess.run(
                ["cargo", "build", "--offline", "--manifest-path",
                 str(subject / "Cargo.toml")],
                cwd=subject, env=env, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stderr)
            owned[0].unlink()


class FrozenAeeEol(unittest.TestCase):
    def test_gitattributes_and_check_attr_pin_aee_paths_to_lf(self):
        lines = (REPO_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        for rule in AEE_LF_ATTRS:
            self.assertIn(rule, lines)
        for rel in AEE_LF_PATHS:
            self.assertEqual(_git_eol(REPO_ROOT, rel), "lf", rel)

    def test_prepare_consumes_worktree_adapter_bytes_without_eol_rewrite(self):
        raw = ADAPTER.read_bytes()
        self.assertNotIn(b"\r\n", raw)
        self.assertEqual(_sha256(raw), run.ADAPTER_DIGEST)
        texts = {
            rel: (REPO_ROOT / rel).read_text(encoding="utf-8") for rel in PHASE_B_PY
        }
        joined = "\n".join(texts.values())
        self.assertNotIn("replace(b\"\\r\\n\"", joined)
        self.assertNotIn("replace('\\r\\n'", joined)
        self.assertNotIn("replace(\"\\r\\n\"", joined)
        self.assertNotIn("core.autocrlf", joined)


class MaterializeVerify(unittest.TestCase):
    def test_payload_digest_mismatch_is_refused_before_use(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "payload.json"
            path.write_text('{"ok":true}\n', encoding="utf-8")
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_file_digest(path, "bb" * 32)
            self.assertIn("digest", str(ctx.exception).lower())




class ExplicitPrepareImage(unittest.TestCase):
    IMAGE = "sha256:" + ("11" * 32)
    OTHER = "sha256:" + ("22" * 32)

    def _pins_doc(self):
        return {
            "corpus": {
                "commit": "59faf842098183ae7b5387ad13e6351c44687279",
                "corpusDigest": (
                    "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579"),
            },
            "instrument": {"commit": run.PHASE_A_INSTRUMENT_COMMIT},
            "subject": {"commit": "25b9dfa797986624f2d680530a7228232aa3ddda"},
        }

    def _probe(self, *, image_id, mode, sealed=True, **_kwargs):
        self.probed.append(image_id)
        contract = _fixture_contract(
            network_mode="none" if sealed else "bridge", offline=bool(sealed))
        if mode in ("deadline-ok", "tmpfs-bytes-ok", "tmpfs-inodes-ok", "output-ok", "ok"):
            return {"state": "completed", "contract": contract}
        if mode == "network" and not sealed:
            return {"state": "completed", "contract": contract}
        if mode == "deadline":
            return {"state": "deadline", "contract": contract}
        if mode == "output":
            return {"state": "output_cap", "contract": contract}
        return {"state": "abnormal", "contract": contract}

    def _materialize(self, _pins, staging, **_kwargs):
        staging = Path(staging)
        staging.mkdir(parents=True, exist_ok=True)
        mats = {
            "corpus": staging / "corpus",
            "vendor": staging / "vendor",
            "tool": staging / "tool",
            "toolchain": {
                "cargo_V": "cargo 1.92.0 (test)",
                "image_id": "sha256:" + ("cd" * 32),
                "index": run.RUST_IMAGE,
                "observation": "vendor-image; checker was not run",
                "platform": "linux/arm64",
                "rustc_Vv": "rustc 1.92.0 (test)",
            },
            "corpus_digest": "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579",
            "corpus_id_count": 250,
            "corpus_id_set_sha256": "dd" * 32,
            "corpus_manifest_sha256": run.FROZEN_CORPUS_MANIFEST_SHA256,
            "corpus_tree_sha256": run.FROZEN_CORPUS_TREE_SHA256,
            "subject_tree_sha256": run.FROZEN_SUBJECT_TREE_SHA256,
            "subject_check_rs_sha256": (
                "1623780ae759c070a85b74e2de6df6dac28f13f068cecbc1ea4b10e070e7a86f"),
            "tool_config_sha256": "ee" * 32,
            "vendor_sha256": "aa" * 32,
            "vendor_outside_subject": True,
            "subject_binary": False,
        }
        for key in ("corpus", "vendor", "tool"):
            mats[key].mkdir(exist_ok=True)
        return mats

    def _patches(self, *, local_ok=True):
        self.probed = []
        self.built = []
        self.platforms = []

        def build(_context):
            self.built.append(self.OTHER)
            return self.OTHER

        def local(image_id):
            if not local_ok:
                raise run.PrepareError("image is not local")
            run.require_image_id(image_id)

        def platform(image_id):
            self.platforms.append(image_id)
            return "linux/arm64"

        return (
            mock.patch.object(run, "verify_phase_a_frozen", return_value=self._pins_doc()),
            mock.patch.object(run, "require_docker_ready", return_value="test"),
            mock.patch.object(run, "build_inert_image", side_effect=build),
            mock.patch.object(run, "require_local_image", side_effect=local),
            mock.patch.object(run, "run_inert_probe", side_effect=self._probe),
            mock.patch.object(run, "materialize_pinned", side_effect=self._materialize),
            mock.patch.object(run, "execution_identity", return_value={
                "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "content_sha256": "cc" * 32,
                "paths": list(run.EXECUTION_PATHS),
            }),
            mock.patch.object(run, "image_platform", side_effect=platform),
            mock.patch.object(run, "docker_bounded", return_value=b"29.7.2"),
            mock.patch.object(run, "record_toolchain", return_value={
                "cargo_V": "cargo 1.92.0 (test)",
                "image_id": "sha256:" + ("cd" * 32),
                "index": run.RUST_IMAGE,
                "observation": "vendor-image; checker was not run",
                "platform": "linux/arm64",
                "rustc_Vv": "rustc 1.92.0 (test)",
            }),
        )

    def _run_prepare(self, dest, image_id=None, root=None):
        root = root or dest.parent / "root"
        pins = dest.parent / "pins"
        patches = self._patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patches[5], patches[6], patches[7], patches[8], patches[9]:
            return run.prepare(pins, dest, root=root, image_id=image_id)

    def test_omitted_image_still_builds_once(self):
        with tempfile.TemporaryDirectory() as d:
            raw = self._run_prepare(Path(d) / "out-a")
        self.assertEqual(self.built, [self.OTHER])
        self.assertTrue(self.probed)
        self.assertTrue(all(image == self.OTHER for image in self.probed))
        self.assertEqual(json.loads(raw)["image"]["id"], self.OTHER)

    def test_supplied_image_skips_build_and_is_used_everywhere(self):
        with tempfile.TemporaryDirectory() as d:
            raw = self._run_prepare(Path(d) / "out-a", image_id=self.IMAGE)
        self.assertEqual(self.built, [])
        self.assertTrue(self.probed)
        self.assertTrue(all(image == self.IMAGE for image in self.probed))
        self.assertTrue(all(image == self.IMAGE for image in self.platforms))
        self.assertEqual(json.loads(raw)["image"]["id"], self.IMAGE)

    def test_two_production_prepares_with_same_image_are_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            left = self._run_prepare(Path(d) / "out-a", image_id=self.IMAGE)
            right = self._run_prepare(Path(d) / "out-b", image_id=self.IMAGE)
        self.assertEqual(left, right)
        self.assertIn(self.IMAGE.encode("ascii"), left)

    def test_malformed_or_absent_local_image_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "out"
            with self.assertRaises(run.PrepareError):
                self._run_prepare(dest, image_id="busybox:latest")
            self.assertEqual(self.built, [])
            def missing(image_id):
                run.require_image_id(image_id)
                raise run.PrepareError("image is not local")
            self.probed = []
            self.built = []
            with mock.patch.object(run, "verify_phase_a_frozen", return_value=self._pins_doc()), \
                    mock.patch.object(run, "require_docker_ready", return_value="test"), \
                    mock.patch.object(run, "build_inert_image", side_effect=lambda *_: self.built.append(1)), \
                    mock.patch.object(run, "require_local_image", side_effect=missing):
                with self.assertRaises(run.PrepareError):
                    run.prepare(Path(d) / "pins", dest, root=Path(d) / "root",
                                image_id=self.IMAGE)
            self.assertEqual(self.built, [])

    def test_main_without_command_writes_usage_and_returns_2(self):
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            rc = run.main(["aee_checker_sealed_run.py"])
        self.assertEqual(rc, 2)
        self.assertIn("usage:", err.getvalue())

    def test_cli_forwards_optional_image_id_without_validating(self):
        captured = {}

        def fake_prepare(pins, dest, *, root, adapter, image_id=None):
            captured["image_id"] = image_id
            return b"{}\n"

        with mock.patch.object(run, "prepare", side_effect=fake_prepare):
            rc = run.main(["aee_checker_sealed_run.py", "prepare", "pins", "out", self.IMAGE])
        self.assertEqual(rc, 0)
        self.assertEqual(captured["image_id"], self.IMAGE)
        with mock.patch.object(run, "prepare", side_effect=fake_prepare):
            rc = run.main(["aee_checker_sealed_run.py", "prepare", "pins", "out"])
        self.assertEqual(captured["image_id"], None)


if __name__ == "__main__":
    unittest.main()
