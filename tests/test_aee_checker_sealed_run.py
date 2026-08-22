#!/usr/bin/env python3
"""Phase B PREPARE + inert OCI contract for issue #211. Standard library only.

Does not invoke aee-checker against aee-conformance. Does not emit a report.
Source-string equality is a structural guard. Biting tests feed hostile
input, wrong digests, abnormal exits, and live inert probes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import aee_checker_sealed_run as run  # noqa: E402

PREREG = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"
ADAPTER = REPO_ROOT / "adapters" / "aee_checker_sealed.py"
CONTAINERFILE = REPO_ROOT / "execution" / "aee-checker-sealed" / "Containerfile"

PHASE_A_DIGESTS = {
    "adapters/aee_checker_sealed.py": (
        "130b36d50df8a286954649771c9d65f35541ecd2f7007918ce5b261ace3aa769"
    ),
    "measurements/aee-checker-25b9dfa/manifest.json": (
        "2f16654dd57a0b1719ec2ec5be7a833192ccae529d08c4c7695c7df4782c32c8"
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
    sealed = root / "execution" / "aee-checker-sealed"
    sealed.mkdir(parents=True)
    (root / "measurements").mkdir()
    shutil.copy2(
        REPO_ROOT / "measurements" / "aee_checker_sealed_run.py",
        root / "measurements" / "aee_checker_sealed_run.py",
    )
    shutil.copy2(CONTAINERFILE, sealed / "Containerfile")
    shutil.copy2(CONTAINERFILE.parent / "probe.sh", sealed / "probe.sh")
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "exec"],
        cwd=root, check=True, capture_output=True,
    )
    return root


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


def _docker_available() -> bool:
    exe = shutil.which("docker")
    if exe is None:
        return False
    try:
        proc = subprocess.run([exe, "info"], capture_output=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


DOCKER = _docker_available()


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
            dest = Path(d) / "out" / "prepare.v0.json"
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_phase_a_frozen(pins)
            self.assertIn("phase-a", str(ctx.exception).lower())
            with self.assertRaises(run.PrepareError):
                run.prepare(pins, dest, root=REPO_ROOT)
            self.assertFalse(dest.exists())

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

    def test_exit_0_small_output_is_completed_without_scoring(self):
        result = run.classify_container_result(0, b'{"probe":"ok"}\n')
        self.assertEqual(result["state"], "completed")
        self.assertNotIn("score", result)
        self.assertNotIn("verdict", result)

    def test_boolean_exit_is_harness_failure(self):
        result = run.classify_container_result(True, b"{}\n")
        self.assertEqual(result["state"], "harness_failure")


class DockerArgvContract(unittest.TestCase):
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
                "corpus_id_set_sha256": "dd" * 32,
                "vendor_sha256": "aa" * 32,
                "vendor_outside_subject": True,
                "subject_binary": False,
            },
            "image": {"id": "sha256:" + ("ab" * 32), "kind": "inert-probe"},
            "toolchain": {
                "rustc_Vv": "rustc test",
                "cargo_V": "cargo test",
                "observation": "host; checker was not run",
            },
            "runtime": {
                "docker": "test",
                "observation": "host-local; not a portable bound",
            },
            "ceilings": dict(run.DECLARED_CEILINGS),
            "probe_evidence": [
                _probe_row("deadline", "deadline"),
                _probe_row("disk", "abnormal"),
                _probe_row("file-count", "abnormal"),
                _probe_row("network-off", "abnormal", control_net="bridge"),
                _probe_row("output", "output_cap"),
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

    def test_regeneration_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as d:
            left = Path(d) / "a.json"
            right = Path(d) / "b.json"
            parts = self._parts()
            self.assertEqual(
                run.emit_prepare_v0(parts, left),
                run.emit_prepare_v0(parts, right),
            )

    def test_extra_prepare_field_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            parts = self._parts()
            parts["score"] = 1
            with self.assertRaises(run.PrepareError):
                run.emit_prepare_v0(parts, dest)


class PublicStrings(unittest.TestCase):
    def test_run_module_does_not_claim_a_result(self):
        text = (REPO_ROOT / "measurements" / "aee_checker_sealed_run.py").read_text(
            encoding="utf-8")
        for word in FORBIDDEN_PUBLIC:
            self.assertNotIn(word, text, word)
        self.assertIn("not a scientific measurement", text)
        self.assertIn("checker was not run", text)
        self.assertIn("after_materialization", text)
        self.assertIn("subject binary is not produced here", text)
        self.assertIn("not efficacy-tested", text)
        self.assertNotIn("cargo build", text)
        self.assertIn("cargo vendor --locked", text)
        self.assertNotIn("entirely offline", text)
        self.assertNotIn("--cpus", text)
        self.assertNotIn("nofile", text)
        self.assertNotIn("cleanup_named_containers", text)
        self.assertNotIn("load_prepare_request", text)
        self.assertNotIn("REQUEST_SCHEMA", text)

    def test_containerfile_is_inert_probe_not_aee_checker(self):
        text = CONTAINERFILE.read_text(encoding="utf-8")
        self.assertNotIn("aee-checker", text)
        self.assertNotIn("aee-conformance", text)
        self.assertNotIn("cargo run", text)
        self.assertIn("@sha256:", text)
        self.assertIn("COPY --chmod=0755", text)
        self.assertNotIn("RUN ", text)


class InspectContract(unittest.TestCase):
    def _ok(self, *, network_mode="none", offline=True, **host_over):
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
        return {
            "HostConfig": host,
            "Config": {"User": "65532:65532", "Env": env},
            "Mounts": [
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
        self.assertEqual(snap["network_mode"], "none")
        self.assertTrue(snap["read_only_root"])
        self.assertEqual(snap["user"], "65532:65532")
        self.assertTrue(snap["offline_env"])


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


class MaterializeBytes(unittest.TestCase):
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

    def test_verify_materialized_uses_disk_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            subject = Path(d) / "subject"
            corpus = Path(d) / "corpus"
            (subject / "src").mkdir(parents=True)
            (corpus / "vectors").mkdir(parents=True)
            (subject / "src" / "check.rs").write_text("fn pinned() {}\n", encoding="utf-8")
            digest = _sha256((subject / "src" / "check.rs").read_bytes())
            manifest = {
                "corpusDigest": "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579",
                "vectors": [{"id": "v1"}],
            }
            (corpus / "vectors" / "MANIFEST.json").write_bytes(
                (json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"))
            pins = {
                "subject": {"path": "src/check.rs", "check_rs_sha256": digest},
                "corpus": {
                    "corpusDigest": "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579",
                    "vectors": "corpus/vectors/MANIFEST.json",
                },
            }
            got = run.verify_materialized(pins, subject, corpus)
            self.assertEqual(got["subject_check_rs_sha256"], digest)
            self.assertEqual(
                got["corpus_digest"],
                "b5aa5fdb4a9320e037658b2877f048d5c3dd7351fd93701d3c4977d69ae7a579")
            (subject / "src" / "check.rs").write_text("fn other() {}\n", encoding="utf-8")
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_materialized(pins, subject, corpus)
            self.assertIn("digest", str(ctx.exception).lower())

    def test_fetch_commit_checks_out_exact_commit(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            source, commit = _local_git_repo(tmp, "src", {"src/check.rs": b"fn x() {}\n"})
            dest = tmp / "checkout"
            run.fetch_commit(str(source), commit, dest)
            self.assertEqual((dest / "src" / "check.rs").read_bytes(), b"fn x() {}\n")
            with self.assertRaises(run.PrepareError):
                run.fetch_commit(str(source), "0" * 40, tmp / "bad")


@unittest.skipUnless(DOCKER, "docker daemon is not available")
class LiveInertProbes(unittest.TestCase):
    image_id = ""
    prefix = "aee-sealed-inert-"
    created_names: list[str] = []

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.mounts = {name: root / name for name in ("input", "vendor", "tool")}
        for path in cls.mounts.values():
            path.mkdir()
        cls.created_names = []
        cls.image_id = run.build_inert_image(CONTAINERFILE.parent)
        run.require_image_id(cls.image_id)

    @classmethod
    def tearDownClass(cls):
        for name in cls.created_names:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        cls._tmp.cleanup()

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
        row = run.record_probe_pair("exit-class", good, bad)
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
        with self.assertRaises(run.PrepareError):
            run.require_container_absent(good["name"], exists=True)

    def test_prepare_emits_artifact_without_subject_binary_or_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "prepare.v0.json"
            root = _committed_execution_root(Path(d) / "exec")
            raw = run.prepare(PREREG, dest, root=root, adapter=ADAPTER)
            doc = json.loads(raw.decode("utf-8"))
        self.assertEqual(doc["schema"], run.PREPARE_SCHEMA)
        self.assertFalse(doc["materialized"]["subject_binary"])
        self.assertNotIn("vectors", doc["materialized"])
        self.assertNotEqual(doc["materialized"]["vendor_sha256"], EMPTY_VENDOR)
        self.assertEqual(doc["pins"]["instrument_commit"], run.PHASE_A_INSTRUMENT_COMMIT)
        self.assertNotEqual(doc["execution"]["commit"], doc["pins"]["instrument_commit"])
        self.assertEqual(doc["network"]["cutoff"], "after_materialization")
        self.assertEqual(doc["ceilings"], run.DECLARED_CEILINGS)
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

    def test_memory_swap_pids_are_inspect_verified_not_efficacy_probed(self):
        good = self._run("ok")
        host = run.defense_in_depth_from_inspect(good["inspect"])
        self.assertEqual(host["memory"], 4 * 1024 * 1024 * 1024)
        self.assertEqual(host["memory_swap"], 4 * 1024 * 1024 * 1024)
        self.assertEqual(host["pids"], 512)
        self.assertEqual(host["claim"], "inspect-verified; not efficacy-tested")


class MaterializeVerify(unittest.TestCase):
    def test_payload_digest_mismatch_is_refused_before_use(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "payload.json"
            path.write_text('{"ok":true}\n', encoding="utf-8")
            with self.assertRaises(run.PrepareError) as ctx:
                run.verify_file_digest(path, "bb" * 32)
            self.assertIn("digest", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
