#!/usr/bin/env python3
"""The hosted pids witness route: identity, dispatch binding, sealing and readback (#197 part 4).

Nothing here starts a container or talks to Docker: the readiness check, the pull, the host
observation and the witness itself are injected, so the suite runs on hosts without a daemon.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "measurements"), str(Path(__file__).resolve().parent)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

import aee_checker_sealed_materialize as materialize  # noqa: E402
import contained_oci as contained  # noqa: E402
import kernel_readback as kr  # noqa: E402
import pids_witness as pw  # noqa: E402

R = "a" * 40
IMAGE = "sha256:" + "cd" * 32
HOST = {"Architecture": "x86_64", "CgroupDriver": "systemd", "CgroupVersion": "2",
        "KernelVersion": "6.11.0-1018-azure", "OperatingSystem": "Ubuntu 24.04.3 LTS",
        "ServerVersion": "28.0.4"}
PROFILE = contained.CANDIDATE_RESOURCE_PROFILE_V2


def _environ(sha=R, workflow_sha=R):
    return {"GITHUB_SHA": sha, "GITHUB_WORKFLOW_SHA": workflow_sha, "GITHUB_RUN_ID": "1",
            "GITHUB_RUN_ATTEMPT": "1", "ImageOS": "ubuntu24", "ImageVersion": "20260914.1"}


def _record(events=b"max 41\n", **raw_over):
    files = {"memory.max": b"4294967296\n", "memory.swap.max": b"0\n",
             "pids.max": b"512\n", "cpu.max": b"100000 100000\n",
             "pids.events": events}
    from kernel_fixtures import kernel_files_for
    argv = ["--memory", "4g", "--memory-swap", "4g", "--pids-limit", "512",
            "--ulimit", "nofile=1024:1024"]
    files["limits"] = kernel_files_for(argv)["limits"]
    raw = {"state": "completed", "process": subprocess.CompletedProcess([], 0, "", ""),
           "create_warnings": (), "cleanup": "removed-and-absent", "kernel_files": files}
    raw.update(raw_over)
    return pw.witness_record(raw, image_id=IMAGE)


def _never(*_args, **_kwargs):
    raise AssertionError("reached a container step before the refusal")


class Hosted:
    """Runs `run_hosted` in a scratch directory with everything outside the process injected."""

    def __init__(self, test, **record_over):
        self.test = test
        self.record_over = record_over

    def run(self, *, environ=None, identity_sha256=None, out=None, witness=None,
            docker_ready=None):
        scratch = Path(tempfile.mkdtemp())
        self.test.addCleanup(shutil.rmtree, scratch)
        self.out = scratch / "out" if out is None else out
        return pw.run_hosted(
            runner_revision=R,
            identity_sha256=(pw.identity()["content_sha256"] if identity_sha256 is None
                             else identity_sha256),
            out_dir=self.out, environ=_environ() if environ is None else environ,
            docker_ready=docker_ready or (lambda: None), pull=lambda: IMAGE,
            host=lambda: dict(HOST),
            witness=witness or (lambda image_id: _record(**self.record_over)))


class TheIdentity(unittest.TestCase):
    def test_the_paths_are_exactly_the_modules_a_witness_run_imports_and_its_workflow(self):
        probe = ("import sys, json; from pathlib import Path; "
                 "sys.path[:0] = [%r, %r]; import pids_witness; root = Path(%r).resolve(); "
                 "files = [Path(m.__file__).resolve() for m in list(sys.modules.values()) "
                 "if getattr(m, '__file__', None)]; "
                 "print(json.dumps(sorted(f.relative_to(root).as_posix() for f in files "
                 "if f.is_relative_to(root))))"
                 % (str(ROOT / "measurements"), str(ROOT), str(ROOT)))
        loaded = json.loads(subprocess.run([sys.executable, "-B", "-c", probe], check=True,
                                           capture_output=True, text=True).stdout)
        self.assertEqual(sorted(loaded + [".github/workflows/pids-witness.yml"]),
                         sorted(pw.EXECUTION_PATHS))

    def test_every_byte_of_every_path_is_in_the_digest(self):
        base = pw.identity()["content_sha256"]
        for relpath in pw.EXECUTION_PATHS:
            with self.subTest(path=relpath), tempfile.TemporaryDirectory() as d:
                for other in pw.EXECUTION_PATHS:
                    target = Path(d) / other
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / other, target)
                self.assertEqual(pw.identity(Path(d))["content_sha256"], base)
                with open(Path(d) / relpath, "ab") as handle:
                    handle.write(b" ")
                self.assertNotEqual(pw.identity(Path(d))["content_sha256"], base)

    def test_the_image_is_the_one_every_owned_run_uses(self):
        self.assertEqual(pw.IMAGE_INDEX, materialize.RUST_IMAGE)


class TheHostedRunRefusesFirst(unittest.TestCase):
    def _refused(self, reason, **kwargs):
        with self.assertRaises(pw.WitnessRouteError) as caught:
            Hosted(self).run(witness=_never, docker_ready=_never, **kwargs)
        self.assertEqual(str(caught.exception), reason)

    def test_a_workflow_not_at_r_is_refused(self):
        self._refused("github_sha_binding", environ=_environ(sha="b" * 40))
        self._refused("github_workflow_sha_binding", environ=_environ(workflow_sha="b" * 40))

    def test_an_unobserved_workflow_is_refused(self):
        self._refused("github_sha_binding", environ={})

    def test_an_identity_other_than_the_dispatched_one_is_refused(self):
        self._refused("identity_binding", identity_sha256="0" * 64)

    def test_malformed_dispatch_values_are_refused(self):
        for revision, digest, reason in (("HEAD", "0" * 64, "runner_revision"),
                                         ("A" * 40, "0" * 64, "runner_revision"),
                                         (R, "abc", "identity_sha256"),
                                         (R, "0" * 63 + "G", "identity_sha256")):
            with self.subTest(reason=reason, revision=revision, digest=digest):
                with self.assertRaises(pw.WitnessRouteError) as caught:
                    pw.run_hosted(runner_revision=revision, identity_sha256=digest,
                                  out_dir=Path("x"), environ=_environ(revision),
                                  docker_ready=_never, pull=_never, host=_never,
                                  witness=_never)
                self.assertEqual(str(caught.exception), reason)


class TheHostedRunSeals(unittest.TestCase):
    def test_it_writes_the_attempt_the_predicate_and_their_sums(self):
        hosted = Hosted(self)
        attempt = hosted.run()
        names = sorted(path.name for path in hosted.out.iterdir())
        self.assertEqual(names, sorted([pw.ATTEMPT_FILENAME, pw.PREDICATE_FILENAME,
                                        pw.SUMS_FILENAME]))
        raw = (hosted.out / pw.ATTEMPT_FILENAME).read_bytes()
        self.assertEqual(json.loads(raw), attempt)
        predicate = json.loads((hosted.out / pw.PREDICATE_FILENAME).read_bytes())
        self.assertEqual(predicate, {"attempt_sha256": hashlib.sha256(raw).hexdigest(),
                                     "identity_sha256": pw.identity()["content_sha256"],
                                     "runner_revision": R, "verdict": "witnessed"})
        for line in (hosted.out / pw.SUMS_FILENAME).read_text().splitlines():
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((hosted.out / name).read_bytes()).hexdigest(),
                             digest)

    def test_an_unproved_witness_is_sealed_too(self):
        hosted = Hosted(self, events=b"max 0\n")
        attempt = hosted.run()
        self.assertEqual(attempt["witness"]["verdict"], "unproved")
        self.assertTrue((hosted.out / pw.SUMS_FILENAME).exists())

    def test_an_existing_output_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileExistsError):
                Hosted(self).run(out=Path(d))


class TheReadback(unittest.TestCase):
    def setUp(self):
        self.hosted = Hosted(self)
        self.hosted.run()
        self.raw = (self.hosted.out / pw.ATTEMPT_FILENAME).read_bytes()
        self.identity = pw.identity()["content_sha256"]

    def _verify(self, raw=None, **kwargs):
        return pw.verify(self.raw if raw is None else raw,
                         runner_revision=kwargs.get("runner_revision", R),
                         identity_sha256=kwargs.get("identity_sha256", self.identity))

    def _tampered(self, mutate):
        doc = json.loads(self.raw)
        mutate(doc)
        return json.dumps(doc).encode("utf-8")

    def test_an_untouched_attempt_verifies(self):
        result = self._verify()
        self.assertEqual(result["verdict"], "witnessed")
        self.assertEqual(result["pids_events"], {"max": 41})

    def test_an_unproved_attempt_verifies_as_unproved(self):
        hosted = Hosted(self, events=b"max 0\n")
        hosted.run()
        result = self._verify((hosted.out / pw.ATTEMPT_FILENAME).read_bytes())
        self.assertEqual(result["verdict"], "unproved")
        self.assertEqual(result["unproved_reasons"], ["pids-limit-not-reached"])

    def test_every_tampering_is_refused_with_its_reason(self):
        def set_path(*path_and_value):
            *path, value = path_and_value

            def mutate(doc):
                target = doc
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
            return mutate

        cases = [
            ("verdict", set_path("witness", "verdict", "unproved")),
            ("reasons", set_path("witness", "unproved_reasons", ["pids-limit-not-reached"])),
            # The kernel said something else, but the record still claims `verified`.
            ("kernel_problems", set_path("witness", "kernel", "observed", "pids_max", 1024)),
            # A limit never reached, relabelled as a witness.
            ("reasons", set_path("witness", "pids_events", {"max": 0})),
            ("reasons", set_path("witness", "exit_code", 83)),
            ("reasons", set_path("witness", "cleanup", "remove-failed")),
            ("reasons", set_path("witness", "create_warnings", ["WARNING"])),
            ("reasons", set_path("witness", "state", "timeout")),
            ("dispatch_binding", set_path("dispatch", "runner_revision", "b" * 40)),
            ("github_sha_binding", set_path("workflow", "github_sha", "b" * 40)),
            ("identity_binding", set_path("identity", "content_sha256", "0" * 64)),
            ("image_index", set_path("image", "index", "docker.io/library/rust:latest")),
            ("witness_binding", set_path("witness", "image_id", "sha256:" + "ef" * 32)),
            ("resource_profile", set_path("witness", "resource_profile", "pids", 4096)),
            ("non_claims", set_path("witness", "non_claims", [])),
            ("attempt_keys", set_path("extra", True)),
            ("witness_keys", set_path("witness", "stdout", "witnessed")),
            ("host_keys", set_path("host", "Extra", 1)),
        ]
        for reason, mutate in cases:
            with self.subTest(reason=reason, mutate=mutate):
                with self.assertRaises(pw.WitnessRouteError) as caught:
                    self._verify(self._tampered(mutate))
                self.assertEqual(str(caught.exception), reason)

    def test_the_wrong_dispatch_values_are_refused(self):
        with self.assertRaises(pw.WitnessRouteError) as caught:
            self._verify(runner_revision="b" * 40)
        self.assertEqual(str(caught.exception), "dispatch_binding")
        with self.assertRaises(pw.WitnessRouteError) as caught:
            self._verify(identity_sha256="0" * 64)
        self.assertEqual(str(caught.exception), "dispatch_binding")

    def test_a_checkout_that_is_not_r_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            for other in pw.EXECUTION_PATHS:
                target = Path(d) / other
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / other, target)
            with open(Path(d) / "measurements" / "pids_witness.py", "ab") as handle:
                handle.write(b"\n")
            with self.assertRaises(pw.WitnessRouteError) as caught:
                pw.verify(self.raw, runner_revision=R, identity_sha256=self.identity,
                          root=Path(d))
        self.assertEqual(str(caught.exception), "identity_root")

    def test_malformed_kernel_text_in_the_record_is_refused_not_trusted(self):
        raw = self._tampered(lambda doc: doc["witness"]["pids_events"].update({"max": -1}))
        with self.assertRaises((pw.WitnessRouteError, kr.ReadbackError)):
            self._verify(raw)


class TheWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / ".github" / "workflows" / "pids-witness.yml").read_text()

    def test_it_is_dispatch_only_with_exactly_the_two_bindings(self):
        self.assertIn("on:\n  workflow_dispatch:\n    inputs:\n", self.text)
        self.assertNotIn("push:", self.text)
        self.assertNotIn("pull_request", self.text)
        inputs = self.text.split("inputs:\n", 1)[1].split("\npermissions:", 1)[0]
        names = [line.strip()[:-1] for line in inputs.splitlines()
                 if line.startswith("      ") and not line.startswith("        ")]
        self.assertEqual(names, ["runner_revision", "identity_sha256"])

    def test_it_checks_out_r_without_credentials_and_runs_the_hosted_command(self):
        self.assertIn("ref: ${{ inputs.runner_revision }}", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("python measurements/pids_witness.py hosted --runner-revision "
                      "\"$RUNNER_REVISION\" --identity-sha256 \"$IDENTITY_SHA256\"", self.text)

    def test_it_uses_only_the_action_pins_the_owned_rail_uses(self):
        owned = (ROOT / ".github" / "workflows" / "owned-contained-v1-publication.yml").read_text()
        uses = [line.split("uses:", 1)[1].strip() for line in self.text.splitlines()
                if "uses:" in line]
        self.assertTrue(uses)
        for pin in uses:
            self.assertIn(pin, owned)

    def test_it_attests_the_sums_with_the_witness_predicate(self):
        self.assertIn("subject-checksums: pids-witness-artifacts/%s" % pw.SUMS_FILENAME,
                      self.text)
        self.assertIn("predicate-type: %s" % pw.PREDICATE_TYPE, self.text)
        self.assertIn("predicate-path: pids-witness-artifacts/%s" % pw.PREDICATE_FILENAME,
                      self.text)


class TheCommandLine(unittest.TestCase):
    def test_identity_prints_the_digest_of_this_checkout(self):
        proc = subprocess.run([sys.executable, "-B", str(ROOT / "measurements" / "pids_witness.py"),
                               "identity"], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(proc.stdout), pw.identity())

    def test_verify_prints_one_pass_line(self):
        hosted = Hosted(self)
        hosted.run()
        proc = subprocess.run(
            [sys.executable, "-B", str(ROOT / "measurements" / "pids_witness.py"), "verify",
             "--attempt", str(hosted.out / pw.ATTEMPT_FILENAME), "--runner-revision", R,
             "--identity-sha256", pw.identity()["content_sha256"]],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "pids-witness-verify=pass verdict=witnessed reasons=-\n")

    def test_a_refused_verify_exits_2_and_names_the_reason(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "a.json"
            path.write_text("{}\n")
            proc = subprocess.run(
                [sys.executable, "-B", str(ROOT / "measurements" / "pids_witness.py"),
                 "verify", "--attempt", str(path), "--runner-revision", R,
                 "--identity-sha256", "0" * 64], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("attempt_keys", proc.stderr)


if __name__ == "__main__":
    unittest.main()
