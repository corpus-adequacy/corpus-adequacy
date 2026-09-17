#!/usr/bin/env python3
"""Sealed attempt statement (#187): seal, canonical shape, offline readback, refusals."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import hosted_attempt_statement as statement  # noqa: E402
import contained_hosted_publication as hosted  # noqa: E402

CANDIDATE = "25b9dfa797986624f2d680530a7228232aa3ddda"
RUNNER = "1345bac5d5853824a6de00dda9a7b03efd906236"
IMAGE = "sha256:" + "d5" * 32
BINDINGS = {"candidate_revision": CANDIDATE, "runner_revision": RUNNER, "image_digest": IMAGE}
INPUTS = dict(BINDINGS, packet_release_tag="hosted-packet-r4",
              packet_manifest_sha256="cf" * 32)
RUN = {"run_id": "35194072925", "run_attempt": "1"}
WORKFLOW = {"github_sha": RUNNER, "github_workflow_sha": RUNNER,
            "image_os": "ubuntu24", "image_version": "20260907.300.1"}
ENVIRON = {
    "GITHUB_SHA": RUNNER, "GITHUB_WORKFLOW_SHA": RUNNER, "ImageOS": "ubuntu24",
    "ImageVersion": "20260907.300.1", "GITHUB_RUN_ID": RUN["run_id"],
    "GITHUB_RUN_ATTEMPT": RUN["run_attempt"],
}


def _write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _publish_surface(out: Path) -> dict:
    """A publish-shaped upload surface: three files plus a two-member collection."""
    files = {
        "setup-status.json": _write(out / "setup-status.json", b'{"setup_status": "ready"}\n'),
        "candidate-result.json": _write(out / "candidate-result.json", b'{"decision": "publish"}\n'),
        "rerun-evidence.jsonl": _write(out / "rerun-evidence.jsonl", b'{"kind": "run-attempt-start"}\n'),
        "effective-envelope-collection.v0/collection-index.v0.json": _write(
            out / "effective-envelope-collection.v0" / "collection-index.v0.json", b'{"attempts": 2}\n'),
        "effective-envelope-collection.v0/member-0000.json": _write(
            out / "effective-envelope-collection.v0" / "member-0000.json", b'{"m": 0}\n'),
        "effective-envelope-collection.v0/member-0001.json": _write(
            out / "effective-envelope-collection.v0" / "member-0001.json", b'{"m": 1}\n'),
    }
    # Not subjects: the materialize tree and a quarantined collection sit under out too.
    _write(out / "materialize" / "subject" / "src.rs", b"fn main() {}\n")
    _write(out / "withheld-collection.diagnostic.v0" / "attempt-0000" / "member-0000.json", b"{}\n")
    _write(out / "effective-envelope.v0.json", b'{"kind": "withheld-envelope-stub"}\n')
    return files


def _seal(out: Path, **over) -> dict:
    kwargs = dict(out_dir=out, rail="aee-contained-v0", bindings=BINDINGS,
                  dispatch_inputs=INPUTS, run_identity=RUN, workflow_identity=WORKFLOW,
                  gate_outcome="success")
    kwargs.update(over)
    return statement.seal_attempt(**kwargs)


class SealShape(unittest.TestCase):
    def test_seal_writes_canonical_sums_predicate_and_statement(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            files = _publish_surface(out)
            result = _seal(out)
            root = out / statement.STATEMENT_DIRNAME
            self.assertEqual(sorted(p.name for p in root.iterdir()),
                             sorted(statement.STATEMENT_FILENAMES))
            sums = (root / statement.SUMS_FILENAME).read_bytes().decode()
            lines = sums[:-1].split("\n")
            self.assertEqual([line.split("  ", 1)[1] for line in lines], sorted(files))
            for line in lines:
                digest, name = line.split("  ", 1)
                self.assertEqual(digest, hashlib.sha256(files[name].read_bytes()).hexdigest())
            self.assertNotIn("materialize", sums)
            self.assertNotIn("withheld-collection", sums)
            self.assertNotIn("effective-envelope.v0.json", sums)
            predicate = json.loads((root / statement.PREDICATE_FILENAME).read_text())
            self.assertEqual(sorted(predicate), sorted(statement.PREDICATE_KEYS))
            self.assertEqual(predicate["subjects"], len(files))
            self.assertEqual(predicate["subjects_sha256"],
                             hashlib.sha256(sums.encode()).hexdigest())
            self.assertEqual(predicate["dispatch_inputs"], INPUTS)
            self.assertEqual(predicate["run_identity"], RUN)
            self.assertEqual(predicate["gate_outcome"], "success")
            doc = json.loads((root / statement.STATEMENT_FILENAME).read_text())
            self.assertEqual(doc["_type"], statement.STATEMENT_TYPE)
            self.assertEqual(doc["predicateType"], statement.PREDICATE_TYPE)
            self.assertEqual(doc["predicate"], predicate)
            self.assertEqual([s["name"] for s in doc["subject"]], sorted(files))
            self.assertEqual(result["subjects"], len(files))
            self.assertEqual(result["statement_sha256"], hashlib.sha256(
                (root / statement.STATEMENT_FILENAME).read_bytes()).hexdigest())

    def test_withhold_surface_seals_the_diagnostic_package_only(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            _write(out / "setup-status.json", b"{}\n")
            _write(out / "candidate-result.json", b"{}\n")
            _write(out / "rerun-evidence.jsonl", b"{}\n")
            _write(out / "withheld-diagnostic-package.v0" / "diagnostic-package.v0.json", b"{}\n")
            _write(out / "withheld-diagnostic-package.v0" / "collection" / "member-0000.json", b"{}\n")
            _seal(out, gate_outcome="failure")
            sums = (out / statement.STATEMENT_DIRNAME / statement.SUMS_FILENAME).read_text()
            self.assertIn("withheld-diagnostic-package.v0/collection/member-0000.json", sums)
            self.assertIn("withheld-diagnostic-package.v0/diagnostic-package.v0.json", sums)
            self.assertEqual(sums.count("\n"), 5)

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            with self.assertRaises(statement.StatementError) as ctx:
                _seal(out)
            self.assertEqual(str(ctx.exception), "no_subjects")
            _publish_surface(out)
            for over, expect in (
                ({"gate_outcome": "green"}, "gate_outcome"),
                ({"bindings": dict(BINDINGS, image_digest="d5" * 32)}, "image_digest"),
                ({"dispatch_inputs": dict(INPUTS, candidate_revision=RUNNER)},
                 "dispatch_inputs:candidate_revision"),
                ({"dispatch_inputs": dict(INPUTS, packet_release_tag="")}, "packet_release_tag"),
                ({"run_identity": {"run_id": "x", "run_attempt": "1"}}, "run_id"),
                ({"workflow_identity": dict(WORKFLOW, github_sha="abc")}, "workflow_identity_sha"),
                ({"rail": ""}, "rail"),
            ):
                with self.assertRaises(statement.StatementError) as ctx:
                    _seal(out, **over)
                self.assertEqual(str(ctx.exception), expect, over)
            self.assertFalse((out / statement.STATEMENT_DIRNAME).exists(), "refusal writes nothing")
            _write(out / "withheld-diagnostic-package.v0" / "diagnostic-package.v0.json", b"{}\n")
            with self.assertRaises(statement.StatementError) as ctx:
                _seal(out)
            self.assertEqual(str(ctx.exception), "subject_dirs")
            (out / "withheld-diagnostic-package.v0" / "diagnostic-package.v0.json").unlink()
            (out / "withheld-diagnostic-package.v0").rmdir()
            _seal(out)
            with self.assertRaises(statement.StatementError) as ctx:
                _seal(out)
            self.assertEqual(str(ctx.exception), "statement_occupied")

    def test_symlinked_subject_refuses(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            _publish_surface(out)
            target = out / "effective-envelope-collection.v0" / "member-0001.json"
            target.unlink()
            os.symlink(out / "setup-status.json", target)
            with self.assertRaises(statement.StatementError) as ctx:
                _seal(out)
            self.assertTrue(str(ctx.exception).startswith("subject:"), ctx.exception)


class OfflineReadback(unittest.TestCase):
    def _sealed(self, raw: str):
        out = Path(raw)
        files = _publish_surface(out)
        _seal(out)
        return out, files

    def _check(self, out: Path, files: dict, **over):
        loaded = statement.load_statement_dir(out / statement.STATEMENT_DIRNAME)
        kwargs = dict(bindings=BINDINGS, run_identity=RUN)
        kwargs.update(over)
        return statement.check_statement_against_files(loaded, files, **kwargs)

    def test_loads_and_verifies_against_the_same_files(self):
        with tempfile.TemporaryDirectory() as raw:
            out, files = self._sealed(raw)
            summary = self._check(out, files)
            self.assertEqual(summary["statement"], "verified-unsigned")
            self.assertEqual(summary["statement_subjects"], len(files))
            self.assertEqual(summary["predicate_type"], statement.PREDICATE_TYPE)

    def test_bite_on_copies(self):
        with tempfile.TemporaryDirectory() as raw:
            out, files = self._sealed(raw)
            root = out / statement.STATEMENT_DIRNAME
            keep = {name: (root / name).read_bytes() for name in statement.STATEMENT_FILENAMES}

            def restore():
                for name, data in keep.items():
                    (root / name).write_bytes(data)

            # A changed subject byte.
            files["candidate-result.json"].write_bytes(b'{"decision": "withhold"}\n')
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "statement_subject_bytes:candidate-result.json")
            files["candidate-result.json"].write_bytes(b'{"decision": "publish"}\n')
            # A subject the reader does not hold, and a held file the seal does not name.
            missing = dict(files)
            del missing["effective-envelope-collection.v0/member-0001.json"]
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, missing)
            self.assertEqual(str(ctx.exception), "statement_subjects")
            extra = dict(files, **{"materialize/subject/src.rs": out / "materialize/subject/src.rs"})
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, extra)
            self.assertEqual(str(ctx.exception), "statement_subjects")
            # Wrong expectations.
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files, run_identity={"run_id": "1", "run_attempt": "1"})
            self.assertEqual(str(ctx.exception), "statement_run_identity")
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files, bindings=dict(BINDINGS, runner_revision=CANDIDATE))
            self.assertEqual(str(ctx.exception), "statement_bindings")
            # Re-stamped predicate (gate outcome flipped, canonical bytes otherwise).
            predicate = json.loads(keep[statement.PREDICATE_FILENAME])
            predicate["gate_outcome"] = "failure"
            (root / statement.PREDICATE_FILENAME).write_bytes(statement.encode_json(predicate))
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "statement_canonical")
            restore()
            # Whitespace-only change to the predicate bytes.
            (root / statement.PREDICATE_FILENAME).write_bytes(
                keep[statement.PREDICATE_FILENAME] + b"\n")
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "predicate_canonical")
            restore()
            # A SHA256SUMS line in binary mode, or reordered.
            sums = keep[statement.SUMS_FILENAME].decode()
            (root / statement.SUMS_FILENAME).write_bytes(sums.replace("  ", " *", 1).encode())
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "sums_mode")
            lines = sums[:-1].split("\n")
            (root / statement.SUMS_FILENAME).write_bytes(
                ("\n".join(reversed(lines)) + "\n").encode())
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "sums_canonical")
            restore()
            # An extra top-level statement key.
            doc = json.loads(keep[statement.STATEMENT_FILENAME])
            doc["signature"] = "x"
            (root / statement.STATEMENT_FILENAME).write_bytes(statement.encode_json(doc))
            with self.assertRaises(statement.StatementError) as ctx:
                self._check(out, files)
            self.assertEqual(str(ctx.exception), "statement_keys")
            restore()
            self.assertEqual(self._check(out, files)["statement"], "verified-unsigned")


class GateIntegration(unittest.TestCase):
    """The gate module's `seal` and `readback --statement` over a real withheld attempt."""

    def test_seal_reads_identity_from_the_runner_environment_and_binds_runner(self):
        with tempfile.TemporaryDirectory() as raw:
            out = Path(raw)
            _publish_surface(out)
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.seal_attempt_statement(
                    out_dir=out, rail="aee-contained-v0", bindings=BINDINGS,
                    packet_release_tag="hosted-packet-r4", packet_manifest_sha256="cf" * 32,
                    gate_outcome="success", environ=dict(ENVIRON, GITHUB_WORKFLOW_SHA=CANDIDATE))
            self.assertEqual(str(ctx.exception), "workflow_sha_binding")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.seal_attempt_statement(
                    out_dir=out, rail="trusted-local", bindings=BINDINGS,
                    packet_release_tag="hosted-packet-r4", packet_manifest_sha256="cf" * 32,
                    gate_outcome="success", environ=ENVIRON)
            self.assertEqual(str(ctx.exception), "statement:rail")
            self.assertFalse((out / statement.STATEMENT_DIRNAME).exists())
            sealed = hosted.seal_attempt_statement(
                out_dir=out, rail="aee-contained-v0", bindings=BINDINGS,
                packet_release_tag="hosted-packet-r4", packet_manifest_sha256="cf" * 32,
                gate_outcome="failure", environ=ENVIRON)
            self.assertEqual(sealed["gate_outcome"], "failure")
            predicate = json.loads(
                (out / statement.STATEMENT_DIRNAME / statement.PREDICATE_FILENAME).read_text())
            self.assertEqual(predicate["workflow_identity"], WORKFLOW)
            self.assertEqual(predicate["run_identity"], RUN)

    def test_cli_seal_then_readback_statement_over_downloaded_bytes(self):
        from tests.test_contained_hosted_publication import (  # noqa: E402
            CANDIDATE as C, IMAGE as I, RUNNER as R, HOSTED_RUN_ID, HOSTED_RUN_ATTEMPT,
            WithheldDiagnosticPackage)
        case = WithheldDiagnosticPackage("test_downloaded_bytes_cli_readback")
        runner_env = {"GITHUB_SHA": R, "GITHUB_WORKFLOW_SHA": R, "ImageOS": "ubuntu24",
                      "ImageVersion": "1", "GITHUB_RUN_ID": HOSTED_RUN_ID,
                      "GITHUB_RUN_ATTEMPT": HOSTED_RUN_ATTEMPT}
        with tempfile.TemporaryDirectory() as raw:
            with unittest.mock.patch.dict(os.environ, runner_env):
                out, decision, _rels = case._withhold(
                    Path(raw),
                    envelope_over={"envelope_status": "unverified",
                                  "unverified_field": "runtime_version"})
            self.assertEqual(decision["decision"], "withhold")
            env = dict(os.environ, **runner_env)
            proc = subprocess.run([
                sys.executable, str(Path(hosted.__file__)), "seal", "--out", str(out),
                "--rail", "aee-contained-v0", "--candidate-revision", C,
                "--runner-revision", R, "--image-digest", I,
                "--packet-release-tag", "hosted-packet-r4",
                "--packet-manifest-sha256", "cf" * 32, "--gate-outcome", "failure",
            ], capture_output=True, text=True, env=env, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertGreaterEqual(json.loads(proc.stdout)["subjects"], 5)
            download = Path(raw) / "download"
            case._copy_downloaded(out, download)
            cmd = case._readback_cmd(download, out) + [
                "--statement", str(out / statement.STATEMENT_DIRNAME)]
            proc = subprocess.run(cmd, cwd=download, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)
            self.assertEqual(summary["decision"], "withhold")
            self.assertEqual(summary["statement"], "verified-unsigned")
            self.assertEqual(summary["gate_outcome"], "failure")
            # Without the directory the readback says so instead of claiming anything.
            proc = subprocess.run(case._readback_cmd(download, out), cwd=download,
                                  capture_output=True, text=True, check=False)
            self.assertEqual(json.loads(proc.stdout)["statement"], "not-provided")
            # A tampered downloaded byte is refused before the statement is even read: the
            # diagnostic manifest binds the same files. A re-stamped digest in the sealed
            # SHA256SUMS is refused by the statement check itself.
            target = download / hosted.CANDIDATE_RESULT_FILENAME
            original = target.read_bytes()
            target.write_bytes(original + b"\n")
            proc = subprocess.run(cmd, cwd=download, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("hosted publication refused: diagnostic_artifacts", proc.stderr)
            target.write_bytes(original)
            # Bytes, not text: on Windows a text-mode write would turn the newlines into
            # CRLF and the refusal would be subject_name instead of the re-stamped digest.
            sums = out / statement.STATEMENT_DIRNAME / statement.SUMS_FILENAME
            text = sums.read_bytes().decode("utf-8")
            line = next(l for l in text.split("\n") if l.endswith(hosted.CANDIDATE_RESULT_FILENAME))
            flipped = ("0" if line[0] != "0" else "1") + line[1:]
            sums.write_bytes(text.replace(line, flipped, 1).encode("utf-8"))
            proc = subprocess.run(cmd, cwd=download, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 2, proc.stdout)
            self.assertIn("statement:predicate_canonical", proc.stderr)


if __name__ == "__main__":
    unittest.main()
