#!/usr/bin/env python3
"""Allowlisted shape for the hosted contained publication workflow (#107)."""

from __future__ import annotations

import unittest
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "contained-hosted-publication.yml"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import envelope_collection as collection  # noqa: E402
import contained_hosted_publication as hosted  # noqa: E402

# Reuse the pinned record builder rather than restating it: a second fixture would be a second
# definition of what a valid envelope is, and the two would drift.
from tests.test_envelope_collection import _valid_record as _inert_record  # noqa: E402


def collection_dirname():
    return hosted.COLLECTION_DIRNAME

ALLOWED_HOSTED_WORKFLOW = {'name': 'contained-hosted-publication',
 'on': {'workflow_dispatch': {'inputs': {'candidate_revision': {'description': 'Immutable '
                                                                               'candidate '
                                                                               'revision '
                                                                               '(40-hex)',
                                                                'required': True,
                                                                'type': 'string'},
                                         'runner_revision': {'description': 'Generic '
                                                                            'runner '
                                                                            'revision '
                                                                            '(40-hex)',
                                                             'required': True,
                                                             'type': 'string'},
                                         'image_digest': {'description': 'Candidate/toolchain '
                                                                         'image digest '
                                                                         'B '
                                                                         '(sha256:64hex)',
                                                          'required': True,
                                                          'type': 'string'},
                                         'packet_root': {'description': 'Declared '
                                                                        'packet root '
                                                                        '(relative) '
                                                                        'holding '
                                                                        'authorize/prepare/pins/bindings',
                                                         'required': True,
                                                         'type': 'string'},
                                         'authorize_path': {'description': 'Path to '
                                                                           'authorize.v0 '
                                                                           'bytes '
                                                                           'relative '
                                                                           'to packet '
                                                                           'root',
                                                            'required': True,
                                                            'type': 'string'},
                                         'prepare_path': {'description': 'Path to '
                                                                         'prepare.v1 '
                                                                         'bytes '
                                                                         'relative to '
                                                                         'packet root',
                                                          'required': True,
                                                          'type': 'string'},
                                         'pins_dir': {'description': 'Path to frozen '
                                                                     'pins directory '
                                                                     'relative to '
                                                                     'packet root',
                                                      'required': True,
                                                      'type': 'string'}}}},
 'permissions': {'contents': 'read'},
 'concurrency': {'group': 'contained-hosted-publication', 'cancel-in-progress': False},
 'env': {'PYTHON_VERSION': '3.13',
         'OPERATOR_EXECUTION_PROFILE': 'contained-oci-v0',
         'MAX_ARTIFACT_BYTES': '5242880',
         'ARTIFACT_RETENTION_DAYS': '14'},
 'jobs': {'hosted-contained': {'runs-on': 'ubuntu-latest',
                               'timeout-minutes': 15,
                               'steps': [{'name': 'Checkout',
                                          'uses': 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                                          'with': {'persist-credentials': False,
                                                   'fetch-depth': 0,
                                                   'ref': '${{ inputs.runner_revision '
                                                          '}}'}},
                                         {'name': 'Set up Python',
                                          'uses': 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97',
                                          'with': {'python-version': '${{ '
                                                                     'env.PYTHON_VERSION '
                                                                     '}}'}},
                                         {'name': 'Gate hosted publication',
                                          'shell': 'bash',
                                          'env': {'CANDIDATE_REVISION': '${{ '
                                                                        'inputs.candidate_revision '
                                                                        '}}',
                                                  'RUNNER_REVISION': '${{ '
                                                                     'inputs.runner_revision '
                                                                     '}}',
                                                  'IMAGE_DIGEST': '${{ '
                                                                  'inputs.image_digest '
                                                                  '}}',
                                                  'PACKET_ROOT': '${{ '
                                                                 'inputs.packet_root '
                                                                 '}}',
                                                  'AUTHORIZE_PATH': '${{ '
                                                                    'inputs.authorize_path '
                                                                    '}}',
                                                  'PREPARE_PATH': '${{ '
                                                                  'inputs.prepare_path '
                                                                  '}}',
                                                  'PINS_DIR': '${{ inputs.pins_dir }}',
                                                  'GITHUB_RUN_ID': '${{ github.run_id '
                                                                   '}}',
                                                  'GITHUB_RUN_ATTEMPT': '${{ '
                                                                        'github.run_attempt '
                                                                        '}}'},
                                          'run': 'python '
                                                 'measurements/contained_hosted_publication.py '
                                                 'gate --candidate-revision '
                                                 '"$CANDIDATE_REVISION" '
                                                 '--runner-revision "$RUNNER_REVISION" '
                                                 '--image-digest "$IMAGE_DIGEST" '
                                                 '--operator-profile '
                                                 '"$OPERATOR_EXECUTION_PROFILE" '
                                                 '--max-artifact-bytes '
                                                 '"$MAX_ARTIFACT_BYTES" --out '
                                                 'artifacts --workspace-root '
                                                 '"$GITHUB_WORKSPACE" --packet-root '
                                                 '"$PACKET_ROOT" --authorize '
                                                 '"$AUTHORIZE_PATH" --prepare '
                                                 '"$PREPARE_PATH" --pins-dir '
                                                 '"$PINS_DIR" --rerun-log '
                                                 'artifacts/rerun-evidence.jsonl'},
                                         {'name': 'Upload setup',
                                          'if': 'always() && !cancelled()',
                                          'uses': 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
                                          'with': {'name': 'setup',
                                                   'path': 'artifacts/setup-status.json',
                                                   'retention-days': 14,
                                                   'if-no-files-found': 'error'}},
                                         {'name': 'Upload effective-envelope',
                                          'if': 'always() && !cancelled()',
                                          'uses': 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
                                          'with': {'name': 'effective-envelope',
                                                   'path': 'artifacts/effective-envelope-collection.v0/',
                                                   'retention-days': 14,
                                                   'if-no-files-found': 'error'}},
                                         {'name': 'Upload candidate-result',
                                          'if': 'always() && !cancelled()',
                                          'uses': 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
                                          'with': {'name': 'candidate-result',
                                                   'path': 'artifacts/candidate-result.json',
                                                   'retention-days': 14,
                                                   'if-no-files-found': 'error'}},
                                         {'name': 'Upload rerun-evidence',
                                          'if': 'always() && !cancelled()',
                                          'uses': 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
                                          'with': {'name': 'rerun-evidence-${{ '
                                                           'github.run_id }}-${{ '
                                                           'github.run_attempt }}',
                                                   'path': 'artifacts/rerun-evidence.jsonl',
                                                   'retention-days': 14,
                                                   'if-no-files-found': 'error'}}]}}}

def _strip_comment(line: str) -> str:
    in_single = in_double = escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _parse_scalar(raw: str):
    raw = raw.strip()
    if raw in ("true", "True", "yes"):
        return True
    if raw in ("false", "False", "no"):
        return False
    if raw in ("null", "~"):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
        return int(raw)
    return raw


def parse_workflow_yaml(text: str):
    items = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if line.strip():
            items.append((len(line) - len(line.lstrip(" ")), line.strip()))
    if not items:
        return {}

    def parse_map(index: int, indent: int):
        mapping = {}
        while index < len(items) and items[index][0] == indent and not items[index][1].startswith("- "):
            _, content = items[index]
            key, _, rest = content.partition(":")
            key, rest = key.strip(), rest.strip()
            index += 1
            if rest:
                mapping[key] = _parse_scalar(rest)
            elif index < len(items) and items[index][0] > indent:
                mapping[key], index = parse(index, items[index][0])
            else:
                mapping[key] = None
        return mapping, index

    def parse_seq(index: int, indent: int):
        seq = []
        while index < len(items) and items[index][0] == indent and items[index][1].startswith("- "):
            body = items[index][1][2:]
            index += 1
            if not body:
                value, index = parse(index, indent + 1)
                seq.append(value)
            elif ":" in body and not body.startswith("${{"):
                key, _, rest = body.partition(":")
                item = {key.strip(): _parse_scalar(rest.strip()) if rest.strip() else None}
                if index < len(items) and items[index][0] > indent and not items[index][1].startswith("- "):
                    extra, index = parse_map(index, items[index][0])
                    item.update(extra)
                seq.append(item)
            else:
                seq.append(_parse_scalar(body))
        return seq, index

    def parse(index: int, indent: int):
        if items[index][1].startswith("- "):
            return parse_seq(index, indent)
        return parse_map(index, indent)

    tree, _ = parse_map(0, items[0][0])
    return tree


def hosted_shape_violations(tree) -> list[str]:
    bad = []
    if tree.get("permissions") != {"contents": "read"}:
        bad.append("permissions must be exactly {contents: read}")
    conc = tree.get("concurrency")
    if not isinstance(conc, dict) or conc.get("group") != "contained-hosted-publication":
        bad.append("concurrency.group must be contained-hosted-publication")
    if not isinstance(conc, dict) or conc.get("cancel-in-progress") is not False:
        bad.append("concurrency.cancel-in-progress must be false")
    env = tree.get("env") or {}
    if env.get("OPERATOR_EXECUTION_PROFILE") != "contained-oci-v0":
        bad.append("OPERATOR_EXECUTION_PROFILE must be contained-oci-v0")
    if env.get("MAX_ARTIFACT_BYTES") != "5242880":
        bad.append("MAX_ARTIFACT_BYTES ceiling missing")
    if env.get("ARTIFACT_RETENTION_DAYS") != "14":
        bad.append("ARTIFACT_RETENTION_DAYS ceiling missing")
    if "HOSTED_RUNS_ON" in env:
        bad.append("HOSTED_RUNS_ON must not be runtime evidence")
    if "HOSTED_PERSIST_CREDENTIALS" in env:
        bad.append("HOSTED_PERSIST_CREDENTIALS must not be runtime evidence")
    if "HOSTED_FORWARDED_ENV_NAMES" in env:
        bad.append("HOSTED_FORWARDED_ENV_NAMES must not be runtime evidence")
    on = tree.get("on") or {}
    inputs = ((on.get("workflow_dispatch") or {}).get("inputs") or {})
    for key in (
        "candidate_revision", "runner_revision", "image_digest", "packet_root",
        "authorize_path", "prepare_path", "pins_dir",
    ):
        if key not in inputs:
            bad.append("missing binding input %s" % key)
    jobs = tree.get("jobs") or {}
    job = jobs.get("hosted-contained") or {}
    if job.get("runs-on") != "ubuntu-latest":
        bad.append("runs-on must be ubuntu-latest (no self-hosted/local)")
    steps = job.get("steps") or []
    upload_names = []
    saw_write_facts = False
    for step in steps:
        if not isinstance(step, dict):
            continue
        if step.get("name") == "Write workflow facts":
            saw_write_facts = True
        uses = str(step.get("uses") or "")
        with_block = step.get("with") or {}
        if uses.startswith("actions/checkout@"):
            if with_block.get("persist-credentials") is not False:
                bad.append("persist-credentials must be false")
            if "docker.sock" in str(with_block).lower():
                bad.append("docker.sock exposure forbidden")
        if uses.startswith("actions/upload-artifact@"):
            upload_names.append(with_block.get("name"))
            if with_block.get("retention-days") != 14:
                bad.append("upload retention-days ceiling missing")
            if with_block.get("if-no-files-found") != "error":
                bad.append("upload if-no-files-found must be error")
            step_if = step.get("if")
            if step_if != "always() && !cancelled()":
                bad.append(
                    "upload steps must run on failure/cancellation "
                    "(if: always() && !cancelled())"
                )
        run = step.get("run")
        if isinstance(run, str):
            if "${{ inputs." in run:
                bad.append("workflow inputs must not appear in run: (shell breakout)")
            if step.get("name") == "Gate hosted publication":
                if step.get("continue-on-error") is True:
                    bad.append("gate continue-on-error would turn refusal green")
                if "trusted-local" in run:
                    bad.append("trusted-local profile forbidden in gate run")
                if "write-workflow-facts" in run:
                    bad.append("write-workflow-facts must not be runtime evidence path")
                for binding in (
                    "$CANDIDATE_REVISION", "$RUNNER_REVISION", "$IMAGE_DIGEST",
                    "$PACKET_ROOT", "$AUTHORIZE_PATH", "$PREPARE_PATH", "$PINS_DIR",
                    "--packet-root",
                ):
                    if binding not in run:
                        bad.append("gate run missing %s" % binding)
                env_step = step.get("env") or {}
                for key in (
                    "CANDIDATE_REVISION", "RUNNER_REVISION", "IMAGE_DIGEST",
                    "PACKET_ROOT", "AUTHORIZE_PATH", "PREPARE_PATH", "PINS_DIR",
                    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                ):
                    if key not in env_step:
                        bad.append("gate env missing %s" % key)
                if "HOSTED_FORWARDED_ENV_NAMES" in env_step:
                    bad.append("HOSTED_FORWARDED_ENV_NAMES must not be runtime evidence")
                if "RUNNER_ENVIRONMENT" in env_step:
                    bad.append("RUNNER_ENVIRONMENT must remain structural-only")
                if "--workspace-root" not in run or "$GITHUB_WORKSPACE" not in run:
                    bad.append("gate run must pass --workspace-root $GITHUB_WORKSPACE")
    if saw_write_facts:
        bad.append("write-workflow-facts step must not exist as runtime evidence")
    expected_uploads = [
        "setup", "effective-envelope", "candidate-result",
    ]
    if len(upload_names) != 4 or upload_names[:3] != expected_uploads:
        bad.append(
            "must upload setup, effective-envelope, candidate-result, "
            "rerun-evidence separately"
        )
    else:
        rerun_name = upload_names[3]
        if not isinstance(rerun_name, str):
            bad.append("rerun-evidence artifact name missing run identity")
        else:
            if "github.run_id" not in rerun_name or "github.run_attempt" not in rerun_name:
                bad.append("rerun-evidence artifact name must include run_id and run_attempt")
            if rerun_name == "rerun-evidence":
                bad.append("rerun-evidence artifact name must not be static")
    if tree != ALLOWED_HOSTED_WORKFLOW and not bad:
        bad.append("workflow diverges from ALLOWED_HOSTED_WORKFLOW")
    return bad


class ContainedHostedWorkflowContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(WORKFLOW.is_file(), "missing hosted workflow")
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.tree = parse_workflow_yaml(self.text)

    def _mutated(self, old: str, new: str):
        self.assertIn(old, self.text)
        return parse_workflow_yaml(self.text.replace(old, new, 1))

    def test_workflow_matches_allowlisted_hosted_shape(self):
        self.assertEqual(self.tree, ALLOWED_HOSTED_WORKFLOW)
        self.assertEqual(hosted_shape_violations(self.tree), [])

    def test_structural_pins_runs_on_and_persist_credentials(self):
        job = self.tree["jobs"]["hosted-contained"]
        self.assertEqual(job["runs-on"], "ubuntu-latest")
        checkout = job["steps"][0]
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_mutation_shell_breakout_inputs_in_run_is_red(self):
        poisoned = self.text.replace(
            'run: python measurements/contained_hosted_publication.py gate --candidate-revision "$CANDIDATE_REVISION"',
            'run: export CANDIDATE_REVISION="${{ inputs.candidate_revision }}"; python measurements/contained_hosted_publication.py gate --candidate-revision "$CANDIDATE_REVISION"',
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("shell breakout" in h for h in hits), hits)

    def test_mutation_route_to_self_hosted_or_local_is_red(self):
        hits = hosted_shape_violations(self._mutated("runs-on: ubuntu-latest", "runs-on: self-hosted"))
        self.assertTrue(any("runs-on" in h for h in hits), hits)

    def test_mutation_allow_trusted_local_profile_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "OPERATOR_EXECUTION_PROFILE: contained-oci-v0",
            "OPERATOR_EXECUTION_PROFILE: trusted-local",
        ))
        self.assertTrue(any("contained-oci-v0" in h for h in hits), hits)

    def test_mutation_docker_socket_or_credential_or_writable_checkout_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "persist-credentials: false", "persist-credentials: true"
        ))
        self.assertTrue(any("persist-credentials" in h for h in hits), hits)

    def test_mutation_collapse_setup_envelope_candidate_artifacts_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "name: effective-envelope", "name: setup"
        ))
        self.assertTrue(any("separately" in h for h in hits), hits)

    def test_mutation_static_rerun_artifact_name_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "name: rerun-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
            "name: rerun-evidence",
        ))
        self.assertTrue(
            any("run_id" in h or "run_attempt" in h or "static" in h for h in hits),
            hits,
        )

    def test_mutation_omit_rerun_evidence_upload_is_red(self):
        block = (
            "      - name: Upload rerun-evidence\n"
            "        if: always() && !cancelled()\n"
            "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n"
            "        with:\n"
            "          name: rerun-evidence-${{ github.run_id }}-${{ github.run_attempt }}\n"
            "          path: artifacts/rerun-evidence.jsonl\n"
            "          retention-days: 14\n"
            "          if-no-files-found: error\n"
        )
        mutated = self.text.replace(block, "", 1)
        self.assertNotEqual(mutated, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(mutated))
        self.assertTrue(any("rerun-evidence" in h or "separately" in h for h in hits), hits)

    def test_mutation_drop_revision_or_digest_binding_is_red(self):
        block = (
            "      image_digest:\n"
            "        description: Candidate/toolchain image digest B (sha256:64hex)\n"
            "        required: true\n"
            "        type: string\n"
        )
        hits = hosted_shape_violations(self._mutated(block, ""))
        self.assertTrue(any("image_digest" in h or "diverges" in h for h in hits), hits)

    def test_mutation_restore_hosted_runs_on_literal_evidence_is_red(self):
        poisoned = self.text.replace(
            '  ARTIFACT_RETENTION_DAYS: "14"\n',
            '  ARTIFACT_RETENTION_DAYS: "14"\n  HOSTED_RUNS_ON: ubuntu-latest\n',
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("HOSTED_RUNS_ON" in h or "diverges" in h for h in hits), hits)

    def test_mutation_remove_each_resource_ceiling_is_red(self):
        for old, needle in (
            ("\nconcurrency:\n  group: contained-hosted-publication\n  cancel-in-progress: false\n", "concurrency"),
            ('  MAX_ARTIFACT_BYTES: "5242880"\n', "MAX_ARTIFACT_BYTES"),
            ('  ARTIFACT_RETENTION_DAYS: "14"\n', "ARTIFACT_RETENTION_DAYS"),
        ):
            mutated_text = self.text.replace(old, "", 1)
            self.assertNotEqual(mutated_text, self.text, needle)
            hits = hosted_shape_violations(parse_workflow_yaml(mutated_text))
            self.assertTrue(hits, needle)


    def test_upload_steps_always_on_failure_and_keep_if_no_files_error(self):
        for step in self.tree["jobs"]["hosted-contained"]["steps"]:
            uses = str(step.get("uses") or "")
            if uses.startswith("actions/upload-artifact@"):
                self.assertEqual(step.get("if"), "always() && !cancelled()")
                self.assertEqual(step["with"].get("if-no-files-found"), "error")
        gate = self.tree["jobs"]["hosted-contained"]["steps"][2]
        self.assertNotEqual(gate.get("continue-on-error"), True)

    def test_mutation_drop_upload_always_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "        if: always() && !cancelled()\n",
            "",
        ))
        self.assertTrue(any("always()" in h or "cancelled" in h for h in hits), hits)

    def test_mutation_restore_forwarded_env_names_is_red(self):
        poisoned = self.text.replace(
            "          GITHUB_RUN_ID: ${{ github.run_id }}\n",
            "          HOSTED_FORWARDED_ENV_NAMES: CANDIDATE_REVISION\n"
            "          GITHUB_RUN_ID: ${{ github.run_id }}\n",
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(
            any("HOSTED_FORWARDED" in h or "diverges" in h for h in hits), hits
        )

    def test_mutation_gate_continue_on_error_is_red(self):
        poisoned = self.text.replace(
            "      - name: Gate hosted publication\n        shell: bash\n",
            "      - name: Gate hosted publication\n"
            "        continue-on-error: true\n"
            "        shell: bash\n",
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("continue-on-error" in h or "diverges" in h for h in hits), hits)


    def test_comment_only_noop_mutation_stays_green(self):
        mutated_text = "# noop comment\n" + self.text
        self.assertEqual(parse_workflow_yaml(mutated_text), ALLOWED_HOSTED_WORKFLOW)
        self.assertEqual(hosted_shape_violations(parse_workflow_yaml(mutated_text)), [])


if __name__ == "__main__":
    unittest.main()


def _upload_selection(tree, artifact_name):
    """The path the workflow ACTUALLY declares for one upload, read from the file."""
    for step in tree["jobs"]["hosted-contained"]["steps"]:
        with_ = step.get("with") or {}
        if with_.get("name") == artifact_name:
            return with_["path"]
    raise AssertionError("no upload step named %r" % artifact_name)


def _select(workspace: Path, path_value: str):
    """Resolve an upload-artifact `path:` over a real tree, as the uploader would.

    `workspace` is the checkout root the workflow runs from, so the declared path is applied
    exactly as written -- `artifacts/...` included -- rather than reinterpreted.

    A directory selects everything beneath it, relative paths included; a file selects itself.
    This is deliberately applied to generated bytes rather than compared against a literal, so a
    path that no longer reaches the members fails here instead of passing a string check.
    """
    rel = path_value.rstrip("/")
    target = workspace / rel
    if target.is_dir():
        return {str(f.relative_to(target)) for f in target.rglob("*") if f.is_file()}
    return {target.name} if target.is_file() else set()


class UploadSelectionRetainsEveryMember(unittest.TestCase):
    """The uploaded proof must carry the exact index and every addressed member byte."""

    def setUp(self):
        self.tree = parse_workflow_yaml(WORKFLOW.read_text(encoding="utf-8"))
        self.selection = _upload_selection(self.tree, "effective-envelope")

    def _artifacts(self, tmp, members=2):
        out = Path(tmp) / "artifacts"
        out.mkdir(parents=True)
        ledger = collection.Ledger()
        for _ in range(members):
            ledger.recorded(ledger.register(), _inert_record())
        collection.write_collection(
            ledger, out / collection_dirname(), report_sha256="c" * 64)
        return out

    # --- positive: complete selection ---
    def test_selection_carries_index_and_every_addressed_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp, members=3)
            coll = out / collection_dirname()
            index = json.loads(
                (coll / collection.INDEX_FILENAME).read_text("utf-8"))
            selected = _select(out.parent, self.selection)
            self.assertIn(collection.INDEX_FILENAME, selected)
            addressed = {m["relpath"] for m in index["members"]}
            self.assertEqual(len(addressed), 3)
            missing = addressed - selected
            self.assertEqual(missing, set(),
                             "addressed members never left the artifact selection")

    # --- RED 1/2: index or a member absent from the selection ---
    def test_index_missing_from_selection_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp)
            (out / collection_dirname() / collection.INDEX_FILENAME).unlink()
            self.assertNotIn(collection.INDEX_FILENAME, _select(out.parent, self.selection))

    def test_member_missing_from_selection_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp)
            coll = out / collection_dirname()
            index = json.loads((coll / collection.INDEX_FILENAME).read_text("utf-8"))
            victim = index["members"][0]["relpath"]
            (coll / victim).unlink()
            self.assertNotIn(victim, _select(out.parent, self.selection))
            with self.assertRaises(collection.CollectionError) as ctx:
                collection.load_collection(coll)
            self.assertEqual(str(ctx.exception), "collection member absent")

    # --- RED 3: correct bytes, changed digest ---
    def test_digest_drift_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp)
            coll = out / collection_dirname()
            index = json.loads((coll / collection.INDEX_FILENAME).read_text("utf-8"))
            index["members"][0]["sha256"] = "0" * 64
            (coll / collection.INDEX_FILENAME).write_text(
                json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaises(collection.CollectionError) as ctx:
                collection.load_collection(coll)
            self.assertEqual(str(ctx.exception), "collection member digest")

    # --- RED 4: collection document disguised at the legacy path ---
    def test_collection_document_is_refused_at_the_legacy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "artifacts"
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.write_separate_artifacts(
                    out, {"k": "s"}, {"schema": collection.COLLECTION_SCHEMA}, {"k": "c"})
            self.assertEqual(str(ctx.exception), "collection_at_legacy_envelope_path")

    # --- RED 5: multi-member, first-only selection ---
    def test_multi_member_first_only_selection_is_not_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp, members=3)
            coll = out / collection_dirname()
            index = json.loads((coll / collection.INDEX_FILENAME).read_text("utf-8"))
            addressed = [m["relpath"] for m in index["members"]]
            first_only = {collection.INDEX_FILENAME, addressed[0]}
            self.assertNotEqual(
                first_only, _select(out.parent, self.selection),
                "a first-member-only selection must not satisfy the upload contract")
            self.assertTrue(set(addressed[1:]) <= _select(out.parent, self.selection))

    # --- RED 6: stale legacy file must not be reused ---
    def test_stale_legacy_file_is_not_part_of_the_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp)
            (out / "effective-envelope.v0.json").write_text(
                '{"stale": true}', encoding="utf-8")
            self.assertNotIn("effective-envelope.v0.json", _select(out.parent, self.selection))

    # --- RED 7: a corrupt collection has no legacy fallback ---
    def test_corrupt_collection_has_no_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self._artifacts(tmp)
            coll = out / collection_dirname()
            (coll / collection.INDEX_FILENAME).write_text("{not json", encoding="utf-8")
            (out / "effective-envelope.v0.json").write_text(
                json.dumps(_inert_record()), encoding="utf-8")
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope_collection(coll)
            self.assertEqual(str(ctx.exception), "json_input")

    # --- the refusal-distinction control ---
    def test_recorded_refusal_and_absent_index_are_distinct(self):
        """A run that recorded a refusal is not the same evidence as a deleted index.

        Missing index alone stays unattributed: it names what is absent and invents no cause.
        """
        import contained_hosted_publication as hosted
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "artifacts"
            out.mkdir(parents=True)
            recorded = out / "recorded"
            ledger = collection.Ledger()
            ledger.raised(ledger.register(), "RuntimeError")
            collection.write_collection(ledger, recorded, report_sha256=None)
            loaded = collection.load_collection(recorded)
            self.assertEqual(loaded["members"], [])
            self.assertEqual(loaded["ledger"][0]["state"], "raised")
            self.assertEqual(loaded["ledger"][0]["exception_type"], "RuntimeError")

            erased = out / "erased"
            erased.mkdir()
            with self.assertRaises(hosted.HostedPublicationError) as ctx:
                hosted.load_envelope_collection(erased)
            self.assertEqual(str(ctx.exception), "envelope_collection_corrupt")
