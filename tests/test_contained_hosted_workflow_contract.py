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
GATE_BOUND_UPLOAD_IF = "steps.gate.outcome == 'success' && !cancelled()"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "contained-hosted-publication.yml"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "measurements"))

import envelope_collection as collection  # noqa: E402
import contained_hosted_publication as hosted  # noqa: E402
import contained_oci as contained  # noqa: E402
import hosted_packet  # noqa: E402
import aee_checker_sealed_execute as sealed_execute  # noqa: E402
from aee_checker_sealed_common import MATERIALIZE_CEILINGS, load_strict  # noqa: E402

PREPARE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "contained-hosted-prepare.yml"
HOSTED_INPUTS = (
    "candidate_revision", "runner_revision", "image_digest",
    "packet_release_tag", "packet_manifest_sha256",
)
RETIRED_INPUTS = ("packet_root", "authorize_path", "prepare_path", "pins_dir")
PINS = REPO_ROOT / "measurements" / "aee-checker-25b9dfa"


def candidate_invocations() -> int:
    """Baseline plus every step of the authorized mutation order, from the pinned inputs.

    Derived from the same functions the execution funnel calls, not restated, so a change to
    the pinned sequence moves the required timeout with it.
    """
    sites = sealed_execute.load_frozen_sites(PINS)
    control = load_strict((PINS / "control.json").read_bytes())
    manifest = json.loads((PINS / "manifest.json").read_text(encoding="utf-8"))
    order = sealed_execute.bind_authorized_mutation_order(
        manifest=manifest, sites=sites, control=control,
        steps=sealed_execute.required_sequence(sites))
    return 1 + len(order)


def worst_case_seconds() -> int:
    """The materialize deadline plus one candidate deadline per invocation."""
    return (MATERIALIZE_CEILINGS["deadline_seconds"]
            + candidate_invocations() * contained.CANDIDATE_RESOURCE_PROFILE["deadline_seconds"])

# Reuse the pinned record builder rather than restating it: a second fixture would be a second
# definition of what a valid envelope is, and the two would drift.
from tests.test_envelope_collection import _valid_record as _inert_record  # noqa: E402


def collection_dirname():
    return hosted.COLLECTION_DIRNAME

UPLOAD_ACTION = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_ACTION = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
PINNED_RUNS_ON = "ubuntu-24.04"

FETCH_RUN = (
    'python measurements/hosted_packet.py fetch --repository "$GITHUB_REPOSITORY" '
    '--tag "$PACKET_RELEASE_TAG" --manifest-sha256 "$PACKET_MANIFEST_SHA256" '
    '--workspace-root "$GITHUB_WORKSPACE" --dest hosted-packet'
)
GATE_RUN = (
    'python measurements/contained_hosted_publication.py gate '
    '--candidate-revision "$CANDIDATE_REVISION" --runner-revision "$RUNNER_REVISION" '
    '--image-digest "$IMAGE_DIGEST" --packet-manifest-sha256 "$PACKET_MANIFEST_SHA256" '
    '--operator-profile "$OPERATOR_EXECUTION_PROFILE" '
    '--max-artifact-bytes "$MAX_ARTIFACT_BYTES" --out artifacts '
    '--workspace-root "$GITHUB_WORKSPACE" --packet-root hosted-packet '
    '--authorize authorize.v0.json --prepare prepare.v1.json --pins-dir pins '
    '--rerun-log artifacts/rerun-evidence.jsonl'
)


def _input(description):
    return {"description": description, "required": True, "type": "string"}


ALLOWED_HOSTED_WORKFLOW = {
    'name': 'contained-hosted-publication',
    'on': {'workflow_dispatch': {'inputs': {
        'candidate_revision': _input('Immutable candidate revision (40-hex)'),
        'runner_revision': _input('Generic runner revision (40-hex)'),
        'image_digest': _input('Candidate/toolchain image digest B (sha256:64hex)'),
        'packet_release_tag': _input(
            'Release tag whose assets carry the owner-authorized packet'),
        'packet_manifest_sha256': _input(
            'SHA-256 of the packet manifest release asset (64-hex)'),
    }}},
    'permissions': {'contents': 'read'},
    'concurrency': {'group': 'contained-hosted-publication', 'cancel-in-progress': False},
    'env': {'PYTHON_VERSION': '3.13',
            'OPERATOR_EXECUTION_PROFILE': 'contained-oci-v0',
            'MAX_ARTIFACT_BYTES': '5242880',
            'ARTIFACT_RETENTION_DAYS': '14'},
    'jobs': {'hosted-contained': {
        'runs-on': PINNED_RUNS_ON,
        'timeout-minutes': 30,
        'steps': [
            {'name': 'Checkout',
             'uses': CHECKOUT_ACTION,
             'with': {'persist-credentials': False,
                      'fetch-depth': 0,
                      'ref': '${{ inputs.runner_revision }}'}},
            {'name': 'Set up Python',
             'uses': SETUP_PYTHON_ACTION,
             'with': {'python-version': '${{ env.PYTHON_VERSION }}'}},
            {'name': 'Fetch hosted packet',
             'shell': 'bash',
             'env': {'PACKET_RELEASE_TAG': '${{ inputs.packet_release_tag }}',
                     'PACKET_MANIFEST_SHA256': '${{ inputs.packet_manifest_sha256 }}'},
             'run': FETCH_RUN},
            {'name': 'Gate hosted publication',
             'id': 'gate',
             'shell': 'bash',
             'env': {'CANDIDATE_REVISION': '${{ inputs.candidate_revision }}',
                     'RUNNER_REVISION': '${{ inputs.runner_revision }}',
                     'IMAGE_DIGEST': '${{ inputs.image_digest }}',
                     'PACKET_MANIFEST_SHA256': '${{ inputs.packet_manifest_sha256 }}',
                     'GITHUB_RUN_ID': '${{ github.run_id }}',
                     'GITHUB_RUN_ATTEMPT': '${{ github.run_attempt }}'},
             'run': GATE_RUN},
            {'name': 'Upload setup',
             'if': 'always() && !cancelled()',
             'uses': UPLOAD_ACTION,
             'with': {'name': 'setup',
                      'path': 'artifacts/setup-status.json',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
            {'name': 'Upload effective-envelope',
             'if': "steps.gate.outcome == 'success' && !cancelled()",
             'uses': UPLOAD_ACTION,
             'with': {'name': 'effective-envelope',
                      'path': 'artifacts/effective-envelope-collection.v0/',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
            {'name': 'Upload candidate-result',
             'if': 'always() && !cancelled()',
             'uses': UPLOAD_ACTION,
             'with': {'name': 'candidate-result',
                      'path': 'artifacts/candidate-result.json',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
            {'name': 'Upload rerun-evidence',
             'if': 'always() && !cancelled()',
             'uses': UPLOAD_ACTION,
             'with': {'name': 'rerun-evidence-${{ github.run_id }}-${{ github.run_attempt }}',
                      'path': 'artifacts/rerun-evidence.jsonl',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
        ]}}}

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
    for key in HOSTED_INPUTS:
        if key not in inputs:
            bad.append("missing binding input %s" % key)
    for key in RETIRED_INPUTS:
        # The packet location is fixed by the fetch step now; an operator-chosen root or path
        # would reopen the choice of which bytes the gate reads.
        if key in inputs:
            bad.append("retired packet-location input %s must not return" % key)
    jobs = tree.get("jobs") or {}
    job = jobs.get("hosted-contained") or {}
    if job.get("runs-on") != PINNED_RUNS_ON:
        bad.append("runs-on must be %s (pinned; no ubuntu-latest, self-hosted or local)"
                   % PINNED_RUNS_ON)
    timeout = job.get("timeout-minutes")
    if type(timeout) is not int or timeout * 60 < worst_case_seconds():
        bad.append("timeout-minutes must cover the worst case of %d s" % worst_case_seconds())
    steps = job.get("steps") or []
    names = [step.get("name") for step in steps if isinstance(step, dict)]
    if ("Fetch hosted packet" not in names or "Gate hosted publication" not in names
            or names.index("Fetch hosted packet") > names.index("Gate hosted publication")):
        bad.append("the packet fetch step must run before the gate")
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
            if with_block.get("name") == "effective-envelope":
                # Fail-closed upload authorization. Quarantine is a filesystem move and can
                # fail; if it does the gate exits nonzero, and the published collection must
                # not be uploaded anyway. This is an authorization boundary, not a claim that
                # a refused run was clean.
                if step_if != GATE_BOUND_UPLOAD_IF:
                    bad.append(
                        "the published collection upload must be bound to gate success "
                        "(if: %s)" % GATE_BOUND_UPLOAD_IF)
            elif step_if != "always() && !cancelled()":
                bad.append(
                    "diagnostic upload steps must run on failure/cancellation "
                    "(if: always() && !cancelled())"
                )
        run = step.get("run")
        if isinstance(run, str):
            if "${{ inputs." in run:
                bad.append("workflow inputs must not appear in run: (shell breakout)")
            if step.get("name") == "Fetch hosted packet":
                if run != FETCH_RUN:
                    bad.append("fetch run must fetch into the fixed fresh directory")
                if "--dest %s" % hosted_packet.PACKET_DIRNAME not in run:
                    bad.append("fetch destination must be %s" % hosted_packet.PACKET_DIRNAME)
            if step.get("name") == "Gate hosted publication":
                if step.get("continue-on-error") is True:
                    bad.append("gate continue-on-error would turn refusal green")
                if "trusted-local" in run:
                    bad.append("trusted-local profile forbidden in gate run")
                if "write-workflow-facts" in run:
                    bad.append("write-workflow-facts must not be runtime evidence path")
                for binding in (
                    "$CANDIDATE_REVISION", "$RUNNER_REVISION", "$IMAGE_DIGEST",
                    "--packet-manifest-sha256 \"$PACKET_MANIFEST_SHA256\"",
                    "--packet-root %s" % hosted_packet.PACKET_DIRNAME,
                    "--authorize %s" % hosted_packet.AUTHORIZE_FILENAME,
                    "--prepare %s" % hosted_packet.PREPARE_FILENAME,
                    "--pins-dir %s" % hosted_packet.PINS_DIRNAME,
                ):
                    if binding not in run:
                        bad.append("gate run missing %s" % binding)
                env_step = step.get("env") or {}
                for key in (
                    "CANDIDATE_REVISION", "RUNNER_REVISION", "IMAGE_DIGEST",
                    "PACKET_MANIFEST_SHA256", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                ):
                    if key not in env_step:
                        bad.append("gate env missing %s" % key)
                for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
                    # The gate reads these from the runner's own default environment; a step
                    # value would let the workflow supply the identity it is checked against.
                    if key in env_step:
                        bad.append("gate env must not set %s" % key)
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
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
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
        hits = hosted_shape_violations(self._mutated("runs-on: ubuntu-24.04", "runs-on: self-hosted"))
        self.assertTrue(any("runs-on" in h for h in hits), hits)

    def test_mutation_unpin_runs_on_to_ubuntu_latest_is_red(self):
        hits = hosted_shape_violations(self._mutated("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"))
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
        diagnostics = 0
        for step in self.tree["jobs"]["hosted-contained"]["steps"]:
            uses = str(step.get("uses") or "")
            if not uses.startswith("actions/upload-artifact@"):
                continue
            self.assertEqual(step["with"].get("if-no-files-found"), "error")
            if step["with"].get("name") == "effective-envelope":
                # Published evidence: authorized only by a successful gate.
                self.assertEqual(step.get("if"), GATE_BOUND_UPLOAD_IF)
            else:
                # Refusal diagnostics: still observable when the gate fails.
                self.assertEqual(step.get("if"), "always() && !cancelled()")
                diagnostics += 1
        self.assertEqual(diagnostics, 3, "setup, candidate and rerun must stay always-on")
        gate = self.tree["jobs"]["hosted-contained"]["steps"][3]
        self.assertEqual(gate.get("name"), "Gate hosted publication")
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
            "      - name: Gate hosted publication\n        id: gate\n        shell: bash\n",
            "      - name: Gate hosted publication\n"
            "        id: gate\n"
            "        continue-on-error: true\n"
            "        shell: bash\n",
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("continue-on-error" in h or "diverges" in h for h in hits), hits)


    def test_phase3_runs_on_is_pinned_and_timeout_covers_the_worst_case(self):
        job = self.tree["jobs"]["hosted-contained"]
        self.assertEqual(job["runs-on"], PINNED_RUNS_ON)
        invocations = candidate_invocations()
        worst = worst_case_seconds()
        # The arithmetic the workflow comment states, recomputed from the pinned inputs.
        self.assertEqual(invocations, 9)
        self.assertEqual(MATERIALIZE_CEILINGS["deadline_seconds"], 300)
        self.assertEqual(contained.CANDIDATE_RESOURCE_PROFILE["deadline_seconds"], 120)
        self.assertEqual(worst, 1380)
        self.assertGreaterEqual(job["timeout-minutes"] * 60, worst)
        # The gate module's mirrors of these two facts must not go stale.
        self.assertEqual(hosted.TIMEOUT_MINUTES, job["timeout-minutes"])
        self.assertEqual(hosted.RUNS_ON, job["runs-on"])
        for fragment in ("300 s", "9 x 120 s", "1380 s", "timeout-minutes: 30"):
            self.assertIn(fragment, self.text)

    def test_mutation_timeout_below_the_worst_case_is_red(self):
        hits = hosted_shape_violations(self._mutated("timeout-minutes: 30", "timeout-minutes: 15"))
        self.assertTrue(any("timeout-minutes" in h for h in hits), hits)

    def test_fixed_packet_paths_are_the_packet_module_constants(self):
        steps = {s["name"]: s for s in self.tree["jobs"]["hosted-contained"]["steps"]}
        fetch = steps["Fetch hosted packet"]["run"]
        gate = steps["Gate hosted publication"]["run"]
        self.assertIn("--dest %s" % hosted_packet.PACKET_DIRNAME, fetch)
        self.assertIn("--packet-root %s" % hosted_packet.PACKET_DIRNAME, gate)
        self.assertIn("--authorize %s" % hosted_packet.AUTHORIZE_FILENAME, gate)
        self.assertIn("--prepare %s" % hosted_packet.PREPARE_FILENAME, gate)
        self.assertIn("--pins-dir %s" % hosted_packet.PINS_DIRNAME, gate)
        self.assertEqual(hosted.DISPATCH_BINDINGS_FILENAME, hosted_packet.BINDINGS_FILENAME)
        # The fixed directory must not exist in R's tree, or a fetched file could replace a
        # tracked one.
        self.assertFalse((REPO_ROOT / hosted_packet.PACKET_DIRNAME).exists())

    def test_mutation_gate_before_fetch_is_red(self):
        tree = parse_workflow_yaml(self.text)
        steps = tree["jobs"]["hosted-contained"]["steps"]
        steps[2], steps[3] = steps[3], steps[2]
        hits = hosted_shape_violations(tree)
        self.assertTrue(any("before the gate" in h for h in hits), hits)

    def test_mutation_operator_chosen_packet_root_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            "--packet-root hosted-packet", '--packet-root "$PACKET_ROOT"'))
        self.assertTrue(any("--packet-root" in h for h in hits), hits)
        block = (
            "      packet_release_tag:\n"
            "        description: Release tag whose assets carry the owner-authorized packet\n"
            "        required: true\n"
            "        type: string\n"
        )
        hits = hosted_shape_violations(self._mutated(
            block, block + block.replace("packet_release_tag", "packet_root")))
        self.assertTrue(any("retired" in h for h in hits), hits)

    def test_mutation_drop_manifest_digest_from_gate_is_red(self):
        hits = hosted_shape_violations(self._mutated(
            ' --packet-manifest-sha256 "$PACKET_MANIFEST_SHA256"', ""))
        self.assertTrue(any("packet-manifest-sha256" in h for h in hits), hits)

    def test_mutation_step_supplied_workflow_sha_is_red(self):
        poisoned = self.text.replace(
            "          GITHUB_RUN_ID: ${{ github.run_id }}\n",
            "          GITHUB_WORKFLOW_SHA: ${{ inputs.runner_revision }}\n"
            "          GITHUB_RUN_ID: ${{ github.run_id }}\n",
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = hosted_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("GITHUB_WORKFLOW_SHA" in h for h in hits), hits)

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


PREPARE_RUN = (
    "python measurements/aee_checker_sealed_run.py prepare-v1 "
    "measurements/aee-checker-25b9dfa hosted-prepare"
)
RECORD_RUN = (
    "python measurements/hosted_packet.py record-prepare "
    "--prepare hosted-prepare/prepare.v1.json "
    "--out hosted-prepare-record/hosted-prepare-record.v0.json"
)

ALLOWED_PREPARE_WORKFLOW = {
    'name': 'contained-hosted-prepare',
    'on': {'workflow_dispatch': None},
    'permissions': {'contents': 'read'},
    'concurrency': {'group': 'contained-hosted-prepare', 'cancel-in-progress': False},
    'env': {'PYTHON_VERSION': '3.13', 'ARTIFACT_RETENTION_DAYS': '14'},
    'jobs': {'hosted-prepare': {
        'runs-on': PINNED_RUNS_ON,
        'timeout-minutes': 30,
        'steps': [
            {'name': 'Checkout',
             'uses': CHECKOUT_ACTION,
             'with': {'persist-credentials': False}},
            {'name': 'Set up Python',
             'uses': SETUP_PYTHON_ACTION,
             'with': {'python-version': '${{ env.PYTHON_VERSION }}'}},
            {'name': 'Prepare', 'shell': 'bash', 'run': PREPARE_RUN},
            {'name': 'Record prepare identity', 'shell': 'bash', 'run': RECORD_RUN},
            {'name': 'Upload prepare',
             'uses': UPLOAD_ACTION,
             'with': {'name': 'hosted-prepare-v1-${{ github.run_id }}-${{ github.run_attempt }}',
                      'path': 'hosted-prepare/prepare.v1.json',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
            {'name': 'Upload prepare record',
             'uses': UPLOAD_ACTION,
             'with': {'name': 'hosted-prepare-record-${{ github.run_id }}-${{ github.run_attempt }}',
                      'path': 'hosted-prepare-record/hosted-prepare-record.v0.json',
                      'retention-days': 14,
                      'if-no-files-found': 'error'}},
        ]}}}

# Anything that would let the PREPARE phase reach candidate execution. PREPARE's own inert
# probes run inside `prepare-v1`; no candidate container is created by that command.
PREPARE_FORBIDDEN_RUN_TOKENS = (
    "contained_hosted_publication", "aee_checker_sealed_driver", "aee_checker_sealed_execute",
    "aee_checker_sealed_authorize", "aee_checker_sealed_candidate", "run_authorized",
    " gate", "execute", "authorize", "docker ",
)


def prepare_shape_violations(tree) -> list[str]:
    bad = []
    if tree.get("permissions") != {"contents": "read"}:
        bad.append("permissions must be exactly {contents: read}")
    on = tree.get("on") or {}
    if list(on) != ["workflow_dispatch"] or on.get("workflow_dispatch") is not None:
        bad.append("PREPARE is a bare workflow_dispatch on the dispatched ref, with no inputs")
    jobs = tree.get("jobs") or {}
    if list(jobs) != ["hosted-prepare"]:
        bad.append("PREPARE has exactly one job")
    job = jobs.get("hosted-prepare") or {}
    if job.get("runs-on") != PINNED_RUNS_ON:
        bad.append("runs-on must be %s (pinned)" % PINNED_RUNS_ON)
    upload_names = []
    prepare_runs = []
    for step in job.get("steps") or []:
        if not isinstance(step, dict):
            continue
        uses = str(step.get("uses") or "")
        with_block = step.get("with") or {}
        if uses.startswith("actions/checkout@"):
            if with_block.get("persist-credentials") is not False:
                bad.append("persist-credentials must be false")
            if "ref" in with_block:
                bad.append("PREPARE checks out the dispatched ref, not a chosen one")
        if uses.startswith("actions/upload-artifact@"):
            name = with_block.get("name")
            upload_names.append(name)
            if (not isinstance(name, str) or "github.run_id" not in name
                    or "github.run_attempt" not in name):
                bad.append("PREPARE artifacts must be attempt-scoped")
            if with_block.get("retention-days") != 14:
                bad.append("upload retention-days ceiling missing")
            if with_block.get("if-no-files-found") != "error":
                bad.append("upload if-no-files-found must be error")
        run = step.get("run")
        if isinstance(run, str):
            if "${{" in run:
                bad.append("expressions must not appear in run: (shell breakout)")
            for token in PREPARE_FORBIDDEN_RUN_TOKENS:
                if token in run:
                    bad.append("PREPARE must not reach candidate execution (%r)" % token.strip())
            if "aee_checker_sealed_run.py" in run:
                prepare_runs.append(run)
    if prepare_runs != [PREPARE_RUN]:
        bad.append("PREPARE runs prepare-v1 exactly once against the in-tree pins")
    if len(upload_names) != 2:
        bad.append("PREPARE uploads the prepare bytes and their record, nothing else")
    if tree != ALLOWED_PREPARE_WORKFLOW and not bad:
        bad.append("workflow diverges from ALLOWED_PREPARE_WORKFLOW")
    return bad


class ContainedHostedPrepareWorkflowContract(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PREPARE_WORKFLOW.is_file(), "missing hosted PREPARE workflow")
        self.text = PREPARE_WORKFLOW.read_text(encoding="utf-8")
        self.tree = parse_workflow_yaml(self.text)

    def _mutated(self, old: str, new: str):
        self.assertIn(old, self.text)
        return parse_workflow_yaml(self.text.replace(old, new, 1))

    def test_workflow_matches_allowlisted_prepare_shape(self):
        self.assertEqual(self.tree, ALLOWED_PREPARE_WORKFLOW)
        self.assertEqual(prepare_shape_violations(self.tree), [])

    def test_prepare_has_no_gate_driver_or_execute_step(self):
        for step in self.tree["jobs"]["hosted-prepare"]["steps"]:
            text = json.dumps(step)
            for token in ("contained_hosted_publication", "aee_checker_sealed_driver",
                          "aee_checker_sealed_execute", "run_authorized"):
                self.assertNotIn(token, text)
            self.assertNotEqual(step.get("name"), "Gate hosted publication")
        self.assertEqual(PREPARE_RUN.count("prepare-v1"), 1)

    def test_mutation_add_gate_step_is_red(self):
        poisoned = self.text.replace(
            "      - name: Record prepare identity\n",
            "      - name: Gate hosted publication\n"
            "        shell: bash\n"
            "        run: python measurements/contained_hosted_publication.py gate\n"
            "      - name: Record prepare identity\n",
            1,
        )
        self.assertNotEqual(poisoned, self.text)
        hits = prepare_shape_violations(parse_workflow_yaml(poisoned))
        self.assertTrue(any("candidate execution" in h for h in hits), hits)

    def test_mutation_call_the_driver_is_red(self):
        hits = prepare_shape_violations(self._mutated(
            PREPARE_RUN,
            PREPARE_RUN + " && python -c 'import aee_checker_sealed_driver'"))
        self.assertTrue(any("candidate execution" in h for h in hits), hits)

    def test_mutation_unpinned_or_self_hosted_runner_is_red(self):
        for runner in ("ubuntu-latest", "self-hosted"):
            with self.subTest(runner=runner):
                hits = prepare_shape_violations(self._mutated(
                    "runs-on: ubuntu-24.04", "runs-on: %s" % runner))
                self.assertTrue(any("runs-on" in h for h in hits), hits)

    def test_mutation_chosen_ref_or_credentials_is_red(self):
        hits = prepare_shape_violations(self._mutated(
            "          persist-credentials: false\n",
            "          persist-credentials: false\n          ref: main\n"))
        self.assertTrue(any("dispatched ref" in h for h in hits), hits)
        hits = prepare_shape_violations(self._mutated(
            "persist-credentials: false", "persist-credentials: true"))
        self.assertTrue(any("persist-credentials" in h for h in hits), hits)

    def test_mutation_write_permission_is_red(self):
        hits = prepare_shape_violations(self._mutated("contents: read", "contents: write"))
        self.assertTrue(any("permissions" in h for h in hits), hits)

    def test_mutation_static_artifact_name_is_red(self):
        hits = prepare_shape_violations(self._mutated(
            "name: hosted-prepare-v1-${{ github.run_id }}-${{ github.run_attempt }}",
            "name: hosted-prepare-v1"))
        self.assertTrue(any("attempt-scoped" in h for h in hits), hits)

    def test_mutation_prepare_v0_is_red(self):
        hits = prepare_shape_violations(self._mutated(
            "aee_checker_sealed_run.py prepare-v1", "aee_checker_sealed_run.py prepare"))
        self.assertTrue(any("prepare-v1" in h for h in hits), hits)

    def test_record_step_names_the_packet_module_constant(self):
        self.assertIn(hosted_packet.PREPARE_RECORD_FILENAME, RECORD_RUN)
        self.assertIn(hosted_packet.PREPARE_FILENAME, RECORD_RUN)

    def test_comment_only_noop_mutation_stays_green(self):
        mutated_text = "# noop comment\n" + self.text
        self.assertEqual(parse_workflow_yaml(mutated_text), ALLOWED_PREPARE_WORKFLOW)
        self.assertEqual(prepare_shape_violations(parse_workflow_yaml(mutated_text)), [])
