#!/usr/bin/env python3
"""Hosted contained publication gate (#107).

Enforces #106 `publication_permission` and attempts a real contained-oci-v0
execution via existing primitives. Does not reimplement the OCI projector or
comparator. Does not score, authenticate, endorse, audit, certify, or claim
escape-proof OCI.

Dispatch bindings (candidate_revision, runner_revision, image_digest) are
sealed into the execution contract: a packet-root bindings file must match,
prepare.pins.subject_commit must equal candidate_revision (sole producer
candidate identity), prepare.execution.commit must match runner_revision,
image_digest is candidate/toolchain image B (not inert probe A), preflight
requires prepare.image.id (probe A) and prepare.toolchain.image_id (B) and
delegates identity/type/distinctness to require_candidate_image, the produced
envelope requested.image_id must match B, and envelope prepare_sha256 must
bind the exact checked prepare bytes (probe A remains prepare-bound). Packet root itself resolves under an explicit
workspace root before any child read. Authorize/prepare/pins/envelope JSON
resolve only as confined regular files under that packet root with byte
ceilings before parse. Child-environment observation comes only from the
contained OCI effective envelope (env_names/mounts); runner.environment,
runs-on, and persist-credentials remain structural workflow facts.

Packet delivery (#107): the packet is fetched from release assets into a fixed
directory by `hosted_packet.py`, and the gate binds it again itself. Before it
parses anything in the packet it compares the manifest bytes' SHA-256 with
`--packet-manifest-sha256`, then holds every listed file, and the authorize and
prepare roles it reads, to the manifest's digests; an entry the manifest does
not list refuses. The dispatch is bound to R as well: GITHUB_SHA and
GITHUB_WORKFLOW_SHA, read from the runner's environment, must both equal
runner_revision, and both are recorded in the rerun evidence and the setup
artifact. This is transport and revision binding, not authentication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import contained_oci as contained  # noqa: E402
import corpus_adequacy as ca  # noqa: E402
import candidate_diagnostics  # noqa: E402
import envelope_collection as collection  # noqa: E402
import effective_envelope  # noqa: E402
import hosted_packet as packet_delivery  # noqa: E402
import aee_checker_sealed_run as sealed_run  # noqa: E402
from hosted_rail_contract import LEGACY_RAIL, OWNED_V1_RAIL, require_rail  # noqa: E402
import hosted_attempt_statement as attempt_statement  # noqa: E402
from aee_checker_sealed_candidate import (  # noqa: E402
    CANDIDATE_MOUNT_SPEC,
    require_candidate_image,
)
REQUIRED_PROFILE = LEGACY_RAIL.execution_profile
REQUIRED_RUNNER_ENVIRONMENT = "github-hosted"
ARTIFACT_SETUP = "setup"
ARTIFACT_ENVELOPE = "effective-envelope"
ARTIFACT_CANDIDATE = "candidate-result"
ARTIFACT_RERUN = "rerun-evidence"
SETUP_STATUS_FILENAME = "setup-status.json"
EFFECTIVE_ENVELOPE_FILENAME = "effective-envelope.v0.json"
COLLECTION_DIRNAME = "effective-envelope-collection.v0"
# Diagnostic retention, deliberately outside every upload selection in the workflow. A refused
# run's observations are kept verbatim here rather than rewritten: the refusal is about what may
# be published, not about what was seen.
WITHHELD_COLLECTION_DIRNAME = "withheld-collection.diagnostic.v0"
QUARANTINE_ATTEMPT_TEMPLATE = "attempt-%04d"
MAX_QUARANTINE_ATTEMPTS = 256
DIAGNOSTIC_DIRNAME = "withheld-diagnostic-package.v0"
DIAGNOSTIC_MANIFEST_FILENAME = "diagnostic-package.v0.json"
DIAGNOSTIC_COLLECTION_DIRNAME = "collection"
DIAGNOSTIC_SCHEMA = "corpus-adequacy.hosted-withhold-diagnostic.v0"
DIAGNOSTIC_SCHEMA_V1 = "corpus-adequacy.hosted-withhold-diagnostic.v1"
DIAGNOSTIC_KIND = "hosted-withhold-diagnostic"
DIAGNOSTIC_PERMISSION = "withheld"
DIAGNOSTIC_ARTIFACT_CLASS = "quarantined-diagnostic"
DIAGNOSTIC_DECISIONS = ("withhold", "unavailable", "refuse")
COLLECTION_PRESENT = "collection_present"
COLLECTION_ABSENT = "collection_absent"
MAX_DIAGNOSTIC_MANIFEST_BYTES = 262144
MAX_DIAGNOSTIC_ENTRIES = collection.MAX_COLLECTION_MEMBERS + 3
MAX_DIAGNOSTIC_PACKAGE_BYTES = (
    collection.MAX_INDEX_BYTES
    + collection.MAX_MEMBER_TOTAL_BYTES
    + MAX_DIAGNOSTIC_MANIFEST_BYTES
    + candidate_diagnostics.MAX_BYTES
)
MAX_RERUN_EVIDENCE_BYTES = 262144
MAX_RERUN_EVIDENCE_ENTRIES = 256
MAX_RERUN_ENTRY_BYTES = 65536
CANDIDATE_RESULT_FILENAME = "candidate-result.json"
# The owned rail's fifth artifact (#186): the canonical report.v0 bytes of a published run. The
# external rail never writes it; its corpus owner consented to no score and no per-mutant result.
REPORT_FILENAME = "report.v0.json"
RERUN_EVIDENCE_FILENAME = "rerun-evidence.jsonl"
# One name for the bindings file: the packet module's closed file-name set carries it.
DISPATCH_BINDINGS_FILENAME = packet_delivery.BINDINGS_FILENAME
CONCURRENCY_GROUP = LEGACY_RAIL.publication_concurrency
CANCEL_IN_PROGRESS = False
RETENTION_DAYS = 14
MAX_ARTIFACT_BYTES = 5242880
MAX_INPUT_BYTES = MAX_ARTIFACT_BYTES
# 300 s materialize deadline + 9 x 120 s candidate invocations = 1380 s, plus setup.
TIMEOUT_MINUTES = 30
RUNS_ON = "ubuntu-24.04"
# (record key, environment variable). The first two are bound to runner_revision; the image
# labels are recorded so a runner-image change between PREPARE and execution is visible.
WORKFLOW_IDENTITY_ENV = (
    ("github_sha", "GITHUB_SHA"),
    ("github_workflow_sha", "GITHUB_WORKFLOW_SHA"),
    ("image_os", "ImageOS"),
    ("image_version", "ImageVersion"),
)
HOSTED_SCHEMA = "corpus-adequacy.hosted-publication.v0"
DISPATCH_BINDING_KEYS = (
    "candidate_revision", "runner_revision", "image_digest",
)

HEX40 = frozenset("0123456789abcdef")
_CREDENTIAL_ENV_EXACT = frozenset({"GITHUB_TOKEN", "GH_TOKEN"})
_CREDENTIAL_ENV_PREFIXES = ("AWS_", "DOCKER_")
_CREDENTIAL_ENV_MARKERS = ("SECRET", "PASSWORD", "CREDENTIAL")

NON_CLAIMS = (
    "Not authentication of the candidate author or operator.",
    "Not endorsement, audit, or certification.",
    "Not proof that OCI is an escape-proof sandbox.",
    "Not a third-party quality score.",
    "Hosted intake is not hosted execution authorization beyond this gate.",
)
DIAGNOSTIC_NON_CLAIMS = (
    "Retains observations from one hosted attempt; it does not verify an unverified member.",
    "Does not authorize publication or execution.",
    "Does not prove kernel-applied limits or cleanup beyond recorded observations.",
    "Not adequacy, endorsement, audit, or certification.",
)
DIAGNOSTIC_MANIFEST_KEYS = (
    "schema", "kind", "artifact_class", "publication_permission", "decision",
    "reason", "execution_began", "collection_state", "run_identity",
    "workflow_identity", "bindings", "dispatch_bindings", "report_sha256",
    "artifacts", "collection", "non_claims",
)
DIAGNOSTIC_MANIFEST_KEYS_V1 = DIAGNOSTIC_MANIFEST_KEYS + ("candidate_diagnostics",)
CANDIDATE_DIAGNOSTIC_STATE_KEYS = ("state", "artifact")
CANDIDATE_DIAGNOSTIC_BINDING_KEYS = ("relpath", "bytes", "sha256")
CANDIDATE_DIAGNOSTIC_STATES = ("present", "unavailable")
RUN_IDENTITY_KEYS = ("run_id", "run_attempt")
FILE_DIGEST_KEYS = ("bytes", "sha256")
COLLECTION_BINDING_KEYS = ("relpath", "index", "members")
INDEX_BINDING_KEYS = ("relpath", "bytes", "sha256")
MEMBER_BINDING_KEYS = ("ordinal", "relpath", "bytes", "sha256")
SETUP_STATUS_KEYS = (
    "schema", "kind", "setup_status", "reason", "bindings", "dispatch_bindings",
    "operator_profile", "workflow_identity", "non_claims",
)
VOID_CANDIDATE_KEYS = (
    "schema", "kind", "score_status", "mutant_status", "reason", "bindings",
    "dispatch_bindings", "non_claims",
)
LEGACY_CANDIDATE_KEYS = (
    "schema", "kind", "score_status", "decision", "bindings", "dispatch_bindings",
    "non_claims",
)
OWNED_CANDIDATE_KEYS = (
    "schema", "kind", "decision", "score_status", "bindings", "dispatch_bindings",
    "report_sha256", "control_status", "unproved", "adequate", "outcomes",
    "non_claims",
)
# The external rail's reduced projection (#184). The external corpus owner's consent covers no
# score and no per-mutant result, so `adequate`, the verdict counts and per-site verdicts are
# absent by construction; `control_status`, `unproved` and per-ordinal completion are the facts
# a reader needs to see that baseline and control held without being shown a score.
EXTERNAL_CANDIDATE_KEYS = tuple(key for key in OWNED_CANDIDATE_KEYS if key != "adequate")
CONTROL_STATUSES = ("killed", "survived", "moved", "error", "absent-or-invalid")
RERUN_START_KEYS = (
    "kind", "bindings", "dispatch_bindings", "workflow_identity", "run_id",
    "run_attempt",
)
RERUN_TERMINAL_KEYS = (
    "kind", "decision", "reason", "collection_state", "diagnostic_package_sha256",
    "bindings", "dispatch_bindings", "run_id", "run_attempt",
)
RERUN_POST_EXECUTE_KEYS = (
    "kind", "reason", "setup_status", "bindings", "dispatch_bindings", "run_id",
    "run_attempt",
)
RERUN_CLEANUP_FAILED_KEYS = (
    "kind", "reason", "cleanup_error_type", "bindings", "dispatch_bindings",
    "run_id", "run_attempt",
)
RERUN_INFRA_KEYS = RERUN_POST_EXECUTE_KEYS
RERUN_KIND_START = "run-attempt-start"
RERUN_KIND_TERMINAL = "run-attempt-terminal"
RERUN_KIND_POST_EXECUTE = "post-execute-refusal"
RERUN_KIND_CLEANUP_FAILED = "post-execute-refusal-cleanup-failed"
RERUN_KIND_INFRA = "infrastructure-failure"
ARTIFACT_SETUP_NAME = SETUP_STATUS_FILENAME
ARTIFACT_CANDIDATE_NAME = CANDIDATE_RESULT_FILENAME


class HostedPublicationError(Exception):
    """Hosted publication was refused before a score could be emitted."""



def _canonical_path(path) -> Path:
    """Cross-platform path identity (macOS /var→/private/var, Win 8.3)."""
    return Path(os.path.realpath(os.fspath(path)))


def paths_equal(left, right) -> bool:
    return _canonical_path(left) == _canonical_path(right)


def _require_hex40(value, where: str) -> str:
    if (not isinstance(value, str) or len(value) != 40 or
            any(ch not in HEX40 for ch in value)):
        raise HostedPublicationError(where)
    return value


def require_bindings(candidate_revision, runner_revision, image_digest) -> dict:
    try:
        image = contained.require_image_id(image_digest)
    except contained.PrepareError as exc:
        raise HostedPublicationError("image_digest") from exc
    return {
        "candidate_revision": _require_hex40(
            candidate_revision, "candidate_revision"),
        "runner_revision": _require_hex40(runner_revision, "runner_revision"),
        "image_digest": image,
    }


def require_operator_profile(profile) -> str:
    if profile != REQUIRED_PROFILE:
        raise HostedPublicationError("operator_profile")
    return profile


def _rail_for_operator_profile(profile):
    for rail in (LEGACY_RAIL, OWNED_V1_RAIL):
        if rail.execution_profile == profile:
            return rail
    raise HostedPublicationError("operator_profile")


def observe_workflow_identity(environ=None) -> dict:
    """What the runner says this run is: read, not checked (see check_workflow_identity)."""
    env = os.environ if environ is None else environ
    return {key: env.get(name) for key, name in WORKFLOW_IDENTITY_ENV}


def check_workflow_identity(identity, *, runner_revision) -> None:
    """GITHUB_SHA == GITHUB_WORKFLOW_SHA == runner_revision, or refuse.

    A dispatch whose workflow definition is not R's is refused while R's gate still runs. Absent
    or empty values refuse: an unobserved identity is not a matching one.
    """
    github_sha = identity.get("github_sha")
    workflow_sha = identity.get("github_workflow_sha")
    if not isinstance(github_sha, str) or not github_sha:
        raise HostedPublicationError("workflow_identity_absent")
    if not isinstance(workflow_sha, str) or not workflow_sha:
        raise HostedPublicationError("workflow_identity_absent")
    if github_sha != runner_revision:
        raise HostedPublicationError("github_sha_binding")
    if workflow_sha != runner_revision:
        raise HostedPublicationError("workflow_sha_binding")


def check_packet_manifest(packet, expected_sha256, *, max_bytes: int = MAX_INPUT_BYTES,
                          rail=LEGACY_RAIL) -> dict:
    """Bind the packet under `packet` to the dispatched manifest digest, in the gate itself.

    The manifest's digest is compared before it is parsed; parsing is the packet module's one
    rule; the packet directory must hold exactly the listed files, the manifest and the pins
    directory; and each listed file is read as a confined regular file and held to its digest.
    Returns {file name: sha256}.
    """
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or
            any(ch not in "0123456789abcdef" for ch in expected_sha256)):
        raise HostedPublicationError("packet_manifest_sha256")
    rail = require_rail(rail)
    manifest_path = resolve_confined_input(
        packet, rail.packet_manifest_filename,
        max_bytes=packet_delivery.MAX_MANIFEST_BYTES)
    try:
        manifest_raw = ca.read_bounded_regular_file(
            manifest_path, cap=packet_delivery.MAX_MANIFEST_BYTES)
    except ca.ManifestError as exc:
        raise HostedPublicationError("max_input_bytes") from exc
    if hashlib.sha256(manifest_raw).hexdigest() != expected_sha256:
        raise HostedPublicationError("packet_manifest_binding")
    try:
        files = packet_delivery.parse_manifest(manifest_raw, rail=rail)
    except packet_delivery.PacketError as exc:
        raise HostedPublicationError("packet_manifest:%s" % exc) from exc
    if tuple(sorted(os.listdir(packet))) != rail.packet_entries:
        raise HostedPublicationError("packet_entries")
    for name, digest in files.items():
        path = resolve_confined_input(packet, name, max_bytes=max_bytes)
        try:
            raw = ca.read_bounded_regular_file(path, cap=max_bytes)
        except ca.ManifestError as exc:
            raise HostedPublicationError("max_input_bytes") from exc
        if hashlib.sha256(raw).hexdigest() != digest:
            raise HostedPublicationError("packet_file_binding")
    return files


def _is_credential_env(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return True
    if name in _CREDENTIAL_ENV_EXACT:
        return True
    if any(name.startswith(prefix) for prefix in _CREDENTIAL_ENV_PREFIXES):
        return True
    upper = name.upper()
    return any(marker in upper for marker in _CREDENTIAL_ENV_MARKERS)


def resolve_confined_input(root, relpath, *, max_bytes: int | None = None) -> Path:
    """Resolve relpath strictly under root; refuse abs/.. /symlink/non-regular.

    When max_bytes is set, the leaf must be a regular file whose size is at
    or under the ceiling (checked via lstat before any read). When max_bytes
    is None, the leaf must be a non-symlink directory (packet root / pins).
    Path comparisons canonicalize both sides so macOS /var vs /private/var and
    Windows long vs 8.3 aliases compare equal while genuine escapes still refuse.
    """
    if not isinstance(relpath, str) or not relpath:
        raise HostedPublicationError("confined_path")
    if relpath.startswith("/") or relpath.startswith("\\"):
        raise HostedPublicationError("confined_path")
    rel = Path(relpath)
    if rel.is_absolute():
        raise HostedPublicationError("confined_path")
    parts = rel.parts
    if not parts or any(part == ".." for part in parts):
        raise HostedPublicationError("confined_path")
    if any(part == "" for part in parts):
        raise HostedPublicationError("confined_path")

    root_path = Path(root)
    try:
        if root_path.is_symlink():
            raise HostedPublicationError("confined_path")
        root_resolved = _canonical_path(root_path.resolve(strict=True))
    except (OSError, HostedPublicationError):
        raise HostedPublicationError("confined_path") from None
    if not root_resolved.is_dir() or root_resolved.is_symlink():
        raise HostedPublicationError("confined_path")

    current = root_resolved
    for part in parts:
        if part in (".", ".."):
            raise HostedPublicationError("confined_path")
        current = current / part
        try:
            st = current.lstat()
        except OSError as exc:
            raise HostedPublicationError("confined_path") from exc
        if stat.S_ISLNK(st.st_mode):
            raise HostedPublicationError("confined_path")

    try:
        st = current.lstat()
    except OSError as exc:
        raise HostedPublicationError("confined_path") from exc
    if stat.S_ISLNK(st.st_mode):
        raise HostedPublicationError("confined_path")

    try:
        resolved = _canonical_path(current.resolve(strict=True))
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise HostedPublicationError("confined_path") from exc
    if resolved.is_symlink():
        raise HostedPublicationError("confined_path")

    if max_bytes is None:
        if not stat.S_ISDIR(st.st_mode):
            raise HostedPublicationError("confined_path")
        return resolved

    if not stat.S_ISREG(st.st_mode):
        raise HostedPublicationError("confined_path")
    if type(max_bytes) is not int or max_bytes < 0:
        raise HostedPublicationError("max_input_bytes")
    if st.st_size > max_bytes:
        raise HostedPublicationError("max_input_bytes")
    return resolved


def _load_json_confined_bytes(root, relpath, *, max_bytes: int):
    """Size-check then read+parse JSON under a confined root (before loads)."""
    path = resolve_confined_input(root, relpath, max_bytes=max_bytes)
    try:
        raw = ca.read_bounded_regular_file(path, cap=max_bytes)
    except ca.ManifestError as exc:
        raise HostedPublicationError("max_input_bytes") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HostedPublicationError("json_input") from exc
    return doc, raw


def load_json_confined(root, relpath, *, max_bytes: int):
    """Size-check then read+parse JSON under a confined root (before loads)."""
    doc, _raw = _load_json_confined_bytes(root, relpath, max_bytes=max_bytes)
    return doc


def resolve_workspace_root(workspace_root) -> Path:
    """Require an explicit existing non-symlink workspace directory."""
    if workspace_root is None or (isinstance(workspace_root, str) and not workspace_root):
        raise HostedPublicationError("workspace_root")
    root = Path(workspace_root)
    try:
        if root.is_symlink():
            raise HostedPublicationError("workspace_root")
        resolved = _canonical_path(root.resolve(strict=True))
    except (OSError, HostedPublicationError):
        raise HostedPublicationError("workspace_root") from None
    if not resolved.is_dir() or resolved.is_symlink():
        raise HostedPublicationError("workspace_root")
    return resolved


def resolve_packet_root(workspace_root, packet_root) -> Path:
    """Constrain packet_root itself beneath the checked-out workspace root."""
    workspace = resolve_workspace_root(workspace_root)
    return resolve_confined_input(workspace, packet_root, max_bytes=None)


def load_dispatch_bindings(packet_root, *, expected: dict,
                           max_bytes: int = MAX_INPUT_BYTES, rail=LEGACY_RAIL) -> dict:
    rail = require_rail(rail)
    doc = load_json_confined(
        packet_root, rail.bindings_filename, max_bytes=max_bytes)
    if type(doc) is not dict:
        raise HostedPublicationError("dispatch_bindings")
    sealed = require_bindings(
        doc.get("candidate_revision"),
        doc.get("runner_revision"),
        doc.get("image_digest"),
    )
    if sealed != expected:
        raise HostedPublicationError("dispatch_bindings")
    return sealed


def check_prepare_bindings(prepare_doc, *, bindings) -> None:
    if type(prepare_doc) is not dict:
        raise HostedPublicationError("prepare_bindings")
    execution = prepare_doc.get("execution")
    if type(execution) is not dict:
        raise HostedPublicationError("runner_revision_binding")
    if execution.get("commit") != bindings["runner_revision"]:
        raise HostedPublicationError("runner_revision_binding")
    image = prepare_doc.get("image")
    if type(image) is not dict:
        raise HostedPublicationError("image_digest_binding")
    toolchain = prepare_doc.get("toolchain")
    if type(toolchain) is not dict:
        raise HostedPublicationError("image_digest_binding")
    try:
        require_candidate_image(
            image_id=bindings["image_digest"],
            toolchain_image_id=toolchain.get("image_id"),
            probe_image_id=image.get("id"),
        )
    except contained.PrepareError as exc:
        raise HostedPublicationError("image_digest_binding") from exc
    pins = prepare_doc.get("pins")
    if type(pins) is not dict:
        raise HostedPublicationError("candidate_revision_binding")
    if pins.get("subject_commit") != bindings["candidate_revision"]:
        raise HostedPublicationError("candidate_revision_binding")


def check_envelope_bindings(envelope_doc, *, bindings, prepare_sha256,
                            rail=LEGACY_RAIL) -> None:
    rail = require_rail(rail)
    if type(envelope_doc) is not dict:
        raise HostedPublicationError("envelope_bindings")
    if envelope_doc.get("execution_commit") != bindings["runner_revision"]:
        raise HostedPublicationError("runner_revision_binding")
    requested = envelope_doc.get("requested")
    if type(requested) is not dict:
        raise HostedPublicationError("image_digest_binding")
    if requested.get("image_id") != bindings["image_digest"]:
        raise HostedPublicationError("image_digest_binding")
    if (not isinstance(prepare_sha256, str) or len(prepare_sha256) != 64 or
            any(ch not in "0123456789abcdef" for ch in prepare_sha256)):
        raise HostedPublicationError("prepare_sha256_binding")
    if envelope_doc.get("prepare_sha256") != prepare_sha256:
        raise HostedPublicationError("prepare_sha256_binding")
    if requested.get("execution_profile") != rail.execution_profile:
        raise HostedPublicationError("execution_profile_binding")
    if requested.get("sealed") is not True:
        raise HostedPublicationError("sealed_binding")
    expected_profile = (contained.CANDIDATE_RESOURCE_PROFILE_V2
                        if rail.execution_profile == "contained-oci-v1"
                        else contained.CANDIDATE_RESOURCE_PROFILE)
    if requested.get("resource_profile") != expected_profile:
        raise HostedPublicationError("resource_profile_binding")
    candidate_mount_destinations = sorted(
        destination for _key, destination in CANDIDATE_MOUNT_SPEC
    )
    if requested.get("mount_spec") != candidate_mount_destinations:
        raise HostedPublicationError("mount_spec_binding")


def observe_child_environment(envelope_doc) -> dict:
    """Sole child-environment observation: contained OCI effective envelope.

    Values come from the envelope projected by contained_oci / effective_envelope
    (env_names and mounts). runner.environment, runs-on, and persist-credentials
    are structural workflow facts and are not read here.

    When envelope_status is not 'verified' and effective is None (a withheld
    run), empty collections (empty tuples for env names, empty list for
    mounts) are returned so refuse_hostile_workflow does not fail on
    missing data. This is an unavailable observation, not a measured-clean
    result; publication_decision strictly requires envelope_status == 'verified'
    and publication_permission == 'permitted' before any output can publish.
    """
    if type(envelope_doc) is not dict:
        raise HostedPublicationError("envelope_effective")
    if envelope_doc.get("envelope_status") != "verified" and envelope_doc.get("effective") is None:
        return {"env_names": (), "mounts": [], "image_env_names": ()}
    effective = envelope_doc.get("effective")
    if type(effective) is not dict:
        raise HostedPublicationError("envelope_effective")
    env_names = effective.get("env_names")
    if type(env_names) not in (list, tuple):
        raise HostedPublicationError("child_env_names")
    for name in env_names:
        if not isinstance(name, str) or not name:
            raise HostedPublicationError("child_env_names")
    mounts = effective.get("mounts")
    if type(mounts) not in (list, tuple):
        raise HostedPublicationError("child_mounts")
    return {
        "env_names": tuple(env_names),
        "mounts": list(mounts),
        "image_env_names": (
            tuple(effective["image_env_names"])
            if type(effective.get("image_env_names")) in (list, tuple)
            else ()),
    }


def refuse_hostile_workflow(*, env_names, mounts=()):
    """Refuse hostile child-environment observations from the OCI envelope."""
    if env_names is None:
        raise HostedPublicationError("child_env_names")
    if type(env_names) not in (list, tuple):
        raise HostedPublicationError("child_env_names")
    for name in env_names:
        if _is_credential_env(name):
            raise HostedPublicationError("credential_env")
    if type(mounts) not in (list, tuple):
        raise HostedPublicationError("child_mounts")
    for mount in mounts:
        if not isinstance(mount, dict):
            raise HostedPublicationError("child_mounts")
        source = str(mount.get("source", "") or mount.get("Source", "") or "")
        destination = str(
            mount.get("destination", "") or mount.get("Destination", "") or "")
        joined = "%s:%s" % (source, destination)
        if ("docker.sock" in source or "docker.sock" in destination
                or "docker.sock" in joined):
            raise HostedPublicationError("docker.sock")
        writable = mount.get("writable", mount.get("RW", mount.get("rw")))
        if writable is True:
            raise HostedPublicationError("writable_checkout")
    return None


def publication_decision(envelope, *, setup_status) -> dict:
    """Gate publication: permitted AND verified envelope_status required."""
    if setup_status != "ready":
        return {
            "decision": "unavailable",
            "score_status": "none",
            "setup_status": setup_status,
            "publication_permission": None,
        }
    permission = None
    envelope_status = None
    if isinstance(envelope, dict):
        permission = envelope.get("publication_permission")
        envelope_status = envelope.get("envelope_status")
    if (envelope is None or permission != "permitted" or
            envelope_status != "verified"):
        return {
            "decision": "withhold",
            "score_status": "none",
            "setup_status": setup_status,
            "publication_permission": permission,
            "envelope_status": envelope_status,
        }
    return {
        "decision": "publish",
        "score_status": "none",
        "setup_status": setup_status,
        "publication_permission": permission,
        "envelope_status": envelope_status,
    }


def void_candidate_result(*, reason, bindings) -> dict:
    if not isinstance(reason, str) or not reason:
        raise HostedPublicationError("reason")
    if type(bindings) is not dict:
        raise HostedPublicationError("bindings")
    return {
        "schema": HOSTED_SCHEMA,
        "kind": "void-hosted-result",
        "score_status": "none",
        "mutant_status": "not-scored",
        "reason": reason,
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "non_claims": list(NON_CLAIMS),
    }


def _encode_json(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def _require_exact(doc, keys, where: str) -> None:
    if type(doc) is not dict:
        raise HostedPublicationError(where)
    if set(doc) != set(keys):
        raise HostedPublicationError(where)


def _is_decimal_id(value) -> bool:
    return isinstance(value, str) and value != "" and value.isdigit()


def _require_run_identity(identity) -> dict:
    if type(identity) is not dict:
        raise HostedPublicationError("run_identity")
    if set(identity) != set(RUN_IDENTITY_KEYS):
        raise HostedPublicationError("run_identity")
    closed = {
        "run_id": identity.get("run_id"),
        "run_attempt": identity.get("run_attempt"),
    }
    if not _is_decimal_id(closed["run_id"]) or not _is_decimal_id(closed["run_attempt"]):
        raise HostedPublicationError("run_identity")
    return closed


def _require_sha256(value, where: str) -> str:
    if (not isinstance(value, str) or len(value) != 64 or
            any(ch not in "0123456789abcdef" for ch in value)):
        raise HostedPublicationError(where)
    return value


def _require_bindings_pair(bindings, dispatch_bindings, expected=None) -> dict:
    if type(bindings) is not dict or type(dispatch_bindings) is not dict:
        raise HostedPublicationError("bindings")
    if bindings != dispatch_bindings:
        raise HostedPublicationError("bindings")
    if expected is not None and bindings != expected:
        raise HostedPublicationError("bindings")
    return dict(bindings)


def _require_attempt_ledger(entries, expected=None, expected_identity=None) -> tuple:
    start = entries[0]
    start_pair = _require_bindings_pair(
        start.get("bindings"), start.get("dispatch_bindings"), expected)
    start_identity = _require_run_identity({
        "run_id": start.get("run_id"),
        "run_attempt": start.get("run_attempt"),
    })
    if expected_identity is not None and start_identity != expected_identity:
        raise HostedPublicationError("attempt_binding")
    for entry in entries:
        _require_bindings_pair(
            entry.get("bindings"), entry.get("dispatch_bindings"), start_pair)
        if (entry.get("run_id") != start_identity["run_id"]
                or entry.get("run_attempt") != start_identity["run_attempt"]):
            raise HostedPublicationError("attempt_binding")
    return start_pair, start_identity


def _require_reason(reason) -> str:
    if not isinstance(reason, str) or not reason:
        raise HostedPublicationError("reason")
    return reason


def _terminal_event(entry) -> dict:
    """Validate the one closed terminal shape shared by publish and diagnostic attempts."""
    if type(entry) is not dict:
        raise HostedPublicationError("rerun_terminal")
    _require_exact(entry, RERUN_TERMINAL_KEYS, "rerun_keys")
    decision = entry.get("decision")
    reason = _require_reason(entry.get("reason"))
    collection_state = entry.get("collection_state")
    diagnostic_digest = entry.get("diagnostic_package_sha256")
    if decision == "publish":
        if (reason != "publication-permitted"
                or collection_state != COLLECTION_PRESENT
                or diagnostic_digest is not None):
            raise HostedPublicationError("rerun_terminal")
    elif decision in DIAGNOSTIC_DECISIONS:
        if collection_state not in (COLLECTION_PRESENT, COLLECTION_ABSENT):
            raise HostedPublicationError("rerun_terminal")
        _require_sha256(diagnostic_digest, "diagnostic_package_sha256")
    else:
        raise HostedPublicationError("rerun_terminal")
    _require_bindings_pair(entry.get("bindings"), entry.get("dispatch_bindings"))
    _require_run_identity({
        "run_id": entry.get("run_id"),
        "run_attempt": entry.get("run_attempt"),
    })
    return dict(entry)


def _is_member_filename(name: str) -> bool:
    if not isinstance(name, str) or not name.startswith("member-") or not name.endswith(".json"):
        return False
    mid = name[7:-5]
    return len(mid) == 4 and mid.isdigit()


def _load_json_file(path, *, max_bytes: int):
    path = Path(path)
    return _load_json_confined_bytes(path.parent, path.name, max_bytes=max_bytes)


def _preflight_files(root: Path, *, max_entries: int, max_total: int) -> list[Path]:
    """Count, type, and size-check before any read or hash."""
    root = Path(root)
    if not root.is_dir() or root.is_symlink():
        raise HostedPublicationError("diagnostic_package")
    files = []
    total = 0

    def walk(directory: Path):
        nonlocal total
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise HostedPublicationError("diagnostic_preflight") from exc
                if stat.S_ISLNK(st.st_mode):
                    raise HostedPublicationError("diagnostic_symlink")
                if stat.S_ISDIR(st.st_mode):
                    walk(path)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise HostedPublicationError("diagnostic_not_regular")
                files.append(path)
                if len(files) > max_entries:
                    raise HostedPublicationError("diagnostic_entry_ceiling")
                total += st.st_size
                if total > max_total:
                    raise HostedPublicationError("diagnostic_package_ceiling")

    walk(root)
    return files


def _preflight_collection_dir(directory: Path) -> None:
    directory = Path(directory)
    files = _preflight_files(
        directory,
        max_entries=MAX_DIAGNOSTIC_ENTRIES,
        max_total=collection.MAX_INDEX_BYTES + collection.MAX_MEMBER_TOTAL_BYTES,
    )
    names = []
    for path in files:
        rel = path.relative_to(directory).as_posix()
        if "/" in rel:
            raise HostedPublicationError("diagnostic_unexpected_path")
        names.append(rel)
        cap = (collection.MAX_INDEX_BYTES if rel == collection.INDEX_FILENAME
               else collection.MAX_MEMBER_BYTES)
        if path.lstat().st_size > cap:
            raise HostedPublicationError("diagnostic_file_ceiling")
        if rel != collection.INDEX_FILENAME and not _is_member_filename(rel):
            raise HostedPublicationError("diagnostic_unexpected_path")
    if collection.INDEX_FILENAME not in names:
        raise HostedPublicationError("collection index absent")


def _digest_file(path: Path, *, cap: int) -> tuple[bytes, str]:
    raw = ca.read_bounded_regular_file(Path(path), cap=cap)
    return raw, hashlib.sha256(raw).hexdigest()


def _file_digest_doc(path: Path, *, cap: int) -> dict:
    raw, digest = _digest_file(path, cap=cap)
    return {"bytes": len(raw), "sha256": digest}


def _outer_collection_binding(coll: Path, loaded: dict) -> dict:
    index_path = Path(coll) / collection.INDEX_FILENAME
    index_raw, index_digest = _digest_file(
        index_path, cap=collection.MAX_INDEX_BYTES)
    members = []
    index_members = loaded["index"]["members"]
    if type(index_members) is not list:
        raise HostedPublicationError("diagnostic_collection")
    for entry in index_members:
        if type(entry) is not dict:
            raise HostedPublicationError("diagnostic_collection")
        relpath = entry.get("relpath")
        ordinal = entry.get("ordinal")
        if not isinstance(relpath, str) or type(ordinal) is not int:
            raise HostedPublicationError("diagnostic_collection")
        member_path = Path(coll) / relpath
        raw, digest = _digest_file(member_path, cap=collection.MAX_MEMBER_BYTES)
        if entry.get("sha256") != digest:
            raise HostedPublicationError("diagnostic_inventory")
        members.append({
            "ordinal": ordinal,
            "relpath": "%s/%s" % (DIAGNOSTIC_COLLECTION_DIRNAME, relpath),
            "bytes": len(raw),
            "sha256": digest,
        })
    members.sort(key=lambda row: row["ordinal"])
    return {
        "relpath": DIAGNOSTIC_COLLECTION_DIRNAME,
        "index": {
            "relpath": "%s/%s" % (DIAGNOSTIC_COLLECTION_DIRNAME, collection.INDEX_FILENAME),
            "bytes": len(index_raw),
            "sha256": index_digest,
        },
        "members": members,
    }


def _inspect_live_collection(out: Path):
    live = Path(out) / COLLECTION_DIRNAME
    if not live.exists():
        return None
    if live.is_symlink() or not live.is_dir():
        raise HostedPublicationError("diagnostic_not_regular")
    _preflight_collection_dir(live)
    try:
        loaded = collection.load_collection(live)
    except collection.CollectionError as exc:
        raise HostedPublicationError(_collection_refusal_reason(exc)) from exc
    return loaded


def _artifact_digests(setup_raw: bytes, candidate_raw: bytes) -> dict:
    return {
        SETUP_STATUS_FILENAME: {
            "bytes": len(setup_raw),
            "sha256": hashlib.sha256(setup_raw).hexdigest(),
        },
        CANDIDATE_RESULT_FILENAME: {
            "bytes": len(candidate_raw),
            "sha256": hashlib.sha256(candidate_raw).hexdigest(),
        },
    }


def _report_sha256_from(loaded, candidate_doc):
    claimed = None
    if loaded is not None:
        claimed = loaded["index"].get("report_sha256")
    carried = candidate_doc.get("report_sha256") if type(candidate_doc) is dict else None
    if claimed is not None:
        _require_sha256(claimed, "report_sha256")
    if carried is not None:
        _require_sha256(carried, "report_sha256")
        if claimed is not None and carried != claimed:
            raise HostedPublicationError("report_sha256")
        if claimed is None:
            claimed = carried
    return claimed


def _closed_manifest(*, decision, reason, execute_began, collection_state,
                     identity, workflow_identity, bindings, report_sha256,
                     artifacts, collection_binding, candidate_diagnostic_binding=None):
    if decision not in DIAGNOSTIC_DECISIONS:
        raise HostedPublicationError("diagnostic_decision")
    if type(execute_began) is not bool:
        raise HostedPublicationError("execution_began")
    if collection_state == COLLECTION_PRESENT:
        if execute_began is not True or collection_binding is None:
            raise HostedPublicationError("collection_state")
    elif collection_state == COLLECTION_ABSENT:
        if collection_binding is not None:
            raise HostedPublicationError("collection_state")
    else:
        raise HostedPublicationError("collection_state")
    result = {
        "schema": (DIAGNOSTIC_SCHEMA_V1 if candidate_diagnostic_binding is not None
                   else DIAGNOSTIC_SCHEMA),
        "kind": DIAGNOSTIC_KIND,
        "artifact_class": DIAGNOSTIC_ARTIFACT_CLASS,
        "publication_permission": DIAGNOSTIC_PERMISSION,
        "decision": decision,
        "reason": _require_reason(reason),
        "execution_began": execute_began,
        "collection_state": collection_state,
        "run_identity": _require_run_identity(identity),
        "workflow_identity": (
            dict(workflow_identity) if workflow_identity is not None else None),
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "report_sha256": report_sha256,
        "artifacts": artifacts,
        "collection": collection_binding,
        "non_claims": list(DIAGNOSTIC_NON_CLAIMS),
    }
    if candidate_diagnostic_binding is not None:
        result["candidate_diagnostics"] = candidate_diagnostic_binding
    return result


def finalize_nonpublish_attempt(
        *, out, setup_doc, candidate_doc, decision, reason,
        execute_began, identity, workflow_identity, bindings,
        rerun_log, max_artifact_bytes=MAX_ARTIFACT_BYTES,
        envelope_doc=None, candidate_diagnostic_rows=None) -> dict:
    """One closed diagnostic package, then separately uploaded setup/candidate bytes."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if setup_doc is None or candidate_doc is None:
        raise HostedPublicationError("collapsed_artifacts")
    setup_raw = _encode_json(setup_doc)
    candidate_raw = _encode_json(candidate_doc)
    if len(setup_raw) > max_artifact_bytes or len(candidate_raw) > max_artifact_bytes:
        raise HostedPublicationError("max_artifact_bytes")
    if envelope_doc is None:
        envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
    artifacts_written = False

    def _write_setup_and_candidate():
        nonlocal artifacts_written
        write_separate_artifacts(
            out, setup_doc, envelope_doc, candidate_doc,
            max_bytes=max_artifact_bytes)
        artifacts_written = True

    try:
        loaded = _inspect_live_collection(out)
        collection_state = COLLECTION_PRESENT if loaded is not None else COLLECTION_ABSENT
        collection_binding = None
        live = out / COLLECTION_DIRNAME
        if loaded is not None:
            collection_binding = _outer_collection_binding(live, loaded)
        report_sha256 = _report_sha256_from(loaded, candidate_doc)
        artifacts = _artifact_digests(setup_raw, candidate_raw)
        try:
            closed_identity = _require_run_identity(identity)
        except HostedPublicationError:
            _write_setup_and_candidate()
            return {
                "decision": decision,
                "collection_state": collection_state,
                "diagnostic_package_sha256": None,
            }
        candidate_diagnostic_raw = None
        candidate_diagnostic_binding = None
        if candidate_diagnostic_rows:
            if loaded is None or collection_binding is None or report_sha256 is None:
                raise HostedPublicationError("candidate_diagnostics_binding")
            diagnostic_bindings = {
                "candidate_revision": bindings["candidate_revision"],
                "runner_revision": bindings["runner_revision"],
                "image_digest": bindings["image_digest"],
                "prepare_sha256": loaded["index"]["prepare_sha256"],
                "report_sha256": report_sha256,
                "collection_index_sha256": collection_binding["index"]["sha256"],
                "workflow_run_id": closed_identity["run_id"],
                "run_attempt": closed_identity["run_attempt"],
            }
            try:
                candidate_diagnostic_raw = candidate_diagnostics.encode_document(
                    candidate_diagnostics.build_document(
                        bindings=diagnostic_bindings,
                        members=list(candidate_diagnostic_rows)))
            except candidate_diagnostics.DiagnosticError as exc:
                raise HostedPublicationError("candidate_diagnostics") from exc
            candidate_diagnostic_binding = {
                "state": "present",
                "artifact": {
                    "relpath": candidate_diagnostics.FILENAME,
                    "bytes": len(candidate_diagnostic_raw),
                    "sha256": hashlib.sha256(candidate_diagnostic_raw).hexdigest(),
                },
            }
        elif execute_began:
            candidate_diagnostic_binding = {"state": "unavailable", "artifact": None}
        manifest = _closed_manifest(
            decision=decision, reason=reason, execute_began=execute_began,
            collection_state=collection_state, identity=closed_identity,
            workflow_identity=workflow_identity, bindings=bindings,
            report_sha256=report_sha256, artifacts=artifacts,
            collection_binding=collection_binding,
            candidate_diagnostic_binding=candidate_diagnostic_binding,
        )
        manifest_raw = _encode_json(manifest)
        if len(manifest_raw) > MAX_DIAGNOSTIC_MANIFEST_BYTES:
            raise HostedPublicationError("diagnostic_manifest_ceiling")
        package_total = len(manifest_raw)
        if candidate_diagnostic_raw is not None:
            package_total += len(candidate_diagnostic_raw)
        if collection_binding is not None:
            package_total += collection_binding["index"]["bytes"]
            package_total += sum(row["bytes"] for row in collection_binding["members"])
        if package_total > MAX_DIAGNOSTIC_PACKAGE_BYTES:
            raise HostedPublicationError("diagnostic_package_ceiling")
        dest = out / DIAGNOSTIC_DIRNAME
        if dest.exists():
            raise HostedPublicationError("diagnostic_package_occupied")
        staging = out / (".%s.staging" % DIAGNOSTIC_DIRNAME)
        if staging.exists():
            raise HostedPublicationError("diagnostic_staging_occupied")
        staging.mkdir()
        (staging / DIAGNOSTIC_MANIFEST_FILENAME).write_bytes(manifest_raw)
        if candidate_diagnostic_raw is not None:
            (staging / candidate_diagnostics.FILENAME).write_bytes(candidate_diagnostic_raw)
        if loaded is not None:
            live.rename(staging / DIAGNOSTIC_COLLECTION_DIRNAME)
        staging.rename(dest)
        _write_setup_and_candidate()
        digest = hashlib.sha256(manifest_raw).hexdigest()
        append_rerun_evidence(rerun_log, _terminal_event({
            "kind": RERUN_KIND_TERMINAL,
            "decision": decision,
            "reason": reason,
            "collection_state": collection_state,
            "diagnostic_package_sha256": digest,
            "bindings": dict(bindings),
            "dispatch_bindings": dict(bindings),
            "run_id": closed_identity["run_id"],
            "run_attempt": closed_identity["run_attempt"],
        }))
        return {
            "decision": decision,
            "collection_state": collection_state,
            "diagnostic_package_sha256": digest,
            "manifest": manifest,
        }
    except BaseException:
        if not artifacts_written:
            try:
                write_separate_artifacts(
                    out, setup_doc, envelope_doc, candidate_doc,
                    max_bytes=max_artifact_bytes, move_live_collection=False)
            except BaseException:
                pass
        raise


def _load_setup_status(path, *, max_bytes: int = MAX_INPUT_BYTES):
    doc, raw = _load_json_file(path, max_bytes=max_bytes)
    _require_exact(doc, SETUP_STATUS_KEYS, "setup_status")
    if doc.get("schema") != HOSTED_SCHEMA or doc.get("kind") != "setup-status":
        raise HostedPublicationError("setup_status")
    return doc, raw


def load_setup_status(path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    doc, _raw = _load_setup_status(path, max_bytes=max_bytes)
    return doc


def _load_candidate_result(path, *, max_bytes: int = MAX_INPUT_BYTES):
    doc, raw = _load_json_file(path, max_bytes=max_bytes)
    kind = doc.get("kind")
    if kind == "void-hosted-result":
        _require_exact(doc, VOID_CANDIDATE_KEYS, "candidate_result")
        if doc.get("schema") != HOSTED_SCHEMA:
            raise HostedPublicationError("candidate_result")
        return doc, raw
    if kind != "hosted-candidate-result":
        raise HostedPublicationError("candidate_result")
    schema = doc.get("schema")
    if schema == HOSTED_SCHEMA:
        # Historical external bytes (r1, r4) and nothing newer: the gate no longer writes it.
        _require_exact(doc, LEGACY_CANDIDATE_KEYS, "candidate_result")
        return doc, raw
    if schema == candidate_result_schema(LEGACY_RAIL):
        _require_exact(doc, EXTERNAL_CANDIDATE_KEYS, "candidate_result")
        _require_projection_facts(doc)
        return doc, raw
    if schema != candidate_result_schema(OWNED_V1_RAIL):
        raise HostedPublicationError("candidate_result")
    _require_exact(doc, OWNED_CANDIDATE_KEYS, "candidate_result")
    _require_sha256(doc.get("report_sha256"), "report_sha256")
    return doc, raw


def _require_projection_facts(doc) -> None:
    """The closed values a reduced projection may carry; nothing score-shaped survives this."""
    _require_sha256(doc.get("report_sha256"), "report_sha256")
    if doc.get("decision") not in ("publish", "withhold"):
        raise HostedPublicationError("candidate_result")
    if doc.get("score_status") != "none":
        raise HostedPublicationError("candidate_result")
    if doc.get("control_status") not in CONTROL_STATUSES:
        raise HostedPublicationError("candidate_result")
    unproved = doc.get("unproved")
    if type(unproved) is not int or unproved < 0:
        raise HostedPublicationError("candidate_result")
    outcomes = doc.get("outcomes")
    if type(outcomes) is not list:
        raise HostedPublicationError("candidate_outcome")
    for position, row in enumerate(outcomes):
        if (type(row) is not dict
                or tuple(sorted(row)) != ("candidate_outcome", "ordinal")
                or type(row["ordinal"]) is not int or row["ordinal"] < 0
                or row["candidate_outcome"] not in effective_envelope.CANDIDATE_OUTCOMES):
            raise HostedPublicationError("candidate_outcome")
        if position and row["ordinal"] <= outcomes[position - 1]["ordinal"]:
            raise HostedPublicationError("candidate_outcome")


def _require_outcomes_match_collection(candidate, loaded_collection) -> None:
    """A carried per-ordinal outcome list must be exactly the collection's members."""
    if "outcomes" not in candidate:
        return
    entries = loaded_collection["index"].get("members") or []
    members = loaded_collection.get("members") or []
    observed = [{"ordinal": entry.get("ordinal"),
                 "candidate_outcome": member.get("candidate_outcome")}
                for entry, member in zip(entries, members)]
    if len(entries) != len(members) or candidate["outcomes"] != observed:
        raise HostedPublicationError("candidate_outcome")


def load_candidate_result(path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    doc, _raw = _load_candidate_result(path, max_bytes=max_bytes)
    return doc


def _rerun_closed_keys(kind):
    if kind == RERUN_KIND_START:
        return RERUN_START_KEYS
    if kind == RERUN_KIND_TERMINAL:
        return RERUN_TERMINAL_KEYS
    if kind == RERUN_KIND_POST_EXECUTE:
        return RERUN_POST_EXECUTE_KEYS
    if kind == RERUN_KIND_CLEANUP_FAILED:
        return RERUN_CLEANUP_FAILED_KEYS
    if kind == RERUN_KIND_INFRA:
        return RERUN_INFRA_KEYS
    return None


def load_rerun_evidence(path, *, max_bytes: int = MAX_RERUN_EVIDENCE_BYTES,
                       max_entries: int = MAX_RERUN_EVIDENCE_ENTRIES,
                       max_entry_bytes: int = MAX_RERUN_ENTRY_BYTES,
                       mode: str = "complete") -> list:
    path = Path(path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise HostedPublicationError("rerun_evidence") from exc
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise HostedPublicationError("rerun_evidence")
    if st.st_size > max_bytes:
        raise HostedPublicationError("rerun_evidence_ceiling")
    try:
        raw = ca.read_bounded_regular_file(path, cap=max_bytes)
    except ca.ManifestError as exc:
        raise HostedPublicationError("rerun_evidence_ceiling") from exc
    lines = raw.splitlines()
    if len(lines) > max_entries:
        raise HostedPublicationError("rerun_evidence_entries")
    entries = []
    for line in lines:
        if len(line) > max_entry_bytes:
            raise HostedPublicationError("rerun_entry_ceiling")
        if not line.strip():
            continue
        try:
            entry = json.loads(line.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise HostedPublicationError("rerun_evidence") from exc
        if type(entry) is not dict:
            raise HostedPublicationError("rerun_evidence")
        kind = entry.get("kind")
        keys = _rerun_closed_keys(kind)
        if keys is None:
            raise HostedPublicationError("rerun_kind")
        _require_exact(entry, keys, "rerun_keys")
        if kind == RERUN_KIND_TERMINAL:
            entry = _terminal_event(entry)
        entries.append(entry)
    if not entries:
        raise HostedPublicationError("rerun_evidence")
    if entries[0].get("kind") != RERUN_KIND_START:
        raise HostedPublicationError("rerun_start")
    if mode == "legacy":
        return entries
    if mode != "complete":
        raise HostedPublicationError("rerun_mode")
    if entries[-1].get("kind") != RERUN_KIND_TERMINAL:
        raise HostedPublicationError("rerun_terminal")
    if any(entry.get("kind") == RERUN_KIND_TERMINAL for entry in entries[:-1]):
        raise HostedPublicationError("rerun_terminal")
    _require_attempt_ledger(entries)
    return entries


def load_diagnostic_package(directory, *, max_bytes: int = MAX_DIAGNOSTIC_PACKAGE_BYTES,
                             max_entries: int = MAX_DIAGNOSTIC_ENTRIES) -> dict:
    directory = Path(directory)
    files = _preflight_files(directory, max_entries=max_entries, max_total=max_bytes)
    names = {path.relative_to(directory).as_posix() for path in files}
    if DIAGNOSTIC_MANIFEST_FILENAME not in names:
        raise HostedPublicationError("diagnostic_manifest")
    with os.scandir(directory) as entries:
        root_names = {entry.name for entry in entries}
    allowed = {DIAGNOSTIC_MANIFEST_FILENAME, DIAGNOSTIC_COLLECTION_DIRNAME,
               candidate_diagnostics.FILENAME}
    if any(name not in allowed for name in root_names):
        raise HostedPublicationError("diagnostic_unexpected_path")
    manifest_path = directory / DIAGNOSTIC_MANIFEST_FILENAME
    if manifest_path.lstat().st_size > MAX_DIAGNOSTIC_MANIFEST_BYTES:
        raise HostedPublicationError("diagnostic_manifest_ceiling")
    manifest, _manifest_raw = _load_json_file(
        manifest_path, max_bytes=MAX_DIAGNOSTIC_MANIFEST_BYTES)
    schema = manifest.get("schema")
    if schema == DIAGNOSTIC_SCHEMA:
        _require_exact(manifest, DIAGNOSTIC_MANIFEST_KEYS, "diagnostic_manifest")
        if candidate_diagnostics.FILENAME in names:
            raise HostedPublicationError("diagnostic_unexpected_path")
    elif schema == DIAGNOSTIC_SCHEMA_V1:
        _require_exact(manifest, DIAGNOSTIC_MANIFEST_KEYS_V1, "diagnostic_manifest")
    else:
        raise HostedPublicationError("diagnostic_permission")
    if (schema not in (DIAGNOSTIC_SCHEMA, DIAGNOSTIC_SCHEMA_V1)
            or manifest.get("kind") != DIAGNOSTIC_KIND
            or manifest.get("artifact_class") != DIAGNOSTIC_ARTIFACT_CLASS
            or manifest.get("publication_permission") != DIAGNOSTIC_PERMISSION):
        raise HostedPublicationError("diagnostic_permission")
    if manifest.get("decision") not in DIAGNOSTIC_DECISIONS:
        raise HostedPublicationError("diagnostic_decision")
    if type(manifest.get("execution_began")) is not bool:
        raise HostedPublicationError("execution_began")
    _require_reason(manifest.get("reason"))
    identity = _require_run_identity(manifest.get("run_identity"))
    _require_bindings_pair(manifest.get("bindings"), manifest.get("dispatch_bindings"))
    artifacts = manifest.get("artifacts")
    if type(artifacts) is not dict or set(artifacts) != {
            SETUP_STATUS_FILENAME, CANDIDATE_RESULT_FILENAME}:
        raise HostedPublicationError("diagnostic_artifacts")
    for name, spec in artifacts.items():
        _require_exact(spec, FILE_DIGEST_KEYS, "diagnostic_artifacts")
        if type(spec.get("bytes")) is not int or spec["bytes"] < 0:
            raise HostedPublicationError("diagnostic_artifacts")
        _require_sha256(spec.get("sha256"), "diagnostic_artifacts")
    collection_state = manifest.get("collection_state")
    binding = manifest.get("collection")
    loaded_collection = None
    coll_dir = directory / DIAGNOSTIC_COLLECTION_DIRNAME
    if collection_state == COLLECTION_ABSENT:
        if binding is not None or coll_dir.exists():
            raise HostedPublicationError("collection_state")
        if manifest.get("execution_began") is True:
            pass
        if manifest.get("report_sha256") not in (None,):
            if manifest.get("report_sha256") is not None:
                _require_sha256(manifest.get("report_sha256"), "report_sha256")
    elif collection_state == COLLECTION_PRESENT:
        if manifest.get("execution_began") is not True:
            raise HostedPublicationError("collection_state")
        if type(binding) is not dict:
            raise HostedPublicationError("collection_state")
        _require_exact(binding, COLLECTION_BINDING_KEYS, "diagnostic_collection")
        if binding.get("relpath") != DIAGNOSTIC_COLLECTION_DIRNAME:
            raise HostedPublicationError("diagnostic_collection")
        _preflight_collection_dir(coll_dir)
        try:
            loaded_collection = collection.load_collection(coll_dir)
        except collection.CollectionError as exc:
            raise HostedPublicationError(_collection_refusal_reason(exc)) from exc
        derived = _outer_collection_binding(coll_dir, loaded_collection)
        if derived != binding:
            raise HostedPublicationError("diagnostic_inventory")
        claimed = loaded_collection["index"].get("report_sha256")
        if claimed != manifest.get("report_sha256"):
            raise HostedPublicationError("report_sha256")
    else:
        raise HostedPublicationError("collection_state")
    loaded_candidate_diagnostics = None
    if schema == DIAGNOSTIC_SCHEMA_V1:
        state_doc = manifest.get("candidate_diagnostics")
        _require_exact(state_doc, CANDIDATE_DIAGNOSTIC_STATE_KEYS,
                       "candidate_diagnostics")
        state = state_doc.get("state")
        if state not in CANDIDATE_DIAGNOSTIC_STATES:
            raise HostedPublicationError("candidate_diagnostics")
        descriptor = state_doc.get("artifact")
        if state == "unavailable":
            if descriptor is not None or candidate_diagnostics.FILENAME in names:
                raise HostedPublicationError("candidate_diagnostics")
            loaded_candidate_diagnostics = {"state": "unavailable", "members": None}
        else:
            _require_exact(descriptor, CANDIDATE_DIAGNOSTIC_BINDING_KEYS,
                           "candidate_diagnostics")
            if descriptor.get("relpath") != candidate_diagnostics.FILENAME:
                raise HostedPublicationError("candidate_diagnostics")
            _require_sha256(descriptor.get("sha256"), "candidate_diagnostics")
            sidecar_path = directory / candidate_diagnostics.FILENAME
            try:
                sidecar_raw = ca.read_bounded_regular_file(
                    sidecar_path, cap=candidate_diagnostics.MAX_BYTES)
            except ca.ManifestError as exc:
                raise HostedPublicationError("candidate_diagnostics") from exc
            if (len(sidecar_raw) != descriptor.get("bytes")
                    or hashlib.sha256(sidecar_raw).hexdigest() != descriptor.get("sha256")):
                raise HostedPublicationError("candidate_diagnostics_digest")
            if loaded_collection is None or manifest.get("report_sha256") is None:
                raise HostedPublicationError("candidate_diagnostics_binding")
            dispatch = manifest.get("bindings")
            if type(dispatch) is not dict or set(dispatch) != set(DISPATCH_BINDING_KEYS):
                raise HostedPublicationError("candidate_diagnostics_binding")
            dispatch = require_bindings(
                dispatch.get("candidate_revision"), dispatch.get("runner_revision"),
                dispatch.get("image_digest"))
            expected_diagnostic_bindings = {
                "candidate_revision": dispatch["candidate_revision"],
                "runner_revision": dispatch["runner_revision"],
                "image_digest": dispatch["image_digest"],
                "prepare_sha256": loaded_collection["index"]["prepare_sha256"],
                "report_sha256": manifest["report_sha256"],
                "collection_index_sha256": manifest["collection"]["index"]["sha256"],
                "workflow_run_id": identity["run_id"],
                "run_attempt": identity["run_attempt"],
            }
            try:
                loaded_doc = candidate_diagnostics.load_document(
                    sidecar_path, expected_bindings=expected_diagnostic_bindings)
            except candidate_diagnostics.DiagnosticError as exc:
                raise HostedPublicationError("candidate_diagnostics") from exc
            diagnostic_members = loaded_doc["members"]
            collection_entries = loaded_collection["index"]["members"]
            collection_members = loaded_collection["members"]
            if (len(diagnostic_members) != len(collection_members)
                    or [row["ordinal"] for row in diagnostic_members]
                    != [row["ordinal"] for row in collection_entries]
                    or [row["candidate_outcome"] for row in diagnostic_members]
                    != [row["candidate_outcome"] for row in collection_members]):
                raise HostedPublicationError("candidate_diagnostics_outcome")
            loaded_candidate_diagnostics = {
                "state": "present", "members": loaded_doc["members"]}
    digest = hashlib.sha256(_manifest_raw).hexdigest()
    result = dict(manifest)
    result["collection"] = loaded_collection
    result["diagnostic_package_sha256"] = digest
    result["manifest_bytes"] = _manifest_raw
    result["candidate_diagnostics"] = loaded_candidate_diagnostics
    return result


def load_hosted_attempt_artifacts(*, setup_path, candidate_path, rerun_path,
                                 diagnostic_dir=None, collection_dir=None,
                                 expected_bindings,
                                 expected_run_id, expected_run_attempt) -> dict:
    setup, setup_raw = _load_setup_status(setup_path)
    candidate, candidate_raw = _load_candidate_result(candidate_path)
    entries = load_rerun_evidence(rerun_path)
    expected = _require_bindings_pair(
        expected_bindings, expected_bindings, expected=expected_bindings)
    _require_bindings_pair(setup.get("bindings"), setup.get("dispatch_bindings"), expected)
    _require_bindings_pair(candidate.get("bindings"), candidate.get("dispatch_bindings"),
                           expected)
    identity = _require_run_identity({
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
    })
    _require_attempt_ledger(entries, expected=expected, expected_identity=identity)
    start = entries[0]
    terminal = entries[-1]
    if setup.get("workflow_identity") != start.get("workflow_identity"):
        raise HostedPublicationError("workflow_identity")
    if terminal.get("decision") == "publish":
        if diagnostic_dir is not None or collection_dir is None:
            raise HostedPublicationError("success_artifacts")
        if (setup.get("setup_status") != "ready"
                or setup.get("reason") != "publication-permitted"
                or candidate.get("kind") != "hosted-candidate-result"
                or candidate.get("decision") != "publish"):
            raise HostedPublicationError("success_artifacts")
        loaded_collection = load_envelope_collection(collection_dir)
        collection_decision = collection_publication_decision(
            loaded_collection, setup_status=setup["setup_status"])
        if collection_decision.get("decision") != "publish":
            raise HostedPublicationError("success_collection_permission")
        rail = _rail_for_operator_profile(setup.get("operator_profile"))
        prepare_sha256 = loaded_collection["index"].get("prepare_sha256")
        for member in loaded_collection["members"]:
            check_envelope_bindings(
                member, bindings=expected, prepare_sha256=prepare_sha256,
                rail=rail)
        carried = candidate.get("report_sha256")
        claimed = loaded_collection["index"].get("report_sha256")
        if carried is not None and carried != claimed:
            raise HostedPublicationError("report_sha256")
        if candidate.get("schema") == candidate_result_schema(LEGACY_RAIL):
            _require_outcomes_match_collection(candidate, loaded_collection)
        projection = {
            "decision": "publish",
            "collection_state": COLLECTION_PRESENT,
            "collection": loaded_collection,
            "report_sha256": claimed,
            "publication_permission": "permitted",
            "candidate_diagnostics": None,
        }
        return {
            "setup": setup,
            "candidate": candidate,
            "rerun": entries,
            "package": None,
            "projection": projection,
        }
    if diagnostic_dir is None or collection_dir is not None:
        raise HostedPublicationError("diagnostic_artifacts")
    package = load_diagnostic_package(diagnostic_dir)
    _require_bindings_pair(package.get("bindings"), package.get("dispatch_bindings"),
                           expected)
    if package["run_identity"] != identity:
        raise HostedPublicationError("attempt_binding")
    if package.get("workflow_identity") != start.get("workflow_identity"):
        raise HostedPublicationError("workflow_identity")
    declared = package["artifacts"]
    if hashlib.sha256(setup_raw).hexdigest() != declared[SETUP_STATUS_FILENAME]["sha256"]:
        raise HostedPublicationError("diagnostic_artifacts")
    if len(setup_raw) != declared[SETUP_STATUS_FILENAME]["bytes"]:
        raise HostedPublicationError("diagnostic_artifacts")
    if hashlib.sha256(candidate_raw).hexdigest() != declared[CANDIDATE_RESULT_FILENAME]["sha256"]:
        raise HostedPublicationError("diagnostic_artifacts")
    if len(candidate_raw) != declared[CANDIDATE_RESULT_FILENAME]["bytes"]:
        raise HostedPublicationError("diagnostic_artifacts")
    carried = candidate.get("report_sha256")
    if carried is not None and carried != package.get("report_sha256"):
        raise HostedPublicationError("report_sha256")
    if package.get("collection") is not None:
        claimed = package["collection"]["index"].get("report_sha256")
        if claimed != package.get("report_sha256"):
            raise HostedPublicationError("report_sha256")
    if terminal.get("diagnostic_package_sha256") != package["diagnostic_package_sha256"]:
        raise HostedPublicationError("diagnostic_package_sha256")
    if terminal.get("decision") != package.get("decision"):
        raise HostedPublicationError("diagnostic_decision")
    if terminal.get("collection_state") != package.get("collection_state"):
        raise HostedPublicationError("collection_state")
    if _require_reason(terminal.get("reason")) != package.get("reason"):
        raise HostedPublicationError("reason")
    if package.get("decision") not in DIAGNOSTIC_DECISIONS:
        raise HostedPublicationError("diagnostic_decision")
    return {
        "setup": setup,
        "candidate": candidate,
        "rerun": entries,
        "package": package,
        "projection": package,
    }


def _readback_summary(package) -> dict:
    loaded = package.get("collection")
    observations = []
    attempts = 0
    members = 0
    if loaded is not None:
        attempts = loaded["index"].get("attempts") or 0
        members = len(loaded.get("members") or [])
        index_members = loaded["index"].get("members") or []
        for entry, member in zip(index_members, loaded.get("members") or []):
            observations.append({
                "ordinal": entry.get("ordinal"),
                "envelope_status": member.get("envelope_status"),
                "unverified_field": member.get("unverified_field"),
                "candidate_outcome": member.get("candidate_outcome"),
                "cleanup": member.get("cleanup"),
            })
    result = {
        "decision": package.get("decision"),
        "collection_state": package.get("collection_state"),
        "attempts": attempts,
        "members": members,
        "report_sha256": package.get("report_sha256"),
        "publication_permission": package.get(
            "publication_permission", DIAGNOSTIC_PERMISSION),
        "member_observations": observations,
    }
    diagnostic = package.get("candidate_diagnostics")
    if isinstance(diagnostic, dict):
        result["candidate_diagnostics"] = list(diagnostic.get("members") or [])
    return result


def _quarantine_current_run_collection(out: Path) -> Path | None:
    """Move THIS invocation's collection out of every upload selection, byte for byte.

    Not a rewrite and not a deletion. The out root is reusable, so a second refusal must not
    cost the first one's evidence: each quarantine lands in its own attempt directory under
    `WITHHELD_COLLECTION_DIRNAME` and an occupied destination is never overwritten. Ordinals are
    assigned by scanning for the first free one rather than from a clock, so the layout is
    deterministic and two retained sets are distinguishable by name.
    """
    live = out / COLLECTION_DIRNAME
    if not live.is_dir():
        return None
    parent = out / WITHHELD_COLLECTION_DIRNAME
    parent.mkdir(parents=True, exist_ok=True)
    ordinal = 0
    while True:
        attempt = parent / (QUARANTINE_ATTEMPT_TEMPLATE % ordinal)
        if not attempt.exists():
            break
        ordinal += 1
        if ordinal > MAX_QUARANTINE_ATTEMPTS:
            raise HostedPublicationError("quarantine_attempt_ceiling")
    live.rename(attempt)
    return attempt


def _refuse_collection_at_legacy_path(doc) -> None:
    """The legacy path names a single envelope. A collection document there would be read as one
    by every consumer that predates the collection, so it is refused rather than written."""
    if isinstance(doc, dict) and (
            doc.get("schema") == collection.COLLECTION_SCHEMA or "members" in doc):
        raise HostedPublicationError("collection_at_legacy_envelope_path")


def write_separate_artifacts(out_dir, setup_doc, envelope_doc, candidate_doc,
                             *, max_bytes: int = MAX_ARTIFACT_BYTES,
                             move_live_collection: bool = True) -> dict:
    """`envelope_doc=None` means the collection directory is the authoritative artifact.

    The legacy single-envelope file is then not written, and any file left there by an earlier
    attempt is removed -- a stale envelope beside a fresh collection is a false record, and
    silently reusing it is exactly the fallback this integration forbids.
    """
    if setup_doc is None or candidate_doc is None:
        raise HostedPublicationError("collapsed_artifacts")
    if (setup_doc is envelope_doc or setup_doc is candidate_doc or
            (envelope_doc is not None and envelope_doc is candidate_doc)):
        raise HostedPublicationError("collapsed_artifacts")
    _refuse_collection_at_legacy_path(envelope_doc)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    if envelope_doc is not None:
        # Production non-publish paths move the live collection into the diagnostic package
        # first. This helper remains for callers that still write a stub without that package:
        # the live directory must not share the success upload surface.
        if move_live_collection and not (out / DIAGNOSTIC_DIRNAME).is_dir():
            _quarantine_current_run_collection(out)
    if envelope_doc is None:
        stale = out / EFFECTIVE_ENVELOPE_FILENAME
        if stale.exists():
            stale.unlink()
    entries = [(SETUP_STATUS_FILENAME, setup_doc), (CANDIDATE_RESULT_FILENAME, candidate_doc)]
    if envelope_doc is not None:
        entries.insert(1, (EFFECTIVE_ENVELOPE_FILENAME, envelope_doc))
    for name, doc in entries:
        raw = _encode_json(doc)
        if len(raw) > max_bytes:
            raise HostedPublicationError("max_artifact_bytes")
        path = out / name
        path.write_bytes(raw)
        written[name] = path
    return written


def append_rerun_evidence(log_path, entry: dict) -> None:
    if type(entry) is not dict:
        raise HostedPublicationError("rerun_evidence")
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8")
    with path.open("ab") as handle:
        handle.write(line)


def withheld_envelope_stub(*, reason, bindings) -> dict:
    return {
        "schema": HOSTED_SCHEMA,
        "kind": "withheld-envelope-stub",
        "publication_permission": "withheld",
        "envelope_status": "unverified",
        "withheld_reason": reason,
        "bindings": dict(bindings),
        "non_claims": list(NON_CLAIMS),
    }


def setup_status_doc(*, status, reason, bindings, workflow_identity=None,
                     rail=LEGACY_RAIL) -> dict:
    rail = require_rail(rail)
    return {
        "schema": HOSTED_SCHEMA,
        "kind": "setup-status",
        "setup_status": status,
        "reason": reason,
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "operator_profile": rail.execution_profile,
        "workflow_identity": (
            dict(workflow_identity) if workflow_identity is not None else None),
        "non_claims": list(NON_CLAIMS),
    }


def load_envelope(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    """Load envelope with pre-parse ceiling; path must be a regular file."""
    path = Path(path)
    parent = path.parent
    doc = load_json_confined(parent, path.name, max_bytes=max_bytes)
    try:
        effective_envelope.validate_envelope_record(doc)
    except effective_envelope.EnvelopeError as exc:
        raise HostedPublicationError("envelope_corrupt") from exc
    return doc


# A member whose own envelope semantics fail is an envelope defect and is named as one; every
# other check is a property of the collection (index, digests, ordinals, ceilings) and is named
# as that. The reason follows the check that actually failed, never the member count -- one
# member does not make a collection failure an envelope failure, and several do not make an
# envelope failure a collection one.
_MEMBER_SEMANTIC_CHECKS = frozenset({"collection member semantics"})
# A payload that will not parse is a JSON-input failure wherever it sits, and the pre-collection
# vocabulary already named it. Keeping that name preserves the distinction rather than folding a
# parse failure into a collection-integrity one.
_JSON_INPUT_CHECKS = frozenset({"collection member json", "collection index json"})


def _collection_refusal_reason(exc) -> str:
    check = str(exc)
    if check in _MEMBER_SEMANTIC_CHECKS:
        return "envelope_corrupt"
    if check in _JSON_INPUT_CHECKS:
        return "json_input"
    return "envelope_collection_corrupt"


def load_envelope_collection(directory, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    """Load every member of a contained run's collection, or refuse.

    No singleton fallback exists: if the index is absent the run is refused rather than read as a
    lone record, or deleting the index would restore the hole this replaces.
    """
    try:
        loaded = collection.load_collection(
            Path(directory), max_index_bytes=max_bytes, max_member_bytes=max_bytes)
    except collection.CollectionError as exc:
        raise HostedPublicationError(_collection_refusal_reason(exc)) from exc
    if collection.collection_permission(loaded) != "permitted":
        # Diagnostics stay representable: the members still load and are returned, and the
        # withheld reason travels with them for the decision below.
        loaded["withheld_reason"] = collection.withheld_reason(loaded)
    return loaded


def collection_publication_decision(loaded, *, setup_status) -> dict:
    """Decide from EVERY observation, reusing the single-record rule unchanged.

    A later member passing cannot rescue an earlier one that did not: the quantifier is
    universal, not positional, and `publication_decision` remains the one rule.
    """
    members = loaded.get("members", []) if isinstance(loaded, dict) else []
    if not members:
        return publication_decision(None, setup_status=setup_status)
    decisions = [publication_decision(m, setup_status=setup_status) for m in members]
    for decision in decisions:
        if decision["decision"] != "publish":
            return decision
    if loaded.get("withheld_reason") is not None:
        withheld = dict(decisions[0])
        withheld["decision"] = "withhold"
        withheld["score_status"] = "none"
        return withheld
    return decisions[0]


def _run_attempt_identity(environ=None) -> dict:
    env = os.environ if environ is None else {**os.environ, **environ}
    return {
        "run_id": env.get("GITHUB_RUN_ID") or env.get("HOSTED_RUN_ID"),
        "run_attempt": (
            env.get("GITHUB_RUN_ATTEMPT") or env.get("HOSTED_RUN_ATTEMPT")),
    }


def default_docker_ready() -> str:
    return contained.require_docker_ready()


def default_sealed_execute(*, authorize_path, prepare_path, pins_dir, root,
                           envelope_dest, materialize_dest,
                           diagnostic_sink=None,
                           max_bytes: int = MAX_INPUT_BYTES,
                           rail=LEGACY_RAIL):
    rail = require_rail(rail)
    import aee_checker_sealed_driver as driver
    authorize_raw = ca.read_bounded_regular_file(
        Path(authorize_path), cap=max_bytes)
    prepare_raw = ca.read_bounded_regular_file(
        Path(prepare_path), cap=max_bytes)
    return driver.run_authorized(
        authorize_raw=authorize_raw,
        prepare_raw=prepare_raw,
        pins_dir=Path(pins_dir),
        materialize_dest=Path(materialize_dest),
        root=Path(root),
        envelope_dest=Path(envelope_dest),
        diagnostic_sink=diagnostic_sink,
        # Explicit: the driver has no default profile; the closed rail selects one.
        execution_profile=rail.execution_profile,
        contract=rail.measurement,
    )


def candidate_result_schema(rail) -> str:
    """The one spelling of a rail's v1 candidate-result schema."""
    return "corpus-adequacy.%s.candidate-result.v1" % require_rail(rail).name


def safe_candidate_projection(report, loaded, *, bindings, rail=LEGACY_RAIL) -> dict:
    """Publish only run validity and declared candidate outcomes; never raw host observations.

    On the external rail the projection is reduced (`EXTERNAL_CANDIDATE_KEYS`): no `adequate`,
    and its `decision` is only a placeholder that the gate replaces with the envelope decision.
    """
    rail = require_rail(rail)
    if type(report) is not dict:
        raise HostedPublicationError("candidate_report")
    count_keys = ("killed", "survived", "silent", "equivalent",
                  "unexercised_out_of_scope", "unproved", "known_holes")
    if report.get("schema") != ca.REPORT_SCHEMA:
        raise HostedPublicationError("candidate_report")
    if any(type(report.get(key)) is not int or report[key] < 0 for key in count_keys):
        raise HostedPublicationError("candidate_report_counts")
    if (type(report.get("failures")) is not list
            or report.get("adequate") is not (not report["failures"])):
        raise HostedPublicationError("candidate_report_adequate")
    if report.get("declared_total") != sum(report[key] for key in count_keys):
        raise HostedPublicationError("candidate_report_total")
    if report.get("control_status") not in (
            "killed", "survived", "moved", "error", "absent-or-invalid"):
        raise HostedPublicationError("candidate_report_control")
    if type(loaded) is not dict or type(loaded.get("index")) is not dict:
        raise HostedPublicationError("candidate_collection")
    try:
        report_sha256 = hashlib.sha256(ca.encode_report_v0(report)).hexdigest()
    except (TypeError, ValueError, ca.ReportEncodingError) as exc:
        raise HostedPublicationError("candidate_report") from exc
    if loaded["index"].get("report_sha256") != report_sha256:
        raise HostedPublicationError("candidate_report_binding")
    members = loaded.get("members")
    entries = loaded["index"].get("members")
    if type(members) is not list or type(entries) is not list or len(entries) != len(members):
        raise HostedPublicationError("candidate_collection")
    outcomes = []
    for entry, member in zip(entries, members):
        ordinal = entry.get("ordinal") if type(entry) is dict else None
        if (type(ordinal) is not int or ordinal < 0 or type(member) is not dict
                or type(member.get("candidate_outcome")) is not str):
            raise HostedPublicationError("candidate_outcome")
        outcomes.append({"ordinal": ordinal,
                         "candidate_outcome": member["candidate_outcome"]})
    publishable = (report["control_status"] == "killed"
                   and report["unproved"] == 0 and report["adequate"] is True)
    result = {
        "schema": candidate_result_schema(rail),
        "kind": "hosted-candidate-result",
        "decision": "publish" if publishable else "withhold",
        "score_status": "none",
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "report_sha256": report_sha256,
        "control_status": report["control_status"],
        "unproved": report["unproved"],
        "adequate": report["adequate"],
        "outcomes": outcomes,
        "non_claims": list(NON_CLAIMS),
    }
    if rail is LEGACY_RAIL:
        del result["adequate"]
        result["decision"] = "withhold"
    return result


def _record_cleanup_failure(rerun_log, primary_reason, cleanup_exc, identity, bindings) -> None:
    """Append the cleanup failure as its own distinguished evidence, never as the outcome."""
    try:
        append_rerun_evidence(rerun_log, {
            "kind": RERUN_KIND_CLEANUP_FAILED,
            "reason": primary_reason,
            "cleanup_error_type": type(cleanup_exc).__name__,
            "bindings": bindings,
            "dispatch_bindings": bindings,
            "run_id": identity.get("run_id") if type(identity) is dict else None,
            "run_attempt": identity.get("run_attempt") if type(identity) is dict else None,
        })
    except BaseException:
        # Evidence appending is best-effort here; it must never mask the primary refusal.
        pass


def materialize_post_execute_refusal(*, out, reason, bindings, rerun_log,
                                         identity, max_artifact_bytes=MAX_ARTIFACT_BYTES,
                                         workflow_identity=None, rail=LEGACY_RAIL):
    """Overwrite success-shaped post-execute artifacts, then caller re-raises.

    Sealed execute may already have written a permitted/verified envelope.
    Replace it with withheld/void/refused documents and append distinguished
    rerun evidence so always() uploads never publish rejected success bytes.
    Does not convert refusal into success.
    """
    setup_doc = setup_status_doc(
        status="refused", reason=reason, bindings=bindings,
        workflow_identity=workflow_identity, rail=rail)
    envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
    candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    append_rerun_evidence(rerun_log, {
        "kind": RERUN_KIND_POST_EXECUTE,
        "reason": reason,
        "setup_status": "refused",
        "bindings": bindings,
        "dispatch_bindings": bindings,
        "run_id": identity.get("run_id"),
        "run_attempt": identity.get("run_attempt"),
    })
    finalize_nonpublish_attempt(
        out=out, setup_doc=setup_doc, candidate_doc=candidate_doc,
        decision="refuse", reason=reason, execute_began=True,
        identity=identity, workflow_identity=workflow_identity,
        bindings=bindings, rerun_log=rerun_log,
        max_artifact_bytes=max_artifact_bytes,
        envelope_doc=envelope_doc,
    )


def _materialize_void(*, out, reason, setup_status, bindings, rerun_log,
                      identity, max_artifact_bytes, kind="infrastructure-failure",
                      workflow_identity=None, rail=LEGACY_RAIL):
    decision = publication_decision(None, setup_status=setup_status)
    setup_doc = setup_status_doc(
        status=setup_status, reason=reason, bindings=bindings,
        workflow_identity=workflow_identity, rail=rail)
    candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    append_rerun_evidence(rerun_log, {
        "kind": kind,
        "reason": reason,
        "setup_status": setup_status,
        "bindings": bindings,
        "dispatch_bindings": bindings,
        "run_id": identity.get("run_id"),
        "run_attempt": identity.get("run_attempt"),
    })
    finalize_nonpublish_attempt(
        out=out, setup_doc=setup_doc, candidate_doc=candidate_doc,
        decision=decision["decision"], reason=reason, execute_began=False,
        identity=identity, workflow_identity=workflow_identity,
        bindings=bindings, rerun_log=rerun_log,
        max_artifact_bytes=max_artifact_bytes,
    )
    return decision


def run_gate(*, candidate_revision, runner_revision, image_digest,
             operator_profile, out_dir,
             packet_root=None, authorize_path=None, prepare_path=None,
             pins_dir=None, root=None, workspace_root=None, rerun_log=None,
             max_artifact_bytes=MAX_ARTIFACT_BYTES,
             max_input_bytes=MAX_INPUT_BYTES,
             docker_ready=None, sealed_execute=None,
             packet_manifest_sha256=None, environ=None, rail=LEGACY_RAIL) -> dict:
    rail = require_rail(rail)
    bindings = require_bindings(
        candidate_revision, runner_revision, image_digest)
    if operator_profile != rail.execution_profile:
        raise HostedPublicationError("operator_profile")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    envelope_dest = out / COLLECTION_DIRNAME
    # A report left by an earlier attempt in a reused out root is not this attempt's evidence.
    stale_report = out / REPORT_FILENAME
    if stale_report.is_symlink() or stale_report.is_file():
        stale_report.unlink()
    elif stale_report.exists():
        # Not a file this gate could have written; refuse before anything runs.
        raise HostedPublicationError("report_path_occupied")
    candidate_diagnostic_rows = []
    if rerun_log is None:
        rerun_log = out / RERUN_EVIDENCE_FILENAME
    else:
        rerun_log = Path(rerun_log)

    identity = _run_attempt_identity(environ)
    workflow_identity = observe_workflow_identity(environ)
    append_rerun_evidence(rerun_log, {
        "kind": RERUN_KIND_START,
        "bindings": bindings,
        "dispatch_bindings": bindings,
        "workflow_identity": dict(workflow_identity),
        "run_id": identity.get("run_id"),
        "run_attempt": identity.get("run_attempt"),
    })
    # Recorded above whatever it says; refused here before containment is even probed.
    check_workflow_identity(
        workflow_identity, runner_revision=bindings["runner_revision"])

    probe = docker_ready or default_docker_ready
    execute = sealed_execute or default_sealed_execute

    envelope = None
    report = None
    setup_status = "unavailable"
    reason = "containment-unavailable"

    try:
        probe()
    except contained.DockerUnavailable as exc:
        reason = "containment-unavailable:%s" % exc
        return _materialize_void(
            out=out, reason=reason, setup_status="unavailable",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes,
            workflow_identity=workflow_identity, rail=rail)
    except contained.PrepareError as exc:
        reason = "containment-refused:%s" % exc
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes,
            workflow_identity=workflow_identity, rail=rail)

    if not (packet_root and authorize_path and prepare_path and pins_dir):
        reason = "execution-packets-required"
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes,
            workflow_identity=workflow_identity, rail=rail)

    if workspace_root is None:
        workspace_root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    packet = resolve_packet_root(workspace_root, packet_root)
    packet_files = check_packet_manifest(
        packet, packet_manifest_sha256, max_bytes=max_input_bytes, rail=rail)
    load_dispatch_bindings(
        packet, expected=bindings, max_bytes=max_input_bytes, rail=rail)
    authorize_resolved = resolve_confined_input(
        packet, authorize_path, max_bytes=max_input_bytes)
    prepare_resolved = resolve_confined_input(
        packet, prepare_path, max_bytes=max_input_bytes)
    pins_resolved = resolve_confined_input(packet, pins_dir, max_bytes=None)
    try:
        prepare_raw = ca.read_bounded_regular_file(
            prepare_resolved, cap=max_input_bytes)
        authorize_raw = ca.read_bounded_regular_file(
            authorize_resolved, cap=max_input_bytes)
    except ca.ManifestError as exc:
        raise HostedPublicationError("max_input_bytes") from exc
    prepare_sha256 = hashlib.sha256(prepare_raw).hexdigest()
    # Every file matched some digest above; this binds each ROLE to its own, so the authorize
    # and prepare paths cannot be swapped between two files the manifest lists.
    if (prepare_sha256 != packet_files[rail.prepare_filename] or
            hashlib.sha256(authorize_raw).hexdigest()
            != packet_files[rail.authorize_filename]):
        raise HostedPublicationError("packet_role_binding")
    try:
        prepare_doc = json.loads(prepare_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HostedPublicationError("json_input") from exc
    check_prepare_bindings(prepare_doc, bindings=bindings)
    if rail is not LEGACY_RAIL:
        try:
            sealed_run.load_prepare_for_profile(
                prepare_raw, execution_profile=rail.execution_profile,
                contract=rail.measurement)
        except sealed_run.PrepareError as exc:
            raise HostedPublicationError("prepare_profile:%s" % exc) from exc

    materialize_dest = out / "materialize"
    execute_began = False
    try:
        execute_began = True
        report = execute(
            authorize_path=authorize_resolved,
            prepare_path=prepare_resolved,
            pins_dir=pins_resolved,
            root=root or _ROOT,
            envelope_dest=envelope_dest,
            diagnostic_sink=candidate_diagnostic_rows.append,
            materialize_dest=materialize_dest,
            max_bytes=max_input_bytes,
            **({"rail": rail} if sealed_execute is None else {}),
        )
        loaded = load_envelope_collection(envelope_dest, max_bytes=max_input_bytes)
        envelope = loaded
        # Every member is bound and observed. Checking one would let a hostile sibling ride along
        # behind a benign first record.
        for member in loaded["members"]:
            check_envelope_bindings(
                member, bindings=bindings, prepare_sha256=prepare_sha256,
                rail=rail)
            observed_child = observe_child_environment(member)
            refuse_hostile_workflow(
                env_names=observed_child["env_names"],
                mounts=observed_child["mounts"],
            )
        setup_status = "unavailable"
        if loaded["members"]:
            setup_status = loaded["members"][0].get("setup_status") or "unavailable"
        reason = "contained-execution"
    except HostedPublicationError as exc:
        if execute_began:
            try:
                materialize_post_execute_refusal(
                    out=out,
                    reason=str(exc),
                    bindings=bindings,
                    rerun_log=rerun_log,
                    identity=identity,
                    max_artifact_bytes=max_artifact_bytes,
                    workflow_identity=workflow_identity,
                    rail=rail,
                )
            except BaseException as cleanup_exc:
                # A sanitization failure must not replace the reason the run was refused: the
                # primary refusal is the finding, the cleanup failure is context on it. The
                # upload authorization does not depend on this succeeding -- the gate exits
                # nonzero either way, and the published collection is bound to gate success.
                _record_cleanup_failure(rerun_log, str(exc), cleanup_exc, identity, bindings)
                raise exc from cleanup_exc
        raise
    except Exception as exc:
        reason = "contained-execution-failed:%s" % exc
        setup_status = "unavailable"
        envelope = None
        append_rerun_evidence(rerun_log, {
            "kind": RERUN_KIND_INFRA,
            "reason": reason,
            "setup_status": setup_status,
            "bindings": bindings,
            "dispatch_bindings": bindings,
            "run_id": identity.get("run_id"),
            "run_attempt": identity.get("run_attempt"),
        })

    # Quantified over every member. `publication_decision` stays the one rule; this only
    # applies it universally, so a later member cannot rescue an earlier one.
    decision = collection_publication_decision(envelope, setup_status=setup_status)
    safe_projection = None
    if rail is LEGACY_RAIL and envelope is not None and decision["decision"] != "unavailable":
        # The external rail publishes only with a bound report (#184). No report on a publish
        # decision, or a report that does not bind to the collection, is a named post-execute
        # refusal, never the historical unbound document. A withheld run without a report keeps
        # its void result: it publishes nothing either way.
        try:
            if report is None and decision["decision"] == "publish":
                raise HostedPublicationError("candidate_report_absent")
            if report is not None:
                safe_projection = safe_candidate_projection(
                    report, envelope, bindings=bindings, rail=rail)
                safe_projection["decision"] = (
                    "publish" if decision["decision"] == "publish" else "withhold")
        except HostedPublicationError as exc:
            try:
                materialize_post_execute_refusal(
                    out=out, reason=str(exc), bindings=bindings, rerun_log=rerun_log,
                    identity=identity, max_artifact_bytes=max_artifact_bytes,
                    workflow_identity=workflow_identity, rail=rail)
            except BaseException as cleanup_exc:
                _record_cleanup_failure(rerun_log, str(exc), cleanup_exc, identity, bindings)
                raise exc from cleanup_exc
            raise
    if rail is not LEGACY_RAIL and envelope is not None:
        safe_projection = safe_candidate_projection(
            report, envelope, bindings=bindings, rail=rail)
        if (decision["decision"] != "publish"
                or safe_projection["decision"] != "publish"):
            safe_projection["decision"] = "withhold"
            decision = dict(decision)
            decision["decision"] = "withhold"
            decision["score_status"] = "none"

    if decision["decision"] == "unavailable":
        setup_doc = setup_status_doc(
            status=setup_status if setup_status in ("unavailable", "refused")
            else "unavailable",
            reason=reason,
            bindings=bindings,
            workflow_identity=workflow_identity, rail=rail,
        )
        candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
        finalize_nonpublish_attempt(
            out=out, setup_doc=setup_doc, candidate_doc=candidate_doc,
            decision="unavailable", reason=reason, execute_began=execute_began,
            identity=identity, workflow_identity=workflow_identity,
            bindings=bindings, rerun_log=rerun_log,
            max_artifact_bytes=max_artifact_bytes)
        return decision
    if decision["decision"] == "withhold":
        withheld_reason = "publication-withheld"
        setup_doc = setup_status_doc(
            status="ready" if setup_status == "ready" else setup_status,
            reason=withheld_reason,
            bindings=bindings,
            workflow_identity=workflow_identity, rail=rail)
        candidate_doc = (safe_projection if safe_projection is not None
                         else void_candidate_result(
                             reason=withheld_reason, bindings=bindings))
        finalize_nonpublish_attempt(
            out=out, setup_doc=setup_doc, candidate_doc=candidate_doc,
            decision="withhold", reason=withheld_reason, execute_began=execute_began,
            identity=identity, workflow_identity=workflow_identity,
            bindings=bindings, rerun_log=rerun_log,
            max_artifact_bytes=max_artifact_bytes,
            candidate_diagnostic_rows=(candidate_diagnostic_rows or None))
        return decision
    setup_doc = setup_status_doc(
        status="ready", reason="publication-permitted", bindings=bindings,
        workflow_identity=workflow_identity, rail=rail)
    # The collection directory is the authoritative artifact. Writing a derived aggregate
    # to the legacy single-envelope path would be a second, weaker authority for the same
    # facts, so nothing is written there on the success path.
    envelope_doc = None
    if safe_projection is None:
        # Unreachable on either rail: both refuse a publish decision without a bound report.
        raise HostedPublicationError("candidate_report_absent")
    candidate_doc = safe_projection
    report_raw = None
    if rail is OWNED_V1_RAIL:
        try:
            report_raw = owned_report_bytes(
                report, report_sha256=safe_projection["report_sha256"],
                max_bytes=max_artifact_bytes)
        except HostedPublicationError as exc:
            try:
                materialize_post_execute_refusal(
                    out=out, reason=str(exc), bindings=bindings, rerun_log=rerun_log,
                    identity=identity, max_artifact_bytes=max_artifact_bytes,
                    workflow_identity=workflow_identity, rail=rail)
            except BaseException as cleanup_exc:
                _record_cleanup_failure(rerun_log, str(exc), cleanup_exc, identity, bindings)
                raise exc from cleanup_exc
            raise
    write_separate_artifacts(
        out, setup_doc, envelope_doc, candidate_doc,
        max_bytes=max_artifact_bytes,
    )
    if report_raw is not None:
        (out / REPORT_FILENAME).write_bytes(report_raw)
    append_rerun_evidence(rerun_log, _terminal_event({
        "kind": RERUN_KIND_TERMINAL,
        "decision": "publish",
        "reason": "publication-permitted",
        "collection_state": COLLECTION_PRESENT,
        "diagnostic_package_sha256": None,
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "run_id": identity["run_id"],
        "run_attempt": identity["run_attempt"],
    }))
    return decision


def owned_report_bytes(report, *, report_sha256, max_bytes=MAX_ARTIFACT_BYTES) -> bytes:
    """The published report's bytes: canonical, bounded, and the ones the digest names."""
    try:
        raw = ca.encode_report_v0(report)
        reparsed = json.loads(raw.decode("utf-8"))
        canonical = ca.encode_report_v0(reparsed) == raw
    except (TypeError, ValueError, ca.ReportEncodingError) as exc:
        raise HostedPublicationError("report_bytes") from exc
    if not canonical:
        raise HostedPublicationError("report_round_trip")
    if len(raw) > max_bytes:
        raise HostedPublicationError("max_artifact_bytes")
    if hashlib.sha256(raw).hexdigest() != report_sha256:
        raise HostedPublicationError("report_sha256")
    return raw


def load_published_report(path, *, candidate, report_sha256,
                          max_bytes: int = MAX_INPUT_BYTES) -> dict:
    """Offline check of downloaded report bytes against the attempt that published them.

    The bytes must be exactly canonical report.v0, hash to the collection's digest and to the
    digest the candidate result carries, and agree with every run-validity fact the candidate
    result states. A candidate result that carries no digest has nothing to bind a report to.
    """
    if type(candidate) is not dict or candidate.get("report_sha256") is None:
        raise HostedPublicationError("report_unbound")
    try:
        raw = ca.read_bounded_regular_file(Path(path), cap=max_bytes)
    except ca.ManifestError as exc:
        raise HostedPublicationError("report_bytes") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HostedPublicationError("report_bytes") from exc
    if type(doc) is not dict or doc.get("schema") != ca.REPORT_SCHEMA:
        raise HostedPublicationError("report_bytes")
    try:
        canonical = ca.encode_report_v0(doc) == raw
    except (TypeError, ValueError, ca.ReportEncodingError) as exc:
        raise HostedPublicationError("report_bytes") from exc
    if not canonical:
        raise HostedPublicationError("report_round_trip")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != report_sha256 or digest != candidate["report_sha256"]:
        raise HostedPublicationError("report_sha256")
    for key in ("control_status", "unproved", "adequate"):
        if key in candidate and doc.get(key) != candidate[key]:
            raise HostedPublicationError("report_fact:%s" % key)
    return {"report": "verified", "report_sha256": digest}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contained_hosted_publication",
        description="Hosted contained publication gate (#107)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="Execute contained lane and gate publication")
    gate.add_argument("--candidate-revision", required=True)
    gate.add_argument("--runner-revision", required=True)
    gate.add_argument("--image-digest", required=True)
    gate.add_argument("--packet-manifest-sha256", default=None)
    gate.add_argument("--operator-profile", default=REQUIRED_PROFILE)
    gate.add_argument("--out", required=True)
    gate.add_argument("--packet-root", default=None)
    gate.add_argument("--authorize", default=None)
    gate.add_argument("--prepare", default=None)
    gate.add_argument("--pins-dir", default=None)
    gate.add_argument("--root", default=None)
    gate.add_argument("--workspace-root", default=None)
    gate.add_argument("--rerun-log", default=None)
    gate.add_argument(
        "--max-artifact-bytes", type=int, default=MAX_ARTIFACT_BYTES)
    gate.add_argument(
        "--max-input-bytes", type=int, default=MAX_INPUT_BYTES)

    readback = sub.add_parser(
        "readback",
        help="Validate downloaded hosted-attempt artifacts without executing",
    )
    readback.add_argument("--setup", required=True)
    readback.add_argument("--candidate", required=True)
    readback.add_argument("--rerun", required=True)
    source = readback.add_mutually_exclusive_group(required=True)
    source.add_argument("--diagnostic")
    source.add_argument("--collection")
    # Only a published attempt has report bytes to check (#186).
    readback.add_argument("--report", default=None)
    readback.add_argument("--candidate-revision", required=True)
    readback.add_argument("--runner-revision", required=True)
    readback.add_argument("--image-digest", required=True)
    readback.add_argument("--run-id", required=True)
    readback.add_argument("--run-attempt", required=True)
    # The sealed `attempt-statement.v0/` directory, when the reader downloaded it. Checked
    # offline against the same files; the signature is `gh attestation verify`'s to check.
    readback.add_argument("--statement", default=None)
    seal = sub.add_parser(
        "seal",
        help="Seal the attempt's upload surface into an unsigned in-toto statement (#187)")
    seal.add_argument("--out", required=True)
    seal.add_argument("--rail", default=LEGACY_RAIL.name)
    seal.add_argument("--candidate-revision", required=True)
    seal.add_argument("--runner-revision", required=True)
    seal.add_argument("--image-digest", required=True)
    seal.add_argument("--packet-release-tag", required=True)
    seal.add_argument("--packet-manifest-sha256", required=True)
    seal.add_argument("--gate-outcome", required=True)
    return parser


def seal_attempt_statement(*, out_dir, rail, bindings, packet_release_tag,
                           packet_manifest_sha256, gate_outcome, environ=None) -> dict:
    """Seal whatever the gate left on the upload surface; run after the gate, on any outcome.

    Identity comes from the runner's own environment, as the gate reads it, never from a
    workflow-supplied value. A rail name outside the closed set refuses.
    """
    rails = {LEGACY_RAIL.name: LEGACY_RAIL, OWNED_V1_RAIL.name: OWNED_V1_RAIL}
    if rail not in rails:
        raise HostedPublicationError("statement:rail")
    rail_contract = require_rail(rails[rail])
    identity = _run_attempt_identity(environ)
    workflow_identity = observe_workflow_identity(environ)
    check_workflow_identity(workflow_identity, runner_revision=bindings["runner_revision"])
    dispatch_inputs = dict(bindings)
    dispatch_inputs["packet_release_tag"] = packet_release_tag
    dispatch_inputs["packet_manifest_sha256"] = packet_manifest_sha256
    try:
        return attempt_statement.seal_attempt(
            out_dir=out_dir, rail=rail_contract.name, bindings=bindings,
            dispatch_inputs=dispatch_inputs, run_identity=identity,
            workflow_identity=workflow_identity, gate_outcome=gate_outcome)
    except attempt_statement.StatementError as exc:
        raise HostedPublicationError("statement:%s" % exc) from exc


def _statement_subject_files(*, setup_path, candidate_path, rerun_path,
                             diagnostic_dir=None, collection_dir=None) -> dict:
    """The reader's files under the names the seal used: upload-surface-relative paths."""
    files = {
        SETUP_STATUS_FILENAME: Path(setup_path),
        CANDIDATE_RESULT_FILENAME: Path(candidate_path),
        RERUN_EVIDENCE_FILENAME: Path(rerun_path),
    }
    for dirname, root in ((COLLECTION_DIRNAME, collection_dir),
                          (DIAGNOSTIC_DIRNAME, diagnostic_dir)):
        if root is None:
            continue
        root = Path(root)
        for path in sorted(root.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            files["%s/%s" % (dirname, path.relative_to(root).as_posix())] = path
    return files


def readback_statement(statement_dir, *, setup_path, candidate_path, rerun_path,
                       diagnostic_dir=None, collection_dir=None, expected_bindings,
                       expected_run_id, expected_run_attempt) -> dict:
    """Offline check of the unsigned statement against the reader's own downloaded files."""
    try:
        loaded = attempt_statement.load_statement_dir(statement_dir)
        return attempt_statement.check_statement_against_files(
            loaded,
            _statement_subject_files(
                setup_path=setup_path, candidate_path=candidate_path,
                rerun_path=rerun_path, diagnostic_dir=diagnostic_dir,
                collection_dir=collection_dir),
            bindings=expected_bindings,
            run_identity={"run_id": expected_run_id, "run_attempt": expected_run_attempt})
    except attempt_statement.StatementError as exc:
        raise HostedPublicationError("statement:%s" % exc) from exc


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "readback":
            loaded = load_hosted_attempt_artifacts(
                setup_path=args.setup,
                candidate_path=args.candidate,
                rerun_path=args.rerun,
                diagnostic_dir=args.diagnostic,
                collection_dir=args.collection,
                expected_bindings=require_bindings(
                    args.candidate_revision, args.runner_revision, args.image_digest),
                expected_run_id=args.run_id,
                expected_run_attempt=args.run_attempt,
            )
            summary = _readback_summary(loaded["projection"])
            summary["candidate_result_schema"] = loaded["candidate"]["schema"]
            summary["report"] = "not-provided"
            if args.report is not None:
                if loaded["projection"].get("decision") != "publish":
                    raise HostedPublicationError("report_not_published")
                summary.update(load_published_report(
                    args.report, candidate=loaded["candidate"],
                    report_sha256=loaded["projection"]["report_sha256"]))
            summary["statement"] = "not-provided"
            if args.statement is not None:
                summary.update(readback_statement(
                    args.statement,
                    setup_path=args.setup, candidate_path=args.candidate,
                    rerun_path=args.rerun, diagnostic_dir=args.diagnostic,
                    collection_dir=args.collection,
                    expected_bindings=require_bindings(
                        args.candidate_revision, args.runner_revision, args.image_digest),
                    expected_run_id=args.run_id,
                    expected_run_attempt=args.run_attempt))
            sys.stdout.write(_encode_json(summary).decode("utf-8"))
            return 0
        if args.command == "seal":
            sealed = seal_attempt_statement(
                out_dir=args.out, rail=args.rail,
                bindings=require_bindings(
                    args.candidate_revision, args.runner_revision, args.image_digest),
                packet_release_tag=args.packet_release_tag,
                packet_manifest_sha256=args.packet_manifest_sha256,
                gate_outcome=args.gate_outcome)
            sys.stdout.write(_encode_json(sealed).decode("utf-8"))
            return 0
        if args.command != "gate":
            parser.error("unsupported command")
        decision = run_gate(
            candidate_revision=args.candidate_revision,
            runner_revision=args.runner_revision,
            image_digest=args.image_digest,
            operator_profile=args.operator_profile,
            out_dir=args.out,
            packet_root=args.packet_root,
            authorize_path=args.authorize,
            prepare_path=args.prepare,
            pins_dir=args.pins_dir,
            root=args.root,
            workspace_root=args.workspace_root,
            rerun_log=args.rerun_log,
            max_artifact_bytes=args.max_artifact_bytes,
            max_input_bytes=args.max_input_bytes,
            packet_manifest_sha256=args.packet_manifest_sha256,
        )
    except HostedPublicationError as exc:
        print("hosted publication refused: %s" % exc, file=sys.stderr)
        return 2
    # The workflow uploads the collection only when this step succeeds, so success must mean
    # publication is permitted. A withheld or unavailable run has already written its stubs
    # and moved its collection out of the upload path; it exits 3, never 0. Anything but an
    # explicit publish decision is not permitted.
    outcome = decision.get("decision") if type(decision) is dict else None
    if outcome != "publish":
        shown = outcome if type(outcome) is str and outcome else "no decision"
        print("hosted publication not permitted: %s" % shown, file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
