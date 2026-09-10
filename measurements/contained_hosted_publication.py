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
import envelope_collection as collection  # noqa: E402
import effective_envelope  # noqa: E402
import hosted_packet as packet_delivery  # noqa: E402
from aee_checker_sealed_candidate import (  # noqa: E402
    CANDIDATE_MOUNT_SPEC,
    require_candidate_image,
)

REQUIRED_PROFILE = "contained-oci-v0"
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
CANDIDATE_RESULT_FILENAME = "candidate-result.json"
RERUN_EVIDENCE_FILENAME = "rerun-evidence.jsonl"
# One name for the bindings file: the packet module's closed file-name set carries it.
DISPATCH_BINDINGS_FILENAME = packet_delivery.BINDINGS_FILENAME
CONCURRENCY_GROUP = "contained-hosted-publication"
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


def check_packet_manifest(packet, expected_sha256, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    """Bind the packet under `packet` to the dispatched manifest digest, in the gate itself.

    The manifest's digest is compared before it is parsed; parsing is the packet module's one
    rule; the packet directory must hold exactly the listed files, the manifest and the pins
    directory; and each listed file is read as a confined regular file and held to its digest.
    Returns {file name: sha256}.
    """
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or
            any(ch not in "0123456789abcdef" for ch in expected_sha256)):
        raise HostedPublicationError("packet_manifest_sha256")
    manifest_path = resolve_confined_input(
        packet, packet_delivery.MANIFEST_FILENAME,
        max_bytes=packet_delivery.MAX_MANIFEST_BYTES)
    try:
        manifest_raw = ca.read_bounded_regular_file(
            manifest_path, cap=packet_delivery.MAX_MANIFEST_BYTES)
    except ca.ManifestError as exc:
        raise HostedPublicationError("max_input_bytes") from exc
    if hashlib.sha256(manifest_raw).hexdigest() != expected_sha256:
        raise HostedPublicationError("packet_manifest_binding")
    try:
        files = packet_delivery.parse_manifest(manifest_raw)
    except packet_delivery.PacketError as exc:
        raise HostedPublicationError("packet_manifest:%s" % exc) from exc
    if tuple(sorted(os.listdir(packet))) != packet_delivery.PACKET_ENTRIES:
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


def load_json_confined(root, relpath, *, max_bytes: int):
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
                           max_bytes: int = MAX_INPUT_BYTES) -> dict:
    doc = load_json_confined(
        packet_root, DISPATCH_BINDINGS_FILENAME, max_bytes=max_bytes)
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


def check_envelope_bindings(envelope_doc, *, bindings, prepare_sha256) -> None:
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
    if requested.get("execution_profile") != REQUIRED_PROFILE:
        raise HostedPublicationError("execution_profile_binding")
    if requested.get("sealed") is not True:
        raise HostedPublicationError("sealed_binding")
    if requested.get("resource_profile") != contained.CANDIDATE_RESOURCE_PROFILE:
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
                             *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict:
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
        # A withheld/refused stub at the legacy path and a live collection on the upload surface
        # must never coexist: the stub says the run was refused while the uploaded directory
        # still carries permitted, verified members -- the exact bytes the refusal rejected.
        # Sanitizing the legacy file alone stopped being sufficient when the upload was
        # retargeted at the collection. The observations are moved, not rewritten, so nothing
        # honest is lost and nothing publishable survives.
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


def setup_status_doc(*, status, reason, bindings, workflow_identity=None) -> dict:
    return {
        "schema": HOSTED_SCHEMA,
        "kind": "setup-status",
        "setup_status": status,
        "reason": reason,
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "operator_profile": REQUIRED_PROFILE,
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


def _run_attempt_identity() -> dict:
    return {
        "run_id": os.environ.get("GITHUB_RUN_ID") or os.environ.get("HOSTED_RUN_ID"),
        "run_attempt": (
            os.environ.get("GITHUB_RUN_ATTEMPT")
            or os.environ.get("HOSTED_RUN_ATTEMPT")),
    }


def default_docker_ready() -> str:
    return contained.require_docker_ready()


def default_sealed_execute(*, authorize_path, prepare_path, pins_dir, root,
                           envelope_dest, materialize_dest,
                           max_bytes: int = MAX_INPUT_BYTES) -> None:
    import aee_checker_sealed_driver as driver
    authorize_raw = ca.read_bounded_regular_file(
        Path(authorize_path), cap=max_bytes)
    prepare_raw = ca.read_bounded_regular_file(
        Path(prepare_path), cap=max_bytes)
    driver.run_authorized(
        authorize_raw=authorize_raw,
        prepare_raw=prepare_raw,
        pins_dir=Path(pins_dir),
        materialize_dest=Path(materialize_dest),
        root=Path(root),
        envelope_dest=Path(envelope_dest),
        # Explicit: the driver has no default profile, and this lane stays v0 (#107).
        execution_profile=REQUIRED_PROFILE,
    )


def _record_cleanup_failure(rerun_log, primary_reason, cleanup_exc, identity, bindings) -> None:
    """Append the cleanup failure as its own distinguished evidence, never as the outcome."""
    try:
        append_rerun_evidence(rerun_log, {
            "kind": "post-execute-refusal-cleanup-failed",
            "reason": primary_reason,
            "cleanup_error_type": type(cleanup_exc).__name__,
            "bindings": bindings,
            "dispatch_bindings": bindings,
            **{k: v for k, v in identity.items() if v is not None},
        })
    except BaseException:
        # Evidence appending is best-effort here; it must never mask the primary refusal.
        pass


def materialize_post_execute_refusal(*, out, reason, bindings, rerun_log,
                                         identity, max_artifact_bytes=MAX_ARTIFACT_BYTES,
                                         workflow_identity=None):
    """Overwrite success-shaped post-execute artifacts, then caller re-raises.

    Sealed execute may already have written a permitted/verified envelope.
    Replace it with withheld/void/refused documents and append distinguished
    rerun evidence so always() uploads never publish rejected success bytes.
    Does not convert refusal into success.
    """
    setup_doc = setup_status_doc(
        status="refused", reason=reason, bindings=bindings,
        workflow_identity=workflow_identity)
    envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
    candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    append_rerun_evidence(rerun_log, {
        "kind": "post-execute-refusal",
        "reason": reason,
        "setup_status": "refused",
        "bindings": bindings,
        "dispatch_bindings": bindings,
        **{k: v for k, v in identity.items() if v is not None},
    })
    write_separate_artifacts(
        out, setup_doc, envelope_doc, candidate_doc,
        max_bytes=max_artifact_bytes)


def _materialize_void(*, out, reason, setup_status, bindings, rerun_log,
                      identity, max_artifact_bytes, kind="infrastructure-failure",
                      workflow_identity=None):
    decision = publication_decision(None, setup_status=setup_status)
    setup_doc = setup_status_doc(
        status=setup_status, reason=reason, bindings=bindings,
        workflow_identity=workflow_identity)
    envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
    candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    append_rerun_evidence(rerun_log, {
        "kind": kind,
        "reason": reason,
        "setup_status": setup_status,
        "bindings": bindings,
        "dispatch_bindings": bindings,
        **{k: v for k, v in identity.items() if v is not None},
    })
    write_separate_artifacts(
        out, setup_doc, envelope_doc, candidate_doc,
        max_bytes=max_artifact_bytes)
    return decision


def run_gate(*, candidate_revision, runner_revision, image_digest,
             operator_profile, out_dir,
             packet_root=None, authorize_path=None, prepare_path=None,
             pins_dir=None, root=None, workspace_root=None, rerun_log=None,
             max_artifact_bytes=MAX_ARTIFACT_BYTES,
             max_input_bytes=MAX_INPUT_BYTES,
             docker_ready=None, sealed_execute=None,
             packet_manifest_sha256=None, environ=None) -> dict:
    bindings = require_bindings(
        candidate_revision, runner_revision, image_digest)
    require_operator_profile(operator_profile)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    envelope_dest = out / COLLECTION_DIRNAME
    if rerun_log is None:
        rerun_log = out / RERUN_EVIDENCE_FILENAME
    else:
        rerun_log = Path(rerun_log)

    identity = _run_attempt_identity()
    workflow_identity = observe_workflow_identity(environ)
    append_rerun_evidence(rerun_log, {
        "kind": "run-attempt-start",
        "bindings": bindings,
        "dispatch_bindings": bindings,
        "workflow_identity": dict(workflow_identity),
        **{k: v for k, v in identity.items() if v is not None},
    })
    # Recorded above whatever it says; refused here before containment is even probed.
    check_workflow_identity(
        workflow_identity, runner_revision=bindings["runner_revision"])

    probe = docker_ready or default_docker_ready
    execute = sealed_execute or default_sealed_execute

    envelope = None
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
            workflow_identity=workflow_identity)
    except contained.PrepareError as exc:
        reason = "containment-refused:%s" % exc
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes,
            workflow_identity=workflow_identity)

    if not (packet_root and authorize_path and prepare_path and pins_dir):
        reason = "execution-packets-required"
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes,
            workflow_identity=workflow_identity)

    if workspace_root is None:
        workspace_root = os.environ.get("GITHUB_WORKSPACE") or os.getcwd()
    packet = resolve_packet_root(workspace_root, packet_root)
    packet_files = check_packet_manifest(
        packet, packet_manifest_sha256, max_bytes=max_input_bytes)
    load_dispatch_bindings(
        packet, expected=bindings, max_bytes=max_input_bytes)
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
    if (prepare_sha256 != packet_files[packet_delivery.PREPARE_FILENAME] or
            hashlib.sha256(authorize_raw).hexdigest()
            != packet_files[packet_delivery.AUTHORIZE_FILENAME]):
        raise HostedPublicationError("packet_role_binding")
    try:
        prepare_doc = json.loads(prepare_raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise HostedPublicationError("json_input") from exc
    check_prepare_bindings(prepare_doc, bindings=bindings)

    materialize_dest = out / "materialize"
    execute_began = False
    try:
        execute_began = True
        execute(
            authorize_path=authorize_resolved,
            prepare_path=prepare_resolved,
            pins_dir=pins_resolved,
            root=root or _ROOT,
            envelope_dest=envelope_dest,
            materialize_dest=materialize_dest,
            max_bytes=max_input_bytes,
        )
        loaded = load_envelope_collection(envelope_dest, max_bytes=max_input_bytes)
        envelope = loaded
        # Every member is bound and observed. Checking one would let a hostile sibling ride along
        # behind a benign first record.
        for member in loaded["members"]:
            check_envelope_bindings(
                member, bindings=bindings, prepare_sha256=prepare_sha256)
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
            "kind": "infrastructure-failure",
            "reason": reason,
            "setup_status": setup_status,
            "bindings": bindings,
            "dispatch_bindings": bindings,
            **{k: v for k, v in identity.items() if v is not None},
        })

    # Quantified over every member. `publication_decision` stays the one rule; this only
    # applies it universally, so a later member cannot rescue an earlier one.
    decision = collection_publication_decision(envelope, setup_status=setup_status)

    if decision["decision"] == "unavailable":
        setup_doc = setup_status_doc(
            status=setup_status if setup_status in ("unavailable", "refused")
            else "unavailable",
            reason=reason,
            bindings=bindings,
            workflow_identity=workflow_identity,
        )
        envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
        candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    elif decision["decision"] == "withhold":
        setup_doc = setup_status_doc(
            status="ready" if setup_status == "ready" else setup_status,
            reason="publication-withheld",
            bindings=bindings,
            workflow_identity=workflow_identity)
        envelope_doc = withheld_envelope_stub(
            reason="publication-withheld", bindings=bindings)
        candidate_doc = void_candidate_result(
            reason="publication-withheld", bindings=bindings)
    else:
        setup_doc = setup_status_doc(
            status="ready", reason="publication-permitted", bindings=bindings,
            workflow_identity=workflow_identity)
        # The collection directory is the authoritative artifact. Writing a derived aggregate
        # to the legacy single-envelope path would be a second, weaker authority for the same
        # facts, so nothing is written there on the success path.
        envelope_doc = None
        candidate_doc = {
            "schema": HOSTED_SCHEMA,
            "kind": "hosted-candidate-result",
            "score_status": "none",
            "decision": "publish",
            "bindings": dict(bindings),
            "dispatch_bindings": dict(bindings),
            "non_claims": list(NON_CLAIMS),
        }

    write_separate_artifacts(
        out, setup_doc, envelope_doc, candidate_doc,
        max_bytes=max_artifact_bytes,
    )
    return decision


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
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command != "gate":
            parser.error("unsupported command")
        run_gate(
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
