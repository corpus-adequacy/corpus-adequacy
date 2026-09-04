#!/usr/bin/env python3
"""Hosted contained publication gate (#107).

Enforces #106 `publication_permission` and attempts a real contained-oci-v0
execution via existing primitives. Does not reimplement the OCI projector or
comparator. Does not score, authenticate, endorse, audit, certify, or claim
escape-proof OCI.

Dispatch bindings (candidate_revision, runner_revision, image_digest) are
sealed into the execution contract: a packet-root bindings file must match,
prepare.execution.commit and the produced envelope must match runner/image,
and setup/candidate artifacts stamp the effective bindings. Authorize,
prepare, pins, envelope and related JSON inputs resolve only as confined
regular files under a declared root with byte ceilings before parse.
Runtime hostility checks use observed runner.environment and an explicit
forwarded env-name list — not duplicated YAML literals.
"""

from __future__ import annotations

import argparse
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

REQUIRED_PROFILE = "contained-oci-v0"
REQUIRED_RUNNER_ENVIRONMENT = "github-hosted"
ARTIFACT_SETUP = "setup"
ARTIFACT_ENVELOPE = "effective-envelope"
ARTIFACT_CANDIDATE = "candidate-result"
ARTIFACT_RERUN = "rerun-evidence"
SETUP_STATUS_FILENAME = "setup-status.json"
EFFECTIVE_ENVELOPE_FILENAME = "effective-envelope.v0.json"
CANDIDATE_RESULT_FILENAME = "candidate-result.json"
RERUN_EVIDENCE_FILENAME = "rerun-evidence.jsonl"
DISPATCH_BINDINGS_FILENAME = "hosted-dispatch-bindings.v0.json"
CONCURRENCY_GROUP = "contained-hosted-publication"
CANCEL_IN_PROGRESS = False
RETENTION_DAYS = 14
MAX_ARTIFACT_BYTES = 5242880
MAX_INPUT_BYTES = MAX_ARTIFACT_BYTES
TIMEOUT_MINUTES = 15
RUNS_ON = "ubuntu-latest"
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
    is None, the leaf must be a non-symlink directory (pins tree).
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
        root_resolved = root_path.resolve(strict=True)
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
        resolved = current.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise HostedPublicationError("confined_path") from exc
    if resolved.is_symlink():
        raise HostedPublicationError("confined_path")

    if max_bytes is None:
        if not stat.S_ISDIR(st.st_mode):
            raise HostedPublicationError("confined_path")
        return current

    if not stat.S_ISREG(st.st_mode):
        raise HostedPublicationError("confined_path")
    if type(max_bytes) is not int or max_bytes < 0:
        raise HostedPublicationError("max_input_bytes")
    if st.st_size > max_bytes:
        raise HostedPublicationError("max_input_bytes")
    return current


def load_json_confined(root, relpath, *, max_bytes: int):
    """Size-check then read+parse JSON under a confined root (before loads)."""
    path = resolve_confined_input(root, relpath, max_bytes=max_bytes)
    try:
        raw = ca.read_bounded_regular_file(path, cap=max_bytes)
    except ca.ManifestError as exc:
        raise HostedPublicationError("max_input_bytes") from exc
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HostedPublicationError("json_input") from exc
    return doc


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
    if image.get("id") != bindings["image_digest"]:
        raise HostedPublicationError("image_digest_binding")


def check_envelope_bindings(envelope_doc, *, bindings) -> None:
    if type(envelope_doc) is not dict:
        raise HostedPublicationError("envelope_bindings")
    if envelope_doc.get("execution_commit") != bindings["runner_revision"]:
        raise HostedPublicationError("runner_revision_binding")
    requested = envelope_doc.get("requested")
    if type(requested) is not dict:
        raise HostedPublicationError("image_digest_binding")
    if requested.get("image_id") != bindings["image_digest"]:
        raise HostedPublicationError("image_digest_binding")


def observe_runtime_workflow(*, environ=None, mounts=None) -> dict:
    """Single producer of runtime workflow observations for refuse_*."""
    env = os.environ if environ is None else environ
    runner_environment = env.get("RUNNER_ENVIRONMENT")
    if not isinstance(runner_environment, str) or not runner_environment:
        raise HostedPublicationError("runner_environment")
    raw_names = env.get("HOSTED_FORWARDED_ENV_NAMES")
    if raw_names is None:
        raise HostedPublicationError("forwarded_env_names")
    if not isinstance(raw_names, str):
        raise HostedPublicationError("forwarded_env_names")
    forwarded_env_names = tuple(name for name in raw_names.split(",") if name)
    return {
        "runner_environment": runner_environment,
        "forwarded_env_names": forwarded_env_names,
        "mounts": list(mounts if mounts is not None else []),
    }


def refuse_hostile_workflow(*, runner_environment, forwarded_env_names,
                            mounts=()):
    """Refuse hostile runtime observations. None forwarded_env_names is error."""
    if runner_environment != REQUIRED_RUNNER_ENVIRONMENT:
        raise HostedPublicationError("runner_environment")
    if forwarded_env_names is None:
        raise HostedPublicationError("forwarded_env_names")
    if type(forwarded_env_names) not in (list, tuple):
        raise HostedPublicationError("forwarded_env_names")
    for name in forwarded_env_names:
        if _is_credential_env(name):
            raise HostedPublicationError("credential_env")
    if type(mounts) not in (list, tuple):
        raise HostedPublicationError("mounts")
    for mount in mounts:
        if not isinstance(mount, dict):
            raise HostedPublicationError("mounts")
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


def write_separate_artifacts(out_dir, setup_doc, envelope_doc, candidate_doc,
                             *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict:
    if setup_doc is None or envelope_doc is None or candidate_doc is None:
        raise HostedPublicationError("collapsed_artifacts")
    if (setup_doc is envelope_doc or setup_doc is candidate_doc or
            envelope_doc is candidate_doc):
        raise HostedPublicationError("collapsed_artifacts")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, doc in (
            (SETUP_STATUS_FILENAME, setup_doc),
            (EFFECTIVE_ENVELOPE_FILENAME, envelope_doc),
            (CANDIDATE_RESULT_FILENAME, candidate_doc),
    ):
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


def setup_status_doc(*, status, reason, bindings) -> dict:
    return {
        "schema": HOSTED_SCHEMA,
        "kind": "setup-status",
        "setup_status": status,
        "reason": reason,
        "bindings": dict(bindings),
        "dispatch_bindings": dict(bindings),
        "operator_profile": REQUIRED_PROFILE,
        "non_claims": list(NON_CLAIMS),
    }


def load_envelope(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> dict:
    """Load envelope with pre-parse ceiling; path must be a regular file."""
    path = Path(path)
    parent = path.parent
    return load_json_confined(parent, path.name, max_bytes=max_bytes)


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
    )


def _materialize_void(*, out, reason, setup_status, bindings, rerun_log,
                      identity, max_artifact_bytes, kind="infrastructure-failure"):
    decision = publication_decision(None, setup_status=setup_status)
    setup_doc = setup_status_doc(
        status=setup_status, reason=reason, bindings=bindings)
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
             pins_dir=None, root=None, rerun_log=None,
             max_artifact_bytes=MAX_ARTIFACT_BYTES,
             max_input_bytes=MAX_INPUT_BYTES,
             docker_ready=None, sealed_execute=None,
             runtime_environ=None) -> dict:
    bindings = require_bindings(
        candidate_revision, runner_revision, image_digest)
    require_operator_profile(operator_profile)

    observed = observe_runtime_workflow(environ=runtime_environ)
    refuse_hostile_workflow(
        runner_environment=observed["runner_environment"],
        forwarded_env_names=observed["forwarded_env_names"],
        mounts=observed["mounts"],
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    envelope_dest = out / EFFECTIVE_ENVELOPE_FILENAME
    if rerun_log is None:
        rerun_log = out / RERUN_EVIDENCE_FILENAME
    else:
        rerun_log = Path(rerun_log)

    identity = _run_attempt_identity()
    append_rerun_evidence(rerun_log, {
        "kind": "run-attempt-start",
        "bindings": bindings,
        "dispatch_bindings": bindings,
        **{k: v for k, v in identity.items() if v is not None},
    })

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
            max_artifact_bytes=max_artifact_bytes)
    except contained.PrepareError as exc:
        reason = "containment-refused:%s" % exc
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes)

    if not (packet_root and authorize_path and prepare_path and pins_dir):
        reason = "execution-packets-required"
        return _materialize_void(
            out=out, reason=reason, setup_status="refused",
            bindings=bindings, rerun_log=rerun_log, identity=identity,
            max_artifact_bytes=max_artifact_bytes)

    packet = Path(packet_root)
    load_dispatch_bindings(
        packet, expected=bindings, max_bytes=max_input_bytes)
    authorize_resolved = resolve_confined_input(
        packet, authorize_path, max_bytes=max_input_bytes)
    prepare_resolved = resolve_confined_input(
        packet, prepare_path, max_bytes=max_input_bytes)
    pins_resolved = resolve_confined_input(packet, pins_dir, max_bytes=None)
    prepare_doc = load_json_confined(
        packet, prepare_path, max_bytes=max_input_bytes)
    check_prepare_bindings(prepare_doc, bindings=bindings)

    materialize_dest = out / "materialize"
    try:
        execute(
            authorize_path=authorize_resolved,
            prepare_path=prepare_resolved,
            pins_dir=pins_resolved,
            root=root or _ROOT,
            envelope_dest=envelope_dest,
            materialize_dest=materialize_dest,
            max_bytes=max_input_bytes,
        )
        envelope = load_envelope(envelope_dest, max_bytes=max_input_bytes)
        check_envelope_bindings(envelope, bindings=bindings)
        setup_status = envelope.get("setup_status") or "unavailable"
        reason = "contained-execution"
    except HostedPublicationError:
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

    decision = publication_decision(envelope, setup_status=setup_status)

    if decision["decision"] == "unavailable":
        setup_doc = setup_status_doc(
            status=setup_status if setup_status in ("unavailable", "refused")
            else "unavailable",
            reason=reason,
            bindings=bindings,
        )
        envelope_doc = (
            envelope if envelope is not None
            else withheld_envelope_stub(reason=reason, bindings=bindings))
        candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
    elif decision["decision"] == "withhold":
        setup_doc = setup_status_doc(
            status="ready" if setup_status == "ready" else setup_status,
            reason="publication-withheld",
            bindings=bindings)
        envelope_doc = (
            envelope if envelope is not None
            else withheld_envelope_stub(
                reason="publication-withheld", bindings=bindings))
        candidate_doc = void_candidate_result(
            reason="publication-withheld", bindings=bindings)
    else:
        setup_doc = setup_status_doc(
            status="ready", reason="publication-permitted", bindings=bindings)
        # Envelope stays AEE schema as-is; bindings already verified above.
        envelope_doc = envelope
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
    gate.add_argument("--operator-profile", default=REQUIRED_PROFILE)
    gate.add_argument("--out", required=True)
    gate.add_argument("--packet-root", default=None)
    gate.add_argument("--authorize", default=None)
    gate.add_argument("--prepare", default=None)
    gate.add_argument("--pins-dir", default=None)
    gate.add_argument("--root", default=None)
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
            rerun_log=args.rerun_log,
            max_artifact_bytes=args.max_artifact_bytes,
            max_input_bytes=args.max_input_bytes,
        )
    except HostedPublicationError as exc:
        print("hosted publication refused: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
