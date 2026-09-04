#!/usr/bin/env python3
"""Hosted contained publication gate (#107).

Enforces #106 `publication_permission` in the hosted lane only. Reuses the
effective-envelope record and contained OCI image-id check; does not reimplement
the projector, comparator, or OCI internals. Does not score, authenticate,
endorse, audit, certify, or claim escape-proof OCI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import contained_oci as contained  # noqa: E402

REQUIRED_PROFILE = "contained-oci-v0"
ARTIFACT_SETUP = "setup"
ARTIFACT_ENVELOPE = "effective-envelope"
ARTIFACT_CANDIDATE = "candidate-result"
SETUP_STATUS_FILENAME = "setup-status.json"
EFFECTIVE_ENVELOPE_FILENAME = "effective-envelope.v0.json"
CANDIDATE_RESULT_FILENAME = "candidate-result.json"
CONCURRENCY_GROUP = "contained-hosted-publication"
CANCEL_IN_PROGRESS = False
RETENTION_DAYS = 14
MAX_ARTIFACT_BYTES = 5242880
TIMEOUT_MINUTES = 15
RUNS_ON = "ubuntu-latest"
HOSTED_SCHEMA = "corpus-adequacy.hosted-publication.v0"

HEX40 = frozenset("0123456789abcdef")
_CREDENTIAL_ENV_EXACT = frozenset({"GITHUB_TOKEN", "GH_TOKEN"})
_CREDENTIAL_ENV_PREFIXES = ("AWS_", "DOCKER_")
_CREDENTIAL_ENV_MARKERS = ("SECRET", "PASSWORD", "CREDENTIAL")
_HOSTILE_RUNNER_LABELS = frozenset({"self-hosted", "local"})

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
    """Bind candidate revision, runner revision, and image digest. Drop any → error."""
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


def _runner_labels(runs_on) -> set[str]:
    if isinstance(runs_on, str):
        return {runs_on}
    if isinstance(runs_on, (list, tuple)):
        return {str(item) for item in runs_on}
    raise HostedPublicationError("runs_on")


def refuse_hostile_workflow(*, runs_on, persist_credentials, mounts, env_names):
    """Refuse self-hosted/local, credential persistence, sock mounts, secrets."""
    labels = _runner_labels(runs_on)
    if labels != {RUNS_ON}:
        raise HostedPublicationError("runs_on")
    if labels & _HOSTILE_RUNNER_LABELS:
        raise HostedPublicationError("runs_on")
    if any(label.startswith("self-hosted") for label in labels):
        raise HostedPublicationError("runs_on")
    if persist_credentials is not False:
        raise HostedPublicationError("persist_credentials")
    if type(mounts) not in (list, tuple):
        raise HostedPublicationError("mounts")
    for mount in mounts:
        if not isinstance(mount, dict):
            raise HostedPublicationError("mounts")
        source = str(mount.get("source", "") or mount.get("Source", "") or "")
        destination = str(
            mount.get("destination", "") or mount.get("Destination", "") or "")
        joined = "%s:%s" % (source, destination)
        if "docker.sock" in source or "docker.sock" in destination or "docker.sock" in joined:
            raise HostedPublicationError("docker.sock")
        writable = mount.get("writable", mount.get("RW", mount.get("rw")))
        if writable is True:
            raise HostedPublicationError("writable_checkout")
    if type(env_names) not in (list, tuple):
        raise HostedPublicationError("env_names")
    for name in env_names:
        if _is_credential_env(name):
            raise HostedPublicationError("credential_env")
    return None


def publication_decision(envelope, *, setup_status) -> dict:
    """Gate publication on setup readiness and envelope publication_permission."""
    if setup_status != "ready":
        return {
            "decision": "unavailable",
            "score_status": "none",
            "setup_status": setup_status,
            "publication_permission": None,
        }
    permission = None
    if isinstance(envelope, dict):
        permission = envelope.get("publication_permission")
    if envelope is None or permission != "permitted":
        return {
            "decision": "withhold",
            "score_status": "none",
            "setup_status": setup_status,
            "publication_permission": permission,
        }
    return {
        "decision": "publish",
        "score_status": "none",
        "setup_status": setup_status,
        "publication_permission": permission,
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
        "non_claims": list(NON_CLAIMS),
    }


def _encode_json(doc) -> bytes:
    return (json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def write_separate_artifacts(out_dir, setup_doc, envelope_doc, candidate_doc,
                             *, max_bytes: int = MAX_ARTIFACT_BYTES) -> dict:
    """Write the three named artifacts. Refuse collapsing any required doc."""
    if setup_doc is None or envelope_doc is None or candidate_doc is None:
        raise HostedPublicationError("collapsed_artifacts")
    if setup_doc is envelope_doc or setup_doc is candidate_doc or envelope_doc is candidate_doc:
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
    """Append one JSONL evidence line. Never truncate an existing log."""
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
        "operator_profile": REQUIRED_PROFILE,
        "non_claims": list(NON_CLAIMS),
    }


def load_envelope(path: Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise HostedPublicationError("envelope") from exc
    if type(doc) is not dict:
        raise HostedPublicationError("envelope")
    return doc


def run_gate(*, candidate_revision, runner_revision, image_digest,
             operator_profile, out_dir, envelope_path=None,
             rerun_log=None, max_artifact_bytes=MAX_ARTIFACT_BYTES) -> dict:
    bindings = require_bindings(
        candidate_revision, runner_revision, image_digest)
    require_operator_profile(operator_profile)

    envelope = None
    setup_status = "unavailable"
    reason = "no-verified-envelope"
    if envelope_path is not None:
        envelope = load_envelope(envelope_path)
        setup_status = envelope.get("setup_status", "unavailable")
        if setup_status == "ready":
            reason = "envelope-loaded"
        else:
            reason = "setup-not-ready"

    decision = publication_decision(envelope, setup_status=setup_status)

    if decision["decision"] == "unavailable":
        setup_doc = setup_status_doc(
            status=setup_status if setup_status in ("unavailable", "refused")
            else "unavailable",
            reason=reason,
            bindings=bindings,
        )
        envelope_doc = withheld_envelope_stub(reason=reason, bindings=bindings)
        candidate_doc = void_candidate_result(reason=reason, bindings=bindings)
        if rerun_log is not None:
            append_rerun_evidence(rerun_log, {
                "kind": "infrastructure-failure",
                "reason": reason,
                "setup_status": setup_doc["setup_status"],
                "bindings": bindings,
            })
    elif decision["decision"] == "withhold":
        setup_doc = setup_status_doc(
            status="ready", reason="publication-withheld", bindings=bindings)
        envelope_doc = envelope if envelope is not None else withheld_envelope_stub(
            reason="publication-withheld", bindings=bindings)
        candidate_doc = void_candidate_result(
            reason="publication-withheld", bindings=bindings)
    else:
        setup_doc = setup_status_doc(
            status="ready", reason="publication-permitted", bindings=bindings)
        envelope_doc = envelope
        candidate_doc = {
            "schema": HOSTED_SCHEMA,
            "kind": "hosted-candidate-result",
            "score_status": "none",
            "decision": "publish",
            "bindings": dict(bindings),
            "non_claims": list(NON_CLAIMS),
        }

    write_separate_artifacts(
        out_dir, setup_doc, envelope_doc, candidate_doc,
        max_bytes=max_artifact_bytes,
    )
    return decision


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contained_hosted_publication",
        description="Hosted contained publication gate (#107)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    gate = sub.add_parser("gate", help="Write setup / envelope / candidate artifacts")
    gate.add_argument("--candidate-revision", required=True)
    gate.add_argument("--runner-revision", required=True)
    gate.add_argument("--image-digest", required=True)
    gate.add_argument("--operator-profile", default=REQUIRED_PROFILE)
    gate.add_argument("--out", required=True)
    gate.add_argument("--envelope", default=None)
    gate.add_argument("--rerun-log", default=None)
    gate.add_argument(
        "--max-artifact-bytes", type=int, default=MAX_ARTIFACT_BYTES)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "gate":
        parser.error("unsupported command")
    try:
        run_gate(
            candidate_revision=args.candidate_revision,
            runner_revision=args.runner_revision,
            image_digest=args.image_digest,
            operator_profile=args.operator_profile,
            out_dir=args.out,
            envelope_path=args.envelope,
            rerun_log=args.rerun_log,
            max_artifact_bytes=args.max_artifact_bytes,
        )
    except HostedPublicationError as exc:
        print("hosted publication refused: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
