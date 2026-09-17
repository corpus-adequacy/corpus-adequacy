#!/usr/bin/env python3
"""Fixed facade for the repository-owned contained-oci-v1 hosted rail."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import aee_checker_sealed_authorize as authorize
import aee_checker_sealed_run as sealed_run
import contained_hosted_publication as publication
import corpus_adequacy as ca
import hosted_packet
from aee_checker_sealed_materialize import (
    abort_atomic_dest,
    begin_atomic_dest,
    commit_atomic_dest,
)
from hosted_rail_contract import OWNED_V1_RAIL

ROOT = Path(__file__).resolve().parents[1]
RAIL = OWNED_V1_RAIL
PREPARE_DIR = "owned-contained-v1-prepare"


def prepare_owned(*, image_id=None) -> dict:
    destination = ROOT / PREPARE_DIR
    raw = sealed_run.prepare(
        ROOT.joinpath(*RAIL.pins_source), destination,
        root=ROOT, adapter=ROOT / RAIL.measurement.adapter_relpath,
        image_id=image_id, schema=sealed_run.PREPARE_V2_SCHEMA,
        contract=RAIL.measurement)
    record_dir = ROOT / "owned-contained-v1-prepare-record"
    record = hosted_packet.record_prepare(
        destination / RAIL.prepare_filename,
        record_dir / RAIL.prepare_record_filename, rail=RAIL)
    return {"prepare_sha256": record["prepare_sha256"], "bytes": len(raw)}


def fetch_owned(*, repository, tag, manifest_sha256) -> dict:
    if not tag.startswith(RAIL.packet_release_prefix):
        raise hosted_packet.PacketError("tag_namespace")
    return hosted_packet.fetch_packet(
        repository=repository, tag=tag, manifest_sha256=manifest_sha256,
        workspace_root=ROOT, dest=RAIL.packet_dirname, rail=RAIL)


def authorize_packet_owned(*, prepare_path, prepare_record_path,
                           expected_prepare_sha256, expected_runner_revision,
                           out_dir) -> dict:
    """Validate hosted PREPARE bytes and atomically assemble the closed release assets.

    This is an offline owner step. It does not fetch, publish, dispatch, execute a
    candidate, or call Docker.
    """
    rail = RAIL
    prepare_raw = ca.read_bounded_regular_file(
        Path(prepare_path), cap=hosted_packet.MAX_FILE_BYTES)
    record_raw = ca.read_bounded_regular_file(
        Path(prepare_record_path), cap=hosted_packet.MAX_FILE_BYTES)
    hosted_packet.validate_prepare_record(
        record_raw, prepare_raw,
        expected_prepare_sha256=expected_prepare_sha256,
        expected_runner_revision=expected_runner_revision, rail=rail)
    prepare_doc = sealed_run.load_prepare_v2(
        prepare_raw, contract=rail.measurement)
    bindings = publication.require_bindings(
        prepare_doc["pins"]["subject_commit"],
        prepare_doc["execution"]["commit"],
        prepare_doc["toolchain"]["image_id"],
    )
    if bindings["runner_revision"] != expected_runner_revision:
        raise hosted_packet.PacketError("prepare_record_runner")
    publication.check_prepare_bindings(prepare_doc, bindings=bindings)

    state = begin_atomic_dest(Path(out_dir))
    try:
        staging = state["staging"]
        authorize_raw = authorize.emit_authorize_v0(
            prepare_raw, staging / rail.authorize_filename,
            contract=rail.measurement)
        authorize.validate_authorize(
            authorize_raw, prepare_raw, contract=rail.measurement)
        bindings_raw = (json.dumps(bindings, sort_keys=True) + "\n").encode("utf-8")
        payloads = {
            rail.authorize_filename: authorize_raw,
            rail.bindings_filename: bindings_raw,
            rail.prepare_filename: prepare_raw,
        }
        manifest_raw = hosted_packet.encode_packet_manifest(payloads, rail=rail)
        hosted_packet.write_new_regular_file(
            staging / rail.bindings_filename, bindings_raw)
        hosted_packet.write_new_regular_file(
            staging / rail.prepare_filename, prepare_raw)
        hosted_packet.write_new_regular_file(
            staging / rail.packet_manifest_filename, manifest_raw)

        files = hosted_packet.parse_manifest(manifest_raw, rail=rail)
        if set(path.name for path in staging.iterdir()) != {
                *rail.packet_filenames, rail.packet_manifest_filename}:
            raise hosted_packet.PacketError("packet_entries")
        for name, digest in files.items():
            raw = ca.read_bounded_regular_file(
                staging / name, cap=hosted_packet.MAX_FILE_BYTES)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise hosted_packet.PacketError("file_digest")
        final_prepare = ca.read_bounded_regular_file(
            staging / rail.prepare_filename, cap=hosted_packet.MAX_FILE_BYTES)
        final_authorize = ca.read_bounded_regular_file(
            staging / rail.authorize_filename, cap=hosted_packet.MAX_FILE_BYTES)
        sealed_run.load_prepare_v2(final_prepare, contract=rail.measurement)
        authorize.validate_authorize(
            final_authorize, final_prepare, contract=rail.measurement)
        publication.load_dispatch_bindings(
            staging, expected=bindings, rail=rail)
        commit_atomic_dest(state)
    except BaseException as primary:
        try:
            abort_atomic_dest(state)
        except BaseException as cleanup_exc:
            sealed_run.preserve_cleanup_failure(
                primary, "owned packet atomic abort", cleanup_exc)
        raise
    return {
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "prepare_sha256": hashlib.sha256(prepare_raw).hexdigest(),
        "bindings": bindings,
        "files": files,
        "candidate_executed": False,
    }


def gate_owned(*, candidate_revision, runner_revision, image_digest,
               packet_manifest_sha256, out_dir) -> dict:
    return publication.run_gate(
        candidate_revision=candidate_revision, runner_revision=runner_revision,
        image_digest=image_digest, operator_profile=RAIL.execution_profile,
        out_dir=out_dir, workspace_root=ROOT, packet_root=RAIL.packet_dirname,
        authorize_path=RAIL.authorize_filename,
        prepare_path=RAIL.prepare_filename, pins_dir="pins",
        packet_manifest_sha256=packet_manifest_sha256, rail=RAIL)


def seal_owned(*, candidate_revision, runner_revision, image_digest,
               packet_release_tag, packet_manifest_sha256, gate_outcome, out_dir) -> dict:
    """Seal the owned attempt's upload surface, report included, after the gate (#187)."""
    return publication.seal_attempt_statement(
        out_dir=out_dir, rail=RAIL.name,
        bindings=publication.require_bindings(
            candidate_revision, runner_revision, image_digest),
        packet_release_tag=packet_release_tag,
        packet_manifest_sha256=packet_manifest_sha256, gate_outcome=gate_outcome)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owned_contained_v1_hosted")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--image-id")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--tag", required=True)
    fetch.add_argument("--manifest-sha256", required=True)
    packet = sub.add_parser("authorize-packet")
    packet.add_argument("--prepare", required=True)
    packet.add_argument("--prepare-record", required=True)
    packet.add_argument("--prepare-sha256", required=True)
    packet.add_argument("--runner-revision", required=True)
    packet.add_argument("--out", required=True)
    gate = sub.add_parser("gate")
    gate.add_argument("--candidate-revision", required=True)
    gate.add_argument("--runner-revision", required=True)
    gate.add_argument("--image-digest", required=True)
    gate.add_argument("--packet-manifest-sha256", required=True)
    gate.add_argument("--out", required=True)
    seal = sub.add_parser("seal")
    seal.add_argument("--candidate-revision", required=True)
    seal.add_argument("--runner-revision", required=True)
    seal.add_argument("--image-digest", required=True)
    seal.add_argument("--packet-release-tag", required=True)
    seal.add_argument("--packet-manifest-sha256", required=True)
    seal.add_argument("--gate-outcome", required=True)
    seal.add_argument("--out", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_owned(image_id=args.image_id)
        elif args.command == "fetch":
            result = fetch_owned(repository=args.repository, tag=args.tag,
                                 manifest_sha256=args.manifest_sha256)
        elif args.command == "authorize-packet":
            result = authorize_packet_owned(
                prepare_path=args.prepare,
                prepare_record_path=args.prepare_record,
                expected_prepare_sha256=args.prepare_sha256,
                expected_runner_revision=args.runner_revision,
                out_dir=args.out)
        elif args.command == "seal":
            result = seal_owned(
                candidate_revision=args.candidate_revision,
                runner_revision=args.runner_revision,
                image_digest=args.image_digest,
                packet_release_tag=args.packet_release_tag,
                packet_manifest_sha256=args.packet_manifest_sha256,
                gate_outcome=args.gate_outcome,
                out_dir=args.out)
        else:
            result = gate_owned(
                candidate_revision=args.candidate_revision,
                runner_revision=args.runner_revision,
                image_digest=args.image_digest,
                packet_manifest_sha256=args.packet_manifest_sha256,
                out_dir=args.out)
    except (hosted_packet.PacketError, publication.HostedPublicationError,
            sealed_run.PrepareError, authorize.AuthorizeError,
            ca.ManifestError) as exc:
        print("owned hosted rail refused: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    if args.command == "gate":
        # The workflow uploads the verified collection only on exit 0, so only an explicit
        # publish decision may exit 0; withhold and unavailable exit 3.
        return 0 if result.get("decision") == "publish" else 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
