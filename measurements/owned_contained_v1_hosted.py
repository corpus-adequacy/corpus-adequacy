#!/usr/bin/env python3
"""Fixed facade for the repository-owned contained-oci-v1 hosted rail."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import aee_checker_sealed_run as sealed_run
import contained_hosted_publication as publication
import hosted_packet
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


def gate_owned(*, candidate_revision, runner_revision, image_digest,
               packet_manifest_sha256, out_dir) -> dict:
    return publication.run_gate(
        candidate_revision=candidate_revision, runner_revision=runner_revision,
        image_digest=image_digest, operator_profile=RAIL.execution_profile,
        out_dir=out_dir, workspace_root=ROOT, packet_root=RAIL.packet_dirname,
        authorize_path=RAIL.authorize_filename,
        prepare_path=RAIL.prepare_filename, pins_dir="pins",
        packet_manifest_sha256=packet_manifest_sha256, rail=RAIL)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="owned_contained_v1_hosted")
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--image-id")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--repository", required=True)
    fetch.add_argument("--tag", required=True)
    fetch.add_argument("--manifest-sha256", required=True)
    gate = sub.add_parser("gate")
    gate.add_argument("--candidate-revision", required=True)
    gate.add_argument("--runner-revision", required=True)
    gate.add_argument("--image-digest", required=True)
    gate.add_argument("--packet-manifest-sha256", required=True)
    gate.add_argument("--out", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_owned(image_id=args.image_id)
        elif args.command == "fetch":
            result = fetch_owned(repository=args.repository, tag=args.tag,
                                 manifest_sha256=args.manifest_sha256)
        else:
            result = gate_owned(
                candidate_revision=args.candidate_revision,
                runner_revision=args.runner_revision,
                image_digest=args.image_digest,
                packet_manifest_sha256=args.packet_manifest_sha256,
                out_dir=args.out)
    except (hosted_packet.PacketError, publication.HostedPublicationError,
            sealed_run.PrepareError) as exc:
        print("owned hosted rail refused: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("decision", "publish") == "publish" else 3


if __name__ == "__main__":
    raise SystemExit(main())
