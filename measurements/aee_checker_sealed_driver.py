#!/usr/bin/env python3
"""Provenance-bound production driver for the frozen AEE measurement rail.

This module authorizes and materializes a candidate run. It does not score,
classify mutations, or construct reports. No experiment runs without explicit
PREPARE-v1 and authorize-v0 bytes supplied by the caller.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import corpus_adequacy as ca  # noqa: E402
import effective_envelope as envelope  # noqa: E402
import aee_checker_sealed_execute as execute  # noqa: E402
import aee_checker_sealed_runtime as runtime  # noqa: E402
from aee_checker_sealed_authorize import (  # noqa: E402
    AuthorizeError,
    validate_authorize,
)
from aee_checker_sealed_common import (  # noqa: E402
    MaterializeBudget,
    PrepareError,
    preserve_cleanup_failure,
    verify_file_digest,
)
from aee_checker_sealed_materialize import materialize_pinned  # noqa: E402
from aee_checker_sealed_run import (  # noqa: E402
    MATERIALIZED_KEYS,
    PHASE_A_PIN_DIGESTS,
    PREPARE_V1_SCHEMA,
    execution_identity,
    verify_phase_a_frozen,
)


class DriverError(Exception):
    """The authorized driver refused before or during the bounded run."""


def _require_materialization(prepare: dict, materialized: dict,
                             dest: Path) -> None:
    expected = prepare["materialized"]
    for key in MATERIALIZED_KEYS:
        if materialized.get(key) != expected.get(key):
            raise DriverError("materialized %s drift" % key)
    if materialized.get("toolchain") != prepare.get("toolchain"):
        raise DriverError("materialized toolchain drift")
    for key in ("subject", "corpus", "vendor", "tool"):
        path = materialized.get(key)
        if not isinstance(path, Path) or path != Path(dest) / key or not path.is_dir():
            raise DriverError("materialized %s path" % key)


def emit_envelope(records, dest: Path, report) -> bytes:
    """Write the sibling envelope record, bound to the report it preceded.

    The record exists whether or not a report does; a run that never reached
    a report still leaves setup, candidate and cleanup evidence behind. The
    binding runs envelope to report digest only. This writes an artifact and
    enforces nothing: publication remains owned by #107.
    """
    if len(records) != 1:
        raise DriverError("one contained run must leave one envelope record")
    digest = None
    if report is not None:
        digest = hashlib.sha256(ca.encode_report_v0(report)).hexdigest()
    raw = envelope.encode_envelope(envelope.bind_report(records[0], digest))
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return raw


def run_authorized(*, authorize_raw: bytes, prepare_raw: bytes,
                   pins_dir: Path, materialize_dest: Path, root: Path,
                   transport=None, envelope_dest: Path | None = None) -> dict:
    """Validate, rematerialize, then invoke the sole generic process engine."""
    try:
        validated = validate_authorize(authorize_raw, prepare_raw)
        prepare = validated["prepare"]
        if prepare.get("schema") != PREPARE_V1_SCHEMA:
            raise DriverError("authorized driver requires prepare.v1")
        if execution_identity(Path(root)) != prepare.get("execution"):
            raise DriverError("execution identity drift")
        pins = verify_phase_a_frozen(Path(pins_dir))
    except (AuthorizeError, PrepareError, ca.ManifestError) as exc:
        raise DriverError(str(exc)) from exc

    try:
        budget = MaterializeBudget(prepare["materialize_ceilings"])
        dest = Path(materialize_dest)
        if dest.exists():
            raise DriverError("materialize destination already exists")
        dest.mkdir()
        materialized = materialize_pinned(
            pins, dest,
            template=Path(root) / "execution" / "aee-checker-sealed" / "cargo-config.toml",
            budget=budget,
        )
        _require_materialization(prepare, materialized, dest)
        manifest_path = Path(pins_dir) / "manifest.json"
        manifest_raw = verify_file_digest(
            manifest_path, PHASE_A_PIN_DIGESTS["manifest.json"])
        manifest = ca.load_manifest_bytes(
            manifest_raw, manifest_path, path_root=dest)
        records = []
        backend = runtime.make_sealed_backend(
            prepare_raw=prepare_raw, materialized=materialized,
            transport=transport, envelope_sink=records.append)
        try:
            report = execute.run_execution_funnel(
                authorize_raw=authorize_raw,
                prepare_raw=prepare_raw,
                pins_dir=Path(pins_dir),
                manifest=manifest,
                manifest_path=manifest_path,
                execution_backend=backend,
                execution_profile="contained-oci-v0",
            )
        except BaseException as primary:
            # The run failed, but the envelope is the record of that failure.
            # Emitting it must never replace the primary refusal.
            if envelope_dest is not None and records:
                try:
                    emit_envelope(records, Path(envelope_dest), None)
                except BaseException as exc:
                    preserve_cleanup_failure(primary, "envelope emit", exc)
            raise
        if envelope_dest is not None and records:
            emit_envelope(records, Path(envelope_dest), report)
        return report
    except (AuthorizeError, PrepareError, ca.ManifestError, execute.ExecuteError,
            envelope.EnvelopeError) as exc:
        raise DriverError(str(exc)) from exc


def main(argv: list[str]) -> int:
    sys.stderr.write(
        "driver requires explicit authorized inputs; no implicit experiment command\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
