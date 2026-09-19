#!/usr/bin/env python3
"""Provenance-bound production driver for the frozen AEE measurement rail.

This module authorizes and materializes a candidate run. It does not score,
classify mutations, or construct reports. No experiment runs without an explicit
execution profile and the PREPARE (v1 under contained-oci-v0, v2 under
contained-oci-v1) and authorize-v0 bytes supplied by the caller.
"""

from __future__ import annotations

import suggestion_evidence as assessment_evidence

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
import envelope_collection as collection  # noqa: E402
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
    container_context,
    execution_identity,
    load_prepare_for_profile,
    verify_phase_a_frozen,
)
from sealed_measurement_contract import AEE_CHECKER_SEALED_CONTRACT  # noqa: E402


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
                   execution_profile, transport=None,
                   envelope_dest: Path | None = None,
                   diagnostic_sink=None, assessment_context=None,
                   assessment_prepare_dir=None, assessment_backend_wrapper=None,
                   assessment_control_observer=None,
                   contract=AEE_CHECKER_SEALED_CONTRACT) -> dict:
    """Validate, rematerialize, then invoke the sole generic process engine.

    `execution_profile` has no default, so omitting it is TypeError rather than an implied
    contained-oci-v0. The shared dispatcher admits the PREPARE under it after authorization
    and before the execution identity; the same profile then builds the backend and reaches
    the funnel, and the engine refuses a backend that declares any other.
    """
    admitted = assessment_evidence.admit_assessment_call(
        assessment_context, execution_profile, contract, prepare_raw,
        authorization_raw=authorize_raw)
    if admitted is not None:
        return _run_owned_assessment(
            context=assessment_context, prepare=admitted, contract=contract,
            root=Path(root), prepare_dir=assessment_prepare_dir,
            materialize_dest=Path(materialize_dest), pins_dir=Path(pins_dir),
            envelope_dest=envelope_dest, transport=transport,
            backend_wrapper=assessment_backend_wrapper, control_observer=assessment_control_observer)
    try:
        validate_authorize(authorize_raw, prepare_raw, contract=contract)
        prepare = load_prepare_for_profile(
            prepare_raw, execution_profile=execution_profile, contract=contract)
        if execution_identity(Path(root), contract=contract) != prepare.get("execution"):
            raise DriverError("execution identity drift")
        pins = verify_phase_a_frozen(Path(pins_dir), contract=contract)
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
            template=container_context(root, contract=contract) / "cargo-config.toml",
            budget=budget,
            contract=contract,
        )
        _require_materialization(prepare, materialized, dest)
        manifest_path = Path(pins_dir) / "manifest.json"
        manifest_raw = verify_file_digest(
            manifest_path, contract.pin_digest("manifest.json"))
        manifest = ca.load_manifest_bytes(
            manifest_raw, manifest_path, path_root=dest)
        records = []
        # One ledger per run. The runtime registers each attempt immediately before the candidate
        # call, so an invocation that raises is still counted.
        ledger = collection.Ledger()
        backend = runtime.make_sealed_backend(
            prepare_raw=prepare_raw, materialized=materialized,
            execution_profile=execution_profile,
            transport=transport, envelope_sink=records.append, ledger=ledger,
            diagnostic_sink=diagnostic_sink,
            contract=contract)
        try:
            report = execute.run_execution_funnel(
                authorize_raw=authorize_raw,
                prepare_raw=prepare_raw,
                pins_dir=Path(pins_dir),
                manifest=manifest,
                manifest_path=manifest_path,
                execution_backend=backend,
                execution_profile=execution_profile,
                contract=contract,
            )
        except BaseException as primary:
            # The run failed, but the collection is the record of that failure. Emitting it must
            # never replace the primary refusal. No `and records` guard: zero attempts is a state
            # to record, not a reason to write nothing.
            if envelope_dest is not None:
                try:
                    collection.write_collection(
                        ledger, Path(envelope_dest), report_sha256=None)
                except BaseException as exc:
                    preserve_cleanup_failure(primary, "collection emit", exc)
            raise
        if envelope_dest is not None:
            report_sha256 = None
            if report is not None:
                report_sha256 = hashlib.sha256(ca.encode_report_v0(report)).hexdigest()
            collection.write_collection(
                ledger, Path(envelope_dest), report_sha256=report_sha256)
        return report
    except (AuthorizeError, PrepareError, ca.ManifestError, execute.ExecuteError,
            envelope.EnvelopeError, collection.CollectionError) as exc:
        raise DriverError(str(exc)) from exc


def _run_owned_assessment(*, context, prepare, contract, root, prepare_dir,
                          materialize_dest, pins_dir, envelope_dest, transport,
                          backend_wrapper, control_observer):
    from aee_checker_sealed_run import assessment_execution_identity
    from aee_checker_sealed_materialize import copy_owned_assessment_preparation
    if assessment_execution_identity(root) != prepare['source']:
        assessment_evidence.refuse('binding', 'source-identity')
    if prepare_dir is None or envelope_dest is None:
        assessment_evidence.refuse('input', 'argument-invalid')
    # Actual source is measured before rematerialization and backend construction.
    materialized=copy_owned_assessment_preparation(prepare_dir,materialize_dest,context=context)
    evidence=dict(context.assessment_inputs.evidence_members)
    for name in ('control.json','sites.json','manifest.json','pins.json'):
        raw=verify_file_digest(pins_dir/name,
            assessment_evidence.digest(evidence[context.variant+'/pins/'+name]))
    manifest_raw=evidence[context.variant+'/pins/manifest.json']
    manifest_path=pins_dir/'manifest.json'
    manifest=ca.load_manifest_bytes(manifest_raw,manifest_path,path_root=materialize_dest)
    ledger=collection.Ledger(max_members=4)
    backend=runtime.make_sealed_backend(prepare_raw=context.prepare_raw,materialized=materialized,
        execution_profile=context.profile,transport=transport,envelope_sink=lambda record: None,
        ledger=ledger,contract=contract,assessment_context=context)
    if backend_wrapper is not None:
        backend=backend_wrapper(backend,ledger)
    try:
        report=execute.run_execution_funnel(authorize_raw=context.variant_authorization_raw,
            prepare_raw=context.prepare_raw,pins_dir=pins_dir,manifest=manifest,
            manifest_path=manifest_path,execution_backend=backend,execution_profile=context.profile,
            contract=contract,assessment_context=context,control_observer=control_observer)
    except BaseException as primary:
        try:
            collection.write_collection(ledger,Path(envelope_dest),report_sha256=None)
        except BaseException as cleanup:
            preserve_cleanup_failure(primary,'assessment collection',cleanup)
        raise
    collection.write_collection(ledger,Path(envelope_dest),report_sha256=None)
    return report


def main(argv: list[str]) -> int:
    sys.stderr.write(
        "driver requires explicit authorized inputs; no implicit experiment command\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
