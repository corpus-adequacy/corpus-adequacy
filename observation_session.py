"""Scoreless process execution. The operator owns the backend and admission."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import uuid
from dataclasses import dataclass

import corpus_adequacy as ca
import execution_observation as codec
from bounded_run import RawTermination, run_capped_bytes


@dataclass(frozen=True)
class _InvocationReceipt:
    invocation_id: str
    step_id: str
    vector_id: str
    source_sha256: str
    raw_sha256: str
    raw_size: int
    evidence_sha256: str
    # Transport-only bytes. Public slots retain only their verified bindings.
    raw_stdout: bytes
    raw_stderr: bytes
    returncode: int | None
    abnormal: str | None
    selector_presence: tuple[bool, bool] | None


@dataclass(frozen=True)
class _ObservationExecution:
    process: ca._ProcessExecution
    receipts: tuple[_InvocationReceipt, ...]


@dataclass(frozen=True)
class _ObservationProceed:
    step_id: str
    evidence_sha256: str


@dataclass(frozen=True)
class _ObservationStop:
    step_id: str
    reason: str
    evidence_sha256: str


def source_digest(manifest):
    """Length-delimited relative declared paths and actual bytes, independent of temp root."""
    digest = hashlib.sha256(b'corpus-adequacy.observation-sources.v0\n')
    root = manifest['_repo_root'].resolve()
    for source in manifest['_source_paths']:
        path = ca._resolved_contained_source(source, root)
        name = path.relative_to(root).as_posix().encode('utf-8')
        raw = path.read_bytes()
        digest.update(str(len(name)).encode('ascii') + b'\n' + name)
        digest.update(str(len(raw)).encode('ascii') + b'\n' + raw)
    return 'sha256:' + digest.hexdigest()


def receipt_evidence(receipt):
    """Canonical invocation receipt. Bytes are persisted separately by their hashes."""
    return codec.canonical_bytes({
        'schema': 'corpus-adequacy.invocation-evidence.v0',
        'invocation_id': receipt.invocation_id, 'step_id': receipt.step_id,
        'vector_id': receipt.vector_id, 'source_sha256': receipt.source_sha256,
        'stdout_sha256': codec.sha256(receipt.raw_stdout), 'stdout_size': len(receipt.raw_stdout),
        'stderr_sha256': codec.sha256(receipt.raw_stderr), 'stderr_size': len(receipt.raw_stderr),
        'returncode': receipt.returncode, 'abnormal': receipt.abnormal,
        'selector_presence': list(receipt.selector_presence) if receipt.selector_presence is not None else None,
    })


def _parsed_capture(manifest, stdout, stderr, returncode, abnormal):
    if abnormal is not None:
        return None, None, abnormal, None, {}
    # The existing classifier runs before any stdout parser or selector access.
    classified = ca.classify(returncode, manifest['accepted_exit_codes'], manifest.get('unproved_exit_codes', []))
    if classified != 'ok':
        return None, None, classified, None, {}
    current = copy.deepcopy(manifest)
    current['_selector_keys_seen'] = {}
    value, diagnostic, kind = ca.child_outcome(
        current, subprocess.CompletedProcess([], returncode, stdout, stderr))
    if kind is not None:
        return None, None, kind, None, {}
    seen = current.get('_selector_keys_seen', {})
    presence = tuple(all(key in seen.get(selector, set())
                         for key in ca.selector_members(current[selector]))
                     if current.get(selector) is not None else True
                     for selector in ('outcome_from', 'diagnostic_from'))
    if not all(presence):
        return None, None, 'selector-missing', presence, seen
    try:
        # Verify the full JSON input too: duplicate keys and non-finite values
        # cannot be hidden by selecting one otherwise valid member.
        ca.load_json_document(stdout, root=dict, where='observation child')
    except (ca.ManifestError, ValueError):
        return None, None, 'parse-error', None, {}
    return value, diagnostic, None, presence, seen


def _make_receipt(request, vid, raw, stderr, returncode, abnormal, presence):
    from dataclasses import replace
    receipt = _InvocationReceipt(request['invocations'][vid], request['step_id'], vid,
        request['source_sha256'], codec.sha256(raw), len(raw), '', raw, stderr,
        returncode, abnormal, presence)
    return replace(receipt, evidence_sha256=codec.sha256(receipt_evidence(receipt)))


class LocalObservationBackend:
    """The fixed trusted-local byte backend; no manifest-selectable importer."""
    accepts_step = True
    execution_profile = 'trusted-local'

    def __call__(self, manifest, vectors=None, *, rebuild=True, step, observation):
        if rebuild:
            built, detail = ca._build(manifest)
            if not built or vectors is None:
                return _ObservationExecution(ca._ProcessExecution(built, detail, {}, {}, {}, {}), ())
        else:
            detail = 'reused unmutated build'
        outcomes, diagnostics, raised, receipts, seen = {}, {}, {}, [], {}
        for vector in vectors or []:
            vid = vector[manifest['id_key']]
            command = [str(x).replace('{vector}', str((manifest['_repo_root'] / vector[manifest['vector_path_key']]).resolve()))
                       for x in manifest['entrypoint_command']]
            abnormal = None
            try:
                completed = run_capped_bytes(command, manifest['_repo_root'], manifest['vector_timeout'])
                stdout, stderr, returncode = completed.stdout, completed.stderr, completed.returncode
            except RawTermination as exc:
                stdout, stderr, returncode, abnormal = exc.stdout, exc.stderr, exc.returncode, exc.reason
            value, diagnostic, kind, presence, emitted = _parsed_capture(
                manifest, stdout, stderr, returncode, abnormal)
            receipt = _make_receipt(observation, vid, stdout, stderr, returncode, abnormal, presence)
            receipts.append(receipt)
            for key, values in emitted.items():
                seen.setdefault(key, set()).update(values)
            if kind is not None:
                raised[vid] = kind
                break
            outcomes[vid] = value; diagnostics[vid] = diagnostic
        return _ObservationExecution(ca._ProcessExecution(True, detail, outcomes, diagnostics, raised, seen), tuple(receipts))


def _snapshot_observation_execution(result, expected_step, expected_vectors, *, manifest, request):
    """Validate original bytes and detach all mutable backend state before retention."""
    if type(result) is not _ObservationExecution or type(result.receipts) is not tuple:
        raise ca.ManifestError('observation backend requires a closed observation result')
    process = ca._snapshot_process_execution(result.process)
    receipts = result.receipts
    if not process.built or expected_vectors is None:
        if receipts or process.outcomes or process.diagnostics or process.raised or process.selector_keys_seen:
            raise ca.ManifestError('build cannot carry vector receipts or values')
        return _ObservationExecution(process, ())
    expected_ids = [v[manifest['id_key']] for v in expected_vectors]
    if any(type(receipt) is not _InvocationReceipt for receipt in receipts):
        raise ca.ManifestError('invalid invocation receipt')
    ids = [receipt.vector_id for receipt in receipts]
    if not ids or ids != expected_ids[:len(ids)] or len(ids) > len(expected_ids):
        raise ca.ManifestError('receipt order/set differs from invocation schedule')
    outcomes, diagnostics, raised, seen = {}, {}, {}, {}
    for index, receipt in enumerate(receipts):
        if (receipt.step_id != request['step_id'] or receipt.source_sha256 != request['source_sha256']
                or receipt.invocation_id != request['invocations'].get(receipt.vector_id)
                or type(receipt.raw_stdout) is not bytes or type(receipt.raw_stderr) is not bytes
                or type(receipt.raw_size) is not int or receipt.raw_size != len(receipt.raw_stdout)
                or receipt.raw_sha256 != codec.sha256(receipt.raw_stdout)):
            raise ca.ManifestError('receipt differs from engine invocation or original bytes')
        if len(receipt.raw_stdout) + len(receipt.raw_stderr) > ca.OUTPUT_CAP_BYTES:
            raise ca.ManifestError('receipt exceeds bounded child bytes')
        if receipt.returncode is not None and type(receipt.returncode) is not int:
            raise ca.ManifestError('invalid captured return code')
        if receipt.abnormal not in (None, 'timeout', 'output-cap', 'incomplete'):
            raise ca.ManifestError('invalid capture abnormal class')
        if receipt.evidence_sha256 != codec.sha256(receipt_evidence(receipt)):
            raise ca.ManifestError('invocation evidence digest mismatch')
        value, diagnostic, kind, presence, emitted = _parsed_capture(
            manifest, receipt.raw_stdout, receipt.raw_stderr, receipt.returncode, receipt.abnormal)
        if receipt.selector_presence != presence:
            raise ca.ManifestError('selector presence differs from original bytes')
        for key, values in emitted.items(): seen.setdefault(key, set()).update(values)
        if kind is not None:
            raised[receipt.vector_id] = kind
            if index != len(receipts) - 1:
                raise ca.ManifestError('backend continued after abnormal invocation')
        else:
            outcomes[receipt.vector_id] = value; diagnostics[receipt.vector_id] = diagnostic
    if len(ids) != len(expected_ids) and not raised:
        raise ca.ManifestError('backend omitted scheduled vectors without a stop')
    if (process.outcomes != outcomes or process.diagnostics != diagnostics or process.raised != raised
            or process.selector_keys_seen != seen):
        raise ca.ManifestError('backend projection differs from original captured evidence')
    return _ObservationExecution(process, tuple(receipts))


class ObservationSession(ca._ProcessMutationSession):
    """Reuse the source guard and backend funnel without constructing a score tally."""
    def __init__(self, manifest, backend):
        super().__init__(manifest, backend, None, {}, 0)
        if not self.accepts_step:
            raise ca.ManifestError('observation backend must accept engine step metadata')
        self.step_id = None
        self.request = None
        self.expected_vectors = None
        self.expected_step = None

    def _backend_kwargs(self, vectors, step):
        if type(self.step_id) is not str or not self.step_id:
            raise ca.ManifestError('missing engine observation step identity')
        ids = [v[self.manifest['id_key']] for v in vectors or []]
        if any(type(vid) is not str or not vid for vid in ids) or len(ids) != len(set(ids)):
            raise ca.ManifestError('observation vector IDs must be unique nonempty strings')
        self.request = {'step_id': self.step_id, 'source_sha256': source_digest(self.manifest),
                        'invocations': {vid: str(uuid.uuid4()) for vid in ids}}
        self.expected_vectors = copy.deepcopy(vectors)
        self.expected_step = copy.deepcopy(step)
        return {'step': copy.deepcopy(step), 'observation': copy.deepcopy(self.request)}

    def _snapshot_execution(self, result):
        return _snapshot_observation_execution(result, self.expected_step, self.expected_vectors,
                                               manifest=self.manifest, request=self.request)

    def execute(self, vectors=None, *, rebuild=True, record_selectors=False, step):
        if record_selectors:
            raise ca.ManifestError('observation route retains per-invocation selectors only')
        return super().execute(vectors, rebuild=rebuild, record_selectors=False, step=step)
