"""Scoreless process execution. The operator owns the backend and admission."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import uuid
import os
import platform
import sys
from contextlib import contextmanager
from pathlib import Path
from types import MappingProxyType
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
    evidence: bytes


@dataclass(frozen=True)
class _ObservationStop:
    step_id: str
    reason: str
    evidence_sha256: str
    evidence: bytes


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


def _persist_new(path, raw):
    """Publish exact bytes once, after file fsync; never overwrite a prior artifact."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.parent, flags)
    temporary = '.pending-' + str(uuid.uuid4())
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
    finally:
        try: os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError: pass
        os.close(directory)


def _blob(root, raw):
    digest = codec.sha256(raw)
    path = root / 'blobs' / digest.removeprefix('sha256:')
    try:
        _persist_new(path, raw)
    except FileExistsError:
        if ca.read_bounded_regular_file(path, cap=codec.MAX_BYTES) != raw:
            raise ca.ManifestError('existing evidence bytes differ from digest')
    return digest


def _evidence_root(output_root, subject_root, session):
    output_root = Path(output_root)
    if output_root.resolve().is_relative_to(subject_root.resolve()):
        raise ca.ManifestError('observation output must be outside the measured tree')
    output_root.mkdir(parents=True, exist_ok=True)
    fd = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(session, mode=0o700, dir_fd=fd); os.fsync(fd)
    finally: os.close(fd)
    root = output_root/session
    (root/'blobs').mkdir(mode=0o700)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    return root


def _corpus_digest(manifest, vectors):
    root = manifest['_repo_root'].resolve()
    index = manifest['_vectors_path']
    if not index.resolve().is_relative_to(root):
        raise ca.ManifestError('observation vectors index must be inside the measured tree')
    rows = [{'index_sha256': codec.sha256(ca.read_bounded_regular_file(index))}]
    for vector in vectors:
        value = vector.get(manifest['vector_path_key'])
        if type(value) is not str or Path(value).is_absolute() or '..' in Path(value).parts:
            raise ca.ManifestError('observation vector file must be a relative contained path')
        path = ca._resolved_contained_source(root/value, root)
        rows.append({'vector_id': vector[manifest['id_key']], 'path': value,
                     'sha256': codec.sha256(ca.read_bounded_regular_file(path))})
    return codec.sha256(codec.canonical_bytes(rows))


def _bindings(manifest, vectors, profile, backend, context_raw, policy_identity, interpreter_identity):
    identity = ca.tool_identity()
    if identity['tool_content_sha256'] is None:
        raise ca.ManifestError('tool source identity is unavailable')
    if type(backend) is LocalObservationBackend:
        backend_digest = codec.sha256(codec.canonical_bytes({'profile': 'trusted-local',
                                    'tool_content_sha256': identity['tool_content_sha256']}))
        environment = codec.sha256(codec.canonical_bytes({
            'python': sys.version, 'platform': platform.platform(),
            'executable_sha256': codec.sha256(Path(sys.executable).resolve().read_bytes())}))
    else:
        backend_digest = getattr(backend, 'backend_identity', None)
        environment = getattr(backend, 'environment_identity', None)
    result = {**identity, 'manifest_sha256': manifest['_manifest_sha256'],
              'corpus_sha256': _corpus_digest(manifest, vectors),
              'source_sha256': source_digest(manifest), 'execution_profile': profile,
              'backend_sha256': backend_digest, 'environment_sha256': environment,
              'context_sha256': codec.sha256(context_raw), 'policy_identity': policy_identity,
              'interpreter_identity': interpreter_identity,
              'selectors': {'outcome_from': ca.selector_members(manifest['outcome_from']),
                            'diagnostic_from': ca.selector_members(manifest['diagnostic_from']) if manifest.get('diagnostic_from') is not None else None},
              'exit_policy': {'accepted_exit_codes': manifest['accepted_exit_codes'],
                              'unproved_exit_codes': manifest.get('unproved_exit_codes', [])}}
    codec._bindings(result)
    return result


def _inputs(manifest_path, profile, backend):
    raw = ca.read_bounded_regular_file(Path(manifest_path))
    declaration = ca.load_json_document(raw, root=dict, where='observation manifest')
    if any(key in declaration for key in ('observation_mode', 'control_preflight', 'admission',
                                         'operator_context', 'policy_identity', 'interpreter_identity', 'backend')):
        raise ca.ManifestError('manifest cannot select operator observation controls')
    m = ca.load_manifest_bytes(raw, Path(manifest_path))
    resolved = ca.resolve_execution_profile(operator=profile, manifest=m)
    if m['runner'] != 'process' or resolved not in ('trusted-local', 'contained-oci-v1'):
        raise ca.ManifestError('initial observation route supports process and trusted-local/contained-oci-v1 only')
    ca._require_contained_execution(profile=resolved, runner=m['runner'], execution_backend=backend)
    if getattr(backend, 'execution_profile', None) != resolved:
        raise ca.ManifestError('observation backend profile differs from operator selection')
    if m.get('equivalent') or m.get('known_holes') or m.get('outcome_parse') == 'test-names':
        raise ca.ManifestError('observation route does not interpret exclusions or test-names')
    for entries in m['mutants'].values():
        for mutant in entries:
            if 'expected_mover' in mutant or mutant.get('scope') != 'declared':
                raise ca.ManifestError('observation route does not interpret mover attribution or excluded scope')
            if mutant.get('control') and 'control_polarity' not in mutant:
                raise ca.ManifestError('observation controls require explicit polarity')
    vectors = ca.load_vector_document(m)
    ids = [v[m['id_key']] for v in vectors]
    if any(type(vid) is not str or not vid for vid in ids) or len(ids) != len(set(ids)):
        raise ca.ManifestError('observation vector IDs must be unique strings')
    failures = ca.structural_failures(m, {ca._group_of(v,m) for v in vectors})
    if failures:
        raise ca.ManifestError('; '.join(failures))
    return m, vectors, resolved


def _schedule(manifest, vectors):
    schedule, work = [], {}
    def add(kind, group=None, mutant=None):
        step_id = 'step-%04d' % len(schedule)
        row = {'step_id': step_id, 'kind': kind, 'group': group,
               'label': mutant['label'] if mutant else None,
               'control_polarity': ca._control_polarity(mutant) if kind == 'control' else None,
               'vector_ids': [v[manifest['id_key']] for v in vectors if ca._group_of(v,manifest)==group] if group is not None else [],
               'mutation_sha256': codec.sha256(codec.canonical_bytes(mutant)) if mutant else None}
        schedule.append(row)
        if mutant is not None: work[step_id] = mutant
    add('build')
    for group in sorted(manifest['mutants']): add('baseline', group)
    controls, ordinary = ca.partition_declared_mutants(manifest['mutants'])
    for group, mutant in controls: add('control', group, mutant)
    for group, mutant in ordinary: add('ordinary', group, mutant)
    codec._schedule(schedule)
    return schedule, work


def _empty_step(row):
    return {'step_id': row['step_id'], 'state': 'pending', 'source_sha256': None,
            'application': 'pending', 'anchor_hits': None, 'build_state': 'not_run',
            'restored': False, 'preflight': None, 'failure': None,
            'slots': [{'vector_id': vid, 'state': 'pending', 'outcome': None,
                       'diagnostic': None, 'selector_presence': None, 'receipt': None,
                       'reason': None, 'evidence_sha256': None} for vid in row['vector_ids']]}


def _not_run(step, reason, evidence):
    step.update(state='not_run', source_sha256=None, application='not_run', anchor_hits=None,
                build_state='not_run', restored=True, preflight=None, failure=None)
    for slot in step['slots']:
        slot.update(state='not_run', outcome=None, diagnostic=None, selector_presence=None,
                    receipt=None, reason=reason, evidence_sha256=evidence)


def _stop(doc, index, reason, evidence):
    doc['phase'] = 'stopped'
    doc['closure'].update(reason=reason, stop_step=doc['steps'][index]['step_id'])
    current = doc['steps'][index]; current['state'] = 'stopped'
    if not (current['preflight'] and current['preflight']['decision'] == 'stop'):
        current['failure'] = {'reason': reason, 'evidence_sha256': evidence}
    for slot in current['slots']:
        if slot['state'] == 'pending':
            slot.update(state='not_run', reason=reason, evidence_sha256=evidence)
    for step in doc['steps'][index+1:]: _not_run(step, reason, evidence)


@contextmanager
def _isolated(manifest, cleanup):
    original = manifest['_repo_root']
    iso = ca.IsolatedMutationTree(original)
    guard = None; isolated_root = None
    with ca._TreeLock(original):
        try:
            isolated_root = iso.materialize()
            m = copy.deepcopy(manifest)
            m['_repo_root'] = isolated_root
            m['_source_paths'] = [isolated_root/p.relative_to(original) for p in manifest['_source_paths']]
            m['_vectors_path'] = isolated_root/manifest['_vectors_path'].relative_to(original)
            guard = ca._SourceGuard(m['_source_paths'], repo_root=None)
            yield m
        finally:
            try:
                if guard is not None:
                    guard.restore(); cleanup['restored'] = not guard.verify_clean()
                else: cleanup['restored'] = True
            finally:
                iso.cleanup()
                cleanup['isolated_tree_removed'] = isolated_root is None or not isolated_root.exists()


def _freeze(value):
    if isinstance(value, dict): return MappingProxyType({key:_freeze(v) for key,v in value.items()})
    if isinstance(value, (tuple,list)): return tuple(_freeze(v) for v in value)
    return value


def _preflight(callback, row, receipts, context_digest, root):
    result = callback(_freeze(row), tuple(receipts), context_digest)
    if type(result) not in (_ObservationProceed, _ObservationStop):
        raise ca.ManifestError('invalid control preflight result')
    if (result.step_id != row['step_id'] or type(result.evidence) is not bytes
            or len(result.evidence) > codec.MAX_BYTES or result.evidence_sha256 != codec.sha256(result.evidence)):
        raise ca.ManifestError('control preflight evidence binding differs')
    if type(result) is _ObservationStop and result.reason != 'operator-prerequisite-refused':
        raise ca.ManifestError('invalid preflight reason')
    _blob(root, result.evidence)
    return {'decision': 'stop' if type(result) is _ObservationStop else 'proceed',
            'reason': result.reason if type(result) is _ObservationStop else None,
            'evidence_sha256': result.evidence_sha256}


def _record_execution(step, row, execution, source_sha, root):
    process = execution.process
    step.update(state='complete', source_sha256=source_sha, restored=True,
                build_state='succeeded' if process.built else 'failed')
    if not process.built:
        return 'build-failed', _blob(root, codec.canonical_bytes({'built':False, 'detail':process.detail}))
    stopped = None
    by_vector = {r.vector_id:r for r in execution.receipts}
    for slot in step['slots']:
        receipt = by_vector.get(slot['vector_id'])
        if receipt is None: continue  # driver closes the exact unstarted suffix
        _blob(root, receipt.raw_stdout); _blob(root, receipt.raw_stderr)
        _blob(root, receipt_evidence(receipt))
        public_receipt = {key:getattr(receipt,key) for key in ('invocation_id','step_id','vector_id','source_sha256','raw_sha256','raw_size','evidence_sha256')}
        slot['receipt'] = public_receipt
        reason = process.raised.get(slot['vector_id'])
        if reason:
            slot.update(state='abnormal', reason=reason, evidence_sha256=receipt.evidence_sha256)
            stopped = (reason, receipt.evidence_sha256)
        else:
            # Existing selectors can return tuples; canonical JSON retains their values as arrays.
            slot.update(state='observed', outcome=json.loads(json.dumps(process.outcomes[slot['vector_id']])),
                        diagnostic=json.loads(json.dumps(process.diagnostics[slot['vector_id']])),
                        selector_presence={'outcome':True, 'diagnostic':True})
    return stopped


def observe_prefix(manifest_path: Path, *, execution_profile: str, backend=None,
                   context_raw: bytes, output_root: Path, policy_identity: str,
                   interpreter_identity: str, control_preflight=None) -> Path:
    """Execute build/baselines/controls, restore and close, then durably pause."""
    if type(context_raw) is not bytes or len(context_raw)>codec.MAX_BYTES:
        raise ca.ManifestError('operator context must be bounded bytes')
    if control_preflight is not None and not callable(control_preflight):
        raise ca.ManifestError('control preflight must be operator callable')
    backend = LocalObservationBackend() if backend is None else backend
    m, vectors, profile = _inputs(manifest_path, execution_profile, backend)
    if ca.fcntl is None or not hasattr(os,'O_NOFOLLOW'):
        raise ca.ManifestError('observation execution requires advisory locking and no-follow opens')
    bindings = _bindings(m,vectors,profile,backend,context_raw,policy_identity,interpreter_identity)
    schedule, work = _schedule(m,vectors)
    session_id = str(uuid.uuid4()); root = _evidence_root(output_root,m['_repo_root'],session_id)
    _blob(root,context_raw)
    doc = {'schema':codec.PREFIX_SCHEMA,'session':session_id,'phase':'awaiting_admission',
           'bindings':bindings,'schedule':schedule,'steps':[_empty_step(row) for row in schedule],
           'cleanup':{'restored':False,'isolated_tree_removed':False,'evidence_sha256':None},
           'closure':{'reason':None,'stop_step':None,'prefix_sha256':None,'admission_sha256':None,'consumption_sha256':None},
           'non_claims':list(codec.NON_CLAIMS)}
    receipts = []; last = 0
    _persist_new(root/'intent.json',codec.canonical_bytes({
        'schema':'corpus-adequacy.observation-intent.v0','session':session_id,
        'bindings':bindings,'schedule':schedule}))
    try:
        with _isolated(m,doc['cleanup']) as isolated:
            if source_digest(isolated) != bindings['source_sha256'] or _corpus_digest(isolated,vectors) != bindings['corpus_sha256']:
                raise ca.ManifestError('inputs changed during isolation')
            session = ObservationSession(isolated,backend)
            for group in sorted(m['mutants']):
                session.baselines[group] = ([v for v in vectors if ca._group_of(v,m)==group],{}, {})
            for index,row in enumerate(schedule):
                if row['kind']=='ordinary': break
                last=index; step=doc['steps'][index]; session.step_id=row['step_id']
                if row['kind']=='control' and control_preflight is not None:
                    if source_digest(session.manifest) != bindings['source_sha256']:
                        raise ca.ManifestError('source drift before control preflight')
                    step['preflight']=_preflight(control_preflight,row,receipts,bindings['context_sha256'],root)
                    if source_digest(session.manifest) != bindings['source_sha256']:
                        raise ca.ManifestError('control preflight changed a declared source')
                    if step['preflight']['decision']=='stop':
                        saved=step['preflight']; _not_run(step,saved['reason'],saved['evidence_sha256']); step['preflight']=saved
                        _stop(doc,index,saved['reason'],saved['evidence_sha256']); break
                if row['kind'] in ('build','baseline'):
                    selected = None if row['kind']=='build' else session.baselines[row['group']][0]
                    step['application']='not_applicable'
                    execution=session.execute(selected,rebuild=row['kind']=='build',step=ca._step(row['kind'],row['group']))
                else:
                    facts=ca._execute_mutation_observation(session,row['group'],work[row['step_id']])
                    step.update(application=facts['application'],anchor_hits=facts['anchor_hits'],restored=facts['restored'])
                    execution=facts['execution']
                    if execution is None:
                        evidence=_blob(root,codec.canonical_bytes({'reason':'anchor-mismatch','detail':facts['detail']}))
                        _stop(doc,index,'anchor-mismatch',evidence); break
                stopped=_record_execution(step,row,execution,session.request['source_sha256'],root)
                receipts.extend(execution.receipts)
                if not stopped:
                    _persist_new(root/(row['step_id']+'.json'),codec.canonical_bytes(step))
                if stopped:
                    _stop(doc,index,*stopped); break
    except BaseException as error:
        # A malformed/throwing backend cannot supply verified per-vector facts.
        # Retain completed checkpoints without inventing execution or not_run
        # for a step whose internal progress is unknown. This is not a prefix.
        interrupted={'schema':'corpus-adequacy.observation-interruption.v0',
                     'state':'unclosed','session':session_id,
                     'step_id':schedule[last]['step_id'],'error_class':type(error).__name__,
                     'cleanup':doc['cleanup']}
        try: _persist_new(root/'interrupted.json',codec.canonical_bytes(interrupted))
        except OSError as persistence_error:
            error.add_note('interruption record could not be persisted: '+type(persistence_error).__name__)
        raise
    cleanup_bytes=codec.canonical_bytes({k:v for k,v in doc['cleanup'].items() if k!='evidence_sha256'})
    doc['cleanup']['evidence_sha256']=_blob(root,cleanup_bytes)
    if not (doc['cleanup']['restored'] and doc['cleanup']['isolated_tree_removed']) and doc['phase']!='stopped':
        _stop(doc,last,'cleanup-failed',doc['cleanup']['evidence_sha256'])
    raw=codec.encode_observation(doc)
    path=root/'prefix.json'; _persist_new(path,raw)
    codec.load_observation(ca.read_bounded_regular_file(path,cap=codec.MAX_BYTES),kind='prefix')
    return path
