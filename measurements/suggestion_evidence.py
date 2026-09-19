"""Pure owned-assessment evidence checks (#224).

No filesystem, network, candidate or process operations. These primitives do not
constitute a producer or a package reader, and never authenticate execution.
"""
from __future__ import annotations

import contained_contract as _contained_contract
import copy
import hashlib
import json
import math
import re

PREFIX = 'corpus-adequacy.owned-suggestion-assessment.'
FAMILY = 'owned-suggestion-assessment-v0'
PROFILE = 'contained-oci-v1'
VARIANTS = ('base', 'outer-whitespace')
MAX_MEMBER_BYTES = 1048576
MAX_TEXT_BYTES = 16384
SANITIZER_TOKENS = (
    'timeout', 'output-cap', 'inner-exit', 'empty-or-missing', 'malformed',
    'projection', 'oom-killed-reported', 'setup', 'candidate-preflight',
    'candidate-copy', 'candidate-build', 'candidate-report-missing',
    'candidate-report-empty', 'candidate-report-read', 'candidate-readback-hold',
)
ABNORMAL_KINDS = frozenset(SANITIZER_TOKENS + (
    'unproved', 'unexpected-exit', 'signal', 'incomplete', 'parse-error'))
STEPS = (('baseline', None), ('control', 'control-positive'),
         ('control', 'control-inert'), ('mutant', 'upper-guard-first-overflow-only'))
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


class EvidenceError(ValueError):
    """A bounded reason, never an untrusted exception string."""

    def __init__(self, stage, code):
        self.stage, self.code = stage, code
        super().__init__(f'{stage}/{code}')


def refuse(stage, code):
    raise EvidenceError(stage, code)


def exact(doc, fields):
    if type(doc) is not dict or set(doc) != set(fields):
        refuse('syntax', 'wrong-shape')
    return doc


def digest(raw):
    if type(raw) is not bytes:
        refuse('syntax', 'wrong-shape')
    return hashlib.sha256(raw).hexdigest()


def require_digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value):
        refuse('syntax', 'wrong-shape')
    return value


def text(value, cap=256):
    if type(value) is not str or not value:
        refuse('syntax', 'wrong-shape')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        refuse('syntax', 'invalid-unicode')
    if size > cap:
        refuse('limits', 'text-bytes')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        refuse('syntax', 'wrong-shape')
    return value


def _bounded(value, depth=0):
    if depth > 16:
        refuse('limits', 'json-depth')
    if type(value) is str:
        try:
            size = len(value.encode('utf-8'))
        except UnicodeError:
            refuse('syntax', 'invalid-unicode')
        if size > MAX_TEXT_BYTES:
            refuse('limits', 'text-bytes')
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                refuse('syntax', 'wrong-shape')
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _bounded(item, depth + 1)
    elif type(value) is float:
        if not math.isfinite(value):
            refuse('syntax', 'invalid-number')
    elif value is not None and type(value) not in (bool, int):
        refuse('syntax', 'wrong-shape')


def encode(value):
    _bounded(value)
    try:
        return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    except (ValueError, UnicodeError, RecursionError):
        refuse('syntax', 'invalid-json')


def decode(raw, *, max_bytes=MAX_MEMBER_BYTES, canonical=False):
    if type(raw) is not bytes or type(max_bytes) is not int or max_bytes < 1:
        refuse('syntax', 'wrong-shape')
    if len(raw) > max_bytes:
        refuse('limits', 'member-bytes')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                refuse('syntax', 'duplicate-key')
            result[key] = value
        return result

    try:
        source = raw.decode('utf-8')
    except UnicodeError:
        refuse('syntax', 'invalid-utf8')
    try:
        value = json.loads(source, object_pairs_hook=pairs,
                           parse_constant=lambda _: refuse('syntax', 'invalid-number'))
    except EvidenceError:
        raise
    except (ValueError, RecursionError):
        refuse('syntax', 'invalid-json')
    _bounded(value)
    if canonical and encode(value) != raw:
        refuse('syntax', 'noncanonical-new-object')
    return value


def require_ids(ids):
    if type(ids) not in (tuple, list) or len(ids) != 5:
        refuse('binding', 'id-set')
    for row_id in ids:
        text(row_id)
    if len({i.casefold() for i in ids}) != 5:
        refuse('binding', 'id-set')
    return tuple(ids)


def require_slot(slot):
    exact(slot, ('variant', 'ordinal', 'step'))
    if (slot['variant'] not in VARIANTS or type(slot['ordinal']) is not int
            or not 0 <= slot['ordinal'] < 4):
        refuse('replay', 'schedule-mismatch')
    step = exact(slot['step'], ('kind', 'group', 'id'))
    if (step['group'] != 'independent'
            or (step['kind'], step['id']) != STEPS[slot['ordinal']]):
        refuse('replay', 'schedule-mismatch')
    return VARIANTS.index(slot['variant']) * 4 + slot['ordinal']


def require_rows(rows, ids, *, diagnostic=False):
    exact(rows, ids)
    for row in rows.values():
        if diagnostic:
            exact(row, ('detail',))
            if type(row['detail']) is not str:
                refuse('syntax', 'wrong-shape')
            _bounded(row['detail'])
        else:
            exact(row, ('accepted', 'reason'))
            if type(row['accepted']) is not bool:
                refuse('syntax', 'wrong-shape')
            text(row['reason'])
    return rows


def _batch(value, ids, diagnostic=False):
    exact(value, ('<batch>',))
    selected = value['<batch>']
    if type(selected) is not list or len(selected) != 1:
        refuse('syntax', 'wrong-shape')
    return require_rows(selected[0], ids, diagnostic=diagnostic)


def require_ref(value):
    exact(value, ('member', 'sha256', 'bytes'))
    member = text(value['member'], 192)
    if ('\\' in member or len(member.split('/')) > 6
            or any(part in ('', '.', '..') for part in member.split('/'))):
        refuse('filesystem', 'unsafe-member')
    require_digest(value['sha256'])
    if type(value['bytes']) is not int or not 0 <= value['bytes'] <= MAX_MEMBER_BYTES:
        refuse('limits', 'member-bytes')
    return value


def project_observation(doc, *, ids, plan_sha256):
    """Validate one observed call and derive a detached pure judgement view.

    This projection cannot authenticate the producer's sanitized detail. It
    never maps a batch termination into a successful per-row distinction.
    """
    ids = require_ids(ids)
    require_digest(plan_sha256)
    # Apply encoded member/depth bounds to in-memory inputs as well as byte loaders.
    if len(encode(doc)) > MAX_MEMBER_BYTES:
        refuse('limits', 'member-bytes')
    exact(doc, ('schema', 'plan_sha256', 'slot', 'route', 'profile', 'state',
                'raw', 'sanitized_reason', 'exception_kind', 'envelope'))
    if doc['schema'] != PREFIX + 'observation.v0':
        refuse('support', 'unsupported-schema')
    if doc['plan_sha256'] != plan_sha256:
        refuse('binding', 'plan-variant')
    require_slot(doc['slot'])
    if doc['profile'] != PROFILE or doc['route'] != 'contained-oci-v1-derived':
        refuse('support', 'unsupported-profile')
    if doc['envelope'] is not None:
        require_ref(doc['envelope'])
    state = doc['state']
    if state in ('exception', 'invalid-return'):
        allowed = ('backend-exception',) if state == 'exception' else (
            'invalid-backend-result', 'observation-budget')
        if (doc['raw'] is not None or doc['sanitized_reason'] is not None
                or doc['exception_kind'] not in allowed):
            refuse('syntax', 'wrong-shape')
        return {'state': state, 'rows': None, 'diagnostics': None, 'abnormal_kind': None}
    if state != 'returned' or doc['exception_kind'] is not None:
        refuse('syntax', 'wrong-shape')
    raw = exact(doc['raw'], ('step', 'built', 'outcomes', 'diagnostics', 'raised'))
    if raw['step'] != doc['slot']['step'] or type(raw['built']) is not bool:
        refuse('syntax', 'wrong-shape')
    reason = doc['sanitized_reason']
    if type(raw['raised']) is not dict:
        refuse('syntax', 'wrong-shape')
    if raw['raised']:
        exact(raw['raised'], ('<batch>',))
        kind = raw['raised']['<batch>']
        if type(kind) is not str or kind not in ABNORMAL_KINDS:
            refuse('syntax', 'wrong-shape')
        if reason is not None and (kind != 'unproved' or reason not in SANITIZER_TOKENS):
            refuse('syntax', 'wrong-shape')
        for channel, diagnostic in (('outcomes', False), ('diagnostics', True)):
            if raw[channel] != {}:
                _batch(raw[channel], ids, diagnostic)
        kinds = {kind}
        if reason is not None:
            kinds.add(reason)
        return {'state': 'abnormal', 'rows': None, 'diagnostics': None,
                'abnormal_kind': sorted(kinds)}
    if reason is not None or raw['built'] is not True:
        refuse('syntax', 'wrong-shape')
    return {'state': 'normal', 'rows': copy.deepcopy(_batch(raw['outcomes'], ids)),
            'diagnostics': copy.deepcopy(_batch(raw['diagnostics'], ids, True)),
            'abnormal_kind': None}


def _gate(gate_id, status='passed', reason=None, witnesses=()):
    return {'id': gate_id, 'status': status, 'reason': reason,
            'witnesses': copy.deepcopy(list(witnesses))}


def _journal(journal, observations):
    if type(journal) is not list or len(journal) > 32:
        refuse('limits', 'journal-events')
    entered = []
    pending = None
    previous = -1
    omitted = set()
    for seq, event in enumerate(journal):
        exact(event, ('seq', 'slot', 'event', 'reason'))
        if type(event['seq']) is not int or event['seq'] != seq:
            refuse('replay', 'schedule-mismatch')
        ordinal = require_slot(event['slot'])
        action = event['event']
        if action == 'started':
            if omitted or pending is not None or ordinal != previous + 1 or event['reason'] is not None:
                refuse('replay', 'schedule-mismatch')
            pending = ordinal
        elif action in ('returned', 'exception'):
            if pending != ordinal:
                refuse('replay', 'schedule-mismatch')
            if (action == 'returned' and event['reason'] is not None) or (
                    action == 'exception' and event['reason'] not in (
                        'backend-exception', 'invalid-backend-result', 'observation-budget')):
                refuse('syntax', 'wrong-shape')
            entered.append((ordinal, action))
            previous, pending = ordinal, None
        elif action in ('not-started', 'preflight-refused'):
            expected = 'prerequisite-refused' if action == 'not-started' else 'preflight-refusal'
            if pending is not None or ordinal != previous + 1 or event['reason'] != expected:
                refuse('replay', 'schedule-mismatch')
            omitted.add(ordinal)
            previous = ordinal
        else:
            refuse('syntax', 'wrong-shape')
    if pending is not None:
        refuse('journal', 'unsettled-attempt')
    if previous != 7:
        refuse('journal', 'unexplained-missing-slot')
    actual = [require_slot(o['slot']) for o in observations]
    if actual != [n for n, _ in entered]:
        refuse('replay', 'schedule-mismatch')
    for (_, action), observation in zip(entered, observations):
        if (action == 'returned') != (observation['state'] == 'returned'):
            refuse('replay', 'schedule-mismatch')
    return omitted


def evaluate_execution_gates(plan, observations, views, engine_controls, journal):
    """Compute gates 3–8 from a closed, already prepared execution snapshot.

    This is deliberately not proposal/source admission: the future producer and
    reader must validate plan artifacts before constructing this snapshot. No
    gate 0–2 is fabricated by this core, and its return cannot alone admit a
    proposal. Observed views are independently reconstructed before comparison.
    """
    exact(plan, ('plan_sha256', 'ids', 'proposal_id', 'reference_rows',
                 'base_vectors', 'transformed_vectors'))
    require_digest(plan['plan_sha256'])
    ids = require_ids(plan['ids'])
    proposal_id = plan['proposal_id']
    if type(proposal_id) is not str or proposal_id not in ids:
        refuse('binding', 'id-set')
    frozen = tuple(i for i in ids if i != proposal_id)
    require_rows(plan['reference_rows'], ids)
    for corpus in ('base_vectors', 'transformed_vectors'):
        exact(plan[corpus], ids)
        if any(type(b) is not bytes or len(b) > 65536 for b in plan[corpus].values()):
            refuse('limits', 'member-bytes')
    transformed = all(plan['transformed_vectors'][i] == b' \n' + plan['base_vectors'][i]
                      + b'\n\t' for i in ids)
    if type(observations) is not list or type(views) is not list or len(observations) > 8:
        refuse('syntax', 'wrong-shape')
    reconstructed = [project_observation(o, ids=ids, plan_sha256=plan['plan_sha256'])
                     for o in observations]
    if encode(reconstructed) != encode(views):
        refuse('replay', 'raw-view-mismatch')
    omitted = _journal(journal, observations)
    by_slot = {require_slot(o['slot']): v for o, v in zip(observations, reconstructed)}
    slots = {require_slot(o['slot']): o['slot'] for o in observations}
    if type(engine_controls) is not list or len(engine_controls) != 2:
        refuse('syntax', 'wrong-shape')
    movements = {}
    for v_index, control in enumerate(engine_controls):
        exact(control, ('variant', 'positive', 'inert', 'barrier'))
        if control['variant'] != VARIANTS[v_index]:
            refuse('replay', 'engine-control-mismatch')
        offset = v_index * 4
        baseline = by_slot.get(offset)
        expected = {}
        for name, k in (('positive', 1), ('inert', 2)):
            current = by_slot.get(offset + k)
            moved = None
            if (current and baseline and current['state'] == baseline['state'] == 'normal'):
                moved = {i for i in ids if current['rows'][i] != baseline['rows'][i]}
            movements[offset + k] = moved
            if current is None:
                expected[name] = 'not-run'
            elif moved is None:
                expected[name] = 'failed'
            else:
                passed = bool(moved.intersection(frozen)) if name == 'positive' else not moved
                expected[name] = 'passed' if passed else 'failed'
        expected['barrier'] = 'continue' if all(x == 'passed' for x in expected.values()) else 'stop'
        if any(control[k] != value for k, value in expected.items()):
            refuse('replay', 'engine-control-mismatch')
        if expected['barrier'] == 'stop' and any(n >= offset + 3 for n in by_slot):
            refuse('replay', 'schedule-mismatch')
    result = []
    stopped = False
    groups = {3: (0, 4), 4: (1, 2, 5, 6), 5: (3, 7), 6: tuple(range(8))}
    for gate_id in (3, 4, 5, 6):
        required = groups[gate_id]
        if stopped:
            result.append(_gate(gate_id, 'not-run', 'prerequisite-refused'))
            stopped = True
            continue
        missing = any(n in omitted for n in required)
        required = tuple(n for n in required if n in by_slot)
        abnormal = [n for n in required if by_slot[n]['state'] != 'normal']
        reason, failed = None, []
        if abnormal:
            reason, failed = 'abnormal-execution', abnormal
        elif gate_id == 3:
            failed = [n for n in required if by_slot[n]['rows'] != plan['reference_rows']]
            if failed:
                reason = 'reference-mismatch'
        elif gate_id == 4:
            checks = (
                ('inert-control-moved', [n for n in (2, 6) if n in by_slot and movements[n]]),
                ('positive-control-proposal-only', [n for n in (1, 5)
                 if n in by_slot and movements[n] == {proposal_id}]),
                ('positive-control-inert', [n for n in (1, 5) if n in by_slot and not movements[n]]),
            )
            for candidate, failures in checks:
                if failures:
                    reason, failed = candidate, failures
                    break
        elif gate_id == 5:
            checks = (
                ('target-frozen-row-change', [n for n in required if any(
                    by_slot[n]['rows'][i] != by_slot[n-3]['rows'][i] for i in frozen)]),
                ('diagnostic-only', [n for n in required if
                    by_slot[n]['rows'][proposal_id] == by_slot[n-3]['rows'][proposal_id]
                    and by_slot[n]['diagnostics'][proposal_id]
                    != by_slot[n-3]['diagnostics'][proposal_id]]),
                ('target-no-distinction', [n for n in required if
                    by_slot[n]['rows'][proposal_id] == by_slot[n-3]['rows'][proposal_id]]),
            )
            for candidate, failures in checks:
                if failures:
                    reason, failed = candidate, failures
                    break
        elif not missing and (not transformed or by_slot[0]['rows'] != by_slot[4]['rows']):
            reason, failed = 'transformation-mismatch', [0, 4]
        if reason:
            result.append(_gate(gate_id, 'refused', reason, (slots[n] for n in failed)))
            stopped = True
        elif missing:
            result.append(_gate(gate_id, 'not-run', 'prerequisite-refused'))
        else:
            result.append(_gate(gate_id, witnesses=(slots[n] for n in required)))
    result.extend((_gate(7, 'not-run', 'missing-review'), _gate(8)))
    # Any unexplained omission with no preceding observed refusal is incomplete,
    # never a valid silently skipped run. More detailed preflight events are a
    # producer responsibility; this execution-only entry cannot vouch for them.
    if omitted:
        first = min(omitted)
        earlier_failure = any(v['state'] != 'normal' for n, v in by_slot.items() if n < first)
        earlier_failure |= any(c['barrier'] == 'stop' for index, c in enumerate(engine_controls)
                               if index * 4 + 1 < first and index * 4 + 1 in by_slot)
        # A semantic refusal is also a legitimate stop. Only actual earlier
        # witnesses justify omissions; a supplied gate or missing call cannot.
        earlier_failure |= any(
            gate['status'] == 'refused' and any(
                require_slot(slot) < first for slot in gate['witnesses'])
            for gate in result)
        if not earlier_failure:
            refuse('journal', 'unexplained-missing-slot')
    return result


def require_assessment_dispatch(family, profile, schema):
    """The assessment loader never broadens legacy profile/schema dispatch."""
    if family != FAMILY:
        refuse('support', 'unsupported-family')
    if profile != PROFILE:
        refuse('support', 'unsupported-profile')
    if schema != PREFIX + 'prepare.v0':
        refuse('support', 'crossed-prepare')
    return schema


# This oracle is the existing installed contract, never the supplied manifest.
from dataclasses import dataclass
from sealed_measurement_contract import OWNED_INDEPENDENT_V0_CONTRACT as _OWNED

BASIS_PATHS = ('LICENSE', 'vectors/MANIFEST.json', 'vectors/allow.json',
               'vectors/boundary.json', 'vectors/negative.json', 'vectors/over-limit.json')
POLICY = 'owned-suggestion-policy-v0'
SOURCE_PATHS = tuple(sorted(set(_OWNED.execution_paths) | {
    'measurements/owned_suggestion_assessment.py', 'measurements/suggestion_admission.py',
    'measurements/suggestion_evidence.py', 'measurements/suggestion_execution.py',
    'measurements/suggestion_readback.py'}))


def _members(snapshot, *, count, max_bytes=65536):
    if type(snapshot) is not tuple or len(snapshot) != count:
        refuse('syntax', 'wrong-shape')
    result = {}
    previous = ''
    folded = set()
    for item in snapshot:
        if type(item) is not tuple or len(item) != 2:
            refuse('syntax', 'wrong-shape')
        name, raw = item
        text(name, 192)
        if (name <= previous or name.casefold() in folded or '\\' in name
                or any(p in ('', '.', '..') for p in name.split('/'))):
            refuse('filesystem', 'unsafe-member')
        if type(raw) is not bytes:
            refuse('syntax', 'wrong-shape')
        if len(raw) > max_bytes:
            refuse('limits', 'member-bytes')
        previous = name
        folded.add(name.casefold())
        result[name] = raw
    return result


def _tree(files, directories=()):
    h = hashlib.sha256()
    for name in sorted(tuple(files) + tuple(directories)):
        h.update(name.encode('utf-8'))
        if name in directories:
            h.update(b'\0dir\0')
        else:
            raw = files[name]
            h.update(b'\0' + str(len(raw)).encode('ascii') + b'\0' + raw)
    return h.hexdigest()


def _corpus_digest(rows, files):
    h = hashlib.sha256()
    for row in rows:
        h.update(row['file'].encode('utf-8') + b'\0' + files[row['file']])
    return h.hexdigest()


def require_basis(snapshot):
    """Verify original six files AND directory against the installed oracle.

    Filesystem safe-open is a future caller responsibility; this pure function
    checks the supplied immutable snapshot, not the original file descriptors.
    """
    files = _members(snapshot, count=6)
    if tuple(files) != BASIS_PATHS:
        refuse('filesystem', 'missing-member')
    if (digest(files['vectors/MANIFEST.json']) != _OWNED.corpus_manifest_sha256
            or _tree(files, ('vectors',)) != _OWNED.corpus_tree_sha256):
        refuse('binding', 'corpus-derivation')
    vectors = {p.removeprefix('vectors/'): b for p, b in files.items()
               if p.startswith('vectors/')}
    manifest = decode(vectors['MANIFEST.json'], max_bytes=65536)
    if _corpus_digest(manifest['vectors'], vectors) != manifest['corpusDigest']:
        refuse('binding', 'corpus-derivation')
    return vectors


@dataclass(frozen=True, slots=True)
class AssessmentInputs:
    """Immutable snapshots, not a capability, approval or cached validation."""

    retained_members: tuple[tuple[str, bytes], ...]
    basis_members: tuple[tuple[str, bytes], ...]
    evidence_members: tuple[tuple[str, bytes], ...] = ()

    def __post_init__(self):
        _members(self.retained_members, count=15)
        require_basis(self.basis_members)
        _evidence_members(self.evidence_members)


def _proposal(doc):
    # Pure counterpart of suggestion_admission.require_proposal. Importing that
    # module would import materialization/runtime into the offline evidence core.
    exact(doc, ('schema', 'proposal_id', 'selection', 'target', 'vector', 'expected', 'authorship'))
    if doc['schema'] != 'corpus-adequacy.suggestion-proposal.v0':
        refuse('syntax', 'wrong-shape')
    token = lambda x: type(x) is str and re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', x)
    if not token(doc['proposal_id']) or doc['selection'] != 'owned-independent-v0':
        refuse('syntax', 'wrong-shape')
    target = exact(doc['target'], ('group', 'mutation_id'))
    if target != {'group': 'independent', 'mutation_id': 'upper-guard-first-overflow-only'}:
        refuse('syntax', 'wrong-shape')
    vector = exact(doc['vector'], ('id', 'file', 'value_class', 'document'))
    if not token(vector['id']) or vector['file'] != vector['id'] + '.json':
        refuse('syntax', 'wrong-shape')
    text(vector['value_class'])
    value = exact(vector['document'], ('value',))['value']
    if type(value) is not int or not -(2**63) <= value < 2**63:
        refuse('syntax', 'wrong-shape')
    outcome = exact(doc['expected'], ('accepted', 'reason'))
    if type(outcome['accepted']) is not bool:
        refuse('syntax', 'wrong-shape')
    text(outcome['reason'])
    a = exact(doc['authorship'], ('author_kind', 'author', 'model_id', 'prompt_sha256',
                                  'input_sha256', 'source_pin'))
    text(a['author'])
    if type(a['source_pin']) is not str or not re.fullmatch('[0-9a-f]{40}', a['source_pin']):
        refuse('syntax', 'wrong-shape')
    if a['author_kind'] == 'model':
        text(a['model_id'])
        for key in ('prompt_sha256', 'input_sha256'):
            if type(a[key]) is not str or not re.fullmatch('sha256:[0-9a-f]{64}', a[key]):
                refuse('syntax', 'wrong-shape')
    elif a['author_kind'] != 'human' or any(a[k] is not None for k in (
            'model_id', 'prompt_sha256', 'input_sha256')):
        refuse('syntax', 'wrong-shape')
    return doc


def _bound_ref(ref, members, member):
    require_ref(ref)
    if ref['member'] != member or member not in members:
        refuse('binding', 'member-digest')
    raw = members[member]
    if ref['sha256'] != digest(raw) or ref['bytes'] != len(raw):
        refuse('binding', 'member-digest')
    return raw


def _source(source):
    exact(source, ('commit', 'files', 'content_sha256'))
    if type(source['commit']) is not str or not re.fullmatch('[0-9a-f]{40}', source['commit']):
        refuse('syntax', 'wrong-shape')
    require_digest(source['content_sha256'])
    _source_files(source['files'])


def _source_files(files):
    if type(files) is not list or len(files) != len(SOURCE_PATHS):
        refuse('binding', 'source-identity')
    for row, path in zip(files, SOURCE_PATHS):
        exact(row, ('path', 'sha256'))
        if row['path'] != path:
            refuse('binding', 'source-identity')
        require_digest(row['sha256'])


_RULE_SOURCES = (
    ('fixtures/contained-v1-owned/candidate/src/check.rs',
     '27063bf9ca3ae862121e456105c9af943bafd46dca1b9600a3603ea9a4a8c5c9'),
    ('measurements/owned-independent-v0/mutation-bundle.json',
     '5e82c5267be5b5281c1aacb065bc3c9912c7afb7b4810c06b4fd798aace513f6'),
)


def _reference(raw, proposal_raw, proposal, ids):
    doc = decode(raw, max_bytes=65536, canonical=True)
    exact(doc, ('schema', 'proposal_sha256', 'selection', 'rule_sources', 'rows',
                'rationale', 'reviewer', 'decision'))
    if doc['schema'] != PREFIX+'reference.v0':
        refuse('support', 'unsupported-schema')
    if (doc['proposal_sha256'] != digest(proposal_raw)
            or doc['selection'] != 'owned-independent-v0'
            or doc['rule_sources'] != [{'path': p, 'sha256': h} for p, h in _RULE_SOURCES]):
        refuse('input', 'reference-mismatch')
    if doc['decision'] == 'reject':
        refuse('input', 'reference-rejected')
    if doc['decision'] != 'accept':
        refuse('syntax', 'wrong-shape')
    text(doc['reviewer']); text(doc['rationale'])
    require_rows(doc['rows'], ids)
    if doc['rows'][proposal['vector']['id']] != proposal['expected']:
        refuse('input', 'reference-mismatch')
    return doc


def evaluate_preflight(inputs):
    """Recompute gates 0–2. This does not measure disk or approve a reference.

    Returns (gates, detached validated values). Values are None after a semantic
    refusal; malformed/misbound snapshots raise, never manufacture passed gates.
    """
    if type(inputs) is not AssessmentInputs:
        refuse('syntax', 'wrong-shape')
    if getattr(inputs, 'evidence_members', None) != ():
        refuse('syntax', 'wrong-shape')
    members = _members(inputs.retained_members, count=15)
    basis = require_basis(inputs.basis_members)
    if not {'plan.json', 'proposal.json', 'reference.json'} <= members.keys():
        refuse('filesystem', 'missing-member')
    plan_raw = members['plan.json']
    plan = decode(plan_raw, max_bytes=65536, canonical=True)
    exact(plan, ('schema', 'family', 'proposal', 'reference', 'source', 'instrument_commit',
                'subject_tree_sha256', 'adapter_sha256', 'profile', 'policy', 'variants',
                'slots', 'control_sha256', 'sites_sha256'))
    if plan['schema'] != PREFIX+'plan.v0':
        refuse('support', 'unsupported-schema')
    _source(plan['source'])
    _bound_ref(plan['proposal'], members, 'proposal.json')
    _bound_ref(plan['reference'], members, 'reference.json')
    # Decode failures remain loading failures; a decoded inadmissible proposal
    # is a faithful gate0 policy refusal.
    proposal = decode(members['proposal.json'], max_bytes=65536)
    try:
        _proposal(proposal)
    except EvidenceError:
        return ([_gate(0, 'refused', 'proposal-shape'),
                 _gate(1, 'not-run', 'prerequisite-refused'),
                 _gate(2, 'not-run', 'prerequisite-refused')], None)
    gates = [_gate(0)]
    expected = {'family': FAMILY, 'profile': PROFILE, 'policy': POLICY,
                'instrument_commit': _OWNED.instrument_commit,
                'subject_tree_sha256': _OWNED.subject_tree_sha256,
                'adapter_sha256': _OWNED.adapter_sha256,
                'control_sha256': _OWNED.pin_digest('control.json'),
                'sites_sha256': _OWNED.pin_digest('sites.json')}
    if any(plan[k] != value for k, value in expected.items()):
        return (gates + [_gate(1, 'refused', 'freeze-drift'),
                        _gate(2, 'not-run', 'prerequisite-refused')], None)
    gates.append(_gate(1))
    if type(plan['slots']) is not list or len(plan['slots']) != 8:
        refuse('syntax', 'wrong-shape')
    if [require_slot(slot) for slot in plan['slots']] != list(range(8)):
        refuse('replay', 'schedule-mismatch')
    if type(plan['variants']) is not list or len(plan['variants']) != 2:
        refuse('syntax', 'wrong-shape')
    original = decode(basis['MANIFEST.json'], max_bytes=65536)
    vector = proposal['vector']
    if (vector['id'].casefold() in {r['id'].casefold() for r in original['vectors']}
            or vector['file'].casefold() in {p.casefold() for p in basis}):
        return gates + [_gate(2, 'refused', 'corpus-separation')], None
    expected_rows = original['vectors'] + [{k: vector[k] for k in ('id', 'file', 'value_class')}]
    ids = require_ids([r['id'] for r in expected_rows])
    reference = _reference(members['reference.json'], members['proposal.json'], proposal, ids)
    base = {p: b for p, b in basis.items() if p != 'MANIFEST.json'}
    base[vector['file']] = json.dumps(vector['document'], separators=(',', ':'), sort_keys=True).encode('utf-8')
    expected_members = {'plan.json', 'proposal.json', 'reference.json'}
    corpora = []
    valid = True
    for variant_name, variant in zip(VARIANTS, plan['variants']):
        exact(variant, ('variant', 'manifest', 'vectors', 'tree_sha256', 'corpus_digest'))
        if variant['variant'] != variant_name:
            refuse('binding', 'plan-variant')
        require_digest(variant['tree_sha256']); require_digest(variant['corpus_digest'])
        if type(variant['vectors']) is not list or len(variant['vectors']) != 5:
            refuse('syntax', 'wrong-shape')
        prefix = variant_name+'/corpus/'
        expected_members.add(prefix+'MANIFEST.json')
        manifest_raw = _bound_ref(variant['manifest'], members, prefix+'MANIFEST.json')
        manifest = decode(manifest_raw, max_bytes=65536)
        exact(manifest, ('vectors', 'corpusDigest'))
        actual_files, expected_files = {}, {}
        seen_ids, seen_files = set(), set()
        for row, expected_row in zip(variant['vectors'], expected_rows):
            exact(row, ('id', 'file', 'sha256', 'bytes'))
            text(row['id']); text(row['file'])
            if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}\.json', row['file']):
                refuse('filesystem', 'unsafe-member')
            if row['id'].casefold() in seen_ids or row['file'].casefold() in seen_files:
                refuse('binding', 'id-set')
            seen_ids.add(row['id'].casefold()); seen_files.add(row['file'].casefold())
            member = prefix+row['file']; expected_members.add(member)
            raw = _bound_ref({'member': member, 'sha256': row['sha256'], 'bytes': row['bytes']}, members, member)
            expected_raw = base[expected_row['file']]
            if variant_name == 'outer-whitespace':
                expected_raw = b' \n'+expected_raw+b'\n\t'
            valid &= row['id'] == expected_row['id'] and row['file'] == expected_row['file'] and raw == expected_raw
            actual_files[row['file']] = raw
            expected_files[expected_row['file']] = expected_raw
        want_digest = _corpus_digest(expected_rows, expected_files)
        want_manifest = {'vectors': expected_rows, 'corpusDigest': want_digest}
        valid &= encode(manifest) == encode(want_manifest) and variant['corpus_digest'] == want_digest
        # The retained tree binds actual bytes, including original manifest formatting.
        if _tree({**actual_files, 'MANIFEST.json': manifest_raw}) != variant['tree_sha256']:
            refuse('binding', 'corpus-derivation')
        corpora.append({r['id']: expected_files[r['file']] for r in expected_rows})
    if set(members) != expected_members:
        refuse('filesystem', 'surplus-member')
    if not valid:
        return gates + [_gate(2, 'refused', 'corpus-separation')], None
    gates.append(_gate(2))
    execution = {'plan_sha256': digest(plan_raw), 'ids': ids, 'proposal_id': vector['id'],
                 'reference_rows': reference['rows'], 'base_vectors': corpora[0],
                 'transformed_vectors': corpora[1]}
    return gates, {'plan': plan, 'proposal': proposal, 'reference': reference, 'execution': execution}


def evaluate_assessment(inputs, observations, views, engine_controls, journal):
    """Full structural replay, deliberately independent of external expectations.

    Arguments are decoded retained wire records. Package loading must separately
    enforce canonical raw bytes and package/index budgets before this boundary.
    """
    structure = require_assessment_structure(inputs, require_collections=True)
    gates, validated = structure['gates'], structure['values']
    plan_hash = digest(dict(inputs.retained_members)['plan.json'])
    if (type(observations) is not list or len(observations) > 8
            or type(views) is not list or len(views) > 8
            or type(journal) is not list or len(journal) > 32):
        refuse('syntax', 'wrong-shape')
    refs, expected_views = {}, []
    for obs in observations:
        if validated is None:
            refuse('replay', 'schedule-mismatch')
        projection = project_observation(obs, ids=validated['execution']['ids'], plan_sha256=plan_hash)
        slot = obs['slot']; ordinal = require_slot(slot)
        member = slot['variant']+'/observations/'+str(slot['ordinal'])+'.json'
        if ordinal in refs:
            refuse('replay', 'schedule-mismatch')
        raw = encode(obs)
        refs[ordinal] = {'member': member, 'sha256': digest(raw), 'bytes': len(raw)}
        if obs['state'] == 'returned':
            expected_views.append({'schema': PREFIX+'view.v0', 'plan_sha256': plan_hash,
                'slot': slot, 'observation': refs[ordinal], 'adapter_sha256': _OWNED.adapter_sha256,
                **projection})
    if encode(views) != encode(expected_views):
        refuse('replay', 'raw-view-mismatch')
    normalized_journal = []
    for event in journal:
        if len(encode(event)) > 2048:
            refuse('limits', 'member-bytes')
        exact(event, ('schema', 'seq', 'plan_sha256', 'slot', 'event', 'observation', 'reason'))
        if event['schema'] != PREFIX+'journal-event.v0':
            refuse('support', 'unsupported-schema')
        if event['plan_sha256'] != plan_hash:
            refuse('binding', 'plan-variant')
        ordinal = require_slot(event['slot'])
        settled = event['event'] in ('returned', 'exception')
        if settled and (ordinal not in refs or encode(event['observation']) != encode(refs[ordinal])):
            refuse('binding', 'member-digest')
        if not settled and event['observation'] is not None:
            refuse('syntax', 'wrong-shape')
        normalized_journal.append({k: event[k] for k in ('seq', 'slot', 'event', 'reason')})
    if any(e['event'] == 'preflight-refused' for e in normalized_journal):
        refuse('replay', 'schedule-mismatch')
    projected = [project_observation(o, ids=validated['execution']['ids'], plan_sha256=plan_hash)
                 for o in observations]
    gates += evaluate_execution_gates(validated['execution'], observations, projected,
                                      engine_controls, normalized_journal)
    unproved = _assessment_envelopes(structure, observations)
    return AssessmentEvaluation(encode(gates), unproved)


# Closed runtime data pinned to the existing source validators; no runtime imports.
_CANDIDATE_RESOURCE_PROFILE_V2 = _contained_contract.CANDIDATE_RESOURCE_PROFILE_V2
_NETWORK_CUTOFF = {'cutoff': 'after_materialization',
 'materialization': 'online',
 'sealed_oci': 'none'}
_OCI_CONTRACT = {'cap_drop': ['ALL'],
 'memory': '4g',
 'memory_swap': '4g',
 'memory_swap_pids_claim': 'inspect-verified; not efficacy-tested',
 'network': 'none',
 'no_new_privileges': True,
 'pids': 512,
 'read_only': True,
 'user': '65532:65532'}
_DECLARED_CEILINGS = _contained_contract.DECLARED_CEILINGS
_MATERIALIZE_CEILINGS = {'deadline_seconds': 300,
 'disk_bytes': 67108864,
 'entry_count': 10000,
 'output_bytes': _contained_contract.OUTPUT_CAP_BYTES}
_INSPECT_KEYS = ('cap_drop', 'memory', 'memory_swap', 'network_mode', 'no_new_privileges', 'offline_env', 'pids', 'read_only_root', 'readonly_mounts', 'tmpfs', 'user')
_TOOL_TREE_SHA256 = '9347dbb76a065d01681b3cb3cae495aad64f5026d5f5b62c90283a0a1e4afa51'


def require_runtime_preparation(runtime):
    """Pure closed data validation; none of these assertions authenticate a host."""
    exact(runtime, ('toolchain', 'image', 'candidate_profile', 'probe_evidence', 'network',
                    'runtime', 'oci', 'ceilings', 'materialize_ceilings'))
    for key, expected in (
            ('candidate_profile', _CANDIDATE_RESOURCE_PROFILE_V2), ('network', _NETWORK_CUTOFF),
            ('oci', _OCI_CONTRACT), ('ceilings', _DECLARED_CEILINGS),
            ('materialize_ceilings', _MATERIALIZE_CEILINGS)):
        if encode(runtime[key]) != encode(expected):
            refuse('syntax', 'wrong-shape')
    tc = exact(runtime['toolchain'], ('cargo_V', 'image_id', 'index', 'observation', 'platform', 'rustc_Vv'))
    image_pattern = r'sha256:[0-9a-f]{64}'
    if (type(tc['image_id']) is not str or not re.fullmatch(image_pattern, tc['image_id'])
            or tc['index'] != 'docker.io/library/rust@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2'
            or tc['observation'] != 'vendor-image; checker was not run'
            or '1.92.0' not in str(tc['rustc_Vv'] or '')
            or '1.92.0' not in str(tc['cargo_V'] or '')
            or not str(tc['platform'] or '').startswith('linux/')):
        refuse('syntax', 'wrong-shape')
    image = exact(runtime['image'], ('id', 'id_scope', 'kind', 'platform'))
    if (type(image['id']) is not str or not re.fullmatch(image_pattern, image['id'])
            or image['id'] == tc['image_id'] or image['id_scope'] != 'host-local'
            or image['kind'] != 'inert-probe'):
        refuse('syntax', 'wrong-shape')
    text(image['platform'])
    host = exact(runtime['runtime'], ('docker', 'observation'))
    text(host['docker'])
    if host['observation'] != 'host-local; not a portable bound':
        refuse('syntax', 'wrong-shape')
    probes = runtime['probe_evidence']
    mechanisms = ('deadline', 'disk', 'file-count', 'network-off', 'output', 'protocol-exit')
    if type(probes) is not list or len(probes) != 6:
        refuse('syntax', 'wrong-shape')
    for name, row in zip(mechanisms, probes):
        exact(row, ('control', 'inspect', 'mechanism', 'refusal'))
        want = {'deadline': 'deadline', 'output': 'output_cap'}.get(name, 'abnormal')
        if row['mechanism'] != name or row['control'] != 'completed' or row['refusal'] != want:
            refuse('syntax', 'wrong-shape')
        exact(row['inspect'], ('control', 'refusal'))
        for side in row['inspect'].values():
            exact(side, _INSPECT_KEYS)
    # Existing probe validation only checks closed inspect keys, not efficacy.
    _bounded(runtime)
    return runtime


def require_expected(raw):
    doc = decode(raw, max_bytes=65536, canonical=True)
    exact(doc, ('schema', 'plan_sha256', 'source_content_sha256', 'reference_sha256',
                'policy', 'receipt_sha256', 'source_files', 'reference_approval'))
    if doc['schema'] != PREFIX+'expected.v0' or doc['policy'] != POLICY:
        refuse('input', 'expected-invalid')
    for key in ('plan_sha256', 'source_content_sha256', 'reference_sha256'):
        require_digest(doc[key])
    if doc['receipt_sha256'] is not None:
        require_digest(doc['receipt_sha256'])
    _source_files(doc['source_files'])
    if doc['reference_approval'] not in ('accept', 'reject', 'unavailable'):
        refuse('input', 'expected-invalid')
    return doc


def _require_expected_admission(expected, plan, plan_hash):
    approval = expected['reference_approval']
    if approval != 'accept':
        refuse('input', 'reference-rejected' if approval == 'reject' else 'reference-required')
    if (expected['plan_sha256'] != plan_hash
            or expected['reference_sha256'] != plan['reference']['sha256']
            or expected['source_content_sha256'] != plan['source']['content_sha256']
            or encode(expected['source_files']) != encode(plan['source']['files'])):
        refuse('expectation', 'expected-identity-mismatch')


def _require_variant_preparation(values, variant_name, prepare_raw, parent_raw, auth_raw):
    plan = values['plan']; plan_hash = values['execution']['plan_sha256']
    index = VARIANTS.index(variant_name); variant = plan['variants'][index]
    prepare = decode(prepare_raw, max_bytes=65536, canonical=True)
    exact(prepare, ('schema', 'family', 'plan_sha256', 'variant', 'profile', 'source',
                    'pins_sha256', 'materialized', 'runtime'))
    require_assessment_dispatch(prepare['family'], prepare['profile'], prepare['schema'])
    if (prepare['plan_sha256'] != plan_hash or prepare['variant'] != variant_name
            or encode(prepare['source']) != encode(plan['source'])):
        refuse('binding', 'source-identity')
    require_digest(prepare['pins_sha256'])
    materialized = exact(prepare['materialized'], ('subject_tree_sha256', 'corpus_tree_sha256',
        'corpus_manifest_sha256', 'corpus_id_count', 'vendor_sha256', 'tool_sha256'))
    want = {'subject_tree_sha256': _OWNED.subject_tree_sha256,
        'corpus_tree_sha256': variant['tree_sha256'], 'corpus_manifest_sha256': variant['manifest']['sha256'],
        'corpus_id_count': 5, 'vendor_sha256': digest(b''), 'tool_sha256': _TOOL_TREE_SHA256}
    if encode(materialized) != encode(want):
        refuse('binding', 'corpus-derivation')
    require_runtime_preparation(prepare['runtime'])
    parent = decode(parent_raw, max_bytes=65536, canonical=True)
    exact(parent, ('schema', 'plan_sha256', 'source_content_sha256', 'profile', 'prepares',
                   'reference_sha256', 'operator', 'decision'))
    if parent['schema'] != PREFIX+'authorization.v0':
        refuse('support', 'unsupported-schema')
    if (parent['plan_sha256'] != plan_hash or parent['profile'] != PROFILE
            or parent['source_content_sha256'] != plan['source']['content_sha256']
            or parent['reference_sha256'] != plan['reference']['sha256'] or parent['decision'] != 'execute'):
        refuse('binding', 'prepare-authorization')
    text(parent['operator'])
    if type(parent['prepares']) is not list or len(parent['prepares']) != 2:
        refuse('syntax', 'wrong-shape')
    for name, row in zip(VARIANTS, parent['prepares']):
        exact(row, ('variant', 'sha256'))
        require_digest(row['sha256'])
        if row['variant'] != name:
            refuse('binding', 'prepare-authorization')
    prepare_hash = digest(prepare_raw)
    if parent['prepares'][index]['sha256'] != prepare_hash:
        refuse('binding', 'prepare-authorization')
    auth = decode(auth_raw, max_bytes=65536, canonical=True)
    expected_auth = {'schema': PREFIX+'variant-authorization.v0',
        'parent_authorization_sha256': digest(parent_raw),
        'plan_sha256': plan_hash, 'variant': variant_name, 'prepare_sha256': prepare_hash,
        'profile': PROFILE, 'source_content_sha256': plan['source']['content_sha256']}
    if encode(auth) != encode(expected_auth):
        refuse('binding', 'prepare-authorization')
    return prepare


def require_assessment_context(context, profile, contract):
    """Shared structural revalidation, then separate trusted-caller expectation."""
    from sealed_measurement_contract import OwnedAssessmentAdmissionContext, OwnedAssessmentVariantContract
    if type(context) is not OwnedAssessmentAdmissionContext:
        refuse('syntax', 'wrong-shape')
    try:
        context.__post_init__()
    except (ValueError, AttributeError, TypeError):
        refuse('syntax', 'wrong-shape')
    if profile != PROFILE or context.profile != profile:
        refuse('support', 'unsupported-profile')
    if context.family != FAMILY:
        refuse('support', 'unsupported-family')
    structure = require_assessment_structure(context.assessment_inputs, require_collections=False)
    values = structure['values']; plan = values['plan']; plan_hash = values['execution']['plan_sha256']
    members = structure['members']; name = context.variant
    for actual, path in ((context.prepare_raw, name+'/prepare.json'),
                         (context.parent_authorization_raw, 'authorization.json'),
                         (context.variant_authorization_raw, name+'/authorization.json')):
        if actual != members[path]:
            refuse('binding', 'prepare-authorization')
    expected = require_expected(context.expected_raw)
    _require_expected_admission(expected, plan, plan_hash)
    variant = plan['variants'][VARIANTS.index(name)]
    derived = OwnedAssessmentVariantContract(plan_hash, name, variant['manifest']['sha256'],
        variant['tree_sha256'], values['execution']['ids'])
    if type(contract) is not OwnedAssessmentVariantContract or contract != derived:
        refuse('binding', 'plan-variant')
    return copy.deepcopy(structure['prepares'][name])


def derive_disposition(evaluation, observations, review, *, proposal_sha256, evidence_index_sha256):
    """Combine freshly recomputed gates with review; never mutate indexed gates.

    This internal composition primitive is not a receipt verifier. Its caller
    must use evaluate_assessment's result, not package-supplied gate claims.
    """
    if type(evaluation) is not AssessmentEvaluation:
        refuse('syntax', 'wrong-shape')
    evaluation.__post_init__()
    gates = decode(evaluation.gates_raw, max_bytes=65536, canonical=True)
    require_digest(proposal_sha256); require_digest(evidence_index_sha256)
    if type(gates) is not list or len(gates) != 9:
        refuse('syntax', 'wrong-shape')
    for n, gate in enumerate(gates):
        exact(gate, ('id', 'status', 'reason', 'witnesses'))
        if type(gate['id']) is not int or gate['id'] != n:
            refuse('replay', 'gate-mismatch')
        if gate['status'] not in ('passed', 'refused', 'not-run'):
            refuse('replay', 'gate-mismatch')
        if type(gate['witnesses']) is not list or len(gate['witnesses']) > 8:
            refuse('replay', 'gate-mismatch')
        for slot in gate['witnesses']:
            require_slot(slot)
    if encode(gates[7]) != encode(_gate(7, 'not-run', 'missing-review')):
        refuse('replay', 'gate-mismatch')
    if encode(gates[8]) != encode(_gate(8)):
        refuse('replay', 'gate-mismatch')
    if review is not None:
        if len(encode(review)) > 65536:
            refuse('limits', 'member-bytes')
        exact(review, ('schema', 'proposal_sha256', 'evidence_index_sha256', 'reviewer', 'decision', 'rationale'))
        if (review['schema'] != PREFIX+'review.v0' or review['proposal_sha256'] != proposal_sha256
                or review['evidence_index_sha256'] != evidence_index_sha256):
            refuse('replay', 'review-binding')
        text(review['reviewer']); text(review['rationale'])
        if review['decision'] not in ('accept', 'reject'):
            refuse('syntax', 'wrong-shape')
    # Even a late accept cannot override faithful failed/abnormal execution.
    if evaluation.envelope_unproved_slots or any(
            o['state'] != 'returned' or o['raw']['raised'] for o in observations):
        return 'unproved'
    checked = [g for g in gates if g['id'] != 7]
    if any(g['status'] == 'refused' for g in checked):
        return 'refused'
    if any(g['status'] != 'passed' for g in checked):
        refuse('replay', 'gate-mismatch')
    if review is None:
        return 'pending-review'
    return 'refused' if review['decision'] == 'reject' else 'eligible-for-human-corpus-PR'


# Shared legacy envelope state model. Runtime wrappers delegate here.
import kernel_readback as _kernel_readback

class EnvelopeContractError(_contained_contract.ContractError):
    def __init__(self, message):
        super().__init__(message, code="contradictory-record")

_envelope_ENVELOPE_SCHEMA = "corpus-adequacy.execution-envelope.v0"


_envelope_ENVELOPE_SCHEMA_V1 = "corpus-adequacy.execution-envelope.v1"


_envelope_ENVELOPE_SCHEMA_V2 = "corpus-adequacy.execution-envelope.v2"


_envelope_ENVELOPE_SCHEMA_V3 = "corpus-adequacy.execution-envelope.v3"


_envelope_ENVELOPE_SCHEMAS = (_envelope_ENVELOPE_SCHEMA, _envelope_ENVELOPE_SCHEMA_V1, _envelope_ENVELOPE_SCHEMA_V2, _envelope_ENVELOPE_SCHEMA_V3)


_envelope_OWNER_BOUND_SCHEMAS = (_envelope_ENVELOPE_SCHEMA_V2, _envelope_ENVELOPE_SCHEMA_V3)


_envelope_RESOURCE_OBSERVING_SCHEMAS = (_envelope_ENVELOPE_SCHEMA_V1, _envelope_ENVELOPE_SCHEMA_V2, _envelope_ENVELOPE_SCHEMA_V3)


_envelope_CONTAINED_PROFILE = "contained-oci-v0"


_envelope_CONTAINED_PROFILE_V1 = "contained-oci-v1"


_envelope_REQUESTED_RESOURCE_PROFILE = {
    _envelope_CONTAINED_PROFILE: _contained_contract.require_resource_profile,
    _envelope_CONTAINED_PROFILE_V1: _contained_contract.require_resource_profile_v2,
}


_envelope_ENVELOPE_SCHEMA_BY_PROFILE = {
    _envelope_CONTAINED_PROFILE: _envelope_ENVELOPE_SCHEMA,
    _envelope_CONTAINED_PROFILE_V1: _envelope_ENVELOPE_SCHEMA_V3,
}


_envelope_CONTAINED_USER = _contained_contract.CONTAINED_USER


_envelope_OFFLINE_ENV_NAME = "CARGO_NET_OFFLINE"


_envelope_SETUP_STATUSES = ("ready", "unavailable", "refused")


_envelope_ENVELOPE_STATUSES = ("verified", "unverified")


_envelope_CANDIDATE_OUTCOMES = ("completed", "timeout", "output-cap", "unproved", "not-run")


_envelope_CLEANUP_RESULTS = ("removed-and-absent", "remove-failed", "absence-unproved")


_envelope_PUBLICATION_PERMISSIONS = ("permitted", "withheld")


_envelope_EFFECTIVE_KEYS = (
    "cap_add", "cap_drop", "devices", "env_names", "image", "image_env_names",
    "memory", "memory_swap", "mounts", "network_mode", "no_new_privileges",
    "pid_mode", "pids_limit", "privileged", "read_only_root",
    "runtime_version", "tmpfs", "user", "userns_mode",
)


_envelope_EFFECTIVE_KEYS_V1 = _envelope_EFFECTIVE_KEYS + (
    "cpu_period", "cpu_quota", "daemon", "nano_cpus", "ulimit_nofile")


_envelope_EFFECTIVE_KEYS_V3 = _envelope_EFFECTIVE_KEYS_V1 + ("kernel",)


_envelope_REQUESTED_KEYS = (
    "execution_profile", "image_id", "mount_spec", "resource_profile", "sealed",
)


_envelope_REQUESTED_KEYS_V2 = _envelope_REQUESTED_KEYS + ("tmpfs",)


_envelope_ENVELOPE_KEYS = (
    "candidate_outcome", "cleanup", "effective", "envelope_status",
    "execution_commit", "non_claims", "prepare_sha256",
    "publication_permission", "report_sha256", "requested", "schema",
    "setup_status", "unverified_field", "withheld_reason",
)


_envelope_NON_CLAIMS = (
    "States the envelope one Docker daemon reported for one container on one "
    "host at one time.",
    "Does not prove kernel or runtime escape resistance.",
    "Does not prove the absence of side channels.",
    "Does not prove an uncompromised daemon or operator.",
    "Does not authenticate the candidate author or prove candidate correctness.",
    "Not a sandbox-completeness claim, not a score, not an audit, not a "
    "certification, and not publication authorization.",
)


def _envelope_effective_keys(schema):
    if schema == _envelope_ENVELOPE_SCHEMA:
        return _envelope_EFFECTIVE_KEYS
    if schema in (_envelope_ENVELOPE_SCHEMA_V1, _envelope_ENVELOPE_SCHEMA_V2):
        return _envelope_EFFECTIVE_KEYS_V1
    if schema == _envelope_ENVELOPE_SCHEMA_V3:
        return _envelope_EFFECTIVE_KEYS_V3
    raise EnvelopeContractError("envelope_schema_shape")


def _envelope_v1_integer(value, where):
    if type(value) is not int or value < 0:
        raise EnvelopeContractError(where)
    return value


def _envelope_v1_identity(value, where):
    if not isinstance(value, str) or not value.strip():
        raise EnvelopeContractError(where)
    return value


def _envelope_v1_options(value, where):
    if type(value) is not list or any(not isinstance(x, str) or not x for x in value):
        raise EnvelopeContractError(where)
    return sorted(value)


def _envelope_require_v1_values(effective):
    """Shared stored-value rules; projection cannot stand in for reader validation."""
    for key in ("cpu_period", "cpu_quota", "nano_cpus"):
        _envelope_v1_integer(effective[key], key)
    daemon = effective["daemon"]
    _envelope_require_exact(daemon, ("kernel_version", "cgroup_version", "cgroup_driver",
                            "security_options"), "daemon")
    for key in ("kernel_version", "cgroup_version", "cgroup_driver"):
        _envelope_v1_identity(daemon[key], "daemon." + key)
    options = daemon["security_options"]
    if options != _envelope_v1_options(options, "daemon.security_options"):
        raise EnvelopeContractError("daemon.security_options")
    nofile = effective["ulimit_nofile"]
    if nofile is not None:
        _envelope_require_exact(nofile, ("soft", "hard"), "ulimit_nofile")
        if (type(nofile["soft"]) is not int or type(nofile["hard"]) is not int or
                not 0 <= nofile["soft"] <= nofile["hard"]):
            raise EnvelopeContractError("ulimit_nofile")


def _envelope_require_kernel_readback(kernel, profile) -> None:
    """The kernel must hold exactly what was requested. The first problem names the field.

    A differing value is `readback_mismatch:<field>`, a value that did not read in the kernel's
    own form is `readback_unreadable:<field>`; either leaves the envelope unverified. This is the
    kernel's view for one container at one moment, not proof the limit was ever reached.
    """
    try:
        problems = _kernel_readback.compare(kernel, _kernel_readback.expected_readback(profile))
    except (_kernel_readback.ReadbackError, _contained_contract.ContractError) as exc:
        raise EnvelopeContractError("kernel") from exc
    if problems:
        raise EnvelopeContractError(problems[0])


def _envelope_resource_profile_loader(execution_profile):
    """The resource-profile loader a requested execution profile admits; any other refuses."""
    if (type(execution_profile) is not str or
            execution_profile not in _envelope_REQUESTED_RESOURCE_PROFILE):
        raise EnvelopeContractError("execution_profile")
    return _envelope_REQUESTED_RESOURCE_PROFILE[execution_profile]


def _envelope_envelope_schema_for_profile(execution_profile) -> str:
    """The envelope schema a candidate run under `execution_profile` emits."""
    if (type(execution_profile) is not str or
            execution_profile not in _envelope_ENVELOPE_SCHEMA_BY_PROFILE):
        raise EnvelopeContractError("execution_profile")
    return _envelope_ENVELOPE_SCHEMA_BY_PROFILE[execution_profile]


def _envelope_require_schema_profile(schema, execution_profile) -> None:
    if schema in _envelope_OWNER_BOUND_SCHEMAS and execution_profile != _envelope_CONTAINED_PROFILE_V1:
        raise EnvelopeContractError("envelope_schema_profile")


def _envelope_requested_envelope(*, execution_profile, image_id, mount_spec,
                       resource_profile, sealed, schema=None) -> dict:
    """The declaration side. These values are compared, never projected.

    The pinned image's own environment is NOT here: it is an observation of
    an immutable artifact, so it sits in `effective` and the environment
    check is observation against observation, with no declaration involved.
    """
    loader = _envelope_resource_profile_loader(execution_profile)
    if type(sealed) is not bool:
        raise EnvelopeContractError("sealed")
    if schema is None:
        schema = _envelope_ENVELOPE_SCHEMA
    if schema not in _envelope_ENVELOPE_SCHEMAS:
        raise EnvelopeContractError("envelope_schema_shape")
    _envelope_require_schema_profile(schema, execution_profile)
    requested = {
        "execution_profile": execution_profile,
        "image_id": _contained_contract.require_image_id(image_id),
        "mount_spec": sorted(
            destination for _key, destination
            in _contained_contract._require_mount_spec(mount_spec)),
        "resource_profile": loader(resource_profile),
        "sealed": sealed,
    }
    if schema in _envelope_OWNER_BOUND_SCHEMAS:
        requested["tmpfs"] = {
            destination: _contained_contract.tmpfs_request(
                requested["resource_profile"], destination=destination, owner_bound=True)
            for destination in ("/tmp", "/work")
        }
    return requested


def _envelope_require_exact(doc, keys, where: str) -> None:
    if type(doc) is not dict or set(doc) != set(keys):
        raise EnvelopeContractError(where)


def _envelope_require_requested_record(requested, *, schema=None) -> dict:
    """Validate that a stored requested declaration conforms to the closed schema.

    Enforces that execution_profile is a contained profile paired with its own
    resource-profile version (contained-oci-v0 with RESOURCE_PROFILE_SCHEMA,
    contained-oci-v1 with RESOURCE_PROFILE_V2_SCHEMA), image_id is a valid
    sha256 digest, sealed is strictly a bool, resource_profile has positive
    integer limits and bool work_exec, and mount_spec is a strictly sorted
    list of unique destination strings starting with '/'.
    """
    keys = _envelope_REQUESTED_KEYS_V2 if schema in _envelope_OWNER_BOUND_SCHEMAS else _envelope_REQUESTED_KEYS
    _envelope_require_exact(requested, keys, "requested")
    _envelope_require_schema_profile(schema, requested["execution_profile"])
    loader = _envelope_resource_profile_loader(requested["execution_profile"])
    try:
        _contained_contract.require_image_id(requested["image_id"])
    except _contained_contract.ContractError as exc:
        raise EnvelopeContractError("image_id") from exc
    if type(requested["sealed"]) is not bool:
        raise EnvelopeContractError("sealed")
    try:
        loader(requested["resource_profile"])
    except _contained_contract.ContractError as exc:
        raise EnvelopeContractError("resource_profile") from exc
    mount_spec = requested["mount_spec"]
    try:
        _contained_contract.validate_mount_destinations(mount_spec, strictly_sorted=True)
    except _contained_contract.ContractError as exc:
        raise EnvelopeContractError("mount_spec") from exc
    if schema in _envelope_OWNER_BOUND_SCHEMAS:
        expected_tmpfs = {
            destination: _contained_contract.tmpfs_request(
                requested["resource_profile"], destination=destination, owner_bound=True)
            for destination in ("/tmp", "/work")
        }
        try:
            for spec in requested["tmpfs"].values():
                _contained_contract.require_tmpfs_spec(spec, owner_bound=True)
        except (AttributeError, _contained_contract.ContractError) as exc:
            raise EnvelopeContractError("tmpfs") from exc
        if requested["tmpfs"] != expected_tmpfs:
            raise EnvelopeContractError("tmpfs")
    return requested


def _envelope_requests_cpu_and_nofile(requested) -> bool:
    """A v2 resource profile is a request for CPU and nofile limits; a v1 one is not.

    After `require_requested_record` this is exactly a contained-oci-v1 request, since that
    profile pairs only with a v2 resource profile.
    """
    return requested["resource_profile"]["schema"] == _contained_contract.RESOURCE_PROFILE_V2_SCHEMA


def _envelope_require_cpu_and_nofile_match(effective, profile) -> None:
    """Exact comparison of daemon-stored CPU and nofile against a v2 request.

    The daemon may discard a limit and store it unset (0, or no nofile entry); that reads as a
    mismatch here, never as satisfied. `NanoCpus` must be stored unset: moby refuses it beside a
    CFS period, so a nonzero value next to the requested period/quota is not what the v2 codec
    asked for. This compares configuration the daemon reports, not a limit the kernel applied.
    """
    if effective["cpu_period"] != _contained_contract.CPU_PERIOD_USEC:
        raise EnvelopeContractError("cpu_period")
    if effective["cpu_quota"] != _contained_contract.cpu_quota_usec(profile):
        raise EnvelopeContractError("cpu_quota")
    if effective["nano_cpus"] != 0:
        raise EnvelopeContractError("nano_cpus")
    if effective["ulimit_nofile"] != {
            "soft": profile["nofile_soft"], "hard": profile["nofile_hard"]}:
        raise EnvelopeContractError("ulimit_nofile")


def _envelope_require_envelope_matches_request(effective, requested, *, schema=_envelope_ENVELOPE_SCHEMA) -> None:
    """Hold one observation against one declaration. Observation cannot yield.

    The v0 fields retain their declaration comparisons. For a v2 request the
    observed CPU period, quota and nofile soft/hard are compared exactly and
    NanoCpus must be stored unset (0), so a v2 request needs a v1 or v2 envelope.
    For a v1 resource request those fields, and the daemon fields always, are
    observations with shape checks, not requested limits.
    """
    _envelope_require_requested_record(requested, schema=schema)
    _envelope_require_exact(effective, _envelope_effective_keys(schema),
                       "effective" if schema == _envelope_ENVELOPE_SCHEMA else "envelope_schema_shape")
    if schema in _envelope_RESOURCE_OBSERVING_SCHEMAS:
        _envelope_require_v1_values(effective)
    profile = requested["resource_profile"]
    if _envelope_requests_cpu_and_nofile(requested) and schema not in _envelope_RESOURCE_OBSERVING_SCHEMAS:
        raise EnvelopeContractError("envelope_schema_profile")

    if effective["image"] != requested["image_id"]:
        raise EnvelopeContractError("image")
    if not isinstance(effective["runtime_version"], str) or not effective[
            "runtime_version"].strip():
        raise EnvelopeContractError("runtime_version")
    if type(effective["privileged"]) is not bool or effective["privileged"] is not False:
        raise EnvelopeContractError("privileged")
    if effective["cap_add"] != [] or type(effective["cap_add"]) is not list:
        raise EnvelopeContractError("cap_add")
    if effective["cap_drop"] != ["ALL"] or type(effective["cap_drop"]) is not list:
        raise EnvelopeContractError("cap_drop")
    if effective["devices"] != [] or type(effective["devices"]) is not list:
        raise EnvelopeContractError("devices")
    if effective["pid_mode"] != "":
        raise EnvelopeContractError("pid_mode")
    if effective["userns_mode"] != "":
        raise EnvelopeContractError("userns_mode")
    if type(effective["no_new_privileges"]) is not bool or effective["no_new_privileges"] is not True:
        raise EnvelopeContractError("no_new_privileges")
    if type(effective["read_only_root"]) is not bool or effective["read_only_root"] is not True:
        raise EnvelopeContractError("read_only_root")
    if effective["user"] != _envelope_CONTAINED_USER:
        raise EnvelopeContractError("user")

    sealed = requested["sealed"]
    if sealed and effective["network_mode"] != "none":
        raise EnvelopeContractError("network_mode")
    if not sealed and effective["network_mode"] == "none":
        raise EnvelopeContractError("network_mode")

    if type(effective["memory"]) is not int or effective["memory"] != profile["memory_bytes"]:
        raise EnvelopeContractError("memory")
    if type(effective["memory_swap"]) is not int or effective["memory_swap"] != profile["memory_swap_bytes"]:
        raise EnvelopeContractError("memory_swap")
    if type(effective["pids_limit"]) is not int or effective["pids_limit"] != profile["pids"]:
        raise EnvelopeContractError("pids_limit")

    if type(effective["tmpfs"]) is not dict:
        raise EnvelopeContractError("tmpfs")
    expected_tmpfs = requested["tmpfs"] if schema in _envelope_OWNER_BOUND_SCHEMAS else {
        "/tmp": {"exec": False, "nr_inodes": profile["tmp_inodes"],
                 "size": profile["tmp_bytes"]},
        "/work": {"exec": profile["work_exec"],
                  "nr_inodes": profile["work_inodes"], "size": profile["work_bytes"]},
    }
    if schema in _envelope_OWNER_BOUND_SCHEMAS:
        try:
            for spec in effective["tmpfs"].values():
                _contained_contract.require_tmpfs_spec(spec, owner_bound=True)
        except (AttributeError, _contained_contract.ContractError) as exc:
            raise EnvelopeContractError("tmpfs") from exc
    if effective["tmpfs"] != expected_tmpfs:
        raise EnvelopeContractError("tmpfs")
    if schema not in _envelope_OWNER_BOUND_SCHEMAS:
        for _dest, spec in effective["tmpfs"].items():
            if type(spec) is not dict:
                raise EnvelopeContractError("tmpfs")
            if type(spec.get("exec")) is not bool:
                raise EnvelopeContractError("tmpfs")
            if type(spec.get("nr_inodes")) is not int or type(spec.get("size")) is not int:
                raise EnvelopeContractError("tmpfs")

    # The allowed environment is the pinned image's own observed environment
    # plus exactly what the create argv adds. A name injected at create time
    # is outside that set by construction, so no denylist is needed and no
    # value is ever read.
    if type(effective["image_env_names"]) not in (list, tuple) or any(
            not isinstance(name, str) or not name for name in effective["image_env_names"]):
        raise EnvelopeContractError("image_env_names")
    if type(effective["env_names"]) not in (list, tuple) or any(
            not isinstance(name, str) or not name for name in effective["env_names"]):
        raise EnvelopeContractError("env_names")

    allowed = set(effective["image_env_names"])
    if sealed:
        allowed.add(_envelope_OFFLINE_ENV_NAME)
    if set(effective["env_names"]) - allowed:
        raise EnvelopeContractError("env_names")
    if sealed != (_envelope_OFFLINE_ENV_NAME in effective["env_names"]):
        raise EnvelopeContractError("env_names")

    if type(effective["mounts"]) not in (list, tuple):
        raise EnvelopeContractError("mounts")
    for mount in effective["mounts"]:
        if type(mount) is not dict:
            raise EnvelopeContractError("mounts")
        if type(mount.get("rw")) is not bool or mount.get("rw") is not False:
            raise EnvelopeContractError("mounts")
        if not isinstance(mount.get("destination"), str) or not isinstance(mount.get("type"), str):
            raise EnvelopeContractError("mounts")

    expected_mounts = [
        {"destination": destination, "rw": False, "type": "bind"}
        for destination in requested["mount_spec"]
    ]
    if effective["mounts"] != expected_mounts:
        raise EnvelopeContractError("mounts")

    if _envelope_requests_cpu_and_nofile(requested):
        _envelope_require_cpu_and_nofile_match(effective, profile)
    if schema == _envelope_ENVELOPE_SCHEMA_V3:
        _envelope_require_kernel_readback(effective["kernel"], profile)


def _envelope_require_member(value, members, where: str) -> str:
    for member in members:
        if value == member:
            return member
    raise EnvelopeContractError(where)


def _envelope_require_hex(value, length: int, where: str) -> str:
    if (not isinstance(value, str) or len(value) != length or
            any(ch not in _contained_contract.HEX64 for ch in value)):
        raise EnvelopeContractError(where)
    return value


def envelope_permission_data(*, setup_status, envelope_status, candidate_outcome,
                           cleanup) -> tuple[str, str | None]:
    """One rule. Permission is derived, never supplied."""
    if setup_status != "ready":
        return "withheld", "setup_status"
    if envelope_status != "verified":
        return "withheld", "envelope_status"
    if candidate_outcome != "completed":
        return "withheld", "candidate_outcome"
    if cleanup != "removed-and-absent":
        return "withheld", "cleanup"
    return "permitted", None


def _envelope_build_envelope_record(*, requested, setup_status, envelope_status,
                          unverified_field, effective, candidate_outcome,
                          cleanup, prepare_sha256, execution_commit,
                          report_sha256, schema=_envelope_ENVELOPE_SCHEMA) -> dict:
    """Close the state model over one contained run.

    Setup, candidate and cleanup failures are preserved rather than folded
    together, and no combination manufactures a score. There is deliberately
    no `publication_permission` parameter: it cannot be caller-supplied.
    """
    _envelope_effective_keys(schema)
    _envelope_require_requested_record(requested, schema=schema)
    # A v2 resource request needs v1's CPU/nofile fields. Historical v1 and v2 records remain
    # valid; new contained-oci-v1 emissions select v3, which also carries the kernel read-back.
    if _envelope_requests_cpu_and_nofile(requested) and schema not in _envelope_RESOURCE_OBSERVING_SCHEMAS:
        raise EnvelopeContractError("envelope_schema_profile")
    setup_status = _envelope_require_member(setup_status, _envelope_SETUP_STATUSES, "setup_status")
    envelope_status = _envelope_require_member(
        envelope_status, _envelope_ENVELOPE_STATUSES, "envelope_status")
    candidate_outcome = _envelope_require_member(
        candidate_outcome, _envelope_CANDIDATE_OUTCOMES, "candidate_outcome")
    cleanup = _envelope_require_member(cleanup, _envelope_CLEANUP_RESULTS, "cleanup")

    if setup_status != "ready":
        if candidate_outcome != "not-run":
            raise EnvelopeContractError("candidate_outcome")
        if envelope_status != "unverified":
            raise EnvelopeContractError("envelope_status")
        if effective is not None:
            raise EnvelopeContractError("effective")

    if envelope_status == "verified":
        if unverified_field is not None:
            raise EnvelopeContractError("unverified_field")
        _envelope_require_exact(effective, _envelope_effective_keys(schema),
                       "effective" if schema == _envelope_ENVELOPE_SCHEMA else "envelope_schema_shape")
        _envelope_require_envelope_matches_request(effective, requested, schema=schema)
    else:
        if not isinstance(unverified_field, str) or not unverified_field:
            raise EnvelopeContractError("unverified_field")
        if effective is not None:
            raise EnvelopeContractError("effective")

    permission, reason = envelope_permission_data(
        setup_status=setup_status,
        envelope_status=envelope_status,
        candidate_outcome=candidate_outcome,
        cleanup=cleanup,
    )
    record = {
        "candidate_outcome": candidate_outcome,
        "cleanup": cleanup,
        "effective": None if effective is None else dict(effective),
        "envelope_status": envelope_status,
        "execution_commit": _envelope_require_hex(execution_commit, 40, "execution_commit"),
        "non_claims": list(_envelope_NON_CLAIMS),
        "prepare_sha256": _envelope_require_hex(prepare_sha256, 64, "prepare_sha256"),
        "publication_permission": permission,
        "report_sha256": (
            None if report_sha256 is None
            else _envelope_require_hex(report_sha256, 64, "report_sha256")),
        "requested": dict(requested),
        "schema": schema,
        "setup_status": setup_status,
        "unverified_field": unverified_field,
        "withheld_reason": reason,
    }
    _envelope_require_exact(record, _envelope_ENVELOPE_KEYS, "envelope")
    return record


def _envelope_bind_report(record: dict, report_sha256) -> dict:
    """Attach the produced report digest. Envelope to report, never back."""
    _envelope_require_exact(record, _envelope_ENVELOPE_KEYS, "envelope")
    _envelope_effective_keys(record["schema"])
    return _envelope_build_envelope_record(
        schema=record["schema"],
        requested=record["requested"],
        setup_status=record["setup_status"],
        envelope_status=record["envelope_status"],
        unverified_field=record["unverified_field"],
        effective=record["effective"],
        candidate_outcome=record["candidate_outcome"],
        cleanup=record["cleanup"],
        prepare_sha256=record["prepare_sha256"],
        execution_commit=record["execution_commit"],
        report_sha256=report_sha256,
    )


def require_envelope_record_data(record: dict) -> dict:
    """Validate that an execution-envelope record is internally consistent.

    Reconstructs the envelope record through bind_report and requires exact
    equality with the original document. Round-trip equality verifies the
    closure of the state model (derived publication permission, withheld reason,
    schema, non-claims, and state invariants) against explicit nested validators
    for requested declarations and effective observations. It does not prove
    that the record was authentic or produced by a specific unverified run.
    An inconsistent or mutated record raises EnvelopeError and is never
    normalized into a pass.
    """
    if type(record) is not dict:
        raise EnvelopeContractError("envelope")
    _envelope_require_exact(record, _envelope_ENVELOPE_KEYS, "envelope")
    _envelope_effective_keys(record["schema"])
    rebuilt = _envelope_bind_report(record, record["report_sha256"])
    if rebuilt != record:
        raise EnvelopeContractError("envelope_semantic_mismatch")
    return record




@dataclass(frozen=True, slots=True)
class AssessmentEvaluation:
    """Local recomputation result, never a retained package authority."""
    gates_raw: bytes
    envelope_unproved_slots: tuple[int, ...]

    def __post_init__(self):
        if type(self.gates_raw) is not bytes or len(self.gates_raw) > 65536:
            refuse('syntax', 'wrong-shape')
        slots = self.envelope_unproved_slots
        if (type(slots) is not tuple or any(type(n) is not int or not 0 <= n < 8 for n in slots)
                or tuple(sorted(set(slots))) != slots):
            refuse('syntax', 'wrong-shape')


def _evidence_members(snapshot):
    if type(snapshot) is not tuple or len(snapshot) > 23:
        refuse('limits', 'entry-count')
    members = _members(snapshot, count=len(snapshot), max_bytes=262144)
    for path, raw in members.items():
        if not path.endswith('/envelopes/collection-index.v0.json') and len(raw) > 65536:
            refuse('limits', 'member-bytes')
    return members


def _require_inventory(members, expected):
    if set(expected) - members.keys():
        refuse('filesystem', 'missing-member')
    if members.keys() - set(expected):
        refuse('filesystem', 'surplus-member')


def require_assessment_structure(inputs, *, require_collections):
    """One pure structural policy; external expected/approval never enters here."""
    if type(inputs) is not AssessmentInputs or type(require_collections) is not bool:
        refuse('syntax', 'wrong-shape')
    try:
        inputs.__post_init__()
    except (AttributeError, TypeError):
        refuse('syntax', 'wrong-shape')
    members = _evidence_members(inputs.evidence_members)
    preflight = AssessmentInputs(inputs.retained_members, inputs.basis_members)
    gates, values = evaluate_preflight(preflight)
    if values is None or any(g['status'] != 'passed' for g in gates):
        refuse('replay', 'preflight-refused')
    plan = values['plan']; plan_hash = values['execution']['plan_sha256']
    required = {'authorization.json'}
    for name in VARIANTS:
        required.update(name+'/'+p for p in ('prepare.json','authorization.json',
            'pins/control.json','pins/sites.json','pins/manifest.json','pins/pins.json'))
    collection_paths = set()
    if require_collections:
        for name in VARIANTS:
            required.add(name+'/envelopes/collection-index.v0.json')
        for path in members:
            if re.fullmatch(r'(base|outer-whitespace)/envelopes/member-000[0-3]\.json', path):
                collection_paths.add(path)
    _require_inventory(members, required | collection_paths)
    prepares = {}
    for name, variant in zip(VARIANTS, plan['variants']):
        prepare = _require_variant_preparation(values, name, members[name+'/prepare.json'],
            members['authorization.json'], members[name+'/authorization.json'])
        # Fixed owned execution manifest includes runner/selectors/build/entrypoint/mutations.
        # Original legacy bytes are admitted by their code-owned pin, not normalized JSON.
        for pin in ('control.json', 'sites.json', 'manifest.json'):
            if digest(members[name+'/pins/'+pin]) != _OWNED.pin_digest(pin):
                refuse('binding', 'corpus-derivation')
        pins_raw = members[name+'/pins/pins.json']
        pins = decode(pins_raw, max_bytes=65536, canonical=True)
        expected_pins = {'schema': PREFIX+'pins.v0', 'plan_sha256': plan_hash, 'variant': name,
            'instrument_commit': _OWNED.instrument_commit, 'subject_tree_sha256': _OWNED.subject_tree_sha256,
            'adapter_sha256': _OWNED.adapter_sha256,
            'corpus': {'kind':'local-derived-owned-v0', 'plan_sha256':plan_hash, 'variant':name,
                'manifest_sha256':variant['manifest']['sha256'], 'tree_sha256':variant['tree_sha256'],
                'corpus_digest':variant['corpus_digest'], 'ids':list(values['execution']['ids'])},
            'control_sha256':_OWNED.pin_digest('control.json'), 'sites_sha256':_OWNED.pin_digest('sites.json'),
            'manifest_sha256':_OWNED.pin_digest('manifest.json')}
        if encode(pins) != encode(expected_pins) or prepare['pins_sha256'] != digest(pins_raw):
            refuse('binding', 'prepare-authorization')
        prepares[name] = prepare
    return {'gates':gates, 'values':values, 'members':members, 'prepares':prepares}


_COLLECTION_SCHEMAS = ('corpus-adequacy.execution-envelope-collection.v0',
                       'corpus-adequacy.execution-envelope-collection.v1')
_COLLECTION_NON_CLAIMS = (
    'States that these attempted invocations left these records in one collection run.',
    'Does not authenticate origin: a digest binds bytes, not who produced them.',
    'Cannot detect substitution of a byte-identical record from a different run.',
    'Not a score, not an audit, not a certification, and not publication authorization.',
)
_COLLECTION_NON_CLAIMS_V1 = _COLLECTION_NON_CLAIMS + (
    "Step attribution is the engine's own record of what it ran; the run nonce names this "
    'index, not its members, so a byte-identical member remains substitutable.',)


def parse_collection_snapshot(snapshot):
    """Bounded transport codec over retained bytes, then the single envelope judge.

    Historical schemas remain supported here; the assessment consumer requires v1/v3.
    Strict JSON/types are intentional new-domain constraints, not legacy loader changes.
    """
    if type(snapshot) is not tuple or len(snapshot) > 257:
        refuse('limits', 'entry-count')
    members = _members(snapshot, count=len(snapshot), max_bytes=262144)
    index_name = 'collection-index.v0.json'
    if index_name not in members:
        refuse('filesystem', 'missing-member')
    index = decode(members[index_name], max_bytes=262144)
    if type(index) is not dict or index.get('schema') not in _COLLECTION_SCHEMAS:
        refuse('support', 'unsupported-schema')
    v1 = index['schema'] == _COLLECTION_SCHEMAS[1]
    keys = ('attempts','execution_commit','ledger','members','non_claims','prepare_sha256','report_sha256','schema')
    exact(index, keys + (('run_nonce',) if v1 else ()))
    if index['non_claims'] != list(_COLLECTION_NON_CLAIMS_V1 if v1 else _COLLECTION_NON_CLAIMS):
        refuse('syntax', 'wrong-shape')
    if v1 and (type(index['run_nonce']) is not str or not re.fullmatch('[0-9a-f]{32}',index['run_nonce'])):
        refuse('syntax', 'wrong-shape')
    attempts = index['attempts']; rows = index['ledger']; entries = index['members']
    if type(attempts) is not int or not 0 <= attempts <= 256:
        refuse('syntax', 'wrong-shape')
    if type(rows) is not list or len(rows) != attempts or type(entries) is not list or len(entries) > 256:
        refuse('syntax', 'wrong-shape')
    for key, size in (('execution_commit',40),('prepare_sha256',64),('report_sha256',64)):
        value=index[key]
        if value is not None and (type(value) is not str or not re.fullmatch('[0-9a-f]{'+str(size)+'}',value)):
            refuse('syntax', 'wrong-shape')
    recorded=[]
    for ordinal,row in enumerate(rows):
        if type(row) is not dict or row.get('state') not in ('recorded','raised','no-envelope'):
            refuse('syntax', 'wrong-shape')
        row_keys=('ordinal','state') + (('step','returncode','run_nonce','previous_member_sha256') if v1 else ())
        exact(row, row_keys + (('exception_type',) if row['state']=='raised' else ()))
        if type(row['ordinal']) is not int or row['ordinal'] != ordinal:
            refuse('replay', 'schedule-mismatch')
        if row['state']=='raised': text(row['exception_type'],128)
        if row['state']=='recorded': recorded.append(ordinal)
        if v1:
            step=exact(row['step'],('kind','group','id'))
            if step['kind'] not in ('build','baseline','control','mutant'):
                refuse('syntax','wrong-shape')
            for key in ('group','id'):
                if step[key] is not None:text(step[key],128)
            if ((step['kind'] in ('control','mutant') and step['group'] is None)
                    or (step['kind'] in ('build','baseline') and step['id'] is not None)):
                refuse('syntax','wrong-shape')
            if row['run_nonce'] != index['run_nonce']:
                refuse('replay','schedule-mismatch')
            rc=row['returncode']
            if rc is not None and (row['state']!='recorded' or type(rc) is not int or not -(2**31)<=rc<2**31):
                refuse('syntax','wrong-shape')
    for entry in entries:
        exact(entry,('ordinal','relpath','sha256'))
        if type(entry['ordinal']) is not int:refuse('syntax','wrong-shape')
        require_digest(entry['sha256'])
    if [e['ordinal'] for e in entries] != recorded:
        refuse('replay','schedule-mismatch')
    required={index_name}; docs=[]; digests={}; total=0
    for entry in entries:
        name='member-%04d.json'%entry['ordinal']
        if entry['relpath']!=name:refuse('replay','schedule-mismatch')
        required.add(name)
        if name not in members:refuse('filesystem','missing-member')
        raw=members[name];total+=len(raw)
        if len(raw)>65536:refuse('limits','member-bytes')
        if total>5242880-262144:refuse('limits','aggregate-bytes')
        if digest(raw)!=entry['sha256']:refuse('binding','envelope-binding')
        doc=decode(raw,max_bytes=65536)
        try:
            require_envelope_record_data(doc)
        except _contained_contract.ContractError:
            refuse('envelope','contradictory-record')
        if doc['report_sha256'] != index['report_sha256']:
            refuse('binding','envelope-binding')
        docs.append(doc);digests[entry['ordinal']]=digest(raw)
    _require_inventory(members,required)
    if v1:
        previous=None
        for row in rows:
            if row['previous_member_sha256']!=previous:refuse('replay','schedule-mismatch')
            if row['state']=='recorded':previous=digests[row['ordinal']]
    return {'index':index,'ledger':rows,'members':docs}


def _assessment_envelopes(structure, observations):
    raw_members=structure['members']; unproved=[]
    for name in VARIANTS:
        prefix=name+'/envelopes/'
        snapshot=tuple((p.removeprefix(prefix),raw) for p,raw in sorted(raw_members.items()) if p.startswith(prefix))
        loaded=parse_collection_snapshot(snapshot);index=loaded['index'];rows=loaded['ledger']
        entered=[o for o in observations if o['slot']['variant']==name]
        if index['schema']!=_COLLECTION_SCHEMAS[1]:refuse('support','unsupported-schema')
        if len(rows)!=len(entered) or len(rows)>4:refuse('replay','schedule-mismatch')
        prepare=structure['prepares'][name]; prepare_hash=digest(raw_members[name+'/prepare.json'])
        source=prepare['source']['commit']; recorded=loaded['members']
        if (index['report_sha256'] is not None or
                index['prepare_sha256'] != (prepare_hash if recorded else None) or
                index['execution_commit'] != (source if recorded else None)):
            refuse('binding','envelope-binding')
        records=iter(recorded)
        for row,obs in zip(rows,entered):
            slot=obs['slot']; ordinal=require_slot(slot)
            if row['ordinal']!=slot['ordinal'] or encode(row['step'])!=encode(slot['step']):
                refuse('replay','schedule-mismatch')
            if row['state']!='recorded':
                if obs['envelope'] is not None:refuse('binding','envelope-binding')
                if (row['state']=='raised') != (obs['state']=='exception'):
                    refuse('replay','schedule-mismatch')
                unproved.append(ordinal);continue
            doc=next(records)
            if doc['schema']!=_envelope_ENVELOPE_SCHEMA_V3:refuse('support','unsupported-schema')
            path=prefix+'member-%04d.json'%row['ordinal'];raw=raw_members[path]
            expected_ref={'member':path,'sha256':digest(raw),'bytes':len(raw)}
            if encode(obs['envelope'])!=encode(expected_ref):refuse('binding','envelope-binding')
            requested=_envelope_requested_envelope(execution_profile=PROFILE,
                image_id=prepare['runtime']['toolchain']['image_id'],
                mount_spec=_contained_contract.DEFAULT_MOUNT_SPEC+(('subject','/subject'),),
                resource_profile=prepare['runtime']['candidate_profile'],sealed=True,
                schema=_envelope_ENVELOPE_SCHEMA_V3)
            if (doc['execution_commit']!=source or doc['prepare_sha256']!=prepare_hash
                    or doc['report_sha256'] is not None or encode(doc['requested'])!=encode(requested)):
                refuse('binding','envelope-binding')
            if doc['publication_permission']!='permitted' or doc['envelope_status']!='verified':
                unproved.append(ordinal)
    return tuple(unproved)


# Closed package grammar. Neither an index nor a package field can widen it.
CORPUS_NAMES = ('MANIFEST.json', 'allow.json', 'boundary.json', 'negative.json',
                'over-limit.json')
RETAINED_PATHS = frozenset(('plan.json', 'proposal.json', 'reference.json')) | frozenset(
    f'{v}/corpus/{name}' for v in VARIANTS for name in CORPUS_NAMES)
PREPARATION_PATHS = frozenset(('authorization.json',)) | frozenset(
    f'{v}/{name}' for v in VARIANTS for name in ('prepare.json', 'authorization.json',
    'pins/control.json', 'pins/sites.json', 'pins/manifest.json', 'pins/pins.json'))
COLLECTION_INDICES = frozenset(f'{v}/envelopes/collection-index.v0.json' for v in VARIANTS)
COLLECTION_MEMBERS = frozenset(f'{v}/envelopes/member-{i:04d}.json' for v in VARIANTS for i in range(4))
OBSERVATION_PATHS = tuple(f'{v}/observations/{i}.json' for v in VARIANTS for i in range(4))
VIEW_PATHS = tuple(f'{v}/views/{i}.json' for v in VARIANTS for i in range(4))
FINAL_PATHS = frozenset(('evidence-index.json', 'decision.json', 'receipt.json'))
REQUIRED_PATHS = RETAINED_PATHS | PREPARATION_PATHS | COLLECTION_INDICES | FINAL_PATHS | {'journal.jsonl', 'gates.json'}
PACKAGE_PATHS = REQUIRED_PATHS | COLLECTION_MEMBERS | frozenset(OBSERVATION_PATHS+VIEW_PATHS) | {'review.json'}
PACKAGE_DIRS = frozenset('/'.join(p.split('/')[:i]) for p in PACKAGE_PATHS for i in range(1, len(p.split('/'))))


def package_member_kind(path):
    if type(path) is str and re.fullmatch(r'(base|outer-whitespace)/corpus/[a-z0-9][a-z0-9-]{0,62}\.json',path):
        return ('corpora',65536)
    if path not in PACKAGE_PATHS:
        refuse('filesystem', 'surplus-member')
    if path in COLLECTION_INDICES: return ('envelopes', 262144)
    if path in COLLECTION_MEMBERS: return ('envelopes', 65536)
    if path in OBSERVATION_PATHS: return ('observations', 1048576)
    if path in VIEW_PATHS: return ('views', 1048576)
    if '/corpus/' in path: return ('corpora', 65536)
    if path == 'journal.jsonl': return ('journal', 65536)
    return ('metadata', 65536)


def read_journal(raw):
    """Frame first; a final valid JSON fragment still is not a settled event."""
    if len(raw) > 65536: refuse('limits', 'member-bytes')
    if raw and not raw.endswith(b'\n'): refuse('journal', 'partial-event')
    lines = raw.splitlines(keepends=True)
    if len(lines) > 32: refuse('limits', 'journal-events')
    events = []
    for line in lines:
        event = decode(line, max_bytes=2048, canonical=True)
        exact(event, ('schema', 'seq', 'plan_sha256', 'slot', 'event', 'observation', 'reason'))
        if event['schema'] != PREFIX+'journal-event.v0': refuse('support', 'unsupported-schema')
        require_digest(event['plan_sha256']); require_slot(event['slot'])
        if event['observation'] is not None: require_ref(event['observation'])
        events.append(event)
    # Reuse the sole schedule validator, with event-derived shape-only observations.
    # This catches an unsettled start before surplus observation/index checks.
    normalized = [{k: e[k] for k in ('seq','slot','event','reason')} for e in events]
    settled = [{'slot': e['slot'], 'state': 'returned' if e['event']=='returned' else 'exception'}
               for e in events if e['event'] in ('returned','exception')]
    _journal(normalized, settled)
    return events


def _new_record(raw, schema, fields, *, max_bytes=65536):
    doc = decode(raw, max_bytes=max_bytes, canonical=True)
    exact(doc, fields)
    if doc['schema'] != PREFIX+schema: refuse('support', 'unsupported-schema')
    return doc


def _raw_ref(members, path):
    return {'member': path, 'sha256': digest(members[path]), 'bytes': len(members[path])}


def _check_ref(ref, members):
    require_ref(ref)
    if ref['member'] not in members: refuse('filesystem', 'missing-member')
    if encode(ref) != encode(_raw_ref(members, ref['member'])): refuse('binding', 'member-digest')


def decode_package(snapshot, basis):
    """Closed raw-byte/index framing followed by inputs for the one evaluator.

    This is not another gate judge. All assessment semantics live in
    evaluate_assessment; package framing cannot select a smaller policy.
    """
    if type(snapshot) is not tuple or len(snapshot) > 128: refuse('limits', 'entry-count')
    members = _members(snapshot, count=len(snapshot), max_bytes=1048576)
    for path, raw in members.items():
        _, cap = package_member_kind(path)
        if len(raw)>cap: refuse('limits','member-bytes')
    if REQUIRED_PATHS-set(members): refuse('filesystem','missing-member')
    journal = read_journal(members['journal.jsonl'])
    # Refuse unsupported/malformed bytes before interpreting digest or gate claims.
    # This pass has no dispatch and does not read the filesystem again.
    new_schemas = {'plan.json':'plan.v0','reference.json':'reference.v0',
        'authorization.json':'authorization.v0','gates.json':'gates.v0',
        'evidence-index.json':'evidence-index.v0','review.json':'review.v0',
        'decision.json':'decision.v0','receipt.json':'receipt.v0'}
    for variant in VARIANTS:
        new_schemas.update({variant+'/'+p:schema for p,schema in (
            ('prepare.json','prepare.v0'),('authorization.json','variant-authorization.v0'),
            ('pins/pins.json','pins.v0'))})
    new_schemas.update({p:'observation.v0' for p in OBSERVATION_PATHS})
    new_schemas.update({p:'view.v0' for p in VIEW_PATHS})
    for path,raw in members.items():
        if path=='journal.jsonl': continue
        doc=decode(raw,max_bytes=package_member_kind(path)[1],canonical=path in new_schemas)
        schema=new_schemas.get(path)
        if schema and (type(doc) is not dict or doc.get('schema')!=PREFIX+schema):
            refuse('support','crossed-prepare' if path.endswith('/prepare.json') else 'unsupported-schema')
        if path in COLLECTION_INDICES and (type(doc) is not dict or doc.get('schema')!=_COLLECTION_SCHEMAS[1]):
            refuse('support','unsupported-schema')
        if path in COLLECTION_MEMBERS and (type(doc) is not dict or doc.get('schema')!=_envelope_ENVELOPE_SCHEMA_V3):
            refuse('support','unsupported-schema')

    observation_paths = []
    observations, views = [], []
    view_paths = []
    for event in journal:
        if event['event'] not in ('returned','exception'): continue
        n = require_slot(event['slot']); path=OBSERVATION_PATHS[n]
        observation_paths.append(path)
        if path not in members: refuse('filesystem','missing-member')
        observation=_new_record(members[path],'observation.v0',
            ('schema','plan_sha256','slot','route','profile','state','raw','sanitized_reason','exception_kind','envelope'),
            max_bytes=1048576)
        if type(observation) is not dict or 'slot' not in observation: refuse('syntax','wrong-shape')
        if encode(observation['slot']) != encode(event['slot']): refuse('replay','schedule-mismatch')
        observations.append(observation)
        if event['event']=='returned':
            view_path=VIEW_PATHS[n];view_paths.append(view_path)
            if view_path not in members: refuse('filesystem','missing-member')
            view=_new_record(members[view_path],'view.v0',
                ('schema','plan_sha256','slot','observation','adapter_sha256','state','rows','diagnostics','abnormal_kind'),
                max_bytes=1048576)
            require_digest(view['plan_sha256']);require_digest(view['adapter_sha256'])
            require_slot(view['slot']);require_ref(view['observation'])
            if view['state'] not in ('normal','abnormal'): refuse('syntax','wrong-shape')
            if view['state']=='normal':
                if type(view['rows']) is not dict or type(view['diagnostics']) is not dict or view['abnormal_kind'] is not None:
                    refuse('syntax','wrong-shape')
                require_rows(view['rows'],require_ids(list(view['rows'])))
                require_rows(view['diagnostics'],require_ids(list(view['diagnostics'])),diagnostic=True)
            else:
                kinds=view['abnormal_kind']
                if (view['rows'] is not None or view['diagnostics'] is not None
                        or type(kinds) is not list or not 1<=len(kinds)<=2
                        or any(type(k) is not str or k not in ABNORMAL_KINDS for k in kinds)
                        or kinds!=sorted(set(kinds))): refuse('syntax','wrong-shape')
            views.append(view)
    if (set(members)&set(OBSERVATION_PATHS)) != set(observation_paths): refuse('filesystem','surplus-member')
    if (set(members)&set(VIEW_PATHS)) != set(view_paths): refuse('filesystem','surplus-member')
    gates = _new_record(members['gates.json'],'gates.v0',
        ('schema','plan_sha256','policy','views','engine_controls','gates'))
    require_digest(gates['plan_sha256'])
    if gates['policy'] != POLICY: refuse('support','unsupported-policy')
    if type(gates['views']) is not list or len(gates['views'])>8: refuse('syntax','wrong-shape')
    for ref in gates['views']: require_ref(ref)
    if type(gates['gates']) is not list or len(gates['gates'])!=9: refuse('syntax','wrong-shape')
    for gate in gates['gates']:
        exact(gate,('id','status','reason','witnesses'))
        if (type(gate['id']) is not int or not 0<=gate['id']<=8
                or gate['status'] not in ('passed','refused','not-run')
                or gate['reason'] not in (None,'proposal-shape','freeze-drift','corpus-separation',
                    'reference-mismatch','positive-control-inert','positive-control-proposal-only',
                    'inert-control-moved','target-no-distinction','target-frozen-row-change',
                    'diagnostic-only','transformation-mismatch','abnormal-execution','missing-review',
                    'review-rejected','accounting-gap','prerequisite-refused')
                or type(gate['witnesses']) is not list or len(gate['witnesses'])>8):
            refuse('syntax','wrong-shape')
        for slot in gate['witnesses']: require_slot(slot)
    if type(gates['engine_controls']) is not list or len(gates['engine_controls'])!=2: refuse('syntax','wrong-shape')
    for control in gates['engine_controls']:
        exact(control,('variant','positive','inert','barrier'))
        if (control['variant'] not in VARIANTS or control['positive'] not in ('passed','failed','not-run')
                or control['inert'] not in ('passed','failed','not-run') or control['barrier'] not in ('continue','stop')):
            refuse('syntax','wrong-shape')
    index = _new_record(members['evidence-index.json'],'evidence-index.v0',
        ('schema','plan_sha256','members','gate_result_sha256','journal_sha256'))
    for key in ('plan_sha256','gate_result_sha256','journal_sha256'): require_digest(index[key])
    if type(index['members']) is not list or len(index['members'])>128: refuse('syntax','wrong-shape')
    for ref in index['members']: require_ref(ref)
    paths = [r['member'] for r in index['members']]
    if paths != sorted(set(paths)): refuse('syntax','wrong-shape')
    indexed = set(members)-FINAL_PATHS-{'review.json'}
    if set(paths)-set(members): refuse('filesystem','missing-member')
    if set(paths)!=indexed: refuse('filesystem','surplus-member')
    decision = _new_record(members['decision.json'],'decision.v0',
        ('schema','plan_sha256','evidence_index_sha256','gates_sha256','review_sha256','disposition'))
    receipt = _new_record(members['receipt.json'],'receipt.v0',
        ('schema','plan_sha256','evidence_index_sha256','decision_sha256','review_sha256',
         'family','profile','source_content_sha256','origin'))
    for doc in (decision,receipt):
        for key in doc:
            if key.endswith('_sha256') and (key!='review_sha256' or doc[key] is not None): require_digest(doc[key])
    if decision['disposition'] not in ('eligible-for-human-corpus-PR','refused','pending-review','unproved'):
        refuse('syntax','wrong-shape')
    if receipt['family'] != FAMILY: refuse('support','unsupported-family')
    if receipt['profile'] != PROFILE: refuse('support','unsupported-profile')
    if receipt['origin'] != 'producer-reported': refuse('syntax','wrong-shape')
    review=None
    if 'review.json' not in members and (decision['review_sha256'] is not None
            or receipt['review_sha256'] is not None or decision['disposition']=='eligible-for-human-corpus-PR'):
        refuse('filesystem','missing-member')
    if 'review.json' in members:
        review=_new_record(members['review.json'],'review.v0',
            ('schema','proposal_sha256','evidence_index_sha256','reviewer','decision','rationale'))
        require_digest(review['proposal_sha256']);require_digest(review['evidence_index_sha256'])
        text(review['reviewer']);text(review['rationale'])
        if review['decision'] not in ('accept','reject'): refuse('syntax','wrong-shape')
    plan=decode(members['plan.json'],max_bytes=65536,canonical=True)
    # Validate the external-comparison surface without replaying preflight twice.
    exact(plan, ('schema','family','proposal','reference','source','instrument_commit',
        'subject_tree_sha256','adapter_sha256','profile','policy','variants','slots','control_sha256','sites_sha256'))
    if plan['schema']!=PREFIX+'plan.v0': refuse('support','unsupported-schema')
    if plan['family']!=FAMILY: refuse('support','unsupported-family')
    if plan['profile']!=PROFILE: refuse('support','unsupported-profile')
    if plan['policy']!=POLICY: refuse('support','unsupported-policy')
    _source(plan['source'])
    require_ref(plan['reference']);require_ref(plan['proposal'])
    retained=set(RETAINED_PATHS)
    if type(plan['variants']) is not list or len(plan['variants'])!=2: refuse('syntax','wrong-shape')
    for name,variant in zip(VARIANTS,plan['variants']):
        if type(variant) is not dict or type(variant.get('vectors')) is not list or len(variant['vectors'])!=5:
            refuse('syntax','wrong-shape')
        for vector in variant['vectors']:
            if type(vector) is not dict or type(vector.get('file')) is not str:
                refuse('syntax','wrong-shape')
            path=name+'/corpus/'+vector['file']
            if not re.fullmatch(r'(base|outer-whitespace)/corpus/[a-z0-9][a-z0-9-]{0,62}\.json',path):
                refuse('filesystem','unsafe-member')
            retained.add(path)
    if retained-set(members): refuse('filesystem','missing-member')
    if {p for p in members if '/corpus/' in p}-retained: refuse('filesystem','surplus-member')
    if len(retained)!=15: refuse('syntax','wrong-shape')
    inputs=AssessmentInputs(tuple((p,members[p]) for p in sorted(retained)),basis,
        tuple((p,raw) for p,raw in snapshot if p in PREPARATION_PATHS|COLLECTION_INDICES|COLLECTION_MEMBERS))
    return {'members':members,'plan':plan,'inputs':inputs,'observations':observations,'views':views,
        'view_paths':view_paths,'journal':journal,'gates':gates,'index':index,'review':review,
        'decision':decision,'receipt':receipt}


def compare_package(package):
    """Replay once, then compare the acyclic stored evidence graph to fresh facts."""
    m=package['members'];plan_hash=digest(m['plan.json']);index=package['index']
    for ref in index['members']: _check_ref(ref,m)
    if (index['plan_sha256']!=plan_hash or index['gate_result_sha256']!=digest(m['gates.json'])
            or index['journal_sha256']!=digest(m['journal.jsonl'])): refuse('binding','member-digest')
    gates=package['gates']
    if gates['plan_sha256']!=plan_hash: refuse('binding','plan-variant')
    if encode(gates['views'])!=encode([_raw_ref(m,p) for p in package['view_paths']]):
        refuse('binding','member-digest')
    evaluation=evaluate_assessment(package['inputs'],package['observations'],package['views'],
        gates['engine_controls'],package['journal'])
    issues=[]
    if encode(gates['gates'])!=evaluation.gates_raw: issues.append(('replay','gate-mismatch','gates.json'))
    disposition=derive_disposition(evaluation,package['observations'],package['review'],
        proposal_sha256=digest(m['proposal.json']),evidence_index_sha256=digest(m['evidence-index.json']))
    review_hash=digest(m['review.json']) if 'review.json' in m else None
    expected_decision={'schema':PREFIX+'decision.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':digest(m['evidence-index.json']),'gates_sha256':digest(m['gates.json']),
        'review_sha256':review_hash,'disposition':disposition}
    if encode(package['decision'])!=encode(expected_decision): issues.append(('replay','decision-mismatch','decision.json'))
    expected_receipt={'schema':PREFIX+'receipt.v0','plan_sha256':plan_hash,
        'evidence_index_sha256':digest(m['evidence-index.json']),'decision_sha256':digest(m['decision.json']),
        'review_sha256':review_hash,'family':FAMILY,'profile':PROFILE,
        'source_content_sha256':package['plan']['source']['content_sha256'],'origin':'producer-reported'}
    if encode(package['receipt'])!=encode(expected_receipt): issues.append(('replay','receipt-mismatch','receipt.json'))
    return disposition,issues
