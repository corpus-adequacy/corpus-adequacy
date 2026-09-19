"""Pure owned-assessment evidence checks (#224).

No filesystem, network, candidate or process operations. These primitives do not
constitute a producer or a package reader, and never authenticate execution.
"""
from __future__ import annotations

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


def _members(snapshot, *, count):
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
        if len(raw) > 65536:
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

    def __post_init__(self):
        _members(self.retained_members, count=15)
        require_basis(self.basis_members)


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
    gates, validated = evaluate_preflight(inputs)
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
    if validated is None:
        _journal(normalized_journal, [])
        expected_controls = [{'variant': v, 'positive': 'not-run', 'inert': 'not-run',
                              'barrier': 'stop'} for v in VARIANTS]
        if encode(engine_controls) != encode(expected_controls):
            refuse('replay', 'engine-control-mismatch')
        if (not normalized_journal or normalized_journal[0]['event'] != 'preflight-refused'
                or any(e['event'] != 'not-started' for e in normalized_journal[1:])):
            refuse('replay', 'schedule-mismatch')
        return gates + [_gate(n, 'not-run', 'prerequisite-refused') for n in range(3, 7)] + [
            _gate(7, 'not-run', 'missing-review'), _gate(8)]
    if any(e['event'] == 'preflight-refused' for e in normalized_journal):
        refuse('replay', 'schedule-mismatch')
    projected = [project_observation(o, ids=validated['execution']['ids'], plan_sha256=plan_hash)
                 for o in observations]
    return gates + evaluate_execution_gates(validated['execution'], observations, projected,
                                            engine_controls, normalized_journal)


# Closed runtime data pinned to the existing source validators; no runtime imports.
_CANDIDATE_RESOURCE_PROFILE_V2 = {'cpu_rate_millicpu': 1000,
 'deadline_seconds': 120,
 'memory_bytes': 4294967296,
 'memory_swap_bytes': 4294967296,
 'nofile_hard': 1024,
 'nofile_soft': 1024,
 'output_bytes': 4194304,
 'pids': 512,
 'schema': 'corpus-adequacy.aee-checker-sealed.resource-profile.v2',
 'tmp_bytes': 16777216,
 'tmp_inodes': 2048,
 'work_bytes': 268435456,
 'work_exec': True,
 'work_inodes': 16384}
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
_DECLARED_CEILINGS = {'deadline_seconds': 8,
 'disk_bytes': 1048576,
 'file_count': 128,
 'output_bytes': 4194304}
_MATERIALIZE_CEILINGS = {'deadline_seconds': 300,
 'disk_bytes': 67108864,
 'entry_count': 10000,
 'output_bytes': 4194304}
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


def require_assessment_context(context, profile, contract):
    """Revalidate actual bytes even for forged instances; no effects or disk claim.

    Explicit expected bytes come from the trusted caller, not a package choice.
    Approval is a supplied assertion, not an authenticated reviewer identity.
    No runtime caller is wired by this module or by constructor success.
    """
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
    gates, values = evaluate_preflight(context.assessment_inputs)
    if values is None or any(g['status'] != 'passed' for g in gates):
        refuse('input', 'argument-invalid')
    plan = values['plan']; plan_hash = values['execution']['plan_sha256']
    expected = require_expected(context.expected_raw)
    _require_expected_admission(expected, plan, plan_hash)
    index = VARIANTS.index(context.variant); variant = plan['variants'][index]
    derived = OwnedAssessmentVariantContract(plan_hash, context.variant,
        variant['manifest']['sha256'], variant['tree_sha256'], values['execution']['ids'])
    if type(contract) is not OwnedAssessmentVariantContract or contract != derived:
        refuse('binding', 'plan-variant')
    prepare = decode(context.prepare_raw, max_bytes=65536, canonical=True)
    exact(prepare, ('schema', 'family', 'plan_sha256', 'variant', 'profile', 'source',
                    'pins_sha256', 'materialized', 'runtime'))
    require_assessment_dispatch(prepare['family'], prepare['profile'], prepare['schema'])
    if (prepare['plan_sha256'] != plan_hash or prepare['variant'] != context.variant
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
    parent = decode(context.parent_authorization_raw, max_bytes=65536, canonical=True)
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
    prepare_hash = digest(context.prepare_raw)
    if parent['prepares'][index]['sha256'] != prepare_hash:
        refuse('binding', 'prepare-authorization')
    auth = decode(context.variant_authorization_raw, max_bytes=65536, canonical=True)
    expected_auth = {'schema': PREFIX+'variant-authorization.v0',
        'parent_authorization_sha256': digest(context.parent_authorization_raw),
        'plan_sha256': plan_hash, 'variant': context.variant, 'prepare_sha256': prepare_hash,
        'profile': PROFILE, 'source_content_sha256': plan['source']['content_sha256']}
    if encode(auth) != encode(expected_auth):
        refuse('binding', 'prepare-authorization')
    return prepare


def derive_disposition(gates, observations, review, *, proposal_sha256, evidence_index_sha256):
    """Combine freshly recomputed gates with review; never mutate indexed gates.

    This internal composition primitive is not a receipt verifier. Its caller
    must use evaluate_assessment's result, not package-supplied gate claims.
    """
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
    if any(o['state'] != 'returned' or o['raw']['raised'] for o in observations):
        return 'unproved'
    checked = [g for g in gates if g['id'] != 7]
    if any(g['status'] == 'refused' for g in checked):
        return 'refused'
    if any(g['status'] != 'passed' for g in checked):
        refuse('replay', 'gate-mismatch')
    if review is None:
        return 'pending-review'
    return 'refused' if review['decision'] == 'reject' else 'eligible-for-human-corpus-PR'
