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
            if pending is not None or ordinal != previous + 1 or event['reason'] is not None:
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
