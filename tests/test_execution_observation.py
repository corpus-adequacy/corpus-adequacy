"""Closed raw-observation artifacts: no execution or domain comparator."""
import copy
import hashlib
import importlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

D = 'sha256:' + 'a' * 64
E = 'sha256:' + 'b' * 64
CONTEXT = b'operator context\n'
DECISION = b'private decision\n'


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def canonical(obj):
    return (json.dumps(obj, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       indent=2) + '\n').encode('utf-8')


def fixture():
    """Hand-authored two-vector schedule; expectations never call the codec."""
    schedule = [
        {'step_id': 'build', 'kind': 'build', 'group': None, 'label': None,
         'control_polarity': None, 'vector_ids': [], 'mutation_sha256': None},
        {'step_id': 'base', 'kind': 'baseline', 'group': 'g', 'label': None,
         'control_polarity': None, 'vector_ids': ['v1', 'v2'], 'mutation_sha256': None},
        {'step_id': 'control', 'kind': 'control', 'group': 'g', 'label': 'change',
         'control_polarity': 'positive', 'vector_ids': ['v1', 'v2'], 'mutation_sha256': E},
        {'step_id': 'ordinary', 'kind': 'ordinary', 'group': 'g', 'label': 'rule',
         'control_polarity': None, 'vector_ids': ['v1', 'v2'], 'mutation_sha256': D},
    ]
    steps = []
    for declaration in schedule:
        pending = declaration['kind'] == 'ordinary'
        mutation = declaration['kind'] in ('control', 'ordinary')
        slots = []
        for vector in declaration['vector_ids']:
            slots.append({
                'vector_id': vector, 'state': 'pending' if pending else 'observed',
                'outcome': None if pending else {'value': 7}, 'diagnostic': None,
                'selector_presence': None if pending else {'outcome': True, 'diagnostic': True},
                'receipt': None if pending else {
                    'invocation_id': declaration['step_id'] + '-' + vector,
                    'step_id': declaration['step_id'], 'vector_id': vector,
                    'source_sha256': E if mutation else D,
                    'raw_sha256': D, 'raw_size': 12, 'evidence_sha256': E},
                'reason': None, 'evidence_sha256': None,
            })
        steps.append({
            'step_id': declaration['step_id'], 'state': 'pending' if pending else 'complete',
            'source_sha256': None if pending else E if mutation else D,
            'application': 'pending' if pending else 'applied' if mutation else 'not_applicable',
            'anchor_hits': None if not mutation or pending else 1,
            'build_state': 'not_run' if pending else 'succeeded',
            'restored': not pending, 'preflight': None, 'failure': None, 'slots': slots,
        })
    return {
        'schema': 'corpus-adequacy.execution-observation-prefix.v0',
        'session': 'session-1', 'phase': 'awaiting_admission',
        'bindings': {
            'tool_version': '0.4.0', 'tool_commit': 'a' * 40, 'tool_content_sha256': D, 'tool_source_state': 'exact',
            'manifest_sha256': D, 'corpus_sha256': D, 'source_sha256': D,
            'execution_profile': 'trusted-local', 'backend_sha256': D,
            'environment_sha256': D, 'context_sha256': digest(CONTEXT),
            'policy_identity': D, 'interpreter_identity': E,
            'selectors': {'outcome_from': ['value'], 'diagnostic_from': None},
            'exit_policy': {'accepted_exit_codes': [0], 'unproved_exit_codes': []},
        },
        'schedule': schedule, 'steps': steps,
        'cleanup': {'restored': True, 'isolated_tree_removed': True, 'evidence_sha256': D},
        'closure': {'reason': None, 'stop_step': None, 'prefix_sha256': None,
                    'admission_sha256': None, 'consumption_sha256': None},
        'non_claims': ['no-adequacy-score', 'no-policy-authentication', 'no-global-replay-prevention'],
    }


def admission(prefix, decision='allow'):
    doc = {'schema': 'corpus-adequacy.execution-admission.v0', 'session': 'session-1',
           'prefix_sha256': digest(canonical(prefix)), 'context_sha256': digest(CONTEXT),
           'decision_sha256': digest(DECISION), 'policy_identity': D, 'interpreter_identity': E,
           'next_step': 'ordinary', 'decision': decision, 'reasons': [] if decision == 'allow' else ['policy-refused'],
           'nonce': 'nonce-1'}
    doc['decision_binding_sha256'] = digest(canonical(doc))
    return doc


def stop_before_control(doc):
    doc['phase'] = 'stopped'
    doc['closure']['reason'] = 'operator-prerequisite-refused'
    doc['closure']['stop_step'] = 'control'
    for step in doc['steps'][2:]:
        current = step['step_id'] == 'control'
        step.update(state='stopped' if current else 'not_run', source_sha256=None,
                    application='not_run', anchor_hits=None, build_state='not_run', restored=True,
                    preflight={'decision': 'stop', 'reason': 'operator-prerequisite-refused',
                               'evidence_sha256': E} if current else None)
        for slot in step['slots']:
            slot.update(state='not_run', outcome=None, diagnostic=None, selector_presence=None,
                        receipt=None, reason='operator-prerequisite-refused', evidence_sha256=E)
    return doc


class ObservationCodec(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.codec = importlib.import_module('execution_observation')

    def test_binds_existing_engine_tool_identity_without_relabeling(self):
        import corpus_adequacy as ca
        doc = fixture()
        doc['bindings'].update(ca.tool_identity())
        self.codec.encode_observation(doc)

    def test_stop_suffix_cannot_change_reason_or_evidence(self):
        for field, value in (('reason', 'timeout'), ('evidence_sha256', D)):
            doc = stop_before_control(fixture())
            doc['steps'][3]['slots'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.codec.encode_observation(doc)

    def test_abnormal_slot_has_no_parsed_value_and_later_slots_never_run(self):
        doc = stop_before_control(fixture())
        step = doc['steps'][2]
        step.update(preflight=None, application='applied', source_sha256=E,
                    anchor_hits=1, build_state='succeeded',
                    failure={'reason': 'timeout', 'evidence_sha256': E})
        doc['closure']['reason'] = 'timeout'
        for item in doc['steps'][2:]:
            for slot in item['slots']: slot['reason'] = 'timeout'
        step['slots'][0].update(state='abnormal', receipt=fixture()['steps'][2]['slots'][0]['receipt'])
        self.codec.encode_observation(doc)
        bad = copy.deepcopy(doc); bad['steps'][2]['slots'][0]['outcome'] = {'value': 7}
        with self.assertRaises(ValueError): self.codec.encode_observation(bad)
        bad = copy.deepcopy(doc); bad['steps'][2]['slots'][1] = fixture()['steps'][2]['slots'][1]
        with self.assertRaises(ValueError): self.codec.encode_observation(bad)

    def test_complete_final_requires_consumption_and_no_pending(self):
        doc = fixture(); prefix = canonical(doc)
        doc.update(schema='corpus-adequacy.execution-observation.v0', phase='complete')
        last = copy.deepcopy(doc['steps'][2]); last['step_id'] = 'ordinary'
        for slot in last['slots']:
            slot['receipt']['step_id'] = 'ordinary'
            slot['receipt']['invocation_id'] = 'ordinary-' + slot['vector_id']
        doc['steps'][3] = last
        doc['closure'].update(prefix_sha256=digest(prefix), admission_sha256=D, consumption_sha256=E)
        self.codec.encode_observation(doc)
        doc['closure']['consumption_sha256'] = None
        with self.assertRaises(ValueError): self.codec.encode_observation(doc)

    def test_refused_final_binds_every_unstarted_slot_to_admission(self):
        doc = fixture(); prefix = canonical(doc)
        doc.update(schema='corpus-adequacy.execution-observation.v0', phase='refused')
        doc['closure'].update(prefix_sha256=digest(prefix), admission_sha256=E, reason='policy-refused')
        last = doc['steps'][3]; last.update(state='not_run', application='not_run', restored=True)
        for slot in last['slots']:
            slot.update(state='not_run', reason='policy-refused', evidence_sha256=E)
        self.codec.encode_observation(doc)
        for field, value in (('reason', 'timeout'), ('evidence_sha256', D)):
            bad = copy.deepcopy(doc); bad['steps'][3]['slots'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.codec.encode_observation(bad)

    def test_invalid_metadata_types_are_refusals(self):
        for target, field in (('root', 'schema'), ('schedule', 'kind'), ('slot', 'state')):
            bad = fixture()
            obj = bad if target == 'root' else bad['schedule'][1] if target == 'schedule' else bad['steps'][1]['slots'][0]
            obj[field] = []
            with self.subTest(field=field), self.assertRaises(ValueError): self.codec.encode_observation(bad)

    def test_cleanup_failure_cannot_be_awaiting_admission(self):
        doc = fixture(); doc['cleanup']['isolated_tree_removed'] = False
        with self.assertRaises(ValueError): self.codec.encode_observation(doc)

    def test_canonical_round_trip_preserves_corpus_values_even_verdict_key(self):
        doc = fixture()
        doc['steps'][1]['slots'][0]['outcome'] = {'verdict': ['survived', {'score': None}]}
        raw = self.codec.encode_observation(doc)
        self.assertEqual(raw, canonical(doc))
        self.assertEqual(self.codec.load_observation(raw, kind='prefix'), doc)

    def test_rejects_extra_metadata_including_null_scoring_fields(self):
        for key in ('score_percent', 'adequate', 'verdict', 'denominator'):
            doc = fixture(); doc[key] = None
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.codec.encode_observation(doc)

    def test_rejects_missing_extra_duplicate_vector_or_step(self):
        variants = []
        doc = fixture(); doc['steps'][1]['slots'].pop(); variants.append(doc)
        doc = fixture(); doc['steps'][1]['slots'].append(copy.deepcopy(doc['steps'][1]['slots'][0])); variants.append(doc)
        doc = fixture(); doc['steps'][1]['slots'][0]['vector_id'] = 'unplanned'; variants.append(doc)
        doc = fixture(); doc['steps'].pop(); variants.append(doc)
        doc = fixture(); doc['steps'][0]['slots'] = copy.deepcopy(doc['steps'][1]['slots']); variants.append(doc)
        for doc in variants:
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                self.codec.encode_observation(doc)

    def test_phase_cannot_hide_execution_or_skipped_controls(self):
        for index, state in ((1, 'not_run'), (2, 'pending'), (3, 'observed')):
            doc = fixture(); doc['steps'][index]['slots'][0]['state'] = state
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.codec.encode_observation(doc)
        doc = fixture(); doc['schema'] = 'corpus-adequacy.execution-observation.v0'; doc['phase'] = 'complete'
        with self.assertRaises(ValueError): self.codec.encode_observation(doc)

    def test_preinvocation_stop_requires_record_and_full_suffix(self):
        doc = stop_before_control(fixture())
        self.assertEqual(self.codec.load_observation(canonical(doc), kind='prefix'), doc)
        for change in ('record', 'pending', 'invocation', 'abnormal'):
            bad = copy.deepcopy(doc)
            if change == 'record': bad['steps'][2]['preflight'] = None
            if change == 'pending': bad['steps'][3]['slots'][0]['state'] = 'pending'
            if change == 'invocation': bad['steps'][2]['slots'][0]['receipt'] = fixture()['steps'][2]['slots'][0]['receipt']
            if change == 'abnormal': bad['steps'][2]['slots'][0]['state'] = 'abnormal'
            with self.subTest(change=change), self.assertRaises(ValueError): self.codec.encode_observation(bad)

    def test_receipts_bind_engine_step_vector_source_and_unique_invocation(self):
        for field, value in (('step_id', 'ordinary'), ('vector_id', 'other'),
                             ('source_sha256', D), ('raw_size', True),
                             ('raw_sha256', 'a' * 64), ('invocation_id', 'base-v1')):
            doc = fixture(); doc['steps'][2]['slots'][0]['receipt'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.codec.encode_observation(doc)
        # Equal report hashes across fresh calls are not a replay.
        self.codec.encode_observation(fixture())

    def test_closed_numeric_and_order_domains(self):
        variants = []
        doc = fixture(); doc['steps'][2]['anchor_hits'] = True; variants.append(doc)
        doc = fixture(); doc['bindings']['exit_policy']['accepted_exit_codes'] = [True]; variants.append(doc)
        doc = fixture(); doc['schedule'][1], doc['schedule'][2] = doc['schedule'][2], doc['schedule'][1]; variants.append(doc)
        doc = fixture(); doc['schedule'][2]['control_polarity'] = 'maybe'; variants.append(doc)
        for doc in variants:
            with self.subTest(doc=doc), self.assertRaises(ValueError): self.codec.encode_observation(doc)

    def test_strict_json_and_canonical_boundary(self):
        raw = canonical(fixture())
        inputs = [b'\xff', b'{"schema":1,"schema":2}', b'{"x":NaN}', b'{"x":1e999}',
                  b'[' * 70 + b'0' + b']' * 70, raw.rstrip(), raw + b' ', b' ' * (8 * 1024 * 1024 + 1)]
        for bad in inputs:
            with self.subTest(start=bad[:30]), self.assertRaises(ValueError): self.codec.load_observation(bad, kind='prefix')

    def test_admission_binds_exact_prefix_context_decision_and_policy(self):
        doc = fixture(); envelope = admission(doc)
        self.codec.validate_admission(doc, envelope, context_raw=CONTEXT, decision_raw=DECISION)
        for field in ('session', 'prefix_sha256', 'context_sha256', 'decision_sha256',
                      'policy_identity', 'interpreter_identity', 'next_step'):
            bad = copy.deepcopy(envelope)
            bad[field] = (D if envelope[field] == E else E) if field.endswith(('sha256', 'identity')) else 'other'
            unsigned = dict(bad); unsigned.pop('decision_binding_sha256')
            bad['decision_binding_sha256'] = digest(canonical(unsigned))
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.codec.validate_admission(doc, bad, context_raw=CONTEXT, decision_raw=DECISION)
        with self.assertRaises(ValueError):
            self.codec.validate_admission(doc, envelope, context_raw=CONTEXT+b'x', decision_raw=DECISION)
        with self.assertRaises(ValueError):
            self.codec.validate_admission(stop_before_control(fixture()), envelope, context_raw=CONTEXT, decision_raw=DECISION)

    def test_admission_self_digest_and_unknown_keys_refuse(self):
        good = admission(fixture())
        self.assertEqual(self.codec.load_observation(canonical(good), kind='admission'), good)
        for field, value in (('nonce', 'changed'), ('decision_binding_sha256', E), ('unexpected', None)):
            bad = dict(good); bad[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.codec.encode_observation(bad)


if __name__ == '__main__': unittest.main()
