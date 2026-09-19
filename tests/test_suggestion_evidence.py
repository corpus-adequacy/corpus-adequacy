"""Pure contracts; all records are synthetic and establish no execution origin."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'measurements'))
import suggestion_evidence as ev

IDS = ('allow', 'boundary', 'negative', 'over-limit', 'proposal')
ROWS = {key: {'accepted': True, 'reason': 'within-range'} for key in IDS}
DIAGNOSTICS = {key: {'detail': 'checked'} for key in IDS}
SLOT = {'variant': 'base', 'ordinal': 0,
        'step': {'kind': 'baseline', 'group': 'independent', 'id': None}}


def observation():
    return {'schema': 'corpus-adequacy.owned-suggestion-assessment.observation.v0',
            'plan_sha256': 'a' * 64, 'slot': copy.deepcopy(SLOT),
            'route': 'contained-oci-v1-derived', 'profile': 'contained-oci-v1',
            'state': 'returned', 'sanitized_reason': None, 'exception_kind': None,
            'envelope': None,
            'raw': {'step': copy.deepcopy(SLOT['step']), 'built': True,
                    'outcomes': {'<batch>': [copy.deepcopy(ROWS)]},
                    'diagnostics': {'<batch>': [copy.deepcopy(DIAGNOSTICS)]}, 'raised': {}}}


class Codec(unittest.TestCase):
    def test_roundtrip_and_exact_cap(self):
        raw = ev.encode({'x': [1, True, None, 'é']})
        self.assertEqual(raw, b'{"x":[1,true,null,"\\u00e9"]}\n')
        self.assertEqual(ev.decode(raw, max_bytes=len(raw)), {'x': [1, True, None, 'é']})
        with self.assertRaises(ev.EvidenceError) as caught:
            ev.decode(raw, max_bytes=len(raw)-1)
        self.assertEqual(caught.exception.code, 'member-bytes')

    def test_ambiguous_json_never_gets_a_value(self):
        for raw, code in [(b'{"x":1,"x":2}', 'duplicate-key'),
                          (b'{"x":NaN}', 'invalid-number'),
                          (b'{"x":1e999}', 'invalid-number'),
                          (b'{"x":"\\ud800"}', 'invalid-unicode'),
                          (b'\xff', 'invalid-utf8')]:
            with self.subTest(raw=raw):
                with self.assertRaises(ev.EvidenceError) as caught:
                    ev.decode(raw)
                self.assertEqual(caught.exception.code, code)

    def test_noncanonical_new_bytes_and_depth(self):
        with self.assertRaises(ev.EvidenceError) as caught:
            ev.decode(b'{ "x":1 }', canonical=True)
        self.assertEqual(caught.exception.code, 'noncanonical-new-object')
        with self.assertRaises(ev.EvidenceError) as caught:
            ev.decode(b'[' * 18 + b'0' + b']' * 18)
        self.assertEqual(caught.exception.code, 'json-depth')


class Projection(unittest.TestCase):
    def project(self, value):
        return ev.project_observation(value, ids=IDS, plan_sha256='a'*64)

    def test_normal_rows_are_detached(self):
        raw = observation()
        result = self.project(raw)
        self.assertEqual(result['rows'], ROWS)
        raw['raw']['outcomes']['<batch>'][0]['allow']['accepted'] = False
        self.assertTrue(result['rows']['allow']['accepted'])

    def test_unproved_preserves_both_tokens_without_fake_rows(self):
        raw = observation()
        raw['raw'].update(outcomes={}, diagnostics={}, raised={'<batch>': 'unproved'})
        raw['sanitized_reason'] = 'candidate-build'
        result = self.project(raw)
        self.assertEqual(result['abnormal_kind'], ['candidate-build', 'unproved'])
        self.assertIsNone(result['rows'])
        raw['raw']['raised']['<batch>'] = 'timeout'
        with self.assertRaises(ev.EvidenceError):
            self.project(raw)  # sanitizer is allowed only beside unproved

    def test_closed_shapes_types_and_id_set(self):
        mutations = [lambda d: d.update(extra=True),
                     lambda d: d.update(schema='unknown'),
                     lambda d: d['slot'].update(ordinal=False),
                     lambda d: d['raw'].update(built=1),
                     lambda d: d['raw']['outcomes']['<batch>'].append(ROWS),
                     lambda d: d['raw']['outcomes']['<batch>'][0].pop('proposal'),
                     lambda d: d['raw']['outcomes']['<batch>'][0]['allow'].update(accepted=1),
                     lambda d: d['raw'].update(raised={'allow': 'timeout'})]
        for change in mutations:
            raw = observation(); change(raw)
            with self.subTest(change=change), self.assertRaises(ev.EvidenceError):
                self.project(raw)


def assessment():
    observations, views, journal = [], [], []
    plan = {'plan_sha256': 'a'*64, 'ids': list(IDS), 'proposal_id': 'proposal',
            'reference_rows': copy.deepcopy(ROWS),
            'base_vectors': {i: b'{\"value\":0}\n' for i in IDS},
            'transformed_vectors': {i: b' \n{\"value\":0}\n\n\t' for i in IDS}}
    controls = []
    for variant in ('base', 'outer-whitespace'):
        controls.append({'variant': variant, 'positive': 'passed', 'inert': 'passed',
                         'barrier': 'continue'})
        for ordinal, (kind, row_id) in enumerate(ev.STEPS):
            raw = observation()
            raw['slot'] = {'variant': variant, 'ordinal': ordinal,
                           'step': {'kind': kind, 'group': 'independent', 'id': row_id}}
            raw['raw']['step'] = copy.deepcopy(raw['slot']['step'])
            if ordinal in (1, 3):
                target = 'allow' if ordinal == 1 else 'proposal'
                raw['raw']['outcomes']['<batch>'][0][target] = {
                    'accepted': False, 'reason': 'changed'}
            observations.append(raw)
            views.append(ev.project_observation(raw, ids=IDS, plan_sha256='a'*64))
            for event in ('started', 'returned'):
                journal.append({'seq': len(journal), 'slot': copy.deepcopy(raw['slot']),
                                'event': event, 'reason': None})
    return plan, observations, views, controls, journal


def stop_after_controls(data):
    data[1][:] = data[1][:3]
    data[2][:] = [ev.project_observation(o, ids=IDS, plan_sha256='a'*64) for o in data[1]]
    data[3][1].update(positive='not-run', inert='not-run', barrier='stop')
    data[4][:] = data[4][:6]
    for n in range(3, 8):
        variant, ordinal = ('base', n) if n < 4 else ('outer-whitespace', n-4)
        kind, row_id = ev.STEPS[ordinal]
        data[4].append({'seq': len(data[4]), 'slot': {'variant': variant,
            'ordinal': ordinal, 'step': {'kind': kind, 'group': 'independent', 'id': row_id}},
            'event': 'not-started', 'reason': 'prerequisite-refused'})


class Evaluation(unittest.TestCase):
    def evaluate(self, data):
        return ev.evaluate_execution_gates(*data)

    def refresh(self, data):
        data[2][:] = [ev.project_observation(o, ids=IDS, plan_sha256='a'*64)
                      for o in data[1]]

    def test_healthy_has_review_placeholder_without_claiming_preflight(self):
        result = self.evaluate(assessment())
        self.assertEqual([g['id'] for g in result], list(range(3, 9)))
        self.assertEqual([g['status'] for g in result],
                         ['passed']*4 + ['not-run', 'passed'])
        self.assertEqual(result[4], {'id': 7, 'status': 'not-run',
                                    'reason': 'missing-review', 'witnesses': []})

    def test_inert_failure_dominates_proposal_only_positive(self):
        data = assessment()
        data[1][1]['raw']['outcomes']['<batch>'][0] = copy.deepcopy(ROWS)
        data[1][1]['raw']['outcomes']['<batch>'][0]['proposal']['accepted'] = False
        data[1][2]['raw']['outcomes']['<batch>'][0]['allow']['accepted'] = False
        data[3][0].update(positive='failed', inert='failed', barrier='stop')
        self.refresh(data)
        stop_after_controls(data)
        result = self.evaluate(data)
        self.assertEqual(result[1]['reason'], 'inert-control-moved')
        self.assertEqual(result[2]['status'], 'not-run')

    def test_diagnostic_change_cannot_establish_distinction(self):
        data = assessment()
        data[1][3]['raw']['outcomes']['<batch>'][0] = copy.deepcopy(ROWS)
        data[1][3]['raw']['diagnostics']['<batch>'][0]['proposal']['detail'] = 'new detail'
        self.refresh(data)
        self.assertEqual(self.evaluate(data)[2]['reason'], 'diagnostic-only')

    def test_reference_and_frozen_row_target_failures(self):
        data = assessment()
        data[1][3]['raw']['outcomes']['<batch>'][0]['allow']['accepted'] = False
        self.refresh(data)
        self.assertEqual(self.evaluate(data)[2]['reason'], 'target-frozen-row-change')
        data[0]['reference_rows']['allow']['accepted'] = False
        self.assertEqual(self.evaluate(data)[0]['reason'], 'reference-mismatch')

    def test_abnormal_target_is_unproved_not_a_distinction(self):
        data = assessment()
        data[1][3]['raw'].update(outcomes={}, diagnostics={}, raised={'<batch>': 'timeout'})
        self.refresh(data)
        result = self.evaluate(data)
        self.assertEqual(result[2]['reason'], 'abnormal-execution')


    def test_integer_outcome_in_retained_view_is_not_boolean_equality(self):
        data = assessment()
        data[2][0]['rows']['allow']['accepted'] = 1
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code, 'raw-view-mismatch')

    def test_retained_view_and_engine_claims_are_not_authority(self):
        data = assessment()
        data[2][3]['rows']['proposal']['reason'] = 'forged'
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code, 'raw-view-mismatch')
        data = assessment(); data[3][0]['positive'] = 'failed'
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code, 'engine-control-mismatch')

    def test_control_barrier_retains_refusal_without_fabricated_later_calls(self):
        data = assessment()
        data[1][1]['raw']['outcomes']['<batch>'][0] = copy.deepcopy(ROWS)
        data[1][:] = data[1][:3]
        self.refresh(data)
        data[3][0].update(positive='failed', barrier='stop')
        data[3][1].update(positive='not-run', inert='not-run', barrier='stop')
        data[4][:] = data[4][:6]
        for n in range(3, 8):
            variant, ordinal = ('base', n) if n < 4 else ('outer-whitespace', n-4)
            kind, row_id = ev.STEPS[ordinal]
            data[4].append({'seq': len(data[4]), 'slot': {'variant': variant,
                'ordinal': ordinal, 'step': {'kind': kind, 'group': 'independent', 'id': row_id}},
                'event': 'not-started', 'reason': 'prerequisite-refused'})
        result = self.evaluate(data)
        self.assertEqual(result[1]['reason'], 'positive-control-inert')
        self.assertEqual(result[2]['status'], 'not-run')

    def test_semantic_target_barrier_allows_truthful_stopped_suffix(self):
        data = assessment()
        data[1][3]['raw']['outcomes']['<batch>'][0] = copy.deepcopy(ROWS)
        data[1][:] = data[1][:4]
        self.refresh(data)
        data[3][1].update(positive='not-run', inert='not-run', barrier='stop')
        data[4][:] = data[4][:8]
        for ordinal, (kind, row_id) in enumerate(ev.STEPS):
            data[4].append({'seq': len(data[4]), 'slot': {'variant': 'outer-whitespace',
                'ordinal': ordinal, 'step': {'kind': kind, 'group': 'independent', 'id': row_id}},
                'event': 'not-started', 'reason': 'prerequisite-refused'})
        result = self.evaluate(data)
        self.assertEqual(result[2]['reason'], 'target-no-distinction')
        self.assertEqual(result[-1]['status'], 'passed')
        # Identical omission after a healthy first variant is unexplained.
        data[1][3]['raw']['outcomes']['<batch>'][0]['proposal']['accepted'] = False
        self.refresh(data)
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code, 'unexplained-missing-slot')

    def test_calls_after_failed_controls_are_accounting_corruption(self):
        data = assessment()
        data[1][1]['raw']['outcomes']['<batch>'][0] = copy.deepcopy(ROWS)
        data[3][0].update(positive='failed', barrier='stop')
        self.refresh(data)
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code, 'schedule-mismatch')

    def test_missing_duplicate_and_reordered_journal_never_pass(self):
        for edit in (lambda j: j.pop(), lambda j: j.append(copy.deepcopy(j[-1])),
                     lambda j: j.reverse()):
            data = assessment(); edit(data[4])
            with self.subTest(edit=edit), self.assertRaises(ev.EvidenceError):
                self.evaluate(data)


if __name__ == '__main__':
    unittest.main()
