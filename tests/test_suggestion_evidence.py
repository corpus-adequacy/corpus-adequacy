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


def basis_snapshot():
    root = ROOT / 'fixtures/contained-v1-owned/corpus'
    return tuple(sorted((str(p.relative_to(root)), p.read_bytes())
                        for p in root.rglob('*') if p.is_file()))


class Basis(unittest.TestCase):
    def test_factory_tree_accepts_and_vectors_only_refuses(self):
        raw = basis_snapshot()
        result = ev.require_basis(raw)
        self.assertEqual(set(result), {'MANIFEST.json', 'allow.json', 'boundary.json',
                                       'negative.json', 'over-limit.json'})
        flat = tuple((name.removeprefix('vectors/'), data) for name, data in raw
                     if name.startswith('vectors/'))
        with self.assertRaises(ev.EvidenceError):
            ev.require_basis(flat)
        changed = tuple((name, data+b'x' if name == 'LICENSE' else data)
                        for name, data in raw)
        with self.assertRaises(ev.EvidenceError):
            ev.require_basis(changed)

    def test_basis_closed_immutable_bounded_inventory(self):
        original = basis_snapshot()
        for snapshot in (list(original), original[:-1], original + (original[0],),
                         tuple(reversed(original)),
                         tuple((p, bytearray(b)) for p, b in original),
                         tuple((p, b'x'*65537 if p == 'LICENSE' else b) for p, b in original)):
            with self.subTest(kind=type(snapshot)), self.assertRaises(ev.EvidenceError):
                ev.require_basis(snapshot)


def prepared_inputs():
    # Synthetic reference only: no real approval or candidate execution.
    from sealed_measurement_contract import OWNED_INDEPENDENT_V0_CONTRACT as owned
    basis = basis_snapshot()
    files = {p.removeprefix('vectors/'): b for p, b in basis if p.startswith('vectors/')}
    proposal = json.loads((ROOT/'tests/fixtures/suggestion-v0/good.json').read_bytes())
    proposal['vector'].update(id='proposal', file='proposal.json')
    proposal['expected'] = copy.deepcopy(ROWS['proposal'])
    members = {'proposal.json': ev.encode(proposal)}
    reference = {'schema': ev.PREFIX+'reference.v0',
        'proposal_sha256': ev.digest(members['proposal.json']),
        'selection': 'owned-independent-v0', 'rule_sources': [
            {'path': path, 'sha256': ev.digest((ROOT/path).read_bytes())}
            for path in ('fixtures/contained-v1-owned/candidate/src/check.rs',
                         'measurements/owned-independent-v0/mutation-bundle.json')],
        'rows': copy.deepcopy(ROWS), 'rationale': 'Synthetic test',
        'reviewer': 'test-only', 'decision': 'accept'}
    members['reference.json'] = ev.encode(reference)
    def ref(path):
        return {'member': path, 'sha256': ev.digest(members[path]), 'bytes': len(members[path])}
    old = json.loads(files.pop('MANIFEST.json'))
    files['proposal.json'] = b'{"value":12}'
    rows = old['vectors'] + [{'id': 'proposal', 'file': 'proposal.json',
                             'value_class': proposal['vector']['value_class']}]
    variants = []
    for variant in ev.VARIANTS:
        import hashlib
        vector_files = {p: b if variant == 'base' else b' \n'+b+b'\n\t'
                        for p, b in files.items()}
        h = hashlib.sha256()
        for row in rows:
            h.update(row['file'].encode()+b'\0'+vector_files[row['file']])
        manifest = {'vectors': rows, 'corpusDigest': h.hexdigest()}
        vector_files['MANIFEST.json'] = (json.dumps(manifest, indent=2, sort_keys=True)+'\n').encode()
        prefix = variant+'/corpus/'
        members.update({prefix+p: raw for p, raw in vector_files.items()})
        tree = hashlib.sha256()
        for p, raw in sorted(vector_files.items()):
            tree.update(p.encode()+b'\0'+str(len(raw)).encode()+b'\0'+raw)
        variants.append({'variant': variant, 'manifest': ref(prefix+'MANIFEST.json'),
            'vectors': [{'id': row['id'], 'file': row['file'],
                         'sha256': ev.digest(vector_files[row['file']]),
                         'bytes': len(vector_files[row['file']])} for row in rows],
            'tree_sha256': tree.hexdigest(), 'corpus_digest': h.hexdigest()})
    slots = [copy.deepcopy(o['slot']) for o in assessment()[1]]
    plan = {'schema': ev.PREFIX+'plan.v0', 'family': ev.FAMILY,
        'proposal': ref('proposal.json'), 'reference': ref('reference.json'),
        'source': {'commit': 'a'*40, 'content_sha256': 'b'*64,
                   'files': [{'path': p, 'sha256': 'c'*64} for p in ev.SOURCE_PATHS]},
        'instrument_commit': owned.instrument_commit, 'subject_tree_sha256': owned.subject_tree_sha256,
        'adapter_sha256': owned.adapter_sha256, 'profile': ev.PROFILE, 'policy': ev.POLICY,
        'variants': variants, 'slots': slots, 'control_sha256': owned.pin_digest('control.json'),
        'sites_sha256': owned.pin_digest('sites.json')}
    members['plan.json'] = ev.encode(plan)
    return ev.AssessmentInputs(tuple(sorted(members.items())), basis)


class Preflight(unittest.TestCase):
    def test_complete_snapshot_passes_all_preflight_gates(self):
        inputs = prepared_inputs()
        gates, data = ev.evaluate_preflight(inputs)
        self.assertEqual([g['status'] for g in gates], ['passed']*3)
        self.assertEqual(data['execution']['ids'], IDS)
        self.assertEqual(data['execution']['plan_sha256'], ev.digest(dict(inputs.retained_members)['plan.json']))

    def test_plan_freeze_change_is_recomputed_not_trusted(self):
        inputs = prepared_inputs(); members = dict(inputs.retained_members)
        plan = ev.decode(members['plan.json']); plan['adapter_sha256'] = 'd'*64
        members['plan.json'] = ev.encode(plan)
        gates, _ = ev.evaluate_preflight(ev.AssessmentInputs(tuple(sorted(members.items())), inputs.basis_members))
        self.assertEqual(gates[1]['reason'], 'freeze-drift')
        self.assertEqual(gates[2]['status'], 'not-run')

    def test_coherent_wrong_vector_is_gate2_refusal(self):
        inputs=prepared_inputs(); members=dict(inputs.retained_members)
        plan=ev.decode(members['plan.json'])
        path='base/corpus/proposal.json'; members[path]=b'{"value":13}'
        row=plan['variants'][0]['vectors'][-1]
        row.update(sha256=ev.digest(members[path]),bytes=len(members[path]))
        # Repair the retained tree ref as an attacker could; original derivation
        # remains anchored in proposal+basis and must still reject.
        files={p.removeprefix('base/corpus/'): b for p,b in members.items() if p.startswith('base/corpus/')}
        plan['variants'][0]['tree_sha256']=ev._tree(files)
        members['plan.json']=ev.encode(plan)
        gates,_=ev.evaluate_preflight(ev.AssessmentInputs(tuple(sorted(members.items())),inputs.basis_members))
        self.assertEqual(gates[2]['reason'],'corpus-separation')

    def test_ref_only_or_forged_mutable_inputs_refuse(self):
        inputs = prepared_inputs()
        forged = object.__new__(ev.AssessmentInputs)
        object.__setattr__(forged, 'retained_members', inputs.retained_members[:1])
        object.__setattr__(forged, 'basis_members', inputs.basis_members)
        with self.assertRaises(ev.EvidenceError):
            ev.evaluate_preflight(forged)
        with self.assertRaises(ev.EvidenceError):
            ev.evaluate_preflight(ev.decode(dict(inputs.retained_members)['plan.json']))


def wire_execution(inputs):
    data = assessment()
    plan_hash = ev.digest(dict(inputs.retained_members)['plan.json'])
    refs = {}
    views = []
    for obs in data[1]:
        obs['plan_sha256'] = plan_hash
        slot = obs['slot']; member = slot['variant']+'/observations/'+str(slot['ordinal'])+'.json'
        refs[(slot['variant'], slot['ordinal'])] = {'member': member,
            'sha256': ev.digest(ev.encode(obs)), 'bytes': len(ev.encode(obs))}
        view = ev.project_observation(obs, ids=IDS, plan_sha256=plan_hash)
        views.append({'schema': ev.PREFIX+'view.v0', 'plan_sha256': plan_hash,
            'slot': copy.deepcopy(slot), 'observation': copy.deepcopy(refs[(slot['variant'], slot['ordinal'])]),
            'adapter_sha256': ev._OWNED.adapter_sha256, **view})
    journal = []
    for event in data[4]:
        slot = event['slot']
        journal.append({'schema': ev.PREFIX+'journal-event.v0', 'plan_sha256': plan_hash,
            **copy.deepcopy(event), 'observation': copy.deepcopy(refs[(slot['variant'], slot['ordinal'])])
                if event['event'] == 'returned' else None})
    return data[1], views, data[3], journal


class FinalReview(unittest.TestCase):
    def test_indexed_gate7_cannot_be_replaced_by_final_review_verdict(self):
        inputs = prepared_inputs()
        observations, views, controls, journal = wire_execution(inputs)
        gates = ev.evaluate_assessment(inputs, observations, views, controls, journal)
        proposal_hash = ev.digest(dict(inputs.retained_members)['proposal.json'])
        review = {'schema': ev.PREFIX+'review.v0', 'proposal_sha256': proposal_hash,
                  'evidence_index_sha256': 'a'*64, 'reviewer': 'synthetic-only',
                  'decision': 'accept', 'rationale': 'test'}
        kwargs = {'proposal_sha256': proposal_hash, 'evidence_index_sha256': 'a'*64}
        # Same-seam positive: final review is accepted without rewriting indexed gate7.
        self.assertEqual(ev.derive_disposition(gates, observations, review, **kwargs),
                         'eligible-for-human-corpus-PR')
        for status, reason in (('passed', None), ('refused', 'review-rejected')):
            changed = copy.deepcopy(gates)
            changed[7].update(status=status, reason=reason)
            with self.subTest(status=status):
                with self.assertRaises(ev.EvidenceError) as caught:
                    ev.derive_disposition(changed, observations, review, **kwargs)
                self.assertEqual((caught.exception.stage, caught.exception.code),
                                 ('replay', 'gate-mismatch'))

    def test_review_is_separate_and_cannot_rewrite_gates(self):
        inputs=prepared_inputs(); execution=wire_execution(inputs)
        gates=ev.evaluate_assessment(inputs,*execution); before=ev.encode(gates)
        proposal_hash=ev.digest(dict(inputs.retained_members)['proposal.json'])
        review={'schema':ev.PREFIX+'review.v0','proposal_sha256':proposal_hash,
            'evidence_index_sha256':'a'*64,'reviewer':'synthetic-only','decision':'accept','rationale':'test'}
        args=dict(proposal_sha256=proposal_hash,evidence_index_sha256='a'*64)
        self.assertEqual(ev.derive_disposition(gates,execution[0],None,**args),'pending-review')
        self.assertEqual(ev.derive_disposition(gates,execution[0],review,**args),'eligible-for-human-corpus-PR')
        review['decision']='reject'
        self.assertEqual(ev.derive_disposition(gates,execution[0],review,**args),'refused')
        review['decision']='accept';review['evidence_index_sha256']='b'*64
        with self.assertRaises(ev.EvidenceError):
            ev.derive_disposition(gates,execution[0],review,**args)
        self.assertEqual(ev.encode(gates),before)
        review['evidence_index_sha256']='a'*64
        abnormal=copy.deepcopy(execution[0])
        abnormal[3]['raw']['raised']={'<batch>':'unproved'}
        refused=copy.deepcopy(gates);refused[5].update(status='refused',reason='abnormal-execution')
        self.assertEqual(ev.derive_disposition(refused,abnormal,review,**args),'unproved')


class ProjectionParity(unittest.TestCase):
    def test_proposal_shape_agrees_with_installed_validator(self):
        import suggestion_admission as legacy
        doc=json.loads((ROOT/'tests/fixtures/suggestion-v0/good.json').read_bytes())
        for mutation in (lambda x:None, lambda x:x.update(extra=True),
                lambda x:x['vector']['document'].update(value=True),
                lambda x:x['expected'].update(accepted=1),
                lambda x:x['authorship'].update(author_kind='unknown')):
            changed=copy.deepcopy(doc); mutation(changed)
            results=[]
            for validator in (legacy.require_proposal,ev._proposal):
                try: validator(changed)
                except (legacy.AdmissionError,ev.EvidenceError):results.append(False)
                else:results.append(True)
            self.assertEqual(results[0],results[1])

    def test_pure_import_does_not_import_execution_modules(self):
        import subprocess
        script="import sys;sys.path.insert(0,'measurements');import suggestion_evidence;assert not any(x.startswith('aee_checker_sealed_') or x in ('contained_oci','suggestion_admission') for x in sys.modules)"
        result=subprocess.run([sys.executable,'-c',script],cwd=ROOT,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)


class FullEvaluation(unittest.TestCase):
    def test_same_full_evaluator_computes_all_nine_gates(self):
        inputs = prepared_inputs()
        gates = ev.evaluate_assessment(inputs, *wire_execution(inputs))
        self.assertEqual([g['id'] for g in gates], list(range(9)))
        self.assertEqual([g['status'] for g in gates], ['passed']*7+['not-run', 'passed'])

    def test_preflight_refusal_never_requires_or_invents_calls(self):
        inputs=prepared_inputs(); members=dict(inputs.retained_members)
        plan=ev.decode(members['plan.json']);plan['adapter_sha256']='d'*64
        members['plan.json']=ev.encode(plan)
        inputs=ev.AssessmentInputs(tuple(sorted(members.items())),inputs.basis_members)
        h=ev.digest(members['plan.json'])
        journal=[{'schema':ev.PREFIX+'journal-event.v0','seq':n,'plan_sha256':h,
                  'slot':slot,'event':'preflight-refused' if n==0 else 'not-started',
                  'observation':None,'reason':'preflight-refusal' if n==0 else 'prerequisite-refused'}
                 for n,slot in enumerate(plan['slots'])]
        controls=[{'variant':v,'positive':'not-run','inert':'not-run','barrier':'stop'} for v in ev.VARIANTS]
        gates=ev.evaluate_assessment(inputs,[],[],controls,journal)
        self.assertEqual(gates[1]['reason'],'freeze-drift')
        self.assertEqual(gates[8]['status'],'passed')
        self.assertTrue(all(g['status']=='not-run' for g in gates[2:8]))

    def test_view_and_journal_reference_bytes_are_checked(self):
        inputs = prepared_inputs()
        for which in ('view', 'journal'):
            obs, views, controls, journal = wire_execution(inputs)
            target = views[0] if which == 'view' else journal[1]
            target['observation']['sha256'] = '0'*64
            with self.subTest(which=which), self.assertRaises(ev.EvidenceError):
                ev.evaluate_assessment(inputs, obs, views, controls, journal)


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

    def test_omitted_slot_cannot_be_followed_by_resumed_calls(self):
        data=assessment()
        data[0]['reference_rows']['allow']['accepted']=False
        omitted_slot=copy.deepcopy(data[1][3]['slot'])
        data[1].pop(3); self.refresh(data)
        data[4][6:8]=[{'seq':6,'slot':omitted_slot,'event':'not-started','reason':'prerequisite-refused'}]
        for seq,event in enumerate(data[4]):event['seq']=seq
        with self.assertRaises(ev.EvidenceError) as caught:
            self.evaluate(data)
        self.assertEqual(caught.exception.code,'schedule-mismatch')

    def test_missing_duplicate_and_reordered_journal_never_pass(self):
        for edit in (lambda j: j.pop(), lambda j: j.append(copy.deepcopy(j[-1])),
                     lambda j: j.reverse()):
            data = assessment(); edit(data[4])
            with self.subTest(edit=edit), self.assertRaises(ev.EvidenceError):
                self.evaluate(data)


if __name__ == '__main__':
    unittest.main()
