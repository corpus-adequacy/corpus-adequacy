"""Real process prefix: pause before ordinary mutation, no scoring route."""
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import corpus_adequacy as ca
import execution_observation as codec
import observation_session as obs

D = 'sha256:' + 'd' * 64
E = 'sha256:' + 'e' * 64


def corpus(root, count=2):
    root.mkdir()
    (root / 'subject.py').write_text('import json\n# inert zero\nVALUE = 7\nprint(json.dumps({"value":VALUE}))\n')
    (root / 'one.json').write_text('{}\n')
    vectors = [{'id': 'v' + str(i), 'path': 'one.json'} for i in range(count)]
    (root / 'vectors.json').write_text(json.dumps(vectors))
    manifest = {'schema': ca.SCHEMA, 'runner': 'process', 'repo_root': '.',
                'implementation_sources': ['subject.py'], 'build': [],
                'entrypoint_command': [sys.executable, 'subject.py', '{vector}'],
                'vectors': 'vectors.json', 'id_key': 'id', 'vector_path_key': 'path',
                'default_group': 'g', 'outcome_from': 'value',
                'mutants': {'g': [
                    {'label': 'inert', 'anchor': '# inert zero', 'replacement': '# inert one',
                     'control': True, 'control_polarity': 'inert'},
                    {'label': 'positive', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 8',
                     'control': True, 'control_polarity': 'positive'},
                    {'label': 'ordinary', 'anchor': 'VALUE = 7', 'replacement': 'VALUE = 9'},
                ]}}
    path = root / 'manifest.json'; path.write_text(json.dumps(manifest))
    return path


@unittest.skipIf(ca.fcntl is None, 'observation execution requires POSIX advisory locks')
class PrefixExecution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = corpus(self.root / 'subject')

    def run_prefix(self, **changes):
        args = dict(execution_profile='trusted-local', backend=obs.LocalObservationBackend(),
                    context_raw=b'context', output_root=self.root/'evidence',
                    policy_identity=D, interpreter_identity=E)
        args.update(changes)
        return obs.observe_prefix(self.manifest, **args)

    def test_real_prefix_has_raw_controls_pending_ordinary_and_no_score_calls(self):
        before = (self.manifest.parent / 'subject.py').read_bytes()
        with ExitStack() as stack:
            for name in ('_record_control','_control_barrier_allows_ordinary','_finalize_process_tally','_scored_denominator','_report_v0'):
                stack.enter_context(mock.patch.object(ca, name, side_effect=AssertionError(name)))
            path = self.run_prefix()
        doc = codec.load_observation(path.read_bytes(), kind='prefix')
        self.assertEqual(doc['phase'], 'awaiting_admission')
        self.assertEqual([s['state'] for s in doc['steps']], ['complete']*4+['pending'])
        self.assertEqual([[v['outcome'] for v in step['slots']] for step in doc['steps'][1:4]], [[7,7],[7,7],[8,8]])
        self.assertTrue(all(v['receipt'] is None for v in doc['steps'][4]['slots']))
        self.assertEqual((self.manifest.parent/'subject.py').read_bytes(), before)
        for step in doc['steps']:
            for slot in step['slots']:
                if slot['receipt']:
                    h = slot['receipt']['raw_sha256'].removeprefix('sha256:')
                    raw = (path.parent/'blobs'/h).read_bytes()
                    self.assertEqual(codec.sha256(raw), slot['receipt']['raw_sha256'])

    def test_preflight_stop_is_before_substitution_and_closes_full_suffix(self):
        evidence = b'private prerequisite refusal'
        def gate(step, receipts, context_sha256):
            self.assertEqual(len(receipts), 2)
            self.assertEqual(context_sha256, codec.sha256(b'context'))
            with self.assertRaises(TypeError): step['label'] = 'tampered'
            return obs._ObservationStop(step['step_id'], 'operator-prerequisite-refused', codec.sha256(evidence), evidence)
        with mock.patch.object(ca, '_execute_mutation_observation', side_effect=AssertionError('source mutation')):
            path = self.run_prefix(control_preflight=gate)
        doc = codec.load_observation(path.read_bytes(), kind='prefix')
        self.assertEqual(doc['phase'], 'stopped')
        self.assertEqual([s['state'] for s in doc['steps']], ['complete','complete','stopped','not_run','not_run'])
        self.assertTrue(all(v['state']=='not_run' for s in doc['steps'][2:] for v in s['slots']))

    def test_wrong_preflight_binding_refuses_before_mutation(self):
        def gate(step, receipts, context_sha256):
            return obs._ObservationProceed('other', D, b'wrong')
        with mock.patch.object(ca, '_execute_mutation_observation', side_effect=AssertionError('source mutation')):
            with self.assertRaises((ValueError, ca.ManifestError)): self.run_prefix(control_preflight=gate)

    def test_preflight_cannot_change_declared_source_outside_mutation(self):
        sources = []
        class Tracked(obs.LocalObservationBackend):
            backend_identity = D
            environment_identity = E
            def __call__(self, manifest, *args, **kwargs):
                sources[:] = manifest['_source_paths']
                return super().__call__(manifest, *args, **kwargs)
        def gate(step, receipts, context_sha256):
            sources[0].write_text(sources[0].read_text() + '# undeclared change\n')
            evidence = b'proceed'
            return obs._ObservationProceed(step['step_id'], codec.sha256(evidence), evidence)
        with mock.patch.object(ca, '_execute_mutation_observation', side_effect=AssertionError('mutation reached')):
            with self.assertRaises(ca.ManifestError): self.run_prefix(backend=Tracked(), control_preflight=gate)

    def test_ordinary_backend_is_never_called_by_prefix(self):
        calls = []
        class Tracked(obs.LocalObservationBackend):
            backend_identity = D
            environment_identity = E
            def __call__(self, manifest, *args, **kwargs):
                calls.append(kwargs['step']['kind'])
                if kwargs['step']['kind'] == 'mutant': raise AssertionError('ordinary executed')
                return super().__call__(manifest, *args, **kwargs)
        self.run_prefix(backend=Tracked())
        # Build-only + one call per vector; still no ordinary mutation.
        self.assertEqual(calls, ['build'] + ['baseline']*2 + ['control']*6)

    def test_vector_only_failure_retains_executed_prefix_without_final(self):
        class BadVectorBackend(obs.LocalObservationBackend):
            backend_identity=D; environment_identity=E
            def __call__(self,m,vectors=None,*,rebuild=True,step,observation):
                if vectors and vectors[0]['id']=='v1':
                    return obs._ObservationExecution(ca._ProcessExecution(False,'invalid vector status',{}, {}, {}, {}),())
                return super().__call__(m,vectors,rebuild=rebuild,step=step,observation=observation)
        with self.assertRaisesRegex(ca.ManifestError,'vector-only'):
            self.run_prefix(backend=BadVectorBackend())
        root=next((self.root/'evidence').iterdir())
        self.assertFalse((root/'prefix.json').exists())
        self.assertEqual(len(list(root.glob('receipt-*.json'))),1)
        self.assertEqual(len(list(root.glob('dispatch-*.json'))),2)
        self.assertEqual(json.loads((root/'interrupted.json').read_bytes())['state'],'unclosed')

    def test_build_failure_is_build_only_and_no_child_runs(self):
        doc = json.loads(self.manifest.read_text()); doc['build'] = [sys.executable,'-c','raise SystemExit(1)']
        self.manifest.write_text(json.dumps(doc))
        with mock.patch.object(obs, 'run_capped_bytes', side_effect=AssertionError('vector child')):
            path = self.run_prefix()
        prefix = codec.load_observation(path.read_bytes(), kind='prefix')
        self.assertEqual(prefix['phase'], 'stopped')
        self.assertEqual(prefix['steps'][0]['slots'], [])
        self.assertTrue(all(s['state']=='not_run' for s in prefix['steps'][1:]))

    def test_six_vectors_and_unmoving_positive_control_still_pause(self):
        doc = json.loads(self.manifest.read_text())
        doc['mutants']['g'][1]['anchor'] = '# inert zero'; doc['mutants']['g'][1]['replacement'] = '# another comment'
        self.manifest.write_text(json.dumps(doc))
        (self.manifest.parent/'vectors.json').write_text(json.dumps([{'id':'v'+str(i),'path':'one.json'} for i in range(6)]))
        prefix = codec.load_observation(self.run_prefix().read_bytes(), kind='prefix')
        self.assertEqual(prefix['phase'],'awaiting_admission')
        self.assertEqual([v['outcome'] for v in prefix['steps'][3]['slots']], [7]*6)

    def test_selector_missing_stops_instead_of_becoming_observation(self):
        (self.manifest.parent/'subject.py').write_text('print("{}")\n# inert zero\nVALUE = 7\n')
        prefix = codec.load_observation(self.run_prefix().read_bytes(), kind='prefix')
        self.assertEqual(prefix['phase'], 'stopped')
        self.assertEqual(prefix['steps'][1]['slots'][0]['state'], 'abnormal')
        self.assertEqual(prefix['steps'][1]['slots'][1]['state'], 'not_run')
        self.assertEqual(prefix['closure']['reason'], 'selector-missing')

    def test_backend_exception_keeps_completed_evidence_but_no_valid_prefix(self):
        class Broken(obs.LocalObservationBackend):
            backend_identity = D
            environment_identity = E
            def __call__(self, manifest, *args, **kwargs):
                if kwargs['step']['kind'] == 'control': raise RuntimeError('backend interrupted')
                return super().__call__(manifest, *args, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'backend interrupted'):
            self.run_prefix(backend=Broken())
        roots = list((self.root/'evidence').iterdir()); self.assertEqual(len(roots),1)
        self.assertFalse((roots[0]/'prefix.json').exists())
        interrupted = json.loads((roots[0]/'interrupted.json').read_bytes())
        self.assertEqual(interrupted['state'], 'unclosed')
        self.assertTrue(interrupted['cleanup']['restored'])
        completed = json.loads((roots[0]/'step-0001.json').read_bytes())
        self.assertEqual([v['outcome'] for v in completed['slots']], [7,7])

    def test_cleanup_failure_never_yields_awaiting_admission(self):
        import shutil
        retained = []
        def leave_tree(tree): retained.append(tree.root)
        try:
            with mock.patch.object(ca.IsolatedMutationTree, 'cleanup', leave_tree):
                prefix = codec.load_observation(self.run_prefix().read_bytes(), kind='prefix')
            self.assertEqual(prefix['phase'], 'stopped')
            self.assertFalse(prefix['cleanup']['isolated_tree_removed'])
            self.assertEqual(prefix['closure']['reason'], 'cleanup-failed')
        finally:
            for path in retained:
                if path is not None and path.exists(): shutil.rmtree(path)

    def test_output_inside_subject_and_candidate_mode_and_equivalence_refuse(self):
        with self.assertRaises((ValueError, ca.ManifestError)):
            self.run_prefix(output_root=self.manifest.parent/'evidence')
        original = json.loads(self.manifest.read_text())
        for key, value in [('observation_mode',True), ('equivalent', {'g':[{'label':'excluded','reason':'external projection'}]})]:
            doc = dict(original); doc[key] = value; self.manifest.write_text(json.dumps(doc))
            with self.subTest(key=key), self.assertRaises((ValueError, ca.ManifestError)):
                self.run_prefix()


if __name__ == '__main__': unittest.main()
